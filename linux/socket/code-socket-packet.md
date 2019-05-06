# Linux Packet Socket

Packet Socket 可以用于捕获进入内核协议栈的以太网报文，并且直接发送以太网报文的能力， 用于tcpdump、pcap等应用软件

## Packet Socket创建

```c
static const struct net_proto_family packet_family_ops = {
	.family =	PF_PACKET,
	.create =	packet_create,
	.owner	=	THIS_MODULE,
};

static int packet_create(struct net *net, struct socket *sock, int protocol,
			 int kern)
{
	struct sock *sk;
	struct packet_sock *po;
	__be16 proto = (__force __be16)protocol; /* weird, but documented */
	int err;

	if (!ns_capable(net->user_ns, CAP_NET_RAW))
		return -EPERM;
	if (sock->type != SOCK_DGRAM && sock->type != SOCK_RAW &&	//仅支持这三类socket
	    sock->type != SOCK_PACKET)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	err = -ENOBUFS;
	sk = sk_alloc(net, PF_PACKET, GFP_KERNEL, &packet_proto);	//创建sock对象
	if (sk == NULL)
		goto out;

	sock->ops = &packet_ops;
	if (sock->type == SOCK_PACKET)
		sock->ops = &packet_ops_spkt;	//SOCK_PACKET类型的socket和其他的两种有差别

	sock_init_data(sock, sk);	//初始化sock对象

	po = pkt_sk(sk);
	sk->sk_family = PF_PACKET;
	po->num = proto;
	po->xmit = dev_queue_xmit;	//发送报文的方式是直接二层发包，需要用户构建完整的二层报文

	err = packet_alloc_pending(po);
	if (err)
		goto out2;

	packet_cached_dev_reset(po);

	sk->sk_destruct = packet_sock_destruct;
	sk_refcnt_debug_inc(sk);

	/*
	 *	Attach a protocol block
	 */

	spin_lock_init(&po->bind_lock);
	mutex_init(&po->pg_vec_lock);
	po->prot_hook.func = packet_rcv;

	if (sock->type == SOCK_PACKET)		//SOCK_PACKET类型的socket与其他两种不同
		po->prot_hook.func = packet_rcv_spkt;

	po->prot_hook.af_packet_priv = sk;	 //packet_rcv函数中，会根据该值，匹配到sock，然后交给sock收包处理

	if (proto) { 
		po->prot_hook.type = proto;	 //协议类型，匹配到协议类型时，会调用packet_rcv函数
		register_prot_hook(sk);		 //注册到协议处理中，这是实现抓包的关键，注册到ptype_all或ptype_base
	}

	mutex_lock(&net->packet.sklist_lock);
	sk_add_node_rcu(sk, &net->packet.sklist);
	mutex_unlock(&net->packet.sklist_lock);

	preempt_disable();
	sock_prot_inuse_add(net, &packet_proto, 1);
	preempt_enable();

	return 0;
out2:
	sk_free(sk);
out:
	return err;
}
```

## Packet Socket收包处理

从收包函数可以看到Packet Socket可以收到完整的以太网报文，例如Weave sleeve容器网络方案。

```c
static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct sockaddr_ll *sll;
	struct packet_sock *po;
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	unsigned int snaplen, res;

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto drop;

	sk = pt->af_packet_priv;
	po = pkt_sk(sk);

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	skb->dev = dev;

	if (dev->header_ops) {
		/* The device has an explicit notion of ll header,
		 * exported to higher levels.
		 *
		 * Otherwise, the device hides details of its frame
		 * structure, so that corresponding packet head is
		 * never delivered to user.
		 */
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));    //skb退回到mac头，上层应用可以收到完整的二层包
		else if (skb->pkt_type == PACKET_OUTGOING) {
			/* Special case: outgoing packets have ll header at head */
			skb_pull(skb, skb_network_offset(skb));
		}
	}

	snaplen = skb->len;

	res = run_filter(skb, sk, snaplen);    //执行过滤
	if (!res)
		goto drop_n_restore;
	if (snaplen > res)
		snaplen = res;

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		goto drop_n_acct;

	if (skb_shared(skb)) {
		struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);
		if (nskb == NULL)
			goto drop_n_acct;

		if (skb_head != skb->data) {
			skb->data = skb_head;
			skb->len = skb_len;
		}
		consume_skb(skb);
		skb = nskb;
	}

	sock_skb_cb_check_size(sizeof(*PACKET_SKB_CB(skb)) + MAX_ADDR_LEN - 8);

	sll = &PACKET_SKB_CB(skb)->sa.ll;
	sll->sll_hatype = dev->type;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);

	/* sll->sll_family and sll->sll_protocol are set in packet_recvmsg().
	 * Use their space for storing the original skb length.
	 */
	PACKET_SKB_CB(skb)->sa.origlen = skb->len;

	if (pskb_trim(skb, snaplen))
		goto drop_n_acct;

	skb_set_owner_r(skb, sk);
	skb->dev = NULL;
	skb_dst_drop(skb);

	/* drop conntrack reference */
	nf_reset(skb);

	spin_lock(&sk->sk_receive_queue.lock);
	po->stats.stats1.tp_packets++;
	sock_skb_set_dropcount(sk, skb);
	__skb_queue_tail(&sk->sk_receive_queue, skb);     //上送到sock收包队列
	spin_unlock(&sk->sk_receive_queue.lock);
	sk->sk_data_ready(sk);
	return 0;

drop_n_acct:
	spin_lock(&sk->sk_receive_queue.lock);
	po->stats.stats1.tp_drops++;
	atomic_inc(&sk->sk_drops);
	spin_unlock(&sk->sk_receive_queue.lock);

drop_n_restore:
	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
drop:
	consume_skb(skb);
	return 0;
}

static int packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
			   struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct sockaddr_pkt *spkt;

	/*
	 *	When we registered the protocol we saved the socket in the data
	 *	field for just this event.
	 */

	sk = pt->af_packet_priv;

	/*
	 *	Yank back the headers [hope the device set this
	 *	right or kerboom...]
	 *
	 *	Incoming packets have ll header pulled,
	 *	push it back.
	 *
	 *	For outgoing ones skb->data == skb_mac_header(skb)
	 *	so that this procedure is noop.
	 */

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto out;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto out;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (skb == NULL)
		goto oom;

	/* drop any routing info */
	skb_dst_drop(skb);

	/* drop conntrack reference */
	nf_reset(skb);

	spkt = &PACKET_SKB_CB(skb)->sa.pkt;

	skb_push(skb, skb->data - skb_mac_header(skb));    //skb退回到mac头，上层应用可以收到完整的二层包

	/*
	 *	The SOCK_PACKET socket receives _all_ frames.
	 */

	spkt->spkt_family = dev->type;
	strlcpy(spkt->spkt_device, dev->name, sizeof(spkt->spkt_device));
	spkt->spkt_protocol = skb->protocol;

	/*
	 *	Charge the memory to the socket. This is done specifically
	 *	to prevent sockets using all the memory up.
	 */

	if (sock_queue_rcv_skb(sk, skb) == 0)   //上送到sock收包队列
		return 0;

out:
	kfree_skb(skb);
oom:
	return 0;
}
```


## Packet Socket发包流程

```c
static const struct proto_ops packet_ops = {
	.family =	PF_PACKET,
	.owner =	THIS_MODULE,
	.release =	packet_release,
	.bind =		packet_bind,
	.connect =	sock_no_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	packet_getname,
	.poll =		packet_poll,
	.ioctl =	packet_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	packet_setsockopt,
	.getsockopt =	packet_getsockopt,
	.sendmsg =	packet_sendmsg,    //发包函数入口
	.recvmsg =	packet_recvmsg,
	.mmap =		packet_mmap,
	.sendpage =	sock_no_sendpage,
};

static int packet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct packet_sock *po = pkt_sk(sk);

	if (po->tx_ring.pg_vec)
		return tpacket_snd(po, msg);
	else
		return packet_snd(sock, msg, len);
}

//直接封装二层报文，并用dev_queue_xmit发送报文
static int tpacket_snd(struct packet_sock *po, struct msghdr *msg)
{
	struct sk_buff *skb;
	struct net_device *dev;
	__be16 proto;
	int err, reserve = 0;
	void *ph;
	DECLARE_SOCKADDR(struct sockaddr_ll *, saddr, msg->msg_name);
	bool need_wait = !(msg->msg_flags & MSG_DONTWAIT);
	int tp_len, size_max;
	unsigned char *addr;
	int len_sum = 0;
	int status = TP_STATUS_AVAILABLE;
	int hlen, tlen;

	mutex_lock(&po->pg_vec_lock);

	if (likely(saddr == NULL)) {
		dev	= packet_cached_dev_get(po);
		proto	= po->num;
		addr	= NULL;
	} else {
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(struct sockaddr_ll))
			goto out;
		if (msg->msg_namelen < (saddr->sll_halen
					+ offsetof(struct sockaddr_ll,
						sll_addr)))
			goto out;
		proto	= saddr->sll_protocol;
		addr	= saddr->sll_addr;
		dev = dev_get_by_index(sock_net(&po->sk), saddr->sll_ifindex);
	}

	err = -ENXIO;
	if (unlikely(dev == NULL))
		goto out;
	err = -ENETDOWN;
	if (unlikely(!(dev->flags & IFF_UP)))
		goto out_put;

	reserve = dev->hard_header_len + VLAN_HLEN;
	size_max = po->tx_ring.frame_size
		- (po->tp_hdrlen - sizeof(struct sockaddr_ll));

	if (size_max > dev->mtu + reserve)
		size_max = dev->mtu + reserve;

	do {
		ph = packet_current_frame(po, &po->tx_ring,
					  TP_STATUS_SEND_REQUEST);
		if (unlikely(ph == NULL)) {
			if (need_wait && need_resched())
				schedule();
			continue;
		}

		status = TP_STATUS_SEND_REQUEST;
		hlen = LL_RESERVED_SPACE(dev);
		tlen = dev->needed_tailroom;
		skb = sock_alloc_send_skb(&po->sk,
				hlen + tlen + sizeof(struct sockaddr_ll),
				!need_wait, &err);

		if (unlikely(skb == NULL)) {
			/* we assume the socket was initially writeable ... */
			if (likely(len_sum > 0))
				err = len_sum;
			goto out_status;
		}
		tp_len = tpacket_fill_skb(po, skb, ph, dev, size_max, proto,
					  addr, hlen);
		if (likely(tp_len >= 0) &&
		    tp_len > dev->mtu + dev->hard_header_len) {
			struct ethhdr *ehdr;
			/* Earlier code assumed this would be a VLAN pkt,
			 * double-check this now that we have the actual
			 * packet in hand.
			 */

			skb_reset_mac_header(skb);
			ehdr = eth_hdr(skb);
			if (ehdr->h_proto != htons(ETH_P_8021Q))
				tp_len = -EMSGSIZE;
		}
		if (unlikely(tp_len < 0)) {
			if (po->tp_loss) {
				__packet_set_status(po, ph,
						TP_STATUS_AVAILABLE);
				packet_increment_head(&po->tx_ring);
				kfree_skb(skb);
				continue;
			} else {
				status = TP_STATUS_WRONG_FORMAT;
				err = tp_len;
				goto out_status;
			}
		}

		packet_pick_tx_queue(dev, skb); 

		skb->destructor = tpacket_destruct_skb;
		__packet_set_status(po, ph, TP_STATUS_SENDING);
		packet_inc_pending(&po->tx_ring);

		status = TP_STATUS_SEND_REQUEST;
		err = po->xmit(skb);                //二层报文发送
		if (unlikely(err > 0)) {
			err = net_xmit_errno(err);
			if (err && __packet_get_status(po, ph) ==
				   TP_STATUS_AVAILABLE) {
				/* skb was destructed already */
				skb = NULL;
				goto out_status;
			}
			/*
			 * skb was dropped but not destructed yet;
			 * let's treat it like congestion or err < 0
			 */
			err = 0;
		}
		packet_increment_head(&po->tx_ring);
		len_sum += tp_len;
	} while (likely((ph != NULL) ||
		/* Note: packet_read_pending() might be slow if we have
		 * to call it as it's per_cpu variable, but in fast-path
		 * we already short-circuit the loop with the first
		 * condition, and luckily don't have to go that path
		 * anyway.
		 */
		 (need_wait && packet_read_pending(&po->tx_ring))));

	err = len_sum;
	goto out_put;

out_status:
	__packet_set_status(po, ph, status);
	kfree_skb(skb);
out_put:
	dev_put(dev);
out:
	mutex_unlock(&po->pg_vec_lock);
	return err;
}

//直接封装二层报文，并用dev_queue_xmit发送报文
static int packet_snd(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	DECLARE_SOCKADDR(struct sockaddr_ll *, saddr, msg->msg_name);
	struct sk_buff *skb;
	struct net_device *dev;
	__be16 proto;
	unsigned char *addr;
	int err, reserve = 0;
	struct virtio_net_hdr vnet_hdr = { 0 };
	int offset = 0;
	int vnet_hdr_len;
	struct packet_sock *po = pkt_sk(sk);
	unsigned short gso_type = 0;
	int hlen, tlen;
	int extra_len = 0;
	ssize_t n;

	/*
	 *	Get and verify the address.
	 */

	if (likely(saddr == NULL)) {
		dev	= packet_cached_dev_get(po);     //获取发包设备，之前收包时缓存
		proto	= po->num;
		addr	= NULL;
	} else {
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(struct sockaddr_ll))
			goto out;
		if (msg->msg_namelen < (saddr->sll_halen + offsetof(struct sockaddr_ll, sll_addr)))
			goto out;
		proto	= saddr->sll_protocol;
		addr	= saddr->sll_addr;
		dev = dev_get_by_index(sock_net(sk), saddr->sll_ifindex);
	}

	err = -ENXIO;
	if (unlikely(dev == NULL))
		goto out_unlock;
	err = -ENETDOWN;
	if (unlikely(!(dev->flags & IFF_UP)))
		goto out_unlock;

	if (sock->type == SOCK_RAW)
		reserve = dev->hard_header_len;
	if (po->has_vnet_hdr) {
		vnet_hdr_len = sizeof(vnet_hdr);

		err = -EINVAL;
		if (len < vnet_hdr_len)
			goto out_unlock;

		len -= vnet_hdr_len;

		err = -EFAULT;
		n = copy_from_iter(&vnet_hdr, vnet_hdr_len, &msg->msg_iter);
		if (n != vnet_hdr_len)
			goto out_unlock;

		if ((vnet_hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    (__virtio16_to_cpu(false, vnet_hdr.csum_start) +
		     __virtio16_to_cpu(false, vnet_hdr.csum_offset) + 2 >
		      __virtio16_to_cpu(false, vnet_hdr.hdr_len)))
			vnet_hdr.hdr_len = __cpu_to_virtio16(false,
				 __virtio16_to_cpu(false, vnet_hdr.csum_start) +
				__virtio16_to_cpu(false, vnet_hdr.csum_offset) + 2);

		err = -EINVAL;
		if (__virtio16_to_cpu(false, vnet_hdr.hdr_len) > len)
			goto out_unlock;

		if (vnet_hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
			switch (vnet_hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
			case VIRTIO_NET_HDR_GSO_TCPV4:
				gso_type = SKB_GSO_TCPV4;
				break;
			case VIRTIO_NET_HDR_GSO_TCPV6:
				gso_type = SKB_GSO_TCPV6;
				break;
			case VIRTIO_NET_HDR_GSO_UDP:
				gso_type = SKB_GSO_UDP;
				break;
			default:
				goto out_unlock;
			}

			if (vnet_hdr.gso_type & VIRTIO_NET_HDR_GSO_ECN)
				gso_type |= SKB_GSO_TCP_ECN;

			if (vnet_hdr.gso_size == 0)
				goto out_unlock;

		}
	}

	if (unlikely(sock_flag(sk, SOCK_NOFCS))) {
		if (!netif_supports_nofcs(dev)) {
			err = -EPROTONOSUPPORT;
			goto out_unlock;
		}
		extra_len = 4; /* We're doing our own CRC */
	}

	err = -EMSGSIZE;
	if (!gso_type && (len > dev->mtu + reserve + VLAN_HLEN + extra_len))
		goto out_unlock;

	err = -ENOBUFS;
	hlen = LL_RESERVED_SPACE(dev);
	tlen = dev->needed_tailroom;
	skb = packet_alloc_skb(sk, hlen + tlen, hlen, len,
			       __virtio16_to_cpu(false, vnet_hdr.hdr_len),
			       msg->msg_flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto out_unlock;

	skb_set_network_header(skb, reserve);

	err = -EINVAL;
	if (sock->type == SOCK_DGRAM) {
		offset = dev_hard_header(skb, dev, ntohs(proto), addr, NULL, len);
		if (unlikely(offset < 0))
			goto out_free;
	} else {
		if (ll_header_truncated(dev, len))
			goto out_free;
	}

	/* Returns -EFAULT on error */
	err = skb_copy_datagram_from_iter(skb, offset, &msg->msg_iter, len);
	if (err)
		goto out_free;

	sock_tx_timestamp(sk, &skb_shinfo(skb)->tx_flags);

	if (!gso_type && (len > dev->mtu + reserve + extra_len)) {
		/* Earlier code assumed this would be a VLAN pkt,
		 * double-check this now that we have the actual
		 * packet in hand.
		 */
		struct ethhdr *ehdr;
		skb_reset_mac_header(skb);
		ehdr = eth_hdr(skb);
		if (ehdr->h_proto != htons(ETH_P_8021Q)) {
			err = -EMSGSIZE;
			goto out_free;
		}
	}

	skb->protocol = proto;
	skb->dev = dev;
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	packet_pick_tx_queue(dev, skb);

	if (po->has_vnet_hdr) {
		if (vnet_hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
			u16 s = __virtio16_to_cpu(false, vnet_hdr.csum_start);
			u16 o = __virtio16_to_cpu(false, vnet_hdr.csum_offset);
			if (!skb_partial_csum_set(skb, s, o)) {
				err = -EINVAL;
				goto out_free;
			}
		}

		skb_shinfo(skb)->gso_size =
			__virtio16_to_cpu(false, vnet_hdr.gso_size);
		skb_shinfo(skb)->gso_type = gso_type;

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;

		len += vnet_hdr_len;
	}

	if (!packet_use_direct_xmit(po))
		skb_probe_transport_header(skb, reserve);
	if (unlikely(extra_len == 4))
		skb->no_fcs = 1;

	err = po->xmit(skb);   //二层报文发送
	if (err > 0 && (err = net_xmit_errno(err)) != 0)
		goto out_unlock;

	dev_put(dev);

	return len;

out_free:
	kfree_skb(skb);
out_unlock:
	if (dev)
		dev_put(dev);
out:
	return err;
}
```

