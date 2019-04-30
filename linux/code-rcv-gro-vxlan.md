# VXLAN GRO

VXLAN作为当前云数据中心主流的网络虚拟化方案，支持VXLAN GRO功能对性能有显著提升。


## 基础数据结构

```c
static const struct net_offload udpv4_offload = {
	.callbacks = {
		.gso_segment = udp4_ufo_fragment,
		.gro_receive  =	udp4_gro_receive,
		.gro_complete =	udp4_gro_complete,
	},
};
```


## 注册vxlan gro收包函数

```c
static struct vxlan_sock *vxlan_socket_create(struct net *net, __be16 port,
					      vxlan_rcv_t *rcv, void *data,
					      u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct socket *sock;
	unsigned int h;
	bool ipv6 = !!(flags & VXLAN_F_IPV6);
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL);
	if (!vs)
		return ERR_PTR(-ENOMEM);

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vs->vni_list[h]);

	INIT_WORK(&vs->del_work, vxlan_del_work);

	sock = vxlan_create_sock(net, ipv6, port, flags);
	if (IS_ERR(sock)) {
		pr_info("Cannot bind port %d, err=%ld\n", ntohs(port),
			PTR_ERR(sock));
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	atomic_set(&vs->refcnt, 1);
	vs->rcv = rcv;
	vs->data = data;
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

	/* Initialize the vxlan udp offloads structure */
	vs->udp_offloads.port = port;
	vs->udp_offloads.callbacks.gro_receive  = vxlan_gro_receive;   
	vs->udp_offloads.callbacks.gro_complete = vxlan_gro_complete;

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));
	vxlan_notify_add_rx_port(vs);
	spin_unlock(&vn->sock_lock);

	/* Mark socket as an encapsulation socket. */
	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_udp_encap_recv;
	tunnel_cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);

	return vs;
}

static void vxlan_notify_add_rx_port(struct vxlan_sock *vs)
{
	struct net_device *dev;
	struct sock *sk = vs->sock->sk;
	struct net *net = sock_net(sk);
	sa_family_t sa_family = sk->sk_family;
	__be16 port = inet_sk(sk)->inet_sport;
	int err;

	if (sa_family == AF_INET) {
		err = udp_add_offload(&vs->udp_offloads);
		if (err)
			pr_warn("vxlan: udp_add_offload failed with status %d\n", err);
	}

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (dev->netdev_ops->ndo_add_vxlan_port)
			dev->netdev_ops->ndo_add_vxlan_port(dev, sa_family,
							    port);
	}
	rcu_read_unlock();
}

int udp_add_offload(struct udp_offload *uo)
{
	struct udp_offload_priv *new_offload = kzalloc(sizeof(*new_offload), GFP_ATOMIC);

	if (!new_offload)
		return -ENOMEM;

	new_offload->offload = uo;

	spin_lock(&udp_offload_lock);
	new_offload->next = udp_offload_base;
	rcu_assign_pointer(udp_offload_base, new_offload);  //添加到udp gro 链表中
	spin_unlock(&udp_offload_lock);

	return 0;
}
```


## UDP GRO收包

```c
static struct sk_buff **udp4_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	struct udphdr *uh = udp_gro_udphdr(skb);	//取到UDP头指针

	if (unlikely(!uh))
		goto flush;

	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (NAPI_GRO_CB(skb)->flush)	//如果flush已经置1，则不进行csum计算
		goto skip;

    //如果csum check失败，则直接flush报文到协议栈
	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,	
						 inet_gro_compute_pseudo))
		goto flush;
	else if (uh->check)	//如果csum_cnt为0，且csum_valid为false使用新计算的伪首部的csum值
		skb_gro_checksum_try_convert(skb, IPPROTO_UDP, uh->check,	
					     inet_gro_compute_pseudo);
skip:
	NAPI_GRO_CB(skb)->is_ipv6 = 0;
	return udp_gro_receive(head, skb, uh);	

flush:
	NAPI_GRO_CB(skb)->flush = 1; //刷新当前报文的flush，调用vxlan等offload后，可能会刷新
	return NULL;
}

struct sk_buff **udp_gro_receive(struct sk_buff **head, struct sk_buff *skb,
				 struct udphdr *uh)
{
	struct udp_offload_priv *uo_priv;
	struct sk_buff *p, **pp = NULL;
	struct udphdr *uh2;
	unsigned int off = skb_gro_offset(skb);	
	int flush = 1;

	if (NAPI_GRO_CB(skb)->udp_mark ||	//如果udp_mark已经被标记
	    (skb->ip_summed != CHECKSUM_PARTIAL &&	//或者ip_summed不等于CHECKSUM_PARTIAL
	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&		//且csum_cnt等于0且csum_valid等于0
	     !NAPI_GRO_CB(skb)->csum_valid))		//直接flush该报文
		goto out;

	/* mark that this skb passed once through the udp gro layer */
	NAPI_GRO_CB(skb)->udp_mark = 1;		//udp_mark置1，避免下次再进入

	rcu_read_lock();
	uo_priv = rcu_dereference(udp_offload_base);
	for (; uo_priv != NULL; uo_priv = rcu_dereference(uo_priv->next)) {
		if (uo_priv->offload->port == uh->dest &&
		    uo_priv->offload->callbacks.gro_receive)  //根据UDP报文目的端口，找到udp_offload对象，例如vxlan报文
			goto unflush;
	}
	goto out_unlock;

unflush:
	flush = 0;

	for (p = *head; p; p = p->next) {	//遍历gro_list中的报文
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = (struct udphdr   *)(p->data + off);	//得到UDP头

		/* Match ports and either checksums are either both zero
		 * or nonzero.
		 */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||	//UDP判断同一条流的条件是：源端口和目的端口一致
		    (!uh->check ^ !uh2->check)) {		//csum要么同为0要么同不为零
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	skb_gro_pull(skb, sizeof(struct udphdr)); /* pull encapsulating udp header */	//报文移到vxlan头或其他的
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));		//刷新csum值
	NAPI_GRO_CB(skb)->proto = uo_priv->offload->ipproto;
	pp = uo_priv->offload->callbacks.gro_receive(head, skb,			//调用vxlan offload等
						     uo_priv->offload);

out_unlock:
	rcu_read_unlock();
out:
	NAPI_GRO_CB(skb)->flush |= flush;	//刷新当前报文的flush，调用四层offload后，可能会刷新
	return pp;
}

static int udp4_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct iphdr *iph = ip_hdr(skb);		//得到IP头
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);	//得到UDP头

	if (uh->check) {
		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;	//如果check不为0，设置为tunnel csum
		uh->check = ~udp_v4_check(skb->len - nhoff, iph->saddr,	//刷新check值
					  iph->daddr, 0);
	} else {
		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;	//check为0，则设置非csum
	}

	return udp_gro_complete(skb, nhoff);
}
```

###  UDP GRO complete

```c
int udp_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct udp_offload_priv *uo_priv;
	__be16 newlen = htons(skb->len - nhoff);	//udp报文的新长度
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);	//得到UDP头
	int err = -ENOSYS;

	uh->len = newlen;	//设置UDP头中报文新的长度

	rcu_read_lock();

	uo_priv = rcu_dereference(udp_offload_base);
	for (; uo_priv != NULL; uo_priv = rcu_dereference(uo_priv->next)) {
		if (uo_priv->offload->port == uh->dest &&
		    uo_priv->offload->callbacks.gro_complete)	//得到下一层的offload，例如vxlan
			break;
	}

	if (uo_priv) {
		NAPI_GRO_CB(skb)->proto = uo_priv->offload->ipproto;
		err = uo_priv->offload->callbacks.gro_complete(skb,	//调用下一层的gro_complete函数，例如vxlan
				nhoff + sizeof(struct udphdr),
				uo_priv->offload);
	}

	rcu_read_unlock();

	if (skb->remcsum_offload)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TUNNEL_REMCSUM;	

	skb->encapsulation = 1;		//设置encapsulation为1
	skb_set_inner_mac_header(skb, nhoff + sizeof(struct udphdr));	//设置inner mace header

	return err;
}
```


## VXLAN GRO收包

```c
static struct sk_buff **vxlan_gro_receive(struct sk_buff **head,
					  struct sk_buff *skb,
					  struct udp_offload *uoff)
{
	struct sk_buff *p, **pp = NULL;
	struct vxlanhdr *vh, *vh2;
	unsigned int hlen, off_vx;
	int flush = 1;
	struct vxlan_sock *vs = container_of(uoff, struct vxlan_sock,	//通过udp_offload对象获得vxlan_sock对象
					     udp_offloads);
	u32 flags;
	struct gro_remcsum grc;

	skb_gro_remcsum_init(&grc);	//初始化grc

	off_vx = skb_gro_offset(skb);
	hlen = off_vx + sizeof(*vh);
	vh   = skb_gro_header_fast(skb, off_vx);	//得到vxlan头
	if (skb_gro_header_hard(skb, hlen)) {
		vh = skb_gro_header_slow(skb, hlen, off_vx);
		if (unlikely(!vh))
			goto out;
	}

	//移动到数据区，实际是内层mac头
	skb_gro_pull(skb, sizeof(struct vxlanhdr)); /* pull vxlan header */	
	skb_gro_postpull_rcsum(skb, vh, sizeof(struct vxlanhdr));	//csum值刷新

	flags = ntohl(vh->vx_flags);

	//即发送方携带SKB_GSO_TUNNEL_REMCSUM标记
	if ((flags & VXLAN_HF_RCO) && (vs->flags & VXLAN_F_REMCSUM_RX)) {	
		vh = vxlan_gro_remcsum(skb, off_vx, vh, sizeof(struct vxlanhdr),	//remcsum校验和刷新
				       ntohl(vh->vx_vni), &grc,
				       !!(vs->flags &
					  VXLAN_F_REMCSUM_NOPARTIAL));

		if (!vh)		//校验不通过，提交当前报文到协议栈
			goto out;
	}

	flush = 0;

	for (p = *head; p; p = p->next) {		//遍历gro_list中的报文
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		vh2 = (struct vxlanhdr *)(p->data + off_vx);
		if (vh->vx_flags != vh2->vx_flags ||	//flags和vni相同才是同一个流
		    vh->vx_vni != vh2->vx_vni) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	pp = eth_gro_receive(head, skb);	//调用mac层的gro_receive

out:
	skb_gro_remcsum_cleanup(skb, &grc);	//check值恢复
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

struct sk_buff **eth_gro_receive(struct sk_buff **head,
				 struct sk_buff *skb)
{
	struct sk_buff *p, **pp = NULL;
	struct ethhdr *eh, *eh2;
	unsigned int hlen, off_eth;
	const struct packet_offload *ptype;
	__be16 type;
	int flush = 1;

	off_eth = skb_gro_offset(skb);
	hlen = off_eth + sizeof(*eh);
	eh = skb_gro_header_fast(skb, off_eth);		//得到mac头
	if (skb_gro_header_hard(skb, hlen)) {
		eh = skb_gro_header_slow(skb, hlen, off_eth);
		if (unlikely(!eh))
			goto out;
	}

	flush = 0;

	for (p = *head; p; p = p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		eh2 = (struct ethhdr *)(p->data + off_eth);
		if (compare_ether_header(eh, eh2)) {		//mac头相同则为同一个流
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	type = eh->h_proto;	//得到3层协议类型，例如IPV4协议

	rcu_read_lock();
	ptype = gro_find_receive_by_type(type);
	if (ptype == NULL) {
		flush = 1;
		goto out_unlock;
	}

	skb_gro_pull(skb, sizeof(*eh));		//报文移到IP头
	skb_gro_postpull_rcsum(skb, eh, sizeof(*eh));	//刷新csum值
	pp = ptype->callbacks.gro_receive(head, skb);	//调用ip层的gro_receive函数

out_unlock:
	rcu_read_unlock();
out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}
```


###  VXLAN GRO complete

```c
static int vxlan_gro_complete(struct sk_buff *skb, int nhoff,
			      struct udp_offload *uoff)
{
	udp_tunnel_gro_complete(skb, nhoff);	//设置skb_shinfo(skb)->gso_type值

	return eth_gro_complete(skb, nhoff + sizeof(struct vxlanhdr));
}

static inline void udp_tunnel_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct udphdr *uh;

	uh = (struct udphdr *)(skb->data + nhoff - sizeof(struct udphdr));
	skb_shinfo(skb)->gso_type |= uh->check ?
				SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
}

int eth_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct ethhdr *eh = (struct ethhdr *)(skb->data + nhoff);
	__be16 type = eh->h_proto;
	struct packet_offload *ptype;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_mac_header(skb, nhoff);

	rcu_read_lock();
	ptype = gro_find_complete_by_type(type);
	if (ptype != NULL)
		err = ptype->callbacks.gro_complete(skb, nhoff +   //链路层gro complete
						    sizeof(struct ethhdr));

	rcu_read_unlock();
	return err;
}
```

