# Raw Socket

Raw Socket允许应用程序能够获取到原始IP报文。


## 基本数据结构

```c
struct proto raw_prot = {
	.name		   = "RAW",
	.owner		   = THIS_MODULE,
	.close		   = raw_close,
	.destroy	   = raw_destroy,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = raw_ioctl,
	.init		   = raw_init,
	.setsockopt	   = raw_setsockopt,
	.getsockopt	   = raw_getsockopt,
	.sendmsg	   = raw_sendmsg,
	.recvmsg	   = raw_recvmsg,
	.bind		   = raw_bind,
	.backlog_rcv   = raw_rcv_skb,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = raw_hash_sk,
	.unhash		   = raw_unhash_sk,
	.obj_size	   = sizeof(struct raw_sock),
	.h.raw_hash	   = &raw_v4_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_raw_setsockopt,
	.compat_getsockopt = compat_raw_getsockopt,
	.compat_ioctl	   = compat_raw_ioctl,
#endif
};

static const struct proto_ops inet_sockraw_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = datagram_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,     //raw socket不需要listen
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};
```


## 创建 raw socket

inet_create函数是IPV4 socket的统一创建函数， 当socket为raw socket（socket type）时会有额外的处理以实现raw socket的收发包处理。

### raw_hash_sk

```c
void raw_hash_sk(struct sock *sk)
{
	struct raw_hashinfo *h = sk->sk_prot->h.raw_hash;   //raw_v4_hashinfo
	struct hlist_head *head;

	head = &h->ht[inet_sk(sk)->inet_num & (RAW_HTABLE_SIZE - 1)];  //根据协议号得到链表

	write_lock_bh(&h->lock);
	sk_add_node(sk, head);     //sk添加到链表中
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);    //添加到net namespace中
	write_unlock_bh(&h->lock);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

void sock_prot_inuse_add(struct net *net, struct proto *prot, int val)
{
    // 添加到net namespace中
	// prot->inuse_idx在调用proto_register时确定
	__this_cpu_add(net->core.inuse->val[prot->inuse_idx], val);   
}
```

### raw_init

```c
static int raw_init(struct sock *sk)
{
	struct raw_sock *rp = raw_sk(sk);

	if (inet_sk(sk)->inet_num == IPPROTO_ICMP)
		memset(&rp->filter, 0, sizeof(rp->filter));   //ICMP协议，清空filter
	return 0;
}
```


## raw socket connect

用户态程序调用connect系统调用，最终会调用到inet_sockraw_ops的connect函数。

```c
int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (!inet_sk(sk)->inet_num && inet_autobind(sk))
		return -EAGAIN;
	return sk->sk_prot->connect(sk, uaddr, addr_len);   //调用proto的connect
}

int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int res;

	lock_sock(sk);
	res = __ip4_datagram_connect(sk, uaddr, addr_len);
	release_sock(sk);
	return res;
}

int __ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;
	struct flowi4 *fl4;
	struct rtable *rt;
	__be32 saddr;
	int oif;
	int err;


	if (addr_len < sizeof(*usin))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	sk_dst_reset(sk);

	oif = sk->sk_bound_dev_if;
	saddr = inet->inet_saddr;
	if (ipv4_is_multicast(usin->sin_addr.s_addr)) {
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, usin->sin_addr.s_addr, saddr,
			      RT_CONN_FLAGS(sk), oif,
			      sk->sk_protocol,
			      inet->inet_sport, usin->sin_port, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		goto out;
	}

	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		err = -EACCES;
		goto out;
	}
	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;	/* Update source address */
	if (!inet->inet_rcv_saddr) {
		inet->inet_rcv_saddr = fl4->saddr;
		if (sk->sk_prot->rehash)
			sk->sk_prot->rehash(sk);
	}
	inet->inet_daddr = fl4->daddr;
	inet->inet_dport = usin->sin_port;
	sk->sk_state = TCP_ESTABLISHED;
	inet_set_txhash(sk);
	inet->inet_id = jiffies;

	sk_dst_set(sk, &rt->dst);
	err = 0;
out:
	return err;
}
```


## raw socket bind

用户态程序调用bind系统调用，最终会调用到inet_sockraw_ops的bind函数。

```c
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {
		err = sk->sk_prot->bind(sk, uaddr, addr_len);   //调用自己bind函数
		goto out;
	}
	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	if (addr->sin_family != AF_INET) {
		/* Compatibility games : accept AF_UNSPEC (mapped to AF_INET)
		 * only if s_addr is INADDR_ANY.
		 */
		err = -EAFNOSUPPORT;
		if (addr->sin_family != AF_UNSPEC ||
		    addr->sin_addr.s_addr != htonl(INADDR_ANY))
			goto out;
	}

	chk_addr_ret = inet_addr_type(net, addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (!net->ipv4.sysctl_ip_nonlocal_bind &&
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	if (snum && snum < PROT_SOCK &&
	    !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}

static int raw_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);
	int ifindex;
	int err = 0;
	int notify_enetdown = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	lock_sock(sk);

	if (ro->bound && addr->can_ifindex == ro->ifindex)
		goto out;

	if (addr->can_ifindex) {
		struct net_device *dev;

		dev = dev_get_by_index(&init_net, addr->can_ifindex);
		if (!dev) {
			err = -ENODEV;
			goto out;
		}
		if (dev->type != ARPHRD_CAN) {
			dev_put(dev);
			err = -ENODEV;
			goto out;
		}
		if (!(dev->flags & IFF_UP))
			notify_enetdown = 1;

		ifindex = dev->ifindex;

		/* filters set by default/setsockopt */
		err = raw_enable_allfilters(dev, sk);
		dev_put(dev);
	} else {
		ifindex = 0;

		/* filters set by default/setsockopt */
		err = raw_enable_allfilters(NULL, sk);
	}

	if (!err) {
		if (ro->bound) {
			/* unregister old filters */
			if (ro->ifindex) {
				struct net_device *dev;

				dev = dev_get_by_index(&init_net, ro->ifindex);
				if (dev) {
					raw_disable_allfilters(dev, sk);
					dev_put(dev);
				}
			} else
				raw_disable_allfilters(NULL, sk);
		}
		ro->ifindex = ifindex;
		ro->bound = 1;
	}

 out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}
```


## raw socket收包

在内核协议栈处理报文时，ip本地报文处理函数ip_local_deliver_finish中会检查是否raw socket收包。

```c
int raw_local_deliver(struct sk_buff *skb, int protocol)
{
	int hash;
	struct sock *raw_sk;
	
	// 根据协议类型计算出hash值，hash值共256个，所以不同的ip协议不会重叠
	hash = protocol & (RAW_HTABLE_SIZE - 1);
	
	// 得到sock，这个sock一定是在创建的时候放到raw_v4_hashinfo中的
	// raw_hash_sk函数中添加了raw socket
	raw_sk = sk_head(&raw_v4_hashinfo.ht[hash]);	

	/* If there maybe a raw socket we must check - if not we
	 * don't care less
	 */
	 //sock不为空，则把报文提交给sock
	if (raw_sk && !raw_v4_input(skb, ip_hdr(skb), hash))	
		raw_sk = NULL;

	return raw_sk != NULL;

}

static int raw_v4_input(struct sk_buff *skb, const struct iphdr *iph, int hash)
{
	struct sock *sk;
	struct hlist_head *head;
	int delivered = 0;
	struct net *net;

	read_lock(&raw_v4_hashinfo.lock);
	head = &raw_v4_hashinfo.ht[hash];	//得到相同hash的sock链表
	if (hlist_empty(head))
		goto out;

	net = dev_net(skb->dev);
	
	// sock是否能够接收报文，匹配协议，如果有ip源地址或ip目的地址则均需要匹配
	// socket的地址通过connect进行设置
	sk = __raw_v4_lookup(net, __sk_head(head), iph->protocol,	
			     iph->saddr, iph->daddr,
			     skb->dev->ifindex);

	//第一个如果不匹配，后续则不再处理，所以次序很重要，对raw socket肯定是能够匹配的报文的
	while (sk) {		
		delivered = 1;
		//报文不是ICMP报文或者sock未设置icmp filter
		if ((iph->protocol != IPPROTO_ICMP || !icmp_filter(sk, skb)) &&	
		    ip_mc_sf_allow(sk, iph->daddr, iph->saddr,	//非组播报文，或者组播报文允许通过
				   skb->dev->ifindex)) {
			struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);	//克隆skb

			/* Not releasing hash table! */
			if (clone)
				raw_rcv(sk, clone);	//提交报文到sock
		}
		sk = __raw_v4_lookup(net, sk_next(sk), iph->protocol,	//取下一个sock
				     iph->saddr, iph->daddr,
				     skb->dev->ifindex);
	}
out:
	read_unlock(&raw_v4_hashinfo.lock);
	return delivered;
}

int raw_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb)) {	//ipset策略检测
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}
	nf_reset(skb);

	//报文移动到ip头，用户看到报文时候包含了IP头
	skb_push(skb, skb->data - skb_network_header(skb));	

	raw_rcv_skb(sk, skb);	//sock接收报文
	return 0;
}

static int raw_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	/* Charge it to the socket. */

	ipv4_pktinfo_prepare(sk, skb);
	if (sock_queue_rcv_skb(sk, skb) < 0) {	//放入sock的收包队列，并唤醒等待进程
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}
```


## raw socket发包

用户态程序调用send系统调用发送消息时，最终会调用到inet_sockraw_ops的sendmsg函数。

```c
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(sk, msg, size);  //调用proto的sendmsg函数
}


static int raw_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	int free = 0;
	__be32 daddr;
	__be32 saddr;
	u8  tos;
	int err;
	struct ip_options_data opt_copy;
	struct raw_frag_vec rfv;

	err = -EMSGSIZE;
	if (len > 0xFFFF)
		goto out;

	/*
	 *	Check the flags.
	 */

	err = -EOPNOTSUPP;
	if (msg->msg_flags & MSG_OOB)	/* Mirror BSD error message */
		goto out;               /* compatibility */

	/*
	 *	Get and verify the address.
	 */

	if (msg->msg_namelen) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usin))
			goto out;
		if (usin->sin_family != AF_INET) {
			pr_info_once("%s: %s forgot to set AF_INET. Fix it!\n",
				     __func__, current->comm);
			err = -EAFNOSUPPORT;
			if (usin->sin_family)
				goto out;
		}
		daddr = usin->sin_addr.s_addr;
		/* ANK: I did not forget to get protocol from port field.
		 * I just do not know, who uses this weirdness.
		 * IP_HDRINCL is much more convenient.
		 */
	} else {
		err = -EDESTADDRREQ;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;
		daddr = inet->inet_daddr;
	}

	ipc.addr = inet->inet_saddr;
	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;
	ipc.oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sock_net(sk), msg, &ipc, false);
		if (err)
			goto out;
		if (ipc.opt)
			free = 1;
	}

	saddr = ipc.addr;
	ipc.addr = daddr;

	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	if (ipc.opt) {
		err = -EINVAL;
		/* Linux does not mangle headers on raw sockets,
		 * so that IP options + IP_HDRINCL is non-sense.
		 */
		if (inet->hdrincl)
			goto done;
		if (ipc.opt->opt.srr) {
			if (!daddr)
				goto done;
			daddr = ipc.opt->opt.faddr;
		}
	}
	tos = get_rtconn_flags(&ipc, sk);
	if (msg->msg_flags & MSG_DONTROUTE)
		tos |= RTO_ONLINK;

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;

	flowi4_init_output(&fl4, ipc.oif, sk->sk_mark, tos,
			   RT_SCOPE_UNIVERSE,
			   inet->hdrincl ? IPPROTO_RAW : sk->sk_protocol,
			   inet_sk_flowi_flags(sk) |
			    (inet->hdrincl ? FLOWI_FLAG_KNOWN_NH : 0),
			   daddr, saddr, 0, 0);

	if (!inet->hdrincl) {
		rfv.msg = msg;
		rfv.hlen = 0;

		err = raw_probe_proto_opt(&rfv, &fl4);
		if (err)
			goto done;
	}

	security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
	rt = ip_route_output_flow(sock_net(sk), &fl4, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto done;
	}

	err = -EACCES;
	if (rt->rt_flags & RTCF_BROADCAST && !sock_flag(sk, SOCK_BROADCAST))
		goto done;

	if (msg->msg_flags & MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	if (inet->hdrincl)
		err = raw_send_hdrinc(sk, &fl4, msg, len,
				      &rt, msg->msg_flags);

	 else {
		sock_tx_timestamp(sk, &ipc.tx_flags);

		if (!ipc.addr)
			ipc.addr = fl4.daddr;
		lock_sock(sk);
		err = ip_append_data(sk, &fl4, raw_getfrag,  
				     &rfv, len, 0,
				     &ipc, &rt, msg->msg_flags);
		if (err)
			ip_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE)) {
			err = ip_push_pending_frames(sk, &fl4);   //发送ip报文
			if (err == -ENOBUFS && !inet->recverr)
				err = 0;
		}
		release_sock(sk);
	}
done:
	if (free)
		kfree(ipc.opt);
	ip_rt_put(rt);

out:
	if (err < 0)
		return err;
	return len;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
}

int ip_push_pending_frames(struct sock *sk, struct flowi4 *fl4)
{
	struct sk_buff *skb;

	skb = ip_finish_skb(sk, fl4);   //构建skb
	if (!skb)
		return 0;

	/* Netfilter gets whole the not fragmented skb. */
	return ip_send_skb(sock_net(sk), skb);   //发送skb
}

int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(skb);   //本地发送
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}
```
