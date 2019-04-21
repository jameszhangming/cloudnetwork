# 内核发包流程

本文将介绍内核链路层和IP层的发包处理流程，UDP和TCP协议将单独介绍， 本文重点讲解整体框架，TSO、qdisc、neigh、router等细节将单独分析。


## 整体收发包流程

![dp](images/dp.png "dp")


## IP层发包

发送报文，当前报文已经封装了传输层的头
```c
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options_rcu *inet_opt;
	struct flowi4 *fl4;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	fl4 = &fl->u.ip4;
	rt = skb_rtable(skb);	//得到skb中已带的路由表信息
	if (rt)
		goto packet_routed;

	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (!rt) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if (inet_opt && inet_opt->opt.srr)
			daddr = inet_opt->opt.faddr;

		/* If this fails, retransmit mechanism of transport layer will
		 * keep trying until route appears or the connection times
		 * itself out.
		 */
		rt = ip_route_output_ports(sock_net(sk), fl4, sk,   //skb中没有路由表信息，查找路由表
					   daddr, inet->inet_saddr,
					   inet->inet_dport,
					   inet->inet_sport,
					   sk->sk_protocol,
					   RT_CONN_FLAGS(sk),
					   sk->sk_bound_dev_if);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);  

packet_routed:
	if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));	//构建IP头
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->dst);    //设置ttl值
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);

	/* Transport layer set skb->h.foo itself. */

	if (inet_opt && inet_opt->opt.optlen) {
		iph->ihl += inet_opt->opt.optlen >> 2;
		ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt, 0);   //设置ip options
	}

	ip_select_ident_segs(sock_net(sk), skb, sk,
			     skb_shinfo(skb)->gso_segs ?: 1);

	/* TODO : should we use skb->sk here instead of sk ? */
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	res = ip_local_out(skb);		//本地发送ip报文，skb已封装IP头
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}
```

发送报文，当前报文已经封装了IP层的头
```c
int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(skb);   //本地发送ip报文
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}
```

发送报文，skb已经设置dst（报文已经是IP报文），调用防火墙处理
```c
static inline int ip_local_out(struct sk_buff *skb)	
{
	return ip_local_out_sk(skb->sk, skb);  //本地报文发送，本地发送的报文都关联着一个sock对象
}

int ip_local_out_sk(struct sock *sk, struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(skb);		//报文安全检测（netfilter）
	if (likely(err == 1))			//返回值为1，说明netfilter允许报文通过，其他值报文被netfilter消耗掉了
		err = dst_output_sk(sk, skb);	//最终会调用ip_output函数

	return err;
}

int __ip_local_out(struct sk_buff *skb)
{
	return __ip_local_out_sk(skb->sk, skb);
}

int __ip_local_out_sk(struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);		//计算IP层csum值
	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, sk, skb, NULL,	//调用netfilter，返回值为1说明允许报文通过
		       skb_dst(skb)->dev, dst_output_sk);
}
```

发送报文，skb已经设置dst（报文已经是IP报文），调用防火墙处理
```c
int ip_output(struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);	//设置报文协议为IPV4

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, sk, skb, 
			    NULL, dev,
			    ip_finish_output,		//报文发送netfilter处理，如果允许则调用ip_finish_output
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

static int ip_finish_output(struct sock *sk, struct sk_buff *skb)
{
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm) {			//仅经过ip_forward流程处理的报文携带该对象
		IPCB(skb)->flags |= IPSKB_REROUTED;	//该flag会影响后续报文的GSO处理
		return dst_output_sk(sk, skb);		//由于SNAT等策略处理，需要再次调用xfrm4_output函数来发包
	}
#endif
	if (skb_is_gso(skb))
		return ip_finish_output_gso(sk, skb);	//如果是gso报文

	if (skb->len > ip_skb_dst_mtu(skb))		//非gso报文，报文大小超过设备MTU值，则需要进行IP分片
		return ip_fragment(sk, skb, ip_finish_output2);

	return ip_finish_output2(sk, skb);		//直接发送报文
}

static inline int ip_finish_output2(struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;		//出口设备
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	u32 nexthop;

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTBCAST, skb->len);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	rcu_read_lock_bh();
	nexthop = (__force u32) rt_nexthop(rt, ip_hdr(skb)->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);	//根据目的IP查找邻居项是否存在
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);	//如果不存在，则创建neigh项
	if (!IS_ERR(neigh)) {
		int res = dst_neigh_output(dst, neigh, skb);	//调用邻居子系统封装MAC头，并且调用二层发包函数完成报文发送

		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

	net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
			    __func__);
	kfree_skb(skb);
	return -EINVAL;
}
```

## 数据链路层发包

数据链路层发包的主要逻辑是qdisc，将会专门进行分析

```c
static inline int dev_queue_xmit(struct sk_buff *skb)
{
	return dev_queue_xmit_sk(skb->sk, skb);
}

int dev_queue_xmit_sk(struct sock *sk, struct sk_buff *skb)
{
	return __dev_queue_xmit(skb, NULL);
}

static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	struct Qdisc *q;
	int rc = -ENOMEM;

	skb_reset_mac_header(skb);	//设置mac header偏移

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
		__skb_tstamp_tx(skb, NULL, skb->sk, SCM_TSTAMP_SCHED);

	/* Disable soft irqs for various locks below. Also
	 * stops preemption for RCU.
	 */
	rcu_read_lock_bh();

	skb_update_prio(skb);	//设置skb->priority值

	/* If device/qdisc don't need skb->dst, release it right now while
	 * its hot in this cpu cache.
	 */
	if (dev->priv_flags & IFF_XMIT_DST_RELEASE)	//释放dst对象
		skb_dst_drop(skb);
	else
		skb_dst_force(skb);

	txq = netdev_pick_tx(dev, skb, accel_priv);	//获取发送队列，根据报文计算出队列
	q = rcu_dereference_bh(txq->qdisc);		//得到qdisc对象

#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_EGRESS);
#endif
	trace_net_dev_queue(skb);
	if (q->enqueue) {
		rc = __dev_xmit_skb(skb, q, dev, txq);		//qdisc发包
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that netif_tx_lock protection is necessary
	   here.  (f.e. loopback and IP tunnels are clean ignoring statistics
	   counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id(); /* ok because BHs are off */

		if (txq->xmit_lock_owner != cpu) {

			if (__this_cpu_read(xmit_recursion) > RECURSION_LIMIT)
				goto recursion_alert;

			skb = validate_xmit_skb(skb, dev);
			if (!skb)
				goto drop;

			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_xmit_stopped(txq)) {
				__this_cpu_inc(xmit_recursion);
				skb = dev_hard_start_xmit(skb, dev, txq, &rc);		//调用驱动发送报文
				__this_cpu_dec(xmit_recursion);
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			net_crit_ratelimited("Virtual device %s asks to queue packet!\n",
					     dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately
			 */
recursion_alert:
			net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
					     dev->name);
		}
	}

	rc = -ENETDOWN;
drop:
	rcu_read_unlock_bh();

	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}
```



