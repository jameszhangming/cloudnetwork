# IPIP

IPIP设备为用户提供了IP over IP的隧道方案。

## 数据结构

```c
static struct rtnl_link_ops ipip_link_ops __read_mostly = {
	.kind		= "ipip",
	.maxtype	= IFLA_IPTUN_MAX,
	.policy		= ipip_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipip_tunnel_setup,
	.newlink	= ipip_newlink,
	.changelink	= ipip_changelink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipip_get_size,
	.fill_info	= ipip_fill_info,
	.get_link_net	= ip_tunnel_get_link_net,
};

//设备驱动
static const struct net_device_ops ipip_netdev_ops = {
	.ndo_init       = ipip_tunnel_init,
	.ndo_uninit     = ip_tunnel_uninit,
	.ndo_start_xmit	= ipip_tunnel_xmit,
	.ndo_do_ioctl	= ipip_tunnel_ioctl,
	.ndo_change_mtu = ip_tunnel_change_mtu,
	.ndo_get_stats64 = ip_tunnel_get_stats64,
	.ndo_get_iflink = ip_tunnel_get_iflink,
};

//net namespace回调函数
static struct pernet_operations ipip_net_ops = {
	.init = ipip_init_net,  //创建net namespace时被调用
	.exit = ipip_exit_net,  //删除net namespace时被调用
	.id   = &ipip_net_id,
	.size = sizeof(struct ip_tunnel_net),
};

//隧道
static struct xfrm_tunnel ipip_handler __read_mostly = {
	.handler	=	ipip_rcv,
	.err_handler	=	ipip_err,
	.priority	=	1,
};

//ipip协议处理入口
static const struct net_protocol tunnel4_protocol = {
	.handler	=	tunnel4_rcv,
	.err_handler	=	tunnel4_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};
```


## tunnel模块初始化

```c
static int __init tunnel4_init(void)
{
	if (inet_add_protocol(&tunnel4_protocol, IPPROTO_IPIP)) {  //注册IPIP协议处理函数
		pr_err("%s: can't add protocol\n", __func__);
		return -EAGAIN;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (inet_add_protocol(&tunnel64_protocol, IPPROTO_IPV6)) {
		pr_err("tunnel64 init: can't add protocol\n");
		inet_del_protocol(&tunnel4_protocol, IPPROTO_IPIP);
		return -EAGAIN;
	}
#endif
	return 0;
}
```


## ipip模块初始化

```c
static int __init ipip_init(void)
{
	int err;

	pr_info("ipip: IPv4 over IPv4 tunneling driver\n");

	err = register_pernet_device(&ipip_net_ops);   //注册net namespace回调函数，更新id值
	if (err < 0)
		return err;
	err = xfrm4_tunnel_register(&ipip_handler, AF_INET);   //注册ipip设备处理
	if (err < 0) {
		pr_info("%s: can't register tunnel\n", __func__);
		goto xfrm_tunnel_failed;
	}
	err = rtnl_link_register(&ipip_link_ops);
	if (err < 0)
		goto rtnl_link_failed;

out:
	return err;

rtnl_link_failed:
	xfrm4_tunnel_deregister(&ipip_handler, AF_INET);
xfrm_tunnel_failed:
	unregister_pernet_device(&ipip_net_ops);
	goto out;
}
```

### 注册ipip收包处理方法

```c
int xfrm4_tunnel_register(struct xfrm_tunnel *handler, unsigned short family)
{
	struct xfrm_tunnel __rcu **pprev;
	struct xfrm_tunnel *t;

	int ret = -EEXIST;
	int priority = handler->priority;

	mutex_lock(&tunnel4_mutex);

	for (pprev = fam_handlers(family);
	     (t = rcu_dereference_protected(*pprev,
			lockdep_is_held(&tunnel4_mutex))) != NULL;
	     pprev = &t->next) {
		if (t->priority > priority)
			break;
		if (t->priority == priority)
			goto err;
	}

	handler->next = *pprev;
	rcu_assign_pointer(*pprev, handler);   //按照优先级，插入到tunnel处理链表中

	ret = 0;

err:
	mutex_unlock(&tunnel4_mutex);

	return ret;
}
```


### net namespace初始化

```c
static int __net_init ipip_init_net(struct net *net)
{
	return ip_tunnel_init_net(net, ipip_net_id, &ipip_link_ops, "tunl0");
}

int ip_tunnel_init_net(struct net *net, int ip_tnl_net_id,
				  struct rtnl_link_ops *ops, char *devname)
{
	struct ip_tunnel_net *itn = net_generic(net, ip_tnl_net_id);
	struct ip_tunnel_parm parms;
	unsigned int i;

	for (i = 0; i < IP_TNL_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&itn->tunnels[i]);      //初始化链表

	if (!ops) {
		itn->fb_tunnel_dev = NULL;
		return 0;
	}

	memset(&parms, 0, sizeof(parms));
	if (devname)
		strlcpy(parms.name, devname, IFNAMSIZ);

	rtnl_lock();
	itn->fb_tunnel_dev = __ip_tunnel_create(net, ops, &parms);
	/* FB netdevice is special: we have one, and only one per netns.
	 * Allowing to move it to another netns is clearly unsafe.
	 */
	if (!IS_ERR(itn->fb_tunnel_dev)) {
		itn->fb_tunnel_dev->features |= NETIF_F_NETNS_LOCAL;
		itn->fb_tunnel_dev->mtu = ip_tunnel_bind_dev(itn->fb_tunnel_dev);
		ip_tunnel_add(itn, netdev_priv(itn->fb_tunnel_dev));
	}
	rtnl_unlock();

	return PTR_ERR_OR_ZERO(itn->fb_tunnel_dev);
}
```


## ipip设备创建

ipip设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）  //未定义
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）  //未定义
6. dev->netdev_ops->ndo_open（打开设备）  //未定义


### setup(macvlan_setup)

```c
static void ipip_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops		= &ipip_netdev_ops;   //设置驱动

	dev->type		= ARPHRD_TUNNEL;
	dev->flags		= IFF_NOARP;
	dev->addr_len		= 4;
	dev->features		|= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->features		|= IPIP_FEATURES;
	dev->hw_features	|= IPIP_FEATURES;
	ip_tunnel_setup(dev, ipip_net_id);   
}

void ip_tunnel_setup(struct net_device *dev, int net_id)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);  //实际为ip_tunnel
	tunnel->ip_tnl_net_id = net_id;
}
```

### newlink(ipip_newlink)

```c
static int ipip_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct ip_tunnel_parm p;
	struct ip_tunnel_encap ipencap;

	if (ipip_netlink_encap_parms(data, &ipencap)) {
		struct ip_tunnel *t = netdev_priv(dev);
		int err = ip_tunnel_encap_setup(t, &ipencap);   //设置encap信息，ipip设备不需要此参数

		if (err < 0)
			return err;
	}

	ipip_netlink_parms(data, &p);   //解析到本地IP和对端IP
	return ip_tunnel_newlink(dev, tb, &p); 
}

int ip_tunnel_encap_setup(struct ip_tunnel *t,
			  struct ip_tunnel_encap *ipencap)
{
	int hlen;

	memset(&t->encap, 0, sizeof(t->encap));

	hlen = ip_encap_hlen(ipencap);  //根据encap类型获取encap头长度
	if (hlen < 0)
		return hlen;

	t->encap.type = ipencap->type;
	t->encap.sport = ipencap->sport;
	t->encap.dport = ipencap->dport;
	t->encap.flags = ipencap->flags;

	t->encap_hlen = hlen;                     //ipip设备该值为0
	t->hlen = t->encap_hlen + t->tun_hlen;    //ipip设备该值为0

	return 0;
}


int ip_tunnel_newlink(struct net_device *dev, struct nlattr *tb[],
		      struct ip_tunnel_parm *p)
{
	struct ip_tunnel *nt;
	struct net *net = dev_net(dev);  //得到网络命名空间
	struct ip_tunnel_net *itn;     //net namespace的全局变量
	int mtu;
	int err;

	nt = netdev_priv(dev);
	itn = net_generic(net, nt->ip_tnl_net_id);  

	if (ip_tunnel_find(itn, p, dev->type))  
		return -EEXIST;

	nt->net = net;
	nt->parms = *p;
	err = register_netdevice(dev);  //注册设备
	if (err)
		goto out;

	if (dev->type == ARPHRD_ETHER && !tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	mtu = ip_tunnel_bind_dev(dev);   //计算设备mtu值
	if (!tb[IFLA_MTU])
		dev->mtu = mtu;

	ip_tunnel_add(itn, nt);   //添加到全局变量中，以hash方式保存

out:
	return err;
}

static int ip_tunnel_bind_dev(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *iph;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int t_hlen = tunnel->hlen + sizeof(struct iphdr);   //隧道头长度（0）+IP头长度

	iph = &tunnel->parms.iph;

	/* Guess output device to choose reasonable mtu and needed_headroom */
	if (iph->daddr) {
		struct flowi4 fl4;
		struct rtable *rt;

		init_tunnel_flow(&fl4, iph->protocol, iph->daddr,
				 iph->saddr, tunnel->parms.o_key,
				 RT_TOS(iph->tos), tunnel->parms.link);
		rt = ip_route_output_key(tunnel->net, &fl4);     //查询路由

		if (!IS_ERR(rt)) {
			tdev = rt->dst.dev;   //出口设备
			tunnel_dst_set(tunnel, &rt->dst, fl4.saddr);   //设置源IP（根据目的IP查找路由获取）
			ip_rt_put(rt);
		}
		if (dev->type != ARPHRD_ETHER)
			dev->flags |= IFF_POINTOPOINT;
	}

	if (!tdev && tunnel->parms.link)
		tdev = __dev_get_by_index(tunnel->net, tunnel->parms.link);

	if (tdev) {
		hlen = tdev->hard_header_len + tdev->needed_headroom;   //hard_header_len 以太网该值为14
		mtu = tdev->mtu;
	}

	dev->needed_headroom = t_hlen + hlen;   // IP头长度 + 以太网头长度 + tdev->needed_headroom
	mtu -= (dev->hard_header_len + t_hlen);  // mtu为底层设备的MTU减去IP头

	if (mtu < 68)
		mtu = 68;

	return mtu;
}
```


### ndo_init(ipip_tunnel_init)

```c
static int ipip_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);

	memcpy(dev->dev_addr, &tunnel->parms.iph.saddr, 4);
	memcpy(dev->broadcast, &tunnel->parms.iph.daddr, 4);

	tunnel->tun_hlen = 0;
	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;
	tunnel->parms.iph.protocol = IPPROTO_IPIP;
	return ip_tunnel_init(dev);
}

int ip_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;
	int err;

	dev->destructor	= ip_tunnel_dev_free;
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	tunnel->dst_cache = alloc_percpu(struct ip_tunnel_dst);
	if (!tunnel->dst_cache) {
		free_percpu(dev->tstats);
		return -ENOMEM;
	}

	err = gro_cells_init(&tunnel->gro_cells, dev);   //初始化gro_cells
	if (err) {
		free_percpu(tunnel->dst_cache);
		free_percpu(dev->tstats);
		return err;
	}

	tunnel->dev = dev;
	tunnel->net = dev_net(dev);
	strcpy(tunnel->parms.name, dev->name);
	iph->version		= 4;
	iph->ihl		= 5;

	return 0;
}

static inline int gro_cells_init(struct gro_cells *gcells, struct net_device *dev)
{
	int i;

	gcells->cells = alloc_percpu(struct gro_cell);
	if (!gcells->cells)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		struct gro_cell *cell = per_cpu_ptr(gcells->cells, i);

		skb_queue_head_init(&cell->napi_skbs);
		netif_napi_add(dev, &cell->napi, gro_cell_poll, 64);    //napi回调函数
		napi_enable(&cell->napi);
	}
	return 0;
}
```


## ipip底层设备收包处理

```c
static int tunnel4_rcv(struct sk_buff *skb)
{
	struct xfrm_tunnel *handler;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto drop;

	for_each_tunnel_rcu(tunnel4_handlers, handler)
		if (!handler->handler(skb))      //优先IPIP设备处理，如果没有该设备，则交给xfrm模块处理
			return 0;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

drop:
	kfree_skb(skb);
	return 0;
}

static int ipip_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn = net_generic(net, ipip_net_id);
	struct ip_tunnel *tunnel;
	const struct iphdr *iph;

	iph = ip_hdr(skb);
	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, TUNNEL_NO_KEY,  //根据源IP和目的IP查找tunnel
			iph->saddr, iph->daddr, 0);
	if (tunnel) {
		if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))   //xfrm检查
			goto drop;
		if (iptunnel_pull_header(skb, 0, tpi.proto))    //skb已经移动到内部IP头
			goto drop;
		return ip_tunnel_rcv(tunnel, skb, &tpi, log_ecn_error);  //ip tunnel收包
	}

	return -1;

drop:
	kfree_skb(skb);
	return 0;
}

int ip_tunnel_rcv(struct ip_tunnel *tunnel, struct sk_buff *skb,
		  const struct tnl_ptk_info *tpi, bool log_ecn_error)
{
	struct pcpu_sw_netstats *tstats;
	const struct iphdr *iph = ip_hdr(skb);   //得到IP头
	int err;

#ifdef CONFIG_NET_IPGRE_BROADCAST
	if (ipv4_is_multicast(iph->daddr)) {
		tunnel->dev->stats.multicast++;
		skb->pkt_type = PACKET_BROADCAST;
	}
#endif

	if ((!(tpi->flags&TUNNEL_CSUM) &&  (tunnel->parms.i_flags&TUNNEL_CSUM)) ||
	     ((tpi->flags&TUNNEL_CSUM) && !(tunnel->parms.i_flags&TUNNEL_CSUM))) {
		tunnel->dev->stats.rx_crc_errors++;
		tunnel->dev->stats.rx_errors++;
		goto drop;
	}

	if (tunnel->parms.i_flags&TUNNEL_SEQ) {
		if (!(tpi->flags&TUNNEL_SEQ) ||
		    (tunnel->i_seqno && (s32)(ntohl(tpi->seq) - tunnel->i_seqno) < 0)) {
			tunnel->dev->stats.rx_fifo_errors++;
			tunnel->dev->stats.rx_errors++;
			goto drop;
		}
		tunnel->i_seqno = ntohl(tpi->seq) + 1;
	}

	skb_reset_network_header(skb);

	err = IP_ECN_decapsulate(iph, skb);
	if (unlikely(err)) {
		if (log_ecn_error)
			net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
					&iph->saddr, iph->tos);
		if (err > 1) {
			++tunnel->dev->stats.rx_frame_errors;
			++tunnel->dev->stats.rx_errors;
			goto drop;
		}
	}

	tstats = this_cpu_ptr(tunnel->dev->tstats);
	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += skb->len;
	u64_stats_update_end(&tstats->syncp);

	skb_scrub_packet(skb, !net_eq(tunnel->net, dev_net(tunnel->dev)));

	if (tunnel->dev->type == ARPHRD_ETHER) {   //不满足
		skb->protocol = eth_type_trans(skb, tunnel->dev);
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
	} else {
		skb->dev = tunnel->dev;
	}

	gro_cells_receive(&tunnel->gro_cells, skb);   //收包
	return 0;

drop:
	kfree_skb(skb);
	return 0;
}

static inline void gro_cells_receive(struct gro_cells *gcells, struct sk_buff *skb)
{
	struct gro_cell *cell;
	struct net_device *dev = skb->dev;

	if (!gcells->cells || skb_cloned(skb) || !(dev->features & NETIF_F_GRO)) {
		netif_rx(skb);    //上送协议栈收包
		return;
	}

	cell = this_cpu_ptr(gcells->cells);

	if (skb_queue_len(&cell->napi_skbs) > netdev_max_backlog) {
		atomic_long_inc(&dev->rx_dropped);
		kfree_skb(skb);
		return;
	}

	/* We run in BH context */
	spin_lock(&cell->napi_skbs.lock);

	__skb_queue_tail(&cell->napi_skbs, skb);    //添加到skbs队列
	if (skb_queue_len(&cell->napi_skbs) == 1)   //如果之前没有报文
		napi_schedule(&cell->napi);   //触发软中断

	spin_unlock(&cell->napi_skbs.lock);
}
```

### napi收包处理

```c
static inline int gro_cell_poll(struct napi_struct *napi, int budget)
{
	struct gro_cell *cell = container_of(napi, struct gro_cell, napi);
	struct sk_buff *skb;
	int work_done = 0;

	spin_lock(&cell->napi_skbs.lock);
	while (work_done < budget) {
		skb = __skb_dequeue(&cell->napi_skbs);   //收取报文
		if (!skb)
			break;
		spin_unlock(&cell->napi_skbs.lock);
		napi_gro_receive(napi, skb);            //调用gro收包
		work_done++;
		spin_lock(&cell->napi_skbs.lock);
	}

	if (work_done < budget)
		napi_complete(napi);
	spin_unlock(&cell->napi_skbs.lock);
	return work_done;
}
```


## ipip发包处理

```c
static netdev_tx_t ipip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);		//当前设备未ip_tunnel设备
	const struct iphdr  *tiph = &tunnel->parms.iph;

	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		goto tx_error;

	skb = iptunnel_handle_offloads(skb, false, SKB_GSO_IPIP);
	if (IS_ERR(skb))
		goto out;

	skb_set_inner_ipproto(skb, IPPROTO_IPIP);	//设置了inner协议

	ip_tunnel_xmit(skb, dev, tiph, tiph->protocol);			//tiph->protocol为ipip协议
	return NETDEV_TX_OK;

tx_error:
	kfree_skb(skb);
out:
	dev->stats.tx_errors++;
	return NETDEV_TX_OK;
}

void ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
		    const struct iphdr *tnl_params, u8 protocol)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *inner_iph;
	struct flowi4 fl4;
	u8     tos, ttl;
	__be16 df;
	struct rtable *rt;		/* Route to the other host */
	unsigned int max_headroom;	/* The extra header space needed */
	__be32 dst;
	int err;
	bool connected;

	inner_iph = (const struct iphdr *)skb_inner_network_header(skb);	//当前skb指向IP头
	connected = (tunnel->parms.iph.daddr != 0);

	dst = tnl_params->daddr;		//获取目标地址
	if (dst == 0) {		//IPIP设备未设置对端的情况，进此分支
		/* NBMA tunnel */

		if (!skb_dst(skb)) {
			dev->stats.tx_fifo_errors++;
			goto tx_error;
		}

		if (skb->protocol == htons(ETH_P_IP)) {			//如果未设置IP地址，
			rt = skb_rtable(skb);				//获取路由表
			dst = rt_nexthop(rt, inner_iph->daddr);		//得到下一跳的dst对象
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (skb->protocol == htons(ETH_P_IPV6)) {
			const struct in6_addr *addr6;
			struct neighbour *neigh;
			bool do_tx_error_icmp;
			int addr_type;

			neigh = dst_neigh_lookup(skb_dst(skb),
						 &ipv6_hdr(skb)->daddr);
			if (!neigh)
				goto tx_error;

			addr6 = (const struct in6_addr *)&neigh->primary_key;
			addr_type = ipv6_addr_type(addr6);

			if (addr_type == IPV6_ADDR_ANY) {
				addr6 = &ipv6_hdr(skb)->daddr;
				addr_type = ipv6_addr_type(addr6);
			}

			if ((addr_type & IPV6_ADDR_COMPATv4) == 0)
				do_tx_error_icmp = true;
			else {
				do_tx_error_icmp = false;
				dst = addr6->s6_addr32[3];
			}
			neigh_release(neigh);
			if (do_tx_error_icmp)
				goto tx_error_icmp;
		}
#endif
		else
			goto tx_error;

		connected = false;
	}

	tos = tnl_params->tos;
	if (tos & 0x1) {
		tos &= ~0x1;
		if (skb->protocol == htons(ETH_P_IP)) {
			tos = inner_iph->tos;
			connected = false;
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			tos = ipv6_get_dsfield((const struct ipv6hdr *)inner_iph);
			connected = false;
		}
	}
	
	//参数赋值给fl4对象，设置了协议，那么可以进入xfrm分支
	init_tunnel_flow(&fl4, protocol, dst, tnl_params->saddr,			
			 tunnel->parms.o_key, RT_TOS(tos), tunnel->parms.link);

	if (ip_tunnel_encap(skb, tunnel, &protocol, &fl4) < 0)
		goto tx_error;

	rt = connected ? tunnel_rtable_get(tunnel, 0, &fl4.saddr) : NULL;

	if (!rt) {
		rt = ip_route_output_key(tunnel->net, &fl4);	//路由查找，xfrm处理

		if (IS_ERR(rt)) {
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}
		if (connected)
			tunnel_dst_set(tunnel, &rt->dst, fl4.saddr);
	}

	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		dev->stats.collisions++;
		goto tx_error;
	}

	if (tnl_update_pmtu(dev, skb, rt, tnl_params->frag_off, inner_iph)) {
		ip_rt_put(rt);
		goto tx_error;
	}

	if (tunnel->err_count > 0) {
		if (time_before(jiffies,
				tunnel->err_time + IPTUNNEL_ERR_TIMEO)) {
			tunnel->err_count--;

			memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	tos = ip_tunnel_ecn_encap(tos, inner_iph, skb);
	ttl = tnl_params->ttl;
	if (ttl == 0) {
		if (skb->protocol == htons(ETH_P_IP))
			ttl = inner_iph->ttl;
#if IS_ENABLED(CONFIG_IPV6)
		else if (skb->protocol == htons(ETH_P_IPV6))
			ttl = ((const struct ipv6hdr *)inner_iph)->hop_limit;
#endif
		else
			ttl = ip4_dst_hoplimit(&rt->dst);
	}

	df = tnl_params->frag_off;
	if (skb->protocol == htons(ETH_P_IP))
		df |= (inner_iph->frag_off&htons(IP_DF));

	max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr)
			+ rt->dst.header_len + ip_encap_hlen(&tunnel->encap);
	if (max_headroom > dev->needed_headroom)
		dev->needed_headroom = max_headroom;

	if (skb_cow_head(skb, dev->needed_headroom)) {
		ip_rt_put(rt);
		dev->stats.tx_dropped++;
		kfree_skb(skb);
		return;
	}
	//发送报文，此时skb还是内层报文
	err = iptunnel_xmit(NULL, rt, skb, fl4.saddr, fl4.daddr, protocol,		
			    tos, ttl, df, !net_eq(tunnel->net, dev_net(dev)));
	iptunnel_xmit_stats(err, &dev->stats, dev->tstats);

	return;

#if IS_ENABLED(CONFIG_IPV6)
tx_error_icmp:
	dst_link_failure(skb);
#endif
tx_error:
	dev->stats.tx_errors++;
	kfree_skb(skb);
}

int iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
		  __be32 src, __be32 dst, __u8 proto,
		  __u8 tos, __u8 ttl, __be16 df, bool xnet)
{
	int pkt_len = skb->len;
	struct iphdr *iph;
	int err;

	skb_scrub_packet(skb, xnet);

	skb_clear_hash(skb);
	skb_dst_set(skb, &rt->dst);
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	/* Push down and install the IP header. */
	skb_push(skb, sizeof(struct iphdr));  //安装外层ip头
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	df;
	iph->protocol	=	proto;
	iph->tos	=	tos;
	iph->daddr	=	dst;
	iph->saddr	=	src;
	iph->ttl	=	ttl;
	__ip_select_ident(dev_net(rt->dst.dev), iph,
			  skb_shinfo(skb)->gso_segs ?: 1);

	err = ip_local_out_sk(sk, skb);	 //发送报文，重新走协议栈发送报文
	if (unlikely(net_xmit_eval(err)))
		pkt_len = 0;
	return pkt_len;
}
```



