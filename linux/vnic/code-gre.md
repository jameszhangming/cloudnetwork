# GRE

GRE是linux实现的三层隧道设备，构建点到点的隧道，内层为IP报文，本文介绍gre设备创建和报文接收和发送流程。


## 数据结构

```c
static struct rtnl_link_ops ipgre_link_ops __read_mostly = {
	.kind		= "gre",
	.maxtype	= IFLA_GRE_MAX,
	.policy		= ipgre_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipgre_tunnel_setup,
	.validate	= ipgre_tunnel_validate,
	.newlink	= ipgre_newlink,
	.changelink	= ipgre_changelink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipgre_get_size,
	.fill_info	= ipgre_fill_info,
	.get_link_net	= ip_tunnel_get_link_net,
};

//设备驱动
static const struct net_device_ops ipgre_netdev_ops = {
	.ndo_init		= ipgre_tunnel_init,
	.ndo_uninit		= ip_tunnel_uninit,
#ifdef CONFIG_NET_IPGRE_BROADCAST
	.ndo_open		= ipgre_open,
	.ndo_stop		= ipgre_close,
#endif
	.ndo_start_xmit		= ipgre_xmit,
	.ndo_do_ioctl		= ipgre_tunnel_ioctl,
	.ndo_change_mtu		= ip_tunnel_change_mtu,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_get_iflink		= ip_tunnel_get_iflink,
};
```


## gre协议模块初始化

```c
static int __init gre_init(void)
{
	pr_info("GRE over IPv4 demultiplexor driver\n");

	if (inet_add_protocol(&net_gre_protocol, IPPROTO_GRE) < 0) {   //注册协议报文处理方法
		pr_err("can't add protocol\n");
		goto err;
	}

	if (gre_add_protocol(&ipgre_protocol, GREPROTO_CISCO) < 0) {
		pr_info("%s: can't add ipgre handler\n", __func__);
		goto err_gre;
	}

	return 0;
err_gre:
	inet_del_protocol(&net_gre_protocol, IPPROTO_GRE);
err:
	return -EAGAIN;
}
```


## gre设备模块初始化

```c
static int __init ipgre_init(void)
{
	int err;

	pr_info("GRE over IPv4 tunneling driver\n");

	err = register_pernet_device(&ipgre_net_ops);  //注册net namespace 操作
	if (err < 0)
		return err;

	err = register_pernet_device(&ipgre_tap_net_ops); //注册net namespace 操作
	if (err < 0)
		goto pnet_tap_faied;

	err = gre_cisco_register(&ipgre_protocol);    
	if (err < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		goto add_proto_failed;
	}

	err = rtnl_link_register(&ipgre_link_ops);  //注册gre link ops
	if (err < 0)
		goto rtnl_link_failed;

	err = rtnl_link_register(&ipgre_tap_ops);  //注册gretap link ops
	if (err < 0)
		goto tap_ops_failed;

	return 0;

tap_ops_failed:
	rtnl_link_unregister(&ipgre_link_ops);
rtnl_link_failed:
	gre_cisco_unregister(&ipgre_protocol);
add_proto_failed:
	unregister_pernet_device(&ipgre_tap_net_ops);
pnet_tap_faied:
	unregister_pernet_device(&ipgre_net_ops);
	return err;
}
```

## gre设备创建

gre设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）  
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）   //未定义
6. dev->netdev_ops->ndo_open（打开设备）


### validate(ipgre_tunnel_validate)

```c
static int ipgre_tunnel_validate(struct nlattr *tb[], struct nlattr *data[])
{
	__be16 flags;

	if (!data)
		return 0;

	flags = 0;
	if (data[IFLA_GRE_IFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_IFLAGS]);
	if (data[IFLA_GRE_OFLAGS])
		flags |= nla_get_be16(data[IFLA_GRE_OFLAGS]);
	if (flags & (GRE_VERSION|GRE_ROUTING))
		return -EINVAL;

	return 0;
}
```


### setup(ipgre_tunnel_setup)

```c
static void ipgre_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops		= &ipgre_netdev_ops;  //设置驱动
	dev->type		= ARPHRD_IPGRE;
	ip_tunnel_setup(dev, ipgre_net_id);  //通用ip隧道设备设置
}

void ip_tunnel_setup(struct net_device *dev, int net_id)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	tunnel->ip_tnl_net_id = net_id;
}
```

### newlink(ipgre_newlink)

```c
static int ipgre_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
{
	struct ip_tunnel_parm p;
	struct ip_tunnel_encap ipencap;

	if (ipgre_netlink_encap_parms(data, &ipencap)) {
		struct ip_tunnel *t = netdev_priv(dev);
		int err = ip_tunnel_encap_setup(t, &ipencap);

		if (err < 0)
			return err;
	}

	ipgre_netlink_parms(data, tb, &p);
	return ip_tunnel_newlink(dev, tb, &p);
}

int ip_tunnel_newlink(struct net_device *dev, struct nlattr *tb[],
		      struct ip_tunnel_parm *p)
{
	struct ip_tunnel *nt;
	struct net *net = dev_net(dev);
	struct ip_tunnel_net *itn;
	int mtu;
	int err;

	nt = netdev_priv(dev);
	itn = net_generic(net, nt->ip_tnl_net_id);  //gre设备私有数据

	if (ip_tunnel_find(itn, p, dev->type))  //gre设备已存在，源IP和目的IP以及其他信息都相同
		return -EEXIST;

	nt->net = net;
	nt->parms = *p;
	err = register_netdevice(dev);   //注册设备
	if (err)
		goto out;

	if (dev->type == ARPHRD_ETHER && !tb[IFLA_ADDRESS])  //不成立，不会设置mac地址
		eth_hw_addr_random(dev);

	mtu = ip_tunnel_bind_dev(dev);  //计算设备mtu值
	if (!tb[IFLA_MTU])
		dev->mtu = mtu;

	ip_tunnel_add(itn, nt);  //添加到全局变量中，以hash方式保存

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


### ndo_init(ipgre_tunnel_init)

```c
static int ipgre_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;

	__gre_tunnel_init(dev);   //初始化feature属性

	memcpy(dev->dev_addr, &iph->saddr, 4);    //设备IP地址为源IP地址
	memcpy(dev->broadcast, &iph->daddr, 4);   //广播地址为对端的IP地址

	dev->flags		= IFF_NOARP;   //bu 需要arp
	netif_keep_dst(dev);
	dev->addr_len		= 4;

	if (iph->daddr) {
#ifdef CONFIG_NET_IPGRE_BROADCAST
		if (ipv4_is_multicast(iph->daddr)) {    //目的IP为组播地址时，设置header_ops
			if (!iph->saddr)
				return -EINVAL;
			dev->flags = IFF_BROADCAST;
			dev->header_ops = &ipgre_header_ops;
		}
#endif
	} else
		dev->header_ops = &ipgre_header_ops;    //目的IP为0时，设置header_ops

	return ip_tunnel_init(dev);  //通用ip隧道初始化，例如gro等
}

static void __gre_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel;
	int t_hlen;

	tunnel = netdev_priv(dev);
	tunnel->tun_hlen = ip_gre_calc_hlen(tunnel->parms.o_flags);  //得到gre头长度
	tunnel->parms.iph.protocol = IPPROTO_GRE;

	tunnel->hlen = tunnel->tun_hlen + tunnel->encap_hlen;  // tunnel->encap_hlen为0

	t_hlen = tunnel->hlen + sizeof(struct iphdr);  // gre头 + IP头

	dev->needed_headroom	= LL_MAX_HEADER + t_hlen + 4;
	dev->mtu		= ETH_DATA_LEN - t_hlen - 4;

	dev->features		|= GRE_FEATURES;
	dev->hw_features	|= GRE_FEATURES;

	if (!(tunnel->parms.o_flags & TUNNEL_SEQ)) {
		/* TCP offload with GRE SEQ is not supported. */
		dev->features    |= NETIF_F_GSO_SOFTWARE;
		dev->hw_features |= NETIF_F_GSO_SOFTWARE;
		/* Can use a lockless transmit, unless we generate
		 * output sequences
		 */
		dev->features |= NETIF_F_LLTX;
	}
}
```


### ndo_open(ipgre_open)

```c
static int ipgre_open(struct net_device *dev)
{
	struct ip_tunnel *t = netdev_priv(dev);

	if (ipv4_is_multicast(t->parms.iph.daddr)) {  //如果目标IP地址为组播地址
		struct flowi4 fl4;
		struct rtable *rt;

		rt = ip_route_output_gre(t->net, &fl4,
					 t->parms.iph.daddr,
					 t->parms.iph.saddr,
					 t->parms.o_key,
					 RT_TOS(t->parms.iph.tos),
					 t->parms.link);
		if (IS_ERR(rt))
			return -EADDRNOTAVAIL;
		dev = rt->dst.dev; 
		ip_rt_put(rt);
		if (!__in_dev_get_rtnl(dev))
			return -EADDRNOTAVAIL;
		t->mlink = dev->ifindex;
		ip_mc_inc_group(__in_dev_get_rtnl(dev), t->parms.iph.daddr);
	}
	return 0;
}
```


## gre底层设备收包处理

```c
static int gre_rcv(struct sk_buff *skb)  //gre协议报文处理入口
{
	const struct gre_protocol *proto;
	u8 ver;
	int ret;

	if (!pskb_may_pull(skb, 12))
		goto drop;

	ver = skb->data[1]&0x7f;
	if (ver >= GREPROTO_MAX)
		goto drop;

	rcu_read_lock();
	proto = rcu_dereference(gre_proto[ver]);  //根据版本号得到gre_protocol
	if (!proto || !proto->handler)
		goto drop_unlock;
	ret = proto->handler(skb); 
	rcu_read_unlock();
	return ret;

drop_unlock:
	rcu_read_unlock();
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static const struct gre_protocol ipgre_protocol = {
	.handler     = gre_cisco_rcv,
	.err_handler = gre_cisco_err,
};

static int gre_cisco_rcv(struct sk_buff *skb)
{
	struct tnl_ptk_info tpi;
	int i;
	bool csum_err = false;

#ifdef CONFIG_NET_IPGRE_BROADCAST
	if (ipv4_is_multicast(ip_hdr(skb)->daddr)) {
		/* Looped back packet, drop it! */
		if (rt_is_output_route(skb_rtable(skb)))
			goto drop;
	}
#endif

	if (parse_gre_header(skb, &tpi, &csum_err) < 0)  //解析gre头，并移动到内层IP头
		goto drop;

	rcu_read_lock();
	for (i = 0; i < GRE_IP_PROTO_MAX; i++) {
		struct gre_cisco_protocol *proto;
		int ret;

		proto = rcu_dereference(gre_cisco_proto_list[i]);
		if (!proto)
			continue;
		ret = proto->handler(skb, &tpi);   //gre内层报文收包，ipgre_protocol
		if (ret == PACKET_RCVD) {
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
drop:
	kfree_skb(skb);
	return 0;
}

static int parse_gre_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
			    bool *csum_err)
{
	const struct gre_base_hdr *greh;
	__be32 *options;
	int hdr_len;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct gre_base_hdr))))
		return -EINVAL;

	greh = (struct gre_base_hdr *)skb_transport_header(skb);
	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
		return -EINVAL;

	tpi->flags = gre_flags_to_tnl_flags(greh->flags);
	hdr_len = ip_gre_calc_hlen(tpi->flags);

	if (!pskb_may_pull(skb, hdr_len))
		return -EINVAL;

	greh = (struct gre_base_hdr *)skb_transport_header(skb);
	tpi->proto = greh->protocol;   //gre头中包含内层报文的协议

	options = (__be32 *)(greh + 1);
	if (greh->flags & GRE_CSUM) {
		if (skb_checksum_simple_validate(skb)) {
			*csum_err = true;
			return -EINVAL;
		}

		skb_checksum_try_convert(skb, IPPROTO_GRE, 0,
					 null_compute_pseudo);

		options++;
	}

	if (greh->flags & GRE_KEY) {
		tpi->key = *options;
		options++;
	} else
		tpi->key = 0;

	if (unlikely(greh->flags & GRE_SEQ)) {
		tpi->seq = *options;
		options++;
	} else
		tpi->seq = 0;

	/* WCCP version 1 and 2 protocol decoding.
	 * - Change protocol to IP
	 * - When dealing with WCCPv2, Skip extra 4 bytes in GRE header
	 */
	if (greh->flags == 0 && tpi->proto == htons(ETH_P_WCCP)) {
		tpi->proto = htons(ETH_P_IP);
		if ((*(u8 *)options & 0xF0) != 0x40) {
			hdr_len += 4;
			if (!pskb_may_pull(skb, hdr_len))
				return -EINVAL;
		}
	}
    //处理gre头，并移动到内层报文
	return iptunnel_pull_header(skb, hdr_len, tpi->proto);
}

int iptunnel_pull_header(struct sk_buff *skb, int hdr_len, __be16 inner_proto)
{
	if (unlikely(!pskb_may_pull(skb, hdr_len)))
		return -ENOMEM;

	skb_pull_rcsum(skb, hdr_len);   //skb移动到内层IP头

	if (inner_proto == htons(ETH_P_TEB)) {  //内层为mac报文
		struct ethhdr *eh;

		if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
			return -ENOMEM;

		eh = (struct ethhdr *)skb->data;
		if (likely(ntohs(eh->h_proto) >= ETH_P_802_3_MIN))
			skb->protocol = eh->h_proto;
		else
			skb->protocol = htons(ETH_P_802_2);

	} else {
		skb->protocol = inner_proto;
	}

	nf_reset(skb);
	secpath_reset(skb);
	skb_clear_hash_if_not_l4(skb);
	skb_dst_drop(skb);
	skb->vlan_tci = 0;
	skb_set_queue_mapping(skb, 0);
	skb->pkt_type = PACKET_HOST;
	return 0;
}

static struct gre_cisco_protocol ipgre_protocol = {
	.handler        = ipgre_rcv,
	.err_handler    = ipgre_err,
	.priority       = 0,
};

static int ipgre_rcv(struct sk_buff *skb, const struct tnl_ptk_info *tpi)
{
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn;
	const struct iphdr *iph;
	struct ip_tunnel *tunnel;

	if (tpi->proto == htons(ETH_P_TEB))
		itn = net_generic(net, gre_tap_net_id);
	else
		itn = net_generic(net, ipgre_net_id);

	iph = ip_hdr(skb);
	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, tpi->flags,
				  iph->saddr, iph->daddr, tpi->key);

	if (tunnel) {
		skb_pop_mac_header(skb);
		ip_tunnel_rcv(tunnel, skb, tpi, log_ecn_error);
		return PACKET_RCVD;
	}
	return PACKET_REJECT;
}

int ip_tunnel_rcv(struct ip_tunnel *tunnel, struct sk_buff *skb,
		  const struct tnl_ptk_info *tpi, bool log_ecn_error)
{
	struct pcpu_sw_netstats *tstats;
	const struct iphdr *iph = ip_hdr(skb);
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

	if (tunnel->dev->type == ARPHRD_ETHER) {   //gretap设备走此分支
		skb->protocol = eth_type_trans(skb, tunnel->dev);  //解析mac头，skb移到IP头
		skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);   //csum计算
	} else {
		skb->dev = tunnel->dev;
	}

	gro_cells_receive(&tunnel->gro_cells, skb);    //内层报文放入gro链表，触发软中断
	return 0;

drop:
	kfree_skb(skb);
	return 0;
}
```


## gre发包处理

```c
static netdev_tx_t ipgre_xmit(struct sk_buff *skb,
			      struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *tnl_params;

	if (dev->header_ops) {   //组播等场景
		/* Need space for new headers */
		if (skb_cow_head(skb, dev->needed_headroom -
				      (tunnel->hlen + sizeof(struct iphdr))))
			goto free_skb;

		tnl_params = (const struct iphdr *)skb->data;

		/* Pull skb since ip_tunnel_xmit() needs skb->data pointing
		 * to gre header.
		 */
		skb_pull(skb, tunnel->hlen + sizeof(struct iphdr));  // header_ops的create函数会增加这个长度的内容
		skb_reset_mac_header(skb);
	} else {
		if (skb_cow_head(skb, dev->needed_headroom))
			goto free_skb;

		tnl_params = &tunnel->parms.iph;
	}

	skb = gre_handle_offloads(skb, !!(tunnel->parms.o_flags&TUNNEL_CSUM));   //offloads处理
	if (IS_ERR(skb))
		goto out;

	__gre_xmit(skb, dev, tnl_params, skb->protocol);

	return NETDEV_TX_OK;

free_skb:
	kfree_skb(skb);
out:
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static void __gre_xmit(struct sk_buff *skb, struct net_device *dev,
		       const struct iphdr *tnl_params,
		       __be16 proto)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct tnl_ptk_info tpi;

	tpi.flags = tunnel->parms.o_flags;
	tpi.proto = proto;
	tpi.key = tunnel->parms.o_key;
	if (tunnel->parms.o_flags & TUNNEL_SEQ)
		tunnel->o_seqno++;
	tpi.seq = htonl(tunnel->o_seqno);

	/* Push GRE header. */
	gre_build_header(skb, &tpi, tunnel->tun_hlen);  //构建gre头

	skb_set_inner_protocol(skb, tpi.proto);

	// ip隧道发送报文，可参考ipip中的代码分析
	ip_tunnel_xmit(skb, dev, tnl_params, tnl_params->protocol);  
}

void gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		      int hdr_len)
{
	struct gre_base_hdr *greh;

	skb_push(skb, hdr_len);

	skb_reset_transport_header(skb);
	greh = (struct gre_base_hdr *)skb->data;
	greh->flags = tnl_flags_to_gre_flags(tpi->flags);
	greh->protocol = tpi->proto;

	if (tpi->flags&(TUNNEL_KEY|TUNNEL_CSUM|TUNNEL_SEQ)) {
		__be32 *ptr = (__be32 *)(((u8 *)greh) + hdr_len - 4);

		if (tpi->flags&TUNNEL_SEQ) {
			*ptr = tpi->seq;
			ptr--;
		}
		if (tpi->flags&TUNNEL_KEY) {
			*ptr = tpi->key;
			ptr--;
		}
		if (tpi->flags&TUNNEL_CSUM &&
		    !(skb_shinfo(skb)->gso_type &
		      (SKB_GSO_GRE|SKB_GSO_GRE_CSUM))) {
			*ptr = 0;
			*(__sum16 *)ptr = csum_fold(skb_checksum(skb, 0,
								 skb->len, 0));
		}
	}
}
```



