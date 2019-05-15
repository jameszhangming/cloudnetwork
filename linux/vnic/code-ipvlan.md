# IPVLAN

MACVLAN是linux模拟以太网二层设备，IPVLAN也是三层以太网设备，类似于在一个物理以太网卡上配置了多个IP地址。

IPVLAN是一个以太网二层设备：

* 有mac地址，mac地址为母设备的MAC地址；
* 有header_ops方法，该方法为调用底层设备的header_ops方法，可以减少三层路由（ipip设备发包时，要多走一次路由）

IPVLAN 有两种模式：

* L2模式
  * 收包时，1）目的mac为组播地址，如果是则会广播；2）目的mac不是组播地址，处理方式和L2相同；
  * 发包时：1）源mac和目的mac相同，目的IP指定的IPVLAN设备收包；2）目的mac会组播地址，广播该报文，发送ipvlan设备不收包；3）直接底层设备二层发包
* L3模式
  * 收包时，根据目的IP来选择ipvlan设备，进行收包；
  * 发包时，需要剥除mac头，重走IP路由进行发包； （为什么不直接用母设备发包？）


## 数据结构

```c
static struct rtnl_link_ops ipvlan_link_ops = {
	.kind		= "ipvlan",
	.priv_size	= sizeof(struct ipvl_dev),
	.get_size	= ipvlan_nl_getsize,
	.policy		= ipvlan_nl_policy,
	.validate	= ipvlan_nl_validate,
	.fill_info	= ipvlan_nl_fillinfo,
	.changelink	= ipvlan_nl_changelink,
	.maxtype	= IFLA_IPVLAN_MAX,
	.setup		= ipvlan_link_setup,
	.newlink	= ipvlan_link_new,
	.dellink	= ipvlan_link_delete,
};

//设备驱动
static const struct net_device_ops ipvlan_netdev_ops = {
	.ndo_init		= ipvlan_init,
	.ndo_uninit		= ipvlan_uninit,
	.ndo_open		= ipvlan_open,
	.ndo_stop		= ipvlan_stop,
	.ndo_start_xmit		= ipvlan_start_xmit,
	.ndo_fix_features	= ipvlan_fix_features,
	.ndo_change_rx_flags	= ipvlan_change_rx_flags,
	.ndo_set_rx_mode	= ipvlan_set_multicast_mac_filter,
	.ndo_get_stats64	= ipvlan_get_stats64,
	.ndo_vlan_rx_add_vid	= ipvlan_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ipvlan_vlan_rx_kill_vid,
	.ndo_get_iflink		= ipvlan_get_iflink,
};
```

## 模块初始化

```c
static int __init ipvlan_init_module(void)
{
	int err;

	ipvlan_init_secret();
	register_netdevice_notifier(&ipvlan_notifier_block);
	register_inet6addr_notifier(&ipvlan_addr6_notifier_block);
	register_inetaddr_notifier(&ipvlan_addr4_notifier_block);

	err = ipvlan_link_register(&ipvlan_link_ops);  //注册link ops
	if (err < 0)
		goto error;

	return 0;
error:
	unregister_inetaddr_notifier(&ipvlan_addr4_notifier_block);
	unregister_inet6addr_notifier(&ipvlan_addr6_notifier_block);
	unregister_netdevice_notifier(&ipvlan_notifier_block);
	return err;
}
```


## ipvlan设备创建

ipvlan设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）  
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）  //未定义
6. dev->netdev_ops->ndo_open（打开设备）

### validate(ipvlan_nl_validate)

```c
static int ipvlan_nl_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (data && data[IFLA_IPVLAN_MODE]) {   //校验mode类型
		u16 mode = nla_get_u16(data[IFLA_IPVLAN_MODE]);

		if (mode < IPVLAN_MODE_L2 || mode >= IPVLAN_MODE_MAX)
			return -EINVAL;
	}
	return 0;
}
```

### setup(ipvlan_link_setup)

```c
static void ipvlan_link_setup(struct net_device *dev)
{
	ether_setup(dev);   //通用以太网设备设置

	dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);
	dev->priv_flags |= IFF_UNICAST_FLT;
	dev->netdev_ops = &ipvlan_netdev_ops;
	dev->destructor = free_netdev;
	dev->header_ops = &ipvlan_header_ops;   //设置header ops，调用底层设备的header_ops
	dev->ethtool_ops = &ipvlan_ethtool_ops;
	dev->tx_queue_len = 0;
}
```

### newlink(ipvlan_link_new)

```c
static int ipvlan_link_new(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[])
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ipvl_port *port;
	struct net_device *phy_dev;
	int err;

	if (!tb[IFLA_LINK])
		return -EINVAL;

	phy_dev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (!phy_dev)
		return -ENODEV;

	if (netif_is_ipvlan(phy_dev)) {
		struct ipvl_dev *tmp = netdev_priv(phy_dev);

		phy_dev = tmp->phy_dev;
	} else if (!netif_is_ipvlan_port(phy_dev)) {
		err = ipvlan_port_create(phy_dev);
		if (err < 0)
			return err;
	}

	port = ipvlan_port_get_rtnl(phy_dev);
	if (data && data[IFLA_IPVLAN_MODE])
		port->mode = nla_get_u16(data[IFLA_IPVLAN_MODE]);

	ipvlan->phy_dev = phy_dev;
	ipvlan->dev = dev;
	ipvlan->port = port;
	ipvlan->sfeatures = IPVLAN_FEATURES;
	INIT_LIST_HEAD(&ipvlan->addrs);
	ipvlan->ipv4cnt = 0;
	ipvlan->ipv6cnt = 0;

	/* TODO Probably put random address here to be presented to the
	 * world but keep using the physical-dev address for the outgoing
	 * packets.
	 */
	memcpy(dev->dev_addr, phy_dev->dev_addr, ETH_ALEN);   //拷贝母设备的mac地址

	dev->priv_flags |= IFF_IPVLAN_SLAVE;

	port->count += 1;
	err = register_netdevice(dev);
	if (err < 0)
		goto ipvlan_destroy_port;

	err = netdev_upper_dev_link(phy_dev, dev);
	if (err)
		goto ipvlan_destroy_port;

	list_add_tail_rcu(&ipvlan->pnode, &port->ipvlans); //添加到port链表中，以母设备为粒度
	netif_stacked_transfer_operstate(phy_dev, dev);
	return 0;

ipvlan_destroy_port:
	port->count -= 1;
	if (!port->count)
		ipvlan_port_destroy(phy_dev);

	return err;
}

static int ipvlan_port_create(struct net_device *dev)
{
	struct ipvl_port *port;
	int err, idx;

	if (dev->type != ARPHRD_ETHER || dev->flags & IFF_LOOPBACK) {
		netdev_err(dev, "Master is either lo or non-ether device\n");
		return -EINVAL;
	}

	if (netif_is_macvlan_port(dev)) {
		netdev_err(dev, "Master is a macvlan port.\n");
		return -EBUSY;
	}

	port = kzalloc(sizeof(struct ipvl_port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->dev = dev;
	port->mode = IPVLAN_MODE_L3;      //默认是L3模式
	INIT_LIST_HEAD(&port->ipvlans);
	for (idx = 0; idx < IPVLAN_HASH_SIZE; idx++)
		INIT_HLIST_HEAD(&port->hlhead[idx]);

	err = netdev_rx_handler_register(dev, ipvlan_handle_frame, port);  //注册收包处理
	if (err)
		goto err;

	dev->priv_flags |= IFF_IPVLAN_MASTER;
	return 0;

err:
	kfree_rcu(port, rcu);
	return err;
}
```


### ndo_init(ipvlan_init)

```c
static int ipvlan_init(struct net_device *dev)
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	const struct net_device *phy_dev = ipvlan->phy_dev;

	dev->state = (dev->state & ~IPVLAN_STATE_MASK) |
		     (phy_dev->state & IPVLAN_STATE_MASK);
	dev->features = phy_dev->features & IPVLAN_FEATURES;
	dev->features |= NETIF_F_LLTX;
	dev->gso_max_size = phy_dev->gso_max_size;
	dev->hard_header_len = phy_dev->hard_header_len;

	ipvlan_set_lockdep_class(dev);

	ipvlan->pcpu_stats = alloc_percpu(struct ipvl_pcpu_stats);
	if (!ipvlan->pcpu_stats)
		return -ENOMEM;

	return 0;
}
```


### ndo_open(ipvlan_open)

```c
static int ipvlan_open(struct net_device *dev)
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct net_device *phy_dev = ipvlan->phy_dev;
	struct ipvl_addr *addr;

	if (ipvlan->port->mode == IPVLAN_MODE_L3)
		dev->flags |= IFF_NOARP;
	else
		dev->flags &= ~IFF_NOARP;

	if (ipvlan->ipv6cnt > 0 || ipvlan->ipv4cnt > 0) {
		list_for_each_entry(addr, &ipvlan->addrs, anode)
			ipvlan_ht_addr_add(ipvlan, addr);
	}
	return dev_uc_add(phy_dev, phy_dev->dev_addr);   //增加单播地址
}
```

## macvlan底层设备收包处理

```c
rx_handler_result_t ipvlan_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct ipvl_port *port = ipvlan_port_get_rcu(skb->dev);

	if (!port)
		return RX_HANDLER_PASS;

	switch (port->mode) {
	case IPVLAN_MODE_L2:
		return ipvlan_handle_mode_l2(pskb, port);
	case IPVLAN_MODE_L3:
		return ipvlan_handle_mode_l3(pskb, port);
	}

	/* Should not reach here */
	WARN_ONCE(true, "ipvlan_handle_frame() called for mode = [%hx]\n",
			  port->mode);
	kfree_skb(skb);
	return NET_RX_DROP;
}
```


### ipvlan_handle_mode_l3

```c
static rx_handler_result_t ipvlan_handle_mode_l3(struct sk_buff **pskb,
						 struct ipvl_port *port)
{
	void *lyr3h;
	int addr_type;
	struct ipvl_addr *addr;
	struct sk_buff *skb = *pskb;
	rx_handler_result_t ret = RX_HANDLER_PASS;

	lyr3h = ipvlan_get_L3_hdr(skb, &addr_type);   //得到三层头，IP、arp、icmp、ipv6等四类
	if (!lyr3h)
		goto out;

	addr = ipvlan_addr_lookup(port, lyr3h, addr_type, true);  //查找到ipvlan对应的IP地址
	if (addr)
		ret = ipvlan_rcv_frame(addr, skb, false);

out:
	return ret;
}
```

### ipvlan_handle_mode_l2

```c
static rx_handler_result_t ipvlan_handle_mode_l2(struct sk_buff **pskb,
						 struct ipvl_port *port)
{
	struct sk_buff *skb = *pskb;
	struct ethhdr *eth = eth_hdr(skb);
	rx_handler_result_t ret = RX_HANDLER_PASS;
	void *lyr3h;
	int addr_type;

	if (is_multicast_ether_addr(eth->h_dest)) {    //目的mac是否为组播地址
		if (ipvlan_external_frame(skb, port))
			ipvlan_multicast_frame(port, skb, NULL, false);   //发送给所有ipvlan设备
	} else {
		struct ipvl_addr *addr;

		lyr3h = ipvlan_get_L3_hdr(skb, &addr_type);  //得到三层头，IP、arp、icmp、ipv6等四类
		if (!lyr3h)
			return ret;

		addr = ipvlan_addr_lookup(port, lyr3h, addr_type, true);  //查找到ipvlan对应的IP地址
		if (addr)
			ret = ipvlan_rcv_frame(addr, skb, false);
	}

	return ret;
}
```

### ipvlan_multicast_frame

```c
static void ipvlan_multicast_frame(struct ipvl_port *port, struct sk_buff *skb,
				   const struct ipvl_dev *in_dev, bool local)
{
	struct ethhdr *eth = eth_hdr(skb);
	struct ipvl_dev *ipvlan;
	struct sk_buff *nskb;
	unsigned int len;
	unsigned int mac_hash;
	int ret;

	if (skb->protocol == htons(ETH_P_PAUSE))
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(ipvlan, &port->ipvlans, pnode) {
		if (local && (ipvlan == in_dev))
			continue;

		mac_hash = ipvlan_mac_hash(eth->h_dest);
		if (!test_bit(mac_hash, ipvlan->mac_filters))
			continue;

		ret = NET_RX_DROP;
		len = skb->len + ETH_HLEN;
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			goto mcast_acct;

		if (ether_addr_equal(eth->h_dest, ipvlan->phy_dev->broadcast))
			nskb->pkt_type = PACKET_BROADCAST;
		else
			nskb->pkt_type = PACKET_MULTICAST;

		nskb->dev = ipvlan->dev;
		if (local)
			ret = dev_forward_skb(ipvlan->dev, nskb);   
		else
			ret = netif_rx(nskb);    //协议栈收包
mcast_acct:
		ipvlan_count_rx(ipvlan, len, ret == NET_RX_SUCCESS, true);
	}
	rcu_read_unlock();

	/* Locally generated? ...Forward a copy to the main-device as
	 * well. On the RX side we'll ignore it (wont give it to any
	 * of the virtual devices.
	 */
	if (local) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (nskb) {
			if (ether_addr_equal(eth->h_dest, port->dev->broadcast))
				nskb->pkt_type = PACKET_BROADCAST;
			else
				nskb->pkt_type = PACKET_MULTICAST;

			dev_forward_skb(port->dev, nskb);
		}
	}
}
```

### ipvlan_rcv_frame

```c
static int ipvlan_rcv_frame(struct ipvl_addr *addr, struct sk_buff *skb,
			    bool local)
{
	struct ipvl_dev *ipvlan = addr->master;   //根据addr得到ipvlan设备
	struct net_device *dev = ipvlan->dev;
	unsigned int len;
	rx_handler_result_t ret = RX_HANDLER_CONSUMED;
	bool success = false;

	len = skb->len + ETH_HLEN;     //报文总长度
	if (unlikely(!(dev->flags & IFF_UP))) {
		kfree_skb(skb);
		goto out;
	}

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out;

	skb->dev = dev;
	skb->pkt_type = PACKET_HOST;   //发送给本地的报文

	if (local) {
		if (dev_forward_skb(ipvlan->dev, skb) == NET_RX_SUCCESS)
			success = true;
	} else {
	    //走此分支，skb的dev设备已经改成ipvlan设备，会重新走收包（略过vlan解析）
		ret = RX_HANDLER_ANOTHER;  
		success = true;
	}

out:
	ipvlan_count_rx(ipvlan, len, success, false);
	return ret;
}
```


## ipvlan发包处理

```c
static netdev_tx_t ipvlan_start_xmit(struct sk_buff *skb,
				     struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	int skblen = skb->len;
	int ret;

	ret = ipvlan_queue_xmit(skb, dev);   //发送报文
	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
		struct ipvl_pcpu_stats *pcptr;

		pcptr = this_cpu_ptr(ipvlan->pcpu_stats);

		u64_stats_update_begin(&pcptr->syncp);
		pcptr->tx_pkts++;
		pcptr->tx_bytes += skblen;
		u64_stats_update_end(&pcptr->syncp);
	} else {
		this_cpu_inc(ipvlan->pcpu_stats->tx_drps);
	}
	return ret;
}

int ipvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ipvl_port *port = ipvlan_port_get_rcu(ipvlan->phy_dev);   //得到port

	if (!port)
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct ethhdr))))
		goto out;

	switch(port->mode) {
	case IPVLAN_MODE_L2:
		return ipvlan_xmit_mode_l2(skb, dev);
	case IPVLAN_MODE_L3:
		return ipvlan_xmit_mode_l3(skb, dev);
	}

	/* Should not reach here */
	WARN_ONCE(true, "ipvlan_queue_xmit() called for mode = [%hx]\n",
			  port->mode);
out:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}
```

### ipvlan_xmit_mode_l2

```c
static int ipvlan_xmit_mode_l2(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ethhdr *eth = eth_hdr(skb);
	struct ipvl_addr *addr;
	void *lyr3h;
	int addr_type;

	if (ether_addr_equal(eth->h_dest, eth->h_source)) {   //判断源mac和目的mac是否相同
		lyr3h = ipvlan_get_L3_hdr(skb, &addr_type);
		if (lyr3h) {
			addr = ipvlan_addr_lookup(ipvlan->port, lyr3h, addr_type, true);  //根据目的IP找到ipvlan设备
			if (addr)
				return ipvlan_rcv_frame(addr, skb, true);   //IPVLAN设备收包
		}
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return NET_XMIT_DROP;

		/* Packet definitely does not belong to any of the
		 * virtual devices, but the dest is local. So forward
		 * the skb for the main-dev. At the RX side we just return
		 * RX_PASS for it to be processed further on the stack.
		 */
		return dev_forward_skb(ipvlan->phy_dev, skb);

	} else if (is_multicast_ether_addr(eth->h_dest)) {   //如果目的mac是组播地址
		u8 ip_summed = skb->ip_summed;

		skb->ip_summed = CHECKSUM_UNNECESSARY;
		ipvlan_multicast_frame(ipvlan->port, skb, ipvlan, true);   //组播收包，发送ipvlan设备不会收到报文
		skb->ip_summed = ip_summed;
	}

	skb->dev = ipvlan->phy_dev;
	return dev_queue_xmit(skb);    //底层设备二层发包，走了两次qdisc
}
```

### ipvlan_xmit_mode_l3

```c
static int ipvlan_xmit_mode_l3(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	void *lyr3h;
	struct ipvl_addr *addr;
	int addr_type;

	lyr3h = ipvlan_get_L3_hdr(skb, &addr_type);  //得到三层头
	if (!lyr3h)
		goto out;

	addr = ipvlan_addr_lookup(ipvlan->port, lyr3h, addr_type, true);   //根据目的IP找到ipvlan设备
	if (addr)
		return ipvlan_rcv_frame(addr, skb, true);    //IPVLAN设备收包

out:
	skb->dev = ipvlan->phy_dev;
	return ipvlan_process_outbound(skb, ipvlan);  
}

static int ipvlan_process_outbound(struct sk_buff *skb,
				   const struct ipvl_dev *ipvlan)
{
	struct ethhdr *ethh = eth_hdr(skb);
	int ret = NET_XMIT_DROP;

	/* In this mode we dont care about multicast and broadcast traffic */
	if (is_multicast_ether_addr(ethh->h_dest)) {
		pr_warn_ratelimited("Dropped {multi|broad}cast of type= [%x]\n",
				    ntohs(skb->protocol));
		kfree_skb(skb);
		goto out;
	}

	/* The ipvlan is a pseudo-L2 device, so the packets that we receive
	 * will have L2; which need to discarded and processed further
	 * in the net-ns of the main-device.
	 */
	if (skb_mac_header_was_set(skb)) {
		skb_pull(skb, sizeof(*ethh));    //剥除mac头
		skb->mac_header = (typeof(skb->mac_header))~0U;
		skb_reset_network_header(skb);
	}

	if (skb->protocol == htons(ETH_P_IPV6))
		ret = ipvlan_process_v6_outbound(skb);
	else if (skb->protocol == htons(ETH_P_IP))
		ret = ipvlan_process_v4_outbound(skb);
	else {
		pr_warn_ratelimited("Dropped outbound packet type=%x\n",
				    ntohs(skb->protocol));
		kfree_skb(skb);
	}
out:
	return ret;
}

static int ipvlan_process_v4_outbound(struct sk_buff *skb)
{
	const struct iphdr *ip4h = ip_hdr(skb);
	struct net_device *dev = skb->dev;
	struct rtable *rt;
	int err, ret = NET_XMIT_DROP;
	struct flowi4 fl4 = {
		.flowi4_oif = dev_get_iflink(dev),
		.flowi4_tos = RT_TOS(ip4h->tos),
		.flowi4_flags = FLOWI_FLAG_ANYSRC,
		.daddr = ip4h->daddr,
		.saddr = ip4h->saddr,
	};

	rt = ip_route_output_flow(dev_net(dev), &fl4, NULL);   //路由查找
	if (IS_ERR(rt))
		goto err;

	if (rt->rt_type != RTN_UNICAST && rt->rt_type != RTN_LOCAL) {
		ip_rt_put(rt);
		goto err;
	}
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);
	err = ip_local_out(skb);      //IP设备本地发出
	if (unlikely(net_xmit_eval(err)))
		dev->stats.tx_errors++;
	else
		ret = NET_XMIT_SUCCESS;
	goto out;
err:
	dev->stats.tx_errors++;
	kfree_skb(skb);
out:
	return ret;
}
```

