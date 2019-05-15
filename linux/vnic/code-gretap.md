# GRETAP

GRETAP是linux实现的二层隧道设备，构建点到点的隧道，内层为MAC报文，本文介绍gretap设备创建和报文接收和发送流程。


## 数据结构

```c
static struct rtnl_link_ops ipgre_tap_ops __read_mostly = {
	.kind		= "gretap",
	.maxtype	= IFLA_GRE_MAX,
	.policy		= ipgre_policy,
	.priv_size	= sizeof(struct ip_tunnel),
	.setup		= ipgre_tap_setup,
	.validate	= ipgre_tap_validate,
	.newlink	= ipgre_newlink,
	.changelink	= ipgre_changelink,
	.dellink	= ip_tunnel_dellink,
	.get_size	= ipgre_get_size,
	.fill_info	= ipgre_fill_info,
	.get_link_net	= ip_tunnel_get_link_net,
};

//设备驱动
static const struct net_device_ops gre_tap_netdev_ops = {
	.ndo_init		= gre_tap_init,
	.ndo_uninit		= ip_tunnel_uninit,
	.ndo_start_xmit		= gre_tap_xmit,
	.ndo_set_mac_address 	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= ip_tunnel_change_mtu,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_get_iflink		= ip_tunnel_get_iflink,
};
```


## gretap设备创建

gretap设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数） 
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）
6. dev->netdev_ops->ndo_open（打开设备）   //未定义


### validate(ipgre_tap_validate)

```c
static int ipgre_tap_validate(struct nlattr *tb[], struct nlattr *data[])
{
	__be32 daddr;

	if (tb[IFLA_ADDRESS]) {   //校验mac地址
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	if (!data)
		goto out;

	if (data[IFLA_GRE_REMOTE]) {   //校验对端
		memcpy(&daddr, nla_data(data[IFLA_GRE_REMOTE]), 4);
		if (!daddr)
			return -EINVAL;
	}

out:
	return ipgre_tunnel_validate(tb, data);   //调用gre设备的validate方法
}
```


### setup(ipgre_tap_setup)

```c
static void ipgre_tap_setup(struct net_device *dev)
{
	ether_setup(dev);   //通用以太网设备设置
	dev->netdev_ops		= &gre_tap_netdev_ops;  //设置驱动
	dev->priv_flags 	|= IFF_LIVE_ADDR_CHANGE;
	ip_tunnel_setup(dev, gre_tap_net_id);   //调用通用ip隧道setup方法
}
```

### newlink(macvlan_common_newlink)

同gre设备的newlink方法


### ndo_init(macvlan_init)

```c
static int gre_tap_init(struct net_device *dev)
{
	__gre_tunnel_init(dev);   //初始化feature属性
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	return ip_tunnel_init(dev);  //通用ip隧道初始化，例如gro等
}
```

### ndo_validate_addr(eth_validate_addr)

使用以太网网络设备的地址检验方法

```c
int eth_validate_addr(struct net_device *dev)
{
	if (!is_valid_ether_addr(dev->dev_addr))
		return -EADDRNOTAVAIL;

	return 0;
}
```


## gretap底层设备收包处理

```c
static rx_handler_result_t macvlan_handle_frame(struct sk_buff **pskb)
{
	struct macvlan_port *port;
	struct sk_buff *skb = *pskb;
	const struct ethhdr *eth = eth_hdr(skb);
	const struct macvlan_dev *vlan;
	const struct macvlan_dev *src;
	struct net_device *dev;
	unsigned int len = 0;
	int ret;
	rx_handler_result_t handle_res;

	port = macvlan_port_get_rcu(skb->dev);   //得到vlan port
	if (is_multicast_ether_addr(eth->h_dest)) {		//组播处理
		skb = ip_check_defrag(skb, IP_DEFRAG_MACVLAN);
		if (!skb)
			return RX_HANDLER_CONSUMED;
		eth = eth_hdr(skb);
		macvlan_forward_source(skb, port, eth->h_source);	//配置smac的macvlan设备收包
		//找到maclan设备的mac地址等于报文源mac，即发送该报文的macvlan设备
		src = macvlan_hash_lookup(port, eth->h_source);	
        //如果是本地发送的组播报文，如果不是brdige模式和VEP模式，只有本设备可以接收		
		if (src && src->mode != MACVLAN_MODE_VEPA &&			
		    src->mode != MACVLAN_MODE_BRIDGE) {
			/* forward to original port. */
			vlan = src;
			ret = macvlan_broadcast_one(skb, vlan, eth, 0) ?:	//设置报文的dev为src设备
			      netif_rx(skb);				  //调用收报函数， 直接以macvlan设备收报
			handle_res = RX_HANDLER_CONSUMED;     //报文已经被消耗，netif_receive_skb将不会进一步进行处理
			goto out;
		}

		MACVLAN_SKB_CB(skb)->src = src;
		macvlan_broadcast_enqueue(port, skb);	//bridge或VEPA模式，或者是外部发送的组播报文，则广播接收报文

		return RX_HANDLER_PASS;
	}

	macvlan_forward_source(skb, port, eth->h_source); //配置smac的macvlan设备收包
	if (port->passthru)
		vlan = list_first_or_null_rcu(&port->vlans,
					      struct macvlan_dev, list);
	else
		vlan = macvlan_hash_lookup(port, eth->h_dest);	//根据目的mac查找到macvlan设备
	if (vlan == NULL)
		return RX_HANDLER_PASS;	 //不再处理，提交给协议栈处理

	dev = vlan->dev;
	if (unlikely(!(dev->flags & IFF_UP))) {
		kfree_skb(skb);
		return RX_HANDLER_CONSUMED;
	}
	len = skb->len + ETH_HLEN;
	skb = skb_share_check(skb, GFP_ATOMIC);	
	if (!skb) {
		ret = NET_RX_DROP;
		handle_res = RX_HANDLER_CONSUMED;
		goto out;
	}

	skb->dev = dev;	//skb的设备设置为macvlan对象
	skb->pkt_type = PACKET_HOST;

	ret = NET_RX_SUCCESS;
	//使得__netif_receive_skb_core函数再处理一轮，以macvlan设备的名义，macvlan设备未设置rx_handler函数，将送往协议栈处理。
	handle_res = RX_HANDLER_ANOTHER;			
out:
	macvlan_count_rx(vlan, len, ret == NET_RX_SUCCESS, false);
	return handle_res;
}

static void macvlan_forward_source(struct sk_buff *skb,
				   struct macvlan_port *port,
				   const unsigned char *addr)
{
	struct macvlan_source_entry *entry;
	u32 idx = macvlan_eth_hash(addr);
	struct hlist_head *h = &port->vlan_source_hash[idx];

	hlist_for_each_entry_rcu(entry, h, hlist) {   
		if (ether_addr_equal_64bits(entry->addr, addr))
			if (entry->vlan->dev->flags & IFF_UP)
				macvlan_forward_source_one(skb, entry->vlan);
	}
}

static void macvlan_forward_source_one(struct sk_buff *skb,
				       struct macvlan_dev *vlan)
{
	struct sk_buff *nskb;
	struct net_device *dev;
	int len;
	int ret;

	dev = vlan->dev;
	if (unlikely(!(dev->flags & IFF_UP)))
		return;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return;

	len = nskb->len + ETH_HLEN;
	nskb->dev = dev;
	nskb->pkt_type = PACKET_HOST;

	ret = netif_rx(nskb);    //内核收包
	macvlan_count_rx(vlan, len, ret == NET_RX_SUCCESS, false);
}
```


## gretap发包处理

```c
static netdev_tx_t gre_tap_xmit(struct sk_buff *skb,
				struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	
	//offloads处理
	skb = gre_handle_offloads(skb, !!(tunnel->parms.o_flags&TUNNEL_CSUM));
	if (IS_ERR(skb))
		goto out;

	if (skb_cow_head(skb, dev->needed_headroom))
		goto free_skb;
	
	//参考ipip设备的发包处理流程
	__gre_xmit(skb, dev, &tunnel->parms.iph, htons(ETH_P_TEB));

	return NETDEV_TX_OK;

free_skb:
	kfree_skb(skb);
out:
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

```



