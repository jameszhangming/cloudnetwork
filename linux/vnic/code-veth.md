# Veth

veth提供点到点的管道设备，从一端发送的报文会从另外一端接收。应用场景包括：容器网络方案、虚拟交换设备连接等。

## 数据结构

```c
static struct rtnl_link_ops veth_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct veth_priv),
	.setup		= veth_setup,
	.validate	= veth_validate,
	.newlink	= veth_newlink,
	.dellink	= veth_dellink,
	.policy		= veth_policy,
	.maxtype	= VETH_INFO_MAX,
	.get_link_net	= veth_get_link_net,
};

static const struct net_device_ops veth_netdev_ops = {
	.ndo_init            = veth_dev_init,
	.ndo_open            = veth_open,
	.ndo_stop            = veth_close,
	.ndo_start_xmit      = veth_xmit,
	.ndo_change_mtu      = veth_change_mtu,
	.ndo_get_stats64     = veth_get_stats64,
	.ndo_set_rx_mode     = veth_set_multicast_list,
	.ndo_set_mac_address = eth_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= veth_poll_controller,
#endif
	.ndo_get_iflink		= veth_get_iflink,
};

static const struct ethtool_ops veth_ethtool_ops = {
	.get_settings		= veth_get_settings,
	.get_drvinfo		= veth_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_strings		= veth_get_strings,
	.get_sset_count		= veth_get_sset_count,
	.get_ethtool_stats	= veth_get_ethtool_stats,
};
```

## 模块初始化

```c
static __init int veth_init(void)
{
	return rtnl_link_register(&veth_link_ops);  //link ops注册
}
```

## veth设备创建

veth设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）   //未定义
6. dev->netdev_ops->ndo_open（打开设备）

### validate(veth_validate)

```c
static int veth_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)  //mac地址长度必须为6
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))  //不能使用组播mac地址
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_veth_mtu(nla_get_u32(tb[IFLA_MTU])))   //校验mtu大小
			return -EINVAL;
	}
	return 0;
}
```

### setup(veth_setup)

```c
static void veth_setup(struct net_device *dev)
{
	ether_setup(dev);   //以太网设备设置

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	dev->netdev_ops = &veth_netdev_ops;  //设置驱动
	dev->ethtool_ops = &veth_ethtool_ops;   //设置ethtool_ops
	dev->features |= NETIF_F_LLTX;
	dev->features |= VETH_FEATURES;
	dev->vlan_features = dev->features &
			     ~(NETIF_F_HW_VLAN_CTAG_TX |
			       NETIF_F_HW_VLAN_STAG_TX |
			       NETIF_F_HW_VLAN_CTAG_RX |
			       NETIF_F_HW_VLAN_STAG_RX);
	dev->destructor = veth_dev_free;

	dev->hw_features = VETH_FEATURES;
	dev->hw_enc_features = VETH_FEATURES;
}
```


### newlink(veth_newlink)

```c
static int veth_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
{
	int err;
	struct net_device *peer;
	struct veth_priv *priv;
	char ifname[IFNAMSIZ];
	struct nlattr *peer_tb[IFLA_MAX + 1], **tbp;
	unsigned char name_assign_type;
	struct ifinfomsg *ifmp;
	struct net *net;

	/*
	 * create and register peer first
	 */
	if (data != NULL && data[VETH_INFO_PEER] != NULL) {
		struct nlattr *nla_peer;

		nla_peer = data[VETH_INFO_PEER];
		ifmp = nla_data(nla_peer);
		err = rtnl_nla_parse_ifla(peer_tb,
					  nla_data(nla_peer) + sizeof(struct ifinfomsg),
					  nla_len(nla_peer) - sizeof(struct ifinfomsg));
		if (err < 0)
			return err;

		err = veth_validate(peer_tb, NULL);
		if (err < 0)
			return err;

		tbp = peer_tb;
	} else {
		ifmp = NULL;
		tbp = tb;
	}

	if (tbp[IFLA_IFNAME]) {
		nla_strlcpy(ifname, tbp[IFLA_IFNAME], IFNAMSIZ);
		name_assign_type = NET_NAME_USER;
	} else {
		snprintf(ifname, IFNAMSIZ, DRV_NAME "%%d");
		name_assign_type = NET_NAME_ENUM;
	}

	net = rtnl_link_get_net(src_net, tbp);
	if (IS_ERR(net))
		return PTR_ERR(net);

	peer = rtnl_create_link(net, ifname, name_assign_type,  //创建对端设备
				&veth_link_ops, tbp);
	if (IS_ERR(peer)) {
		put_net(net);
		return PTR_ERR(peer);
	}

	if (tbp[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(peer);

	if (ifmp && (dev->ifindex != 0))
		peer->ifindex = ifmp->ifi_index;

	err = register_netdevice(peer);    //注册对端设备
	put_net(net);
	net = NULL;
	if (err < 0)
		goto err_register_peer;

	netif_carrier_off(peer);

	err = rtnl_configure_link(peer, ifmp);   //打开对端设备
	if (err < 0)
		goto err_configure_peer;

	/*
	 * register dev last
	 *
	 * note, that since we've registered new device the dev's name
	 * should be re-allocated
	 */

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strlcpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);    //注册本端设备
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);

	/*
	 * tie the deviced together
	 */

	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->peer, peer);   //设置对端设备

	priv = netdev_priv(peer);
	rcu_assign_pointer(priv->peer, dev);
	return 0;

err_register_dev:
	/* nothing to do */
err_configure_peer:
	unregister_netdevice(peer);
	return err;

err_register_peer:
	free_netdev(peer);
	return err;
}
```

### ndo_init(veth_dev_init)

```c
static int veth_dev_init(struct net_device *dev)
{
	dev->vstats = netdev_alloc_pcpu_stats(struct pcpu_vstats);
	if (!dev->vstats)
		return -ENOMEM;
	return 0;
}
```

### ndo_open(veth_open)

```c
static int veth_open(struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *peer = rtnl_dereference(priv->peer);

	if (!peer)
		return -ENOTCONN;

	if (peer->flags & IFF_UP) {
		netif_carrier_on(dev);   //本端设备up
		netif_carrier_on(peer);  //对端设备up
	}
	return 0;
}
```

## veth设备发包

```c
static netdev_tx_t veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct veth_priv *priv = netdev_priv(dev);
	struct net_device *rcv;
	int length = skb->len;

	rcu_read_lock();
	rcv = rcu_dereference(priv->peer);   //对端设备
	if (unlikely(!rcv)) {
		kfree_skb(skb);
		goto drop;
	}
	/* don't change ip_summed == CHECKSUM_PARTIAL, as that
	 * will cause bad checksum on forwarded packets
	 */
	if (skb->ip_summed == CHECKSUM_NONE &&
	    rcv->features & NETIF_F_RXCSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (likely(dev_forward_skb(rcv, skb) == NET_RX_SUCCESS)) {	//处理完MAC头，并上送到协议栈收包
		struct pcpu_vstats *stats = this_cpu_ptr(dev->vstats);

		u64_stats_update_begin(&stats->syncp);
		stats->bytes += length;
		stats->packets++;
		u64_stats_update_end(&stats->syncp);
	} else {
drop:
		atomic64_inc(&priv->dropped);
	}
	rcu_read_unlock();
	return NETDEV_TX_OK;
}
```

