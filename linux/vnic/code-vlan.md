# VLAN

Linux 里 802.1.q VLAN 设备是以母子关系成对出现的，母设备相当于现实世界中的交换机 TRUNK 口，用于连接上级网络，子设备相当于普通接口用于连接下级网络。
母子设备之间是一对多的关系，一个母设备可以有多个子设备，一个子设备只有一个母设备。
当一个子设备有一包数据需要发送时，数据将被加入 VLAN Tag 然后从母设备发送出去。
当母设备收到一包数据时，它将会分析其中的 VLAN Tag，如果有对应的子设备存在，则把数据转发到那个子设备上并根据设置移除 VLAN Tag，否则丢弃该数据（否则应该是给母设备）。
母子设备的数据也是有方向的，子设备收到的数据不会进入母设备，同样母设备上请求发送的数据不会被转到子设备上。
母子 VLAN 设备拥有相同的 MAC 地址，可以把它当成现实世界中 802.1.q 交换机的 MAC，因此多个 VLAN 设备会共享一个 MAC。
当一个母设备拥有多个 VLAN 子设备时，子设备之间是隔离的，不存在 Bridge 那样的交换转发关系，原因如下：802.1.q VLAN 协议的主要目的是从逻辑上隔离子网。
现实世界中的 802.1.q 交换机存在多个 VLAN，每个 VLAN 拥有多个端口，同一 VLAN 端口之间可以交换转发，不同 VLAN 端口之间隔离，所以其包含两层功能：交换与隔离。
Linux VLAN device 实现的是隔离功能，没有交换功能。
一个 VLAN 母设备不可能拥有两个相同 ID 的 VLAN 子设备，因此也就不可能出现数据交换情况。

## 数据结构

```c
struct rtnl_link_ops vlan_link_ops __read_mostly = {
	.kind		= "vlan",
	.maxtype	= IFLA_VLAN_MAX,
	.policy		= vlan_policy,
	.priv_size	= sizeof(struct vlan_dev_priv),
	.setup		= vlan_setup,
	.validate	= vlan_validate,
	.newlink	= vlan_newlink,
	.changelink	= vlan_changelink,
	.dellink	= unregister_vlan_dev,
	.get_size	= vlan_get_size,
	.fill_info	= vlan_fill_info,
	.get_link_net	= vlan_get_link_net,
};

//设备驱动
static const struct net_device_ops vlan_netdev_ops = {
	.ndo_change_mtu		= vlan_dev_change_mtu,
	.ndo_init		= vlan_dev_init,
	.ndo_uninit		= vlan_dev_uninit,
	.ndo_open		= vlan_dev_open,
	.ndo_stop		= vlan_dev_stop,
	.ndo_start_xmit =  vlan_dev_hard_start_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= vlan_dev_set_mac_address,
	.ndo_set_rx_mode	= vlan_dev_set_rx_mode,
	.ndo_change_rx_flags	= vlan_dev_change_rx_flags,
	.ndo_do_ioctl		= vlan_dev_ioctl,
	.ndo_neigh_setup	= vlan_dev_neigh_setup,
	.ndo_get_stats64	= vlan_dev_get_stats64,
#if IS_ENABLED(CONFIG_FCOE)
	.ndo_fcoe_ddp_setup	= vlan_dev_fcoe_ddp_setup,
	.ndo_fcoe_ddp_done	= vlan_dev_fcoe_ddp_done,
	.ndo_fcoe_enable	= vlan_dev_fcoe_enable,
	.ndo_fcoe_disable	= vlan_dev_fcoe_disable,
	.ndo_fcoe_get_wwn	= vlan_dev_fcoe_get_wwn,
	.ndo_fcoe_ddp_target	= vlan_dev_fcoe_ddp_target,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= vlan_dev_poll_controller,
	.ndo_netpoll_setup	= vlan_dev_netpoll_setup,
	.ndo_netpoll_cleanup	= vlan_dev_netpoll_cleanup,
#endif
	.ndo_fix_features	= vlan_dev_fix_features,
	.ndo_get_lock_subclass  = vlan_dev_get_lock_subclass,
	.ndo_get_iflink		= vlan_dev_get_iflink,
};

static const struct ethtool_ops vlan_ethtool_ops = {
	.get_settings	        = vlan_ethtool_get_settings,
	.get_drvinfo	        = vlan_ethtool_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= vlan_ethtool_get_ts_info,
};
```

## 模块初始化

```c
static int __init vlan_proto_init(void)
{
	int err;

	pr_info("%s v%s\n", vlan_fullname, vlan_version);

	err = register_pernet_subsys(&vlan_net_ops);  //注册net namespace 操作
	if (err < 0)
		goto err0;

	err = register_netdevice_notifier(&vlan_notifier_block);   //注册vlan设备注册回调
	if (err < 0)
		goto err2;

	err = vlan_gvrp_init();
	if (err < 0)
		goto err3;

	err = vlan_mvrp_init();
	if (err < 0)
		goto err4;

	err = vlan_netlink_init();   //注册vlan netlink ops
	if (err < 0)
		goto err5;

	vlan_ioctl_set(vlan_ioctl_handler);
	return 0;

err5:
	vlan_mvrp_uninit();
err4:
	vlan_gvrp_uninit();
err3:
	unregister_netdevice_notifier(&vlan_notifier_block);
err2:
	unregister_pernet_subsys(&vlan_net_ops);
err0:
	return err;
}
```

## vlan设备创建

vlan设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）  
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）
6. dev->netdev_ops->ndo_open（打开设备）


### validate(macvlan_setup)

```c
static int vlan_validate(struct nlattr *tb[], struct nlattr *data[])
{
	struct ifla_vlan_flags *flags;
	u16 id;
	int err;

	if (tb[IFLA_ADDRESS]) {   //mac地址校验
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	if (!data)
		return -EINVAL;

	if (data[IFLA_VLAN_PROTOCOL]) {   //协议校验
		switch (nla_get_be16(data[IFLA_VLAN_PROTOCOL])) {
		case htons(ETH_P_8021Q):
		case htons(ETH_P_8021AD):
			break;
		default:
			return -EPROTONOSUPPORT;
		}
	}

	if (data[IFLA_VLAN_ID]) {   //vlan id校验
		id = nla_get_u16(data[IFLA_VLAN_ID]);
		if (id >= VLAN_VID_MASK)
			return -ERANGE;
	}
	if (data[IFLA_VLAN_FLAGS]) {
		flags = nla_data(data[IFLA_VLAN_FLAGS]);
		if ((flags->flags & flags->mask) &
		    ~(VLAN_FLAG_REORDER_HDR | VLAN_FLAG_GVRP |
		      VLAN_FLAG_LOOSE_BINDING | VLAN_FLAG_MVRP))
			return -EINVAL;
	}

	err = vlan_validate_qos_map(data[IFLA_VLAN_INGRESS_QOS]);
	if (err < 0)
		return err;
	err = vlan_validate_qos_map(data[IFLA_VLAN_EGRESS_QOS]);
	if (err < 0)
		return err;
	return 0;
}
```


### setup(vlan_setup)

```c
void vlan_setup(struct net_device *dev)
{
	ether_setup(dev);  //通用以太网设备设置

	dev->priv_flags		|= IFF_802_1Q_VLAN;
	dev->priv_flags		&= ~IFF_TX_SKB_SHARING;
	netif_keep_dst(dev);
	dev->tx_queue_len	= 0;

	dev->netdev_ops		= &vlan_netdev_ops;  //设置驱动
	dev->destructor		= vlan_dev_free;
	dev->ethtool_ops	= &vlan_ethtool_ops;

	eth_zero_addr(dev->broadcast);  //修改广播地址（mac地址）为0
}

void ether_setup(struct net_device *dev)
{
	dev->header_ops		= &eth_header_ops;
	dev->type		= ARPHRD_ETHER;         //以太网头
	dev->hard_header_len 	= ETH_HLEN;     //以太网头长度
	dev->mtu		= ETH_DATA_LEN;    //MTU，默认1500
	dev->addr_len		= ETH_ALEN;
	dev->tx_queue_len	= 1000;	/* Ethernet wants good queues */
	dev->flags		= IFF_BROADCAST|IFF_MULTICAST;
	dev->priv_flags		|= IFF_TX_SKB_SHARING;

	eth_broadcast_addr(dev->broadcast);  
}
```

### newlink(vlan_newlink)

```c
static int vlan_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
	struct net_device *real_dev;
	__be16 proto;
	int err;

	if (!data[IFLA_VLAN_ID])
		return -EINVAL;

	if (!tb[IFLA_LINK])
		return -EINVAL;
	real_dev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));  //获取母设备
	if (!real_dev)
		return -ENODEV;

	if (data[IFLA_VLAN_PROTOCOL])  
		proto = nla_get_be16(data[IFLA_VLAN_PROTOCOL]);
	else
		proto = htons(ETH_P_8021Q);   //默认协议

	vlan->vlan_proto = proto;
	vlan->vlan_id	 = nla_get_u16(data[IFLA_VLAN_ID]); 
	vlan->real_dev	 = real_dev;
	vlan->flags	 = VLAN_FLAG_REORDER_HDR;

	err = vlan_check_real_dev(real_dev, vlan->vlan_proto, vlan->vlan_id);  //判断vlan设备是否已存在
	if (err < 0)
		return err;

	if (!tb[IFLA_MTU])
		dev->mtu = real_dev->mtu;
	else if (dev->mtu > real_dev->mtu)
		return -EINVAL;

	err = vlan_changelink(dev, tb, data);    //设置vlan设备其他属性
	if (err < 0)
		return err;

	return register_vlan_dev(dev); 
}

static int vlan_changelink(struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[])
{
	struct ifla_vlan_flags *flags;
	struct ifla_vlan_qos_mapping *m;
	struct nlattr *attr;
	int rem;

	if (data[IFLA_VLAN_FLAGS]) {
		flags = nla_data(data[IFLA_VLAN_FLAGS]);
		vlan_dev_change_flags(dev, flags->flags, flags->mask);
	}
	if (data[IFLA_VLAN_INGRESS_QOS]) {
		nla_for_each_nested(attr, data[IFLA_VLAN_INGRESS_QOS], rem) {
			m = nla_data(attr);
			vlan_dev_set_ingress_priority(dev, m->to, m->from);
		}
	}
	if (data[IFLA_VLAN_EGRESS_QOS]) {
		nla_for_each_nested(attr, data[IFLA_VLAN_EGRESS_QOS], rem) {
			m = nla_data(attr);
			vlan_dev_set_egress_priority(dev, m->from, m->to);
		}
	}
	return 0;
}

int register_vlan_dev(struct net_device *dev)
{
	struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
	struct net_device *real_dev = vlan->real_dev;
	u16 vlan_id = vlan->vlan_id;
	struct vlan_info *vlan_info;
	struct vlan_group *grp;
	int err;

	err = vlan_vid_add(real_dev, vlan->vlan_proto, vlan_id);
	if (err)
		return err;

	vlan_info = rtnl_dereference(real_dev->vlan_info);
	/* vlan_info should be there now. vlan_vid_add took care of it */
	BUG_ON(!vlan_info);

	grp = &vlan_info->grp;
	if (grp->nr_vlan_devs == 0) {
		err = vlan_gvrp_init_applicant(real_dev);
		if (err < 0)
			goto out_vid_del;
		err = vlan_mvrp_init_applicant(real_dev);
		if (err < 0)
			goto out_uninit_gvrp;
	}

	err = vlan_group_prealloc_vid(grp, vlan->vlan_proto, vlan_id);
	if (err < 0)
		goto out_uninit_mvrp;

	vlan->nest_level = dev_get_nest_level(real_dev, is_vlan_dev) + 1;
	err = register_netdevice(dev);
	if (err < 0)
		goto out_uninit_mvrp;

	err = netdev_upper_dev_link(real_dev, dev);
	if (err)
		goto out_unregister_netdev;

	/* Account for reference in struct vlan_dev_priv */
	dev_hold(real_dev);

	netif_stacked_transfer_operstate(real_dev, dev);
	linkwatch_fire_event(dev); /* _MUST_ call rfc2863_policy() */

	/* So, got the sucker initialized, now lets place
	 * it into our local structure.
	 */
	vlan_group_set_device(grp, vlan->vlan_proto, vlan_id, dev);
	grp->nr_vlan_devs++;

	return 0;

out_unregister_netdev:
	unregister_netdevice(dev);
out_uninit_mvrp:
	if (grp->nr_vlan_devs == 0)
		vlan_mvrp_uninit_applicant(real_dev);
out_uninit_gvrp:
	if (grp->nr_vlan_devs == 0)
		vlan_gvrp_uninit_applicant(real_dev);
out_vid_del:
	vlan_vid_del(real_dev, vlan->vlan_proto, vlan_id);
	return err;
}
```


### ndo_init(vlan_dev_init)

```c
static int vlan_dev_init(struct net_device *dev)
{
	struct net_device *real_dev = vlan_dev_priv(dev)->real_dev;

	netif_carrier_off(dev);

	/* IFF_BROADCAST|IFF_MULTICAST; ??? */
	dev->flags  = real_dev->flags & ~(IFF_UP | IFF_PROMISC | IFF_ALLMULTI |
					  IFF_MASTER | IFF_SLAVE);
	dev->state  = (real_dev->state & ((1<<__LINK_STATE_NOCARRIER) |
					  (1<<__LINK_STATE_DORMANT))) |
		      (1<<__LINK_STATE_PRESENT);

	dev->hw_features = NETIF_F_ALL_CSUM | NETIF_F_SG |
			   NETIF_F_FRAGLIST | NETIF_F_GSO_SOFTWARE |
			   NETIF_F_HIGHDMA | NETIF_F_SCTP_CSUM |
			   NETIF_F_ALL_FCOE;

	dev->features |= real_dev->vlan_features | NETIF_F_LLTX |
			 NETIF_F_GSO_SOFTWARE;
	dev->gso_max_size = real_dev->gso_max_size;
	if (dev->features & NETIF_F_VLAN_FEATURES)
		netdev_warn(real_dev, "VLAN features are set incorrectly.  Q-in-Q configurations may not work correctly.\n");

	dev->vlan_features = real_dev->vlan_features & ~NETIF_F_ALL_FCOE;

	/* ipv6 shared card related stuff */
	dev->dev_id = real_dev->dev_id;

	if (is_zero_ether_addr(dev->dev_addr))  //如果没有设置mac地址，则使用母设备的mac地址
		eth_hw_addr_inherit(dev, real_dev); 
	if (is_zero_ether_addr(dev->broadcast))
		memcpy(dev->broadcast, real_dev->broadcast, dev->addr_len);   //拷贝母设备的广播地址

#if IS_ENABLED(CONFIG_FCOE)
	dev->fcoe_ddp_xid = real_dev->fcoe_ddp_xid;
#endif

	dev->needed_headroom = real_dev->needed_headroom;
	if (vlan_hw_offload_capable(real_dev->features,
				    vlan_dev_priv(dev)->vlan_proto)) {
		dev->header_ops      = &vlan_passthru_header_ops;
		dev->hard_header_len = real_dev->hard_header_len;
	} else {
		dev->header_ops      = &vlan_header_ops;
		dev->hard_header_len = real_dev->hard_header_len + VLAN_HLEN;
	}

	dev->netdev_ops = &vlan_netdev_ops;

	SET_NETDEV_DEVTYPE(dev, &vlan_type);

	vlan_dev_set_lockdep_class(dev, vlan_dev_get_lock_subclass(dev));

	vlan_dev_priv(dev)->vlan_pcpu_stats = netdev_alloc_pcpu_stats(struct vlan_pcpu_stats);
	if (!vlan_dev_priv(dev)->vlan_pcpu_stats)
		return -ENOMEM;

	return 0;
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

### ndo_open(vlan_dev_open)

```c
static int vlan_dev_open(struct net_device *dev)
{
	struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
	struct net_device *real_dev = vlan->real_dev;
	int err;

	if (!(real_dev->flags & IFF_UP) &&
	    !(vlan->flags & VLAN_FLAG_LOOSE_BINDING))
		return -ENETDOWN;

	if (!ether_addr_equal(dev->dev_addr, real_dev->dev_addr)) {
		err = dev_uc_add(real_dev, dev->dev_addr);
		if (err < 0)
			goto out;
	}

	if (dev->flags & IFF_ALLMULTI) {
		err = dev_set_allmulti(real_dev, 1);
		if (err < 0)
			goto del_unicast;
	}
	if (dev->flags & IFF_PROMISC) {
		err = dev_set_promiscuity(real_dev, 1);
		if (err < 0)
			goto clear_allmulti;
	}

	ether_addr_copy(vlan->real_dev_addr, real_dev->dev_addr);  //拷贝母设备的mac地址

	if (vlan->flags & VLAN_FLAG_GVRP)
		vlan_gvrp_request_join(dev);

	if (vlan->flags & VLAN_FLAG_MVRP)
		vlan_mvrp_request_join(dev);

	if (netif_carrier_ok(real_dev))  //设备up
		netif_carrier_on(dev);
	return 0;

clear_allmulti:
	if (dev->flags & IFF_ALLMULTI)
		dev_set_allmulti(real_dev, -1);
del_unicast:
	if (!ether_addr_equal(dev->dev_addr, real_dev->dev_addr))
		dev_uc_del(real_dev, dev->dev_addr);
out:
	netif_carrier_off(dev);
	return err;
}
```

## vlan底层设备收包处理

linux内核二层收包__netif_receive_skb_core函数中，如果报文包含vlan头，则尝试vlan收包。

```c
bool vlan_do_receive(struct sk_buff **skbp)
{
	struct sk_buff *skb = *skbp;
	__be16 vlan_proto = skb->vlan_proto;
	u16 vlan_id = skb_vlan_tag_get_id(skb);
	struct net_device *vlan_dev;
	struct vlan_pcpu_stats *rx_stats;

	vlan_dev = vlan_find_dev(skb->dev, vlan_proto, vlan_id);	//找到vlan设备
	if (!vlan_dev)   //如果没有vlan设备，则直接返回
		return false;

	skb = *skbp = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return false;

	skb->dev = vlan_dev;
	if (unlikely(skb->pkt_type == PACKET_OTHERHOST)) {
		/* Our lower layer thinks this is not local, let's make sure.
		 * This allows the VLAN to have a different MAC than the
		 * underlying device, and still route correctly. */
		if (ether_addr_equal_64bits(eth_hdr(skb)->h_dest, vlan_dev->dev_addr))
			skb->pkt_type = PACKET_HOST;
	}

	if (!(vlan_dev_priv(vlan_dev)->flags & VLAN_FLAG_REORDER_HDR)) { //如果要保留vlan头
		unsigned int offset = skb->data - skb_mac_header(skb);		

		/*
		 * vlan_insert_tag expect skb->data pointing to mac header.
		 * So change skb->data before calling it and change back to
		 * original position later
		 */
		skb_push(skb, offset);		//恢复整个mac头(没有vlan头)
		skb = *skbp = vlan_insert_tag(skb, skb->vlan_proto,		//添加vlan头
					      skb->vlan_tci);
		if (!skb)
			return false;
		//去掉mac头，报文状态未改变（skb->data指向内层报文头，但是mac头的内容已经恢复到了之前的状态）
		skb_pull(skb, offset + VLAN_HLEN);				
		skb_reset_mac_len(skb);
	}

	skb->priority = vlan_get_ingress_priority(vlan_dev, skb->vlan_tci);
	skb->vlan_tci = 0;

	rx_stats = this_cpu_ptr(vlan_dev_priv(vlan_dev)->vlan_pcpu_stats);

	u64_stats_update_begin(&rx_stats->syncp);
	rx_stats->rx_packets++;
	rx_stats->rx_bytes += skb->len;
	if (skb->pkt_type == PACKET_MULTICAST)
		rx_stats->rx_multicast++;
	u64_stats_update_end(&rx_stats->syncp);

	return true;
}
```


## vlan发包处理

```c
static netdev_tx_t vlan_dev_hard_start_xmit(struct sk_buff *skb,
					    struct net_device *dev)
{
	struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)(skb->data);
	unsigned int len;
	int ret;

	/* Handle non-VLAN frames if they are sent to us, for example by DHCP.
	 *
	 * NOTE: THIS ASSUMES DIX ETHERNET, SPECIFICALLY NOT SUPPORTING
	 * OTHER THINGS LIKE FDDI/TokenRing/802.3 SNAPs...
	 */
	if (veth->h_vlan_proto != vlan->vlan_proto ||
	    vlan->flags & VLAN_FLAG_REORDER_HDR) {   //当前报文为非vlan协议
		u16 vlan_tci;
		vlan_tci = vlan->vlan_id;
		vlan_tci |= vlan_dev_get_egress_qos_mask(dev, skb->priority);
		__vlan_hwaccel_put_tag(skb, vlan->vlan_proto, vlan_tci);  //skb设置vlan信息
	}

	skb->dev = vlan->real_dev;   //报文的dev改成母设备
	len = skb->len;
	if (unlikely(netpoll_tx_running(dev)))
		return vlan_netpoll_send_skb(vlan, skb);

	ret = dev_queue_xmit(skb);   //直接发送报文，驱动完成vlan头插入？

	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
		struct vlan_pcpu_stats *stats;

		stats = this_cpu_ptr(vlan->vlan_pcpu_stats);
		u64_stats_update_begin(&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += len;
		u64_stats_update_end(&stats->syncp);
	} else {
		this_cpu_inc(vlan->vlan_pcpu_stats->tx_dropped);
	}

	return ret;
}
```



