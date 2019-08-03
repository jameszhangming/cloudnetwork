# internal设备操作

内核态OVS添加/删除internal设备涉及到管理面的netdev设备管理和数据面的vport设备管理。


# netdev_class

1. 添加port流程中，netdev_class的两个主要的函数时alloc和construct函数。
2. 删除port流程中，netdev_class的两个主要的函数时destruct和dealloc函数。

```
const struct netdev_class netdev_internal_class =
    NETDEV_LINUX_CLASS(
        "internal",
        netdev_linux_construct,
        netdev_internal_get_stats,
        NULL,                  /* get_features */
        netdev_internal_get_status);
```

所有操作同netdev_linux_class。



# vport_ops


## internal_dev_create

```
static struct vport *internal_dev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct internal_dev *internal_dev;
	int err;

	vport = ovs_vport_alloc(0, &ovs_internal_vport_ops, parms);   //申请vport对象
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	vport->dev = alloc_netdev(sizeof(struct internal_dev),   //创建net device设备，实际为internal_dev设备
				  parms->name, NET_NAME_UNKNOWN, do_setup); 
	if (!vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	dev_net_set(vport->dev, ovs_dp_get_net(vport->dp));   //设置网络空间
	internal_dev = internal_dev_priv(vport->dev);         //得到internal_dev设备
	internal_dev->vport = vport;

	/* Restrict bridge port to current netns. */
	if (vport->port_no == OVSP_LOCAL)
		vport->dev->features |= NETIF_F_NETNS_LOCAL;

	rtnl_lock();
	err = register_netdevice(vport->dev);    //注册网络设备
	if (err)
		goto error_free_netdev;

	dev_set_promiscuity(vport->dev, 1);      //设置混杂模式
	rtnl_unlock();
	netif_start_queue(vport->dev);           //启动设备队列

	return vport;

error_free_netdev:
	rtnl_unlock();
	free_netdev(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

	netdev->netdev_ops = &internal_dev_netdev_ops;   //设置驱动

	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_OPENVSWITCH;
	netdev->destructor = internal_dev_destructor;
	netdev->ethtool_ops = &internal_dev_ethtool_ops;   //设置ethtool ops
	netdev->rtnl_link_ops = &internal_dev_link_ops;    //设置link ops
	netdev->tx_queue_len = 0;

	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |   //设置设备feature
			   NETIF_F_HIGHDMA | NETIF_F_HW_CSUM |
			   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

	netdev->vlan_features = netdev->features;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	netdev->hw_enc_features = netdev->features;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	netdev->hw_features = netdev->features & ~NETIF_F_LLTX;
#endif
	eth_hw_addr_random(netdev);    //设置mac地址，随机
}
```


## internal_dev_destroy

```
static void internal_dev_destroy(struct vport *vport)
{
	netif_stop_queue(vport->dev);
	rtnl_lock();
	dev_set_promiscuity(vport->dev, -1);

	/* unregister_netdevice() waits for an RCU grace period. */
	unregister_netdevice(vport->dev);

	rtnl_unlock();
}
```


## internal_dev_recv

内核OVS从internal发包，即上送到内核协议栈。

```
static netdev_tx_t internal_dev_recv(struct sk_buff *skb)
{
	struct net_device *netdev = skb->dev;
#ifdef HAVE_DEV_TSTATS
	struct pcpu_sw_netstats *stats;
#endif

	if (unlikely(!(netdev->flags & IFF_UP))) {
		kfree_skb(skb);
		netdev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
	if (skb_vlan_tag_present(skb)) {
		if (unlikely(!vlan_insert_tag_set_proto(skb,
							skb->vlan_proto,
							skb_vlan_tag_get(skb))))
			return NETDEV_TX_OK;

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum,
					     csum_partial(skb->data + (2 * ETH_ALEN),
							  VLAN_HLEN, 0));

		vlan_set_tci(skb, 0);
	}
#endif

	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);    //解析以太网协议
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);  //报文头移到IP头

#ifdef HAVE_DEV_TSTATS
	stats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)netdev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);
#endif

	netif_rx(skb);           //协议栈收包
	return NETDEV_TX_OK;
}
```


# net_device_ops(驱动)

```
static const struct net_device_ops internal_dev_netdev_ops = {
#ifdef HAVE_DEV_TSTATS
	.ndo_init = internal_dev_init,
	.ndo_uninit = internal_dev_uninit,
	.ndo_get_stats64 = ip_tunnel_get_stats64,
#endif
	.ndo_open = internal_dev_open,
	.ndo_stop = internal_dev_stop,
	.ndo_start_xmit = internal_dev_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu = internal_dev_change_mtu,
};
```


## internal_dev_xmit

协议栈通过inernal port发送报文，经过此函数进入OVS。

```
static int internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	int len, err;

	len = skb->len;
	rcu_read_lock();
	err = ovs_vport_receive(internal_dev_priv(netdev)->vport, skb, NULL);   //OVS的vport收包
	rcu_read_unlock();

	if (likely(!err)) {
#ifdef HAVE_DEV_TSTATS
		struct pcpu_sw_netstats *tstats;

		tstats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)netdev->tstats);

		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += len;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
#endif
	} else {
		netdev->stats.tx_errors++;
	}
	return 0;
}
```



