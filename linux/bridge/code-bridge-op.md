# bridge 操作

本文分析bridge的基本操作流程。


## 网桥ioctl入口

```c
int br_ioctl_deviceless_stub(struct net *net, unsigned int cmd, void __user *uarg)
{
	switch (cmd) {
	case SIOCGIFBR:
	case SIOCSIFBR:
		return old_deviceless(net, uarg);

	case SIOCBRADDBR:
	case SIOCBRDELBR:
	{
		char buf[IFNAMSIZ];

		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (copy_from_user(buf, uarg, IFNAMSIZ))
			return -EFAULT;

		buf[IFNAMSIZ-1] = 0;
		if (cmd == SIOCBRADDBR)
			return br_add_bridge(net, buf);   //添加网桥

		return br_del_bridge(net, buf);   //删除网桥
	}
	}
	return -EOPNOTSUPP;
}

static int old_deviceless(struct net *net, void __user *uarg)
{
	unsigned long args[3];

	if (copy_from_user(args, uarg, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_GET_VERSION:
		return BRCTL_VERSION;

	case BRCTL_GET_BRIDGES:
	{
		int *indices;
		int ret = 0;

		if (args[2] >= 2048)
			return -ENOMEM;
		indices = kcalloc(args[2], sizeof(int), GFP_KERNEL);
		if (indices == NULL)
			return -ENOMEM;

		args[2] = get_bridge_ifindices(net, indices, args[2]);

		ret = copy_to_user((void __user *)args[1], indices, args[2]*sizeof(int))
			? -EFAULT : args[2];

		kfree(indices);
		return ret;
	}

	case BRCTL_ADD_BRIDGE:
	case BRCTL_DEL_BRIDGE:
	{
		char buf[IFNAMSIZ];

		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (copy_from_user(buf, (void __user *)args[1], IFNAMSIZ))
			return -EFAULT;

		buf[IFNAMSIZ-1] = 0;

		if (args[0] == BRCTL_ADD_BRIDGE)
			return br_add_bridge(net, buf);   //添加网桥

		return br_del_bridge(net, buf);   //删除网桥
	}
	}

	return -EOPNOTSUPP;
}
```

## 网桥if ioctl入口

```c
int br_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct net_bridge *br = netdev_priv(dev);

	switch (cmd) {
	case SIOCDEVPRIVATE:
		return old_dev_ioctl(dev, rq, cmd);

	case SIOCBRADDIF:
	case SIOCBRDELIF:
		return add_del_if(br, rq->ifr_ifindex, cmd == SIOCBRADDIF);  //添加if

	}

	br_debug(br, "Bridge does not support ioctl 0x%x\n", cmd);
	return -EOPNOTSUPP;
}
```


## br_add_bridge

```c
int br_add_bridge(struct net *net, const char *name)
{
	struct net_device *dev;
	int res;

	dev = alloc_netdev(sizeof(struct net_bridge), name, NET_NAME_UNKNOWN,
			   br_dev_setup);  //分配设备并初始化

	if (!dev)
		return -ENOMEM;

	dev_net_set(dev, net);
	dev->rtnl_link_ops = &br_link_ops;   //设置link ops

	res = register_netdev(dev);  //注册设备
	if (res)
		free_netdev(dev);
	return res;
}

void br_dev_setup(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	eth_hw_addr_random(dev);  //随机生成mac地址
	ether_setup(dev);   //以太网通用网卡设置

	dev->netdev_ops = &br_netdev_ops;   //设置驱动
	dev->destructor = br_dev_free;
	dev->ethtool_ops = &br_ethtool_ops;
	SET_NETDEV_DEVTYPE(dev, &br_type);    //设置设备类型
	dev->tx_queue_len = 0;
	dev->priv_flags = IFF_EBRIDGE;

	dev->features = COMMON_FEATURES | NETIF_F_LLTX | NETIF_F_NETNS_LOCAL |
			NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
	dev->hw_features = COMMON_FEATURES | NETIF_F_HW_VLAN_CTAG_TX |
			   NETIF_F_HW_VLAN_STAG_TX;
	dev->vlan_features = COMMON_FEATURES;

	br->dev = dev;
	spin_lock_init(&br->lock);
	INIT_LIST_HEAD(&br->port_list);
	spin_lock_init(&br->hash_lock);

	br->bridge_id.prio[0] = 0x80;
	br->bridge_id.prio[1] = 0x00;

	ether_addr_copy(br->group_addr, eth_reserved_addr_base);   //拷贝组播地址

	br->stp_enabled = BR_NO_STP;
	br->group_fwd_mask = BR_GROUPFWD_DEFAULT;
	br->group_fwd_mask_required = BR_GROUPFWD_DEFAULT;

	br->designated_root = br->bridge_id;
	br->bridge_max_age = br->max_age = 20 * HZ;
	br->bridge_hello_time = br->hello_time = 2 * HZ;
	br->bridge_forward_delay = br->forward_delay = 15 * HZ;
	br->ageing_time = 300 * HZ;

	br_netfilter_rtable_init(br);
	br_stp_timer_init(br);
	br_multicast_init(br);
}
```


## add_del_if

```c
static int add_del_if(struct net_bridge *br, int ifindex, int isadd)
{
	struct net *net = dev_net(br->dev);
	struct net_device *dev;
	int ret;

	if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	dev = __dev_get_by_index(net, ifindex);
	if (dev == NULL)
		return -EINVAL;

	if (isadd)
		ret = br_add_if(br, dev);
	else
		ret = br_del_if(br, dev);

	return ret;
}


int br_add_if(struct net_bridge *br, struct net_device *dev)
{
	struct net_bridge_port *p;
	int err = 0;
	bool changed_addr;

	/* Don't allow bridging non-ethernet like devices, or DSA-enabled
	 * master network devices since the bridge layer rx_handler prevents
	 * the DSA fake ethertype handler to be invoked, so we do not strip off
	 * the DSA switch tag protocol header and the bridge layer just return
	 * RX_HANDLER_CONSUMED, stopping RX processing for these frames.
	 */
	if ((dev->flags & IFF_LOOPBACK) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    !is_valid_ether_addr(dev->dev_addr) ||
	    netdev_uses_dsa(dev))
		return -EINVAL;

	/* No bridging of bridges */
	if (dev->netdev_ops->ndo_start_xmit == br_dev_xmit)
		return -ELOOP;

	/* Device is already being bridged */
	if (br_port_exists(dev))
		return -EBUSY;

	/* No bridging devices that dislike that (e.g. wireless) */
	if (dev->priv_flags & IFF_DONT_BRIDGE)
		return -EOPNOTSUPP;

	p = new_nbp(br, dev);  //创建port
	if (IS_ERR(p))
		return PTR_ERR(p);

	call_netdevice_notifiers(NETDEV_JOIN, dev);

	err = dev_set_allmulti(dev, 1);
	if (err)
		goto put_back;

	err = kobject_init_and_add(&p->kobj, &brport_ktype, &(dev->dev.kobj),
				   SYSFS_BRIDGE_PORT_ATTR);
	if (err)
		goto err1;

	err = br_sysfs_addif(p);
	if (err)
		goto err2;

	err = br_netpoll_enable(p);
	if (err)
		goto err3;

	err = netdev_rx_handler_register(dev, br_handle_frame, p);   //注册rx_handler函数
	if (err)
		goto err4;

	dev->priv_flags |= IFF_BRIDGE_PORT;

	err = netdev_master_upper_dev_link(dev, br->dev);
	if (err)
		goto err5;

	dev_disable_lro(dev);

	list_add_rcu(&p->list, &br->port_list);  //端口添加到bridge的端口链表中

	nbp_update_port_count(br);

	netdev_update_features(br->dev);

	if (br->dev->needed_headroom < dev->needed_headroom)
		br->dev->needed_headroom = dev->needed_headroom;

	if (br_fdb_insert(br, p, dev->dev_addr, 0))   //添加fdb表
		netdev_err(dev, "failed insert local address bridge forwarding table\n");

	if (nbp_vlan_init(p))
		netdev_err(dev, "failed to initialize vlan filtering on this port\n");

	spin_lock_bh(&br->lock);
	changed_addr = br_stp_recalculate_bridge_id(br);

	if (netif_running(dev) && netif_oper_up(dev) &&
	    (br->dev->flags & IFF_UP))
		br_stp_enable_port(p);
	spin_unlock_bh(&br->lock);

	br_ifinfo_notify(RTM_NEWLINK, p);

	if (changed_addr)
		call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

	dev_set_mtu(br->dev, br_min_mtu(br));

	kobject_uevent(&p->kobj, KOBJ_ADD);

	return 0;

err5:
	dev->priv_flags &= ~IFF_BRIDGE_PORT;
	netdev_rx_handler_unregister(dev);
err4:
	br_netpoll_disable(p);
err3:
	sysfs_remove_link(br->ifobj, p->dev->name);
err2:
	kobject_put(&p->kobj);
	p = NULL; /* kobject_put frees */
err1:
	dev_set_allmulti(dev, -1);
put_back:
	dev_put(dev);
	kfree(p);
	return err;
}
```




