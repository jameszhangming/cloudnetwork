# Bond

bond是把多个物理网卡聚合成一张虚拟网卡，协议栈使用该虚拟网卡对外通信，实现网络高可用，本文介绍bond设备初始化过程以及报文处理流程。


## bond模式

* BOND_MODE_ROUNDROBIN（0，平衡抡循环策略）
  * 链路负载均衡，增加带宽，支持容错，一条链路故障会自动切换正常链路。交换机需要配置聚合口，思科叫port channel。
  * 传输数据包顺序是依次传输，此模式提供负载平衡和容错能力；但是我们知道如果一个连接或者会话的数据包从不同的接口发出的话，中途再经过不同的链路，在客户端很有可能会出现数据包无序到达的问题，而无序到达的数据包需要重新要求被发送，这样网络的吞吐量就会下降
    * 随机模式
	* 单个报文轮询
	* 多个报文轮询
* BOND_MODE_ACTIVEBACKUP（1，主备策略）
  * 表示主备模式，只有一块网卡是active,另外一块是备的standby，这时如果交换机配的是捆绑，将不能正常工作，因为交换机往两块网卡发包，有一半包是丢弃的。
  * 只有一个设备处于活动状态，当一个宕掉另一个马上由备份转换为主设备。mac地址是外部可见得，从外面看来，bond的MAC地址是唯一的，以避免switch(交换机)发生混乱。
  * 此模式只提供了容错能力；由此可见此算法的优点是可以提供高网络连接的可用性，但是它的资源利用率较低，只有一个接口处于工作状态，在有 N 个网络接口的情况下，资源利用率为1/N。
* BOND_MODE_XOR（2，平衡策略）
  * 表示XOR Hash负载分担，和交换机的聚合强制不协商方式配合。（需要xmit_hash_policy，需要交换机配置port channel）
  * 基于指定的传输HASH策略传输数据包。缺省的策略是：(源MAC地址 XOR 目标MAC地址) % slave数量。其他的传输策略可以通过xmit_hash_policy选项指定，此模式提供负载平衡和容错能力。
* BOND_MODE_BROADCAST（3，广播策略）
  * 表示所有包从所有interface发出，这个不均衡，只有冗余机制...和交换机的聚合强制不协商方式配合。
  * 在每个slave接口上传输每个数据包，此模式提供了容错能力。
* BOND_MODE_8023AD（4，动态链接聚合）
  * 表示支持802.3ad协议，和交换机的聚合LACP方式配合（需要xmit_hash_policy）。标准要求所有设备在聚合操作时，要在同样的速率和双工模式，而且，和除了balance-rr模式外的其它bonding负载均衡模式一样，任何连接都不能使用多于一个接口的带宽。
  * 创建一个聚合组，它们共享同样的速率和双工设定。根据802.3ad规范将多个slave工作在同一个激活的聚合体下。外出流量的slave选举是基于传输hash策略，该策略可以通过xmit_hash_policy选项从缺省的XOR策略改变到其他策略。
* BOND_MODE_TLB（5，适配器传输负载均衡）
  * 是根据每个slave的负载情况选择slave进行发送，接收时使用当前轮到的slave。该模式要求slave接口的网络设备驱动有某种ethtool支持；而且ARP监控不可用。
  * 不需要任何特别的switch(交换机)支持的通道bonding。在每个slave上根据当前的负载（根据速度计算）分配外出流量。如果正在接受数据的slave出故障了，另一个slave接管失败的slave的MAC地址。
* BOND_MODE_ALB（6，适配器适应性负载均衡）
  * 在5的tlb基础上增加了rlb(接收负载均衡receive load balance)。不需要任何switch(交换机)的支持。接收负载均衡是通过ARP协商实现的。
  * 该模式包含了balance-tlb模式，同时加上针对IPV4流量的接收负载均衡(receive load balance, rlb)，而且不需要任何switch(交换机)的支持。接收负载均衡是通过ARP协商实现的。bonding驱动截获本机发送的ARP应答，并把源硬件地址改写为bond中某个slave的唯一硬件地址，从而使得不同的对端使用不同的硬件地址进行通信。
  * 来自服务器端的接收流量也会被均衡。当本机发送ARP请求时，bonding驱动把对端的IP信息从ARP包中复制并保存下来。当ARP应答从对端到达 时，bonding驱动把它的硬件地址提取出来，并发起一个ARP应答给bond中的某个slave。
  * 使用ARP协商进行负载均衡的一个问题是：每次广播 ARP请求时都会使用bond的硬件地址，因此对端学习到这个硬件地址后，接收流量将会全部流向当前的slave。这个问题可以通过给所有的对端发送更新 （ARP应答）来解决，应答中包含他们独一无二的硬件地址，从而导致流量重新分布。
  * 当新的slave加入到bond中时，或者某个未激活的slave重新 激活时，接收流量也要重新分布。接收的负载被顺序地分布（round robin）在bond中最高速的slave上当某个链路被重新接上，或者一个新的slave加入到bond中，接收流量在所有当前激活的slave中全部重新分配，通过使用指定的MAC地址给每个 client发起ARP应答。

  
常用的有三种：

* mode=0：平衡负载模式，有自动备援，但需要”Switch”支援及设定。
* mode=1：自动备援模式，其中一条线若断线，其他线路将会自动备援。
* mode=6：平衡负载模式，有自动备援，不必”Switch”支援及设定。
  
  
## 数据结构

```c
struct rtnl_link_ops bond_link_ops __read_mostly = {
	.kind			= "bond",
	.priv_size		= sizeof(struct bonding),
	.setup			= bond_setup,
	.maxtype		= IFLA_BOND_MAX,
	.policy			= bond_policy,
	.validate		= bond_validate,
	.newlink		= bond_newlink,
	.changelink		= bond_changelink,
	.get_size		= bond_get_size,
	.fill_info		= bond_fill_info,
	.get_num_tx_queues	= bond_get_num_tx_queues,
	.get_num_rx_queues	= bond_get_num_tx_queues, /* Use the same number
							     as for TX queues */
	.slave_maxtype		= IFLA_BOND_SLAVE_MAX,
	.slave_policy		= bond_slave_policy,
	.slave_changelink	= bond_slave_changelink,
	.get_slave_size		= bond_get_slave_size,
	.fill_slave_info	= bond_fill_slave_info,
};

//设备驱动
static const struct net_device_ops bond_netdev_ops = {
	.ndo_init		= bond_init,
	.ndo_uninit		= bond_uninit,
	.ndo_open		= bond_open,
	.ndo_stop		= bond_close,
	.ndo_start_xmit		= bond_start_xmit,
	.ndo_select_queue	= bond_select_queue,
	.ndo_get_stats64	= bond_get_stats,
	.ndo_do_ioctl		= bond_do_ioctl,
	.ndo_change_rx_flags	= bond_change_rx_flags,
	.ndo_set_rx_mode	= bond_set_rx_mode,
	.ndo_change_mtu		= bond_change_mtu,
	.ndo_set_mac_address	= bond_set_mac_address,
	.ndo_neigh_setup	= bond_neigh_setup,
	.ndo_vlan_rx_add_vid	= bond_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= bond_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_setup	= bond_netpoll_setup,
	.ndo_netpoll_cleanup	= bond_netpoll_cleanup,
	.ndo_poll_controller	= bond_poll_controller,
#endif
	.ndo_add_slave		= bond_enslave,
	.ndo_del_slave		= bond_release,
	.ndo_fix_features	= bond_fix_features,
	.ndo_bridge_setlink	= ndo_dflt_netdev_switch_port_bridge_setlink,
	.ndo_bridge_dellink	= ndo_dflt_netdev_switch_port_bridge_dellink,
	.ndo_features_check	= passthru_features_check,
};

static const struct ethtool_ops bond_ethtool_ops = {
	.get_drvinfo		= bond_ethtool_get_drvinfo,
	.get_settings		= bond_ethtool_get_settings,
	.get_link		= ethtool_op_get_link,
};
```

## 模块初始化

```c
static int __init bonding_init(void)
{
	int i;
	int res;

	pr_info("%s", bond_version);

	res = bond_check_params(&bonding_defaults);
	if (res)
		goto out;

	res = register_pernet_subsys(&bond_net_ops);
	if (res)
		goto out;

	res = bond_netlink_init();  //注册bond_link_ops
	if (res)
		goto err_link;

	bond_create_debugfs();

	for (i = 0; i < max_bonds; i++) {
		res = bond_create(&init_net, NULL);  //创建bond设备
		if (res)
			goto err;
	}
	
	//注册设备注册回调函数
	register_netdevice_notifier(&bond_netdev_notifier);
out:
	return res;
err:
	bond_destroy_debugfs();
	bond_netlink_fini();
err_link:
	unregister_pernet_subsys(&bond_net_ops);
	goto out;

}
```

## bond设备创建

bond设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数） 
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）   //未定义
6. dev->netdev_ops->ndo_open（打开设备）


### validate(bond_validate)

```c
static int bond_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}
```


### setup(bond_setup)

```c
void bond_setup(struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);

	spin_lock_init(&bond->mode_lock);
	bond->params = bonding_defaults;

	/* Initialize pointers */
	bond->dev = bond_dev;

	/* Initialize the device entry points */
	ether_setup(bond_dev);    // 以太网设备设置
	bond_dev->netdev_ops = &bond_netdev_ops;  // 设置驱动
	bond_dev->ethtool_ops = &bond_ethtool_ops;

	bond_dev->destructor = bond_destructor;

	SET_NETDEV_DEVTYPE(bond_dev, &bond_type);

	/* Initialize the device options */
	bond_dev->tx_queue_len = 0;
	bond_dev->flags |= IFF_MASTER|IFF_MULTICAST;
	bond_dev->priv_flags |= IFF_BONDING | IFF_UNICAST_FLT;
	bond_dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);

	/* don't acquire bond device's netif_tx_lock when transmitting */
	bond_dev->features |= NETIF_F_LLTX;

	/* By default, we declare the bond to be fully
	 * VLAN hardware accelerated capable. Special
	 * care is taken in the various xmit functions
	 * when there are slaves that are not hw accel
	 * capable
	 */

	/* Don't allow bond devices to change network namespaces. */
	bond_dev->features |= NETIF_F_NETNS_LOCAL;

	bond_dev->hw_features = BOND_VLAN_FEATURES |
				NETIF_F_HW_VLAN_CTAG_TX |
				NETIF_F_HW_VLAN_CTAG_RX |
				NETIF_F_HW_VLAN_CTAG_FILTER;

	bond_dev->hw_features &= ~(NETIF_F_ALL_CSUM & ~NETIF_F_HW_CSUM);
	bond_dev->hw_features |= NETIF_F_GSO_ENCAP_ALL;
	bond_dev->features |= bond_dev->hw_features;
}
```


### newlink(bond_newlink)

```c
static int bond_newlink(struct net *src_net, struct net_device *bond_dev,
			struct nlattr *tb[], struct nlattr *data[])
{
	int err;

	err = bond_changelink(bond_dev, tb, data);   //修改bond设备属性
	if (err < 0)
		return err;

	return register_netdevice(bond_dev);   //注册设备
}


static int bond_changelink(struct net_device *bond_dev,
			   struct nlattr *tb[], struct nlattr *data[])
{
	struct bonding *bond = netdev_priv(bond_dev);
	struct bond_opt_value newval;
	int miimon = 0;
	int err;

	if (!data)
		return 0;

	if (data[IFLA_BOND_MODE]) {   //设置bond模式
		int mode = nla_get_u8(data[IFLA_BOND_MODE]);

		bond_opt_initval(&newval, mode);
		err = __bond_opt_set(bond, BOND_OPT_MODE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ACTIVE_SLAVE]) {  //设置active slave
		int ifindex = nla_get_u32(data[IFLA_BOND_ACTIVE_SLAVE]);
		struct net_device *slave_dev;
		char *active_slave = "";

		if (ifindex != 0) {
			slave_dev = __dev_get_by_index(dev_net(bond_dev),
						       ifindex);
			if (!slave_dev)
				return -ENODEV;
			active_slave = slave_dev->name;
		}
		bond_opt_initstr(&newval, active_slave);
		err = __bond_opt_set(bond, BOND_OPT_ACTIVE_SLAVE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_MIIMON]) {
		miimon = nla_get_u32(data[IFLA_BOND_MIIMON]);

		bond_opt_initval(&newval, miimon);
		err = __bond_opt_set(bond, BOND_OPT_MIIMON, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_UPDELAY]) {
		int updelay = nla_get_u32(data[IFLA_BOND_UPDELAY]);

		bond_opt_initval(&newval, updelay);
		err = __bond_opt_set(bond, BOND_OPT_UPDELAY, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_DOWNDELAY]) {
		int downdelay = nla_get_u32(data[IFLA_BOND_DOWNDELAY]);

		bond_opt_initval(&newval, downdelay);
		err = __bond_opt_set(bond, BOND_OPT_DOWNDELAY, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_USE_CARRIER]) {
		int use_carrier = nla_get_u8(data[IFLA_BOND_USE_CARRIER]);

		bond_opt_initval(&newval, use_carrier);
		err = __bond_opt_set(bond, BOND_OPT_USE_CARRIER, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ARP_INTERVAL]) {
		int arp_interval = nla_get_u32(data[IFLA_BOND_ARP_INTERVAL]);

		if (arp_interval && miimon) {
			netdev_err(bond->dev, "ARP monitoring cannot be used with MII monitoring\n");
			return -EINVAL;
		}

		bond_opt_initval(&newval, arp_interval);
		err = __bond_opt_set(bond, BOND_OPT_ARP_INTERVAL, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ARP_IP_TARGET]) {
		struct nlattr *attr;
		int i = 0, rem;

		bond_option_arp_ip_targets_clear(bond);
		nla_for_each_nested(attr, data[IFLA_BOND_ARP_IP_TARGET], rem) {
			__be32 target;

			if (nla_len(attr) < sizeof(target))
				return -EINVAL;

			target = nla_get_be32(attr);

			bond_opt_initval(&newval, (__force u64)target);
			err = __bond_opt_set(bond, BOND_OPT_ARP_TARGETS,
					     &newval);
			if (err)
				break;
			i++;
		}
		if (i == 0 && bond->params.arp_interval)
			netdev_warn(bond->dev, "Removing last arp target with arp_interval on\n");
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ARP_VALIDATE]) {
		int arp_validate = nla_get_u32(data[IFLA_BOND_ARP_VALIDATE]);

		if (arp_validate && miimon) {
			netdev_err(bond->dev, "ARP validating cannot be used with MII monitoring\n");
			return -EINVAL;
		}

		bond_opt_initval(&newval, arp_validate);
		err = __bond_opt_set(bond, BOND_OPT_ARP_VALIDATE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ARP_ALL_TARGETS]) {
		int arp_all_targets =
			nla_get_u32(data[IFLA_BOND_ARP_ALL_TARGETS]);

		bond_opt_initval(&newval, arp_all_targets);
		err = __bond_opt_set(bond, BOND_OPT_ARP_ALL_TARGETS, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_PRIMARY]) {   //设置主设备
		int ifindex = nla_get_u32(data[IFLA_BOND_PRIMARY]);
		struct net_device *dev;
		char *primary = "";

		dev = __dev_get_by_index(dev_net(bond_dev), ifindex);
		if (dev)
			primary = dev->name;

		bond_opt_initstr(&newval, primary);
		err = __bond_opt_set(bond, BOND_OPT_PRIMARY, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_PRIMARY_RESELECT]) {
		int primary_reselect =
			nla_get_u8(data[IFLA_BOND_PRIMARY_RESELECT]);

		bond_opt_initval(&newval, primary_reselect);
		err = __bond_opt_set(bond, BOND_OPT_PRIMARY_RESELECT, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_FAIL_OVER_MAC]) {
		int fail_over_mac =
			nla_get_u8(data[IFLA_BOND_FAIL_OVER_MAC]);

		bond_opt_initval(&newval, fail_over_mac);
		err = __bond_opt_set(bond, BOND_OPT_FAIL_OVER_MAC, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_XMIT_HASH_POLICY]) {
		int xmit_hash_policy =
			nla_get_u8(data[IFLA_BOND_XMIT_HASH_POLICY]);

		bond_opt_initval(&newval, xmit_hash_policy);
		err = __bond_opt_set(bond, BOND_OPT_XMIT_HASH, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_RESEND_IGMP]) {
		int resend_igmp =
			nla_get_u32(data[IFLA_BOND_RESEND_IGMP]);

		bond_opt_initval(&newval, resend_igmp);
		err = __bond_opt_set(bond, BOND_OPT_RESEND_IGMP, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_NUM_PEER_NOTIF]) {
		int num_peer_notif =
			nla_get_u8(data[IFLA_BOND_NUM_PEER_NOTIF]);

		bond_opt_initval(&newval, num_peer_notif);
		err = __bond_opt_set(bond, BOND_OPT_NUM_PEER_NOTIF, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_ALL_SLAVES_ACTIVE]) {
		int all_slaves_active =
			nla_get_u8(data[IFLA_BOND_ALL_SLAVES_ACTIVE]);

		bond_opt_initval(&newval, all_slaves_active);
		err = __bond_opt_set(bond, BOND_OPT_ALL_SLAVES_ACTIVE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_MIN_LINKS]) {
		int min_links =
			nla_get_u32(data[IFLA_BOND_MIN_LINKS]);

		bond_opt_initval(&newval, min_links);
		err = __bond_opt_set(bond, BOND_OPT_MINLINKS, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_LP_INTERVAL]) {
		int lp_interval =
			nla_get_u32(data[IFLA_BOND_LP_INTERVAL]);

		bond_opt_initval(&newval, lp_interval);
		err = __bond_opt_set(bond, BOND_OPT_LP_INTERVAL, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_PACKETS_PER_SLAVE]) {
		int packets_per_slave =
			nla_get_u32(data[IFLA_BOND_PACKETS_PER_SLAVE]);

		bond_opt_initval(&newval, packets_per_slave);
		err = __bond_opt_set(bond, BOND_OPT_PACKETS_PER_SLAVE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_AD_LACP_RATE]) {
		int lacp_rate =
			nla_get_u8(data[IFLA_BOND_AD_LACP_RATE]);

		bond_opt_initval(&newval, lacp_rate);
		err = __bond_opt_set(bond, BOND_OPT_LACP_RATE, &newval);
		if (err)
			return err;
	}
	if (data[IFLA_BOND_AD_SELECT]) {
		int ad_select =
			nla_get_u8(data[IFLA_BOND_AD_SELECT]);

		bond_opt_initval(&newval, ad_select);
		err = __bond_opt_set(bond, BOND_OPT_AD_SELECT, &newval);
		if (err)
			return err;
	}
	return 0;
}

//设备注册回调函数
static int bond_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *event_dev = netdev_notifier_info_to_dev(ptr);

	netdev_dbg(event_dev, "event: %lx\n", event);

	if (!(event_dev->priv_flags & IFF_BONDING))
		return NOTIFY_DONE;

	if (event_dev->flags & IFF_MASTER) {
		netdev_dbg(event_dev, "IFF_MASTER\n");
		return bond_master_netdev_event(event, event_dev);
	}

	if (event_dev->flags & IFF_SLAVE) {
		netdev_dbg(event_dev, "IFF_SLAVE\n");
		return bond_slave_netdev_event(event, event_dev);
	}

	return NOTIFY_DONE;
}
```


### ndo_init(bond_init)

```c
static int bond_init(struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);
	struct bond_net *bn = net_generic(dev_net(bond_dev), bond_net_id);

	netdev_dbg(bond_dev, "Begin bond_init\n");

	bond->wq = create_singlethread_workqueue(bond_dev->name);
	if (!bond->wq)
		return -ENOMEM;

	bond_set_lockdep_class(bond_dev);

	list_add_tail(&bond->bond_list, &bn->dev_list);  //添加到net namespace的链表中

	bond_prepare_sysfs_group(bond);

	bond_debug_register(bond);

	/* Ensure valid dev_addr */
	if (is_zero_ether_addr(bond_dev->dev_addr) &&
	    bond_dev->addr_assign_type == NET_ADDR_PERM)
		eth_hw_addr_random(bond_dev);    //生成随机的mac地址

	return 0;
}
```


### ndo_open(bond_open)

```c
static int bond_open(struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);
	struct list_head *iter;
	struct slave *slave;

	/* reset slave->backup and slave->inactive */
	if (bond_has_slaves(bond)) {
		bond_for_each_slave(bond, slave, iter) {
			if (bond_uses_primary(bond) &&
			    slave != rcu_access_pointer(bond->curr_active_slave)) {
				bond_set_slave_inactive_flags(slave,
							      BOND_SLAVE_NOTIFY_NOW);
			} else if (BOND_MODE(bond) != BOND_MODE_8023AD) {
				bond_set_slave_active_flags(slave,
							    BOND_SLAVE_NOTIFY_NOW);
			}
		}
	}

	bond_work_init_all(bond);

	if (bond_is_lb(bond)) {
		/* bond_alb_initialize must be called before the timer
		 * is started.
		 */
		if (bond_alb_initialize(bond, (BOND_MODE(bond) == BOND_MODE_ALB)))
			return -ENOMEM;
		if (bond->params.tlb_dynamic_lb)
			queue_delayed_work(bond->wq, &bond->alb_work, 0);
	}

	if (bond->params.miimon)  /* link check interval, in milliseconds. */
		queue_delayed_work(bond->wq, &bond->mii_work, 0);

	if (bond->params.arp_interval) {  /* arp interval, in milliseconds. */
		queue_delayed_work(bond->wq, &bond->arp_work, 0);
		bond->recv_probe = bond_arp_rcv;
	}

	if (BOND_MODE(bond) == BOND_MODE_8023AD) {
		queue_delayed_work(bond->wq, &bond->ad_work, 0);
		/* register to receive LACPDUs */
		bond->recv_probe = bond_3ad_lacpdu_recv;
		bond_3ad_initiate_agg_selection(bond, 1);
	}

	if (bond_mode_uses_xmit_hash(bond))
		bond_update_slave_arr(bond, NULL);

	return 0;
}
```


## bond添加网卡

```c
static int bond_option_slaves_set(struct bonding *bond,
				  const struct bond_opt_value *newval)
{
	char command[IFNAMSIZ + 1] = { 0, };
	struct net_device *dev;
	char *ifname;
	int ret;

	sscanf(newval->string, "%16s", command); /* IFNAMSIZ*/
	ifname = command + 1;
	if ((strlen(command) <= 1) ||
	    !dev_valid_name(ifname))
		goto err_no_cmd;

	dev = __dev_get_by_name(dev_net(bond->dev), ifname);
	if (!dev) {
		netdev_info(bond->dev, "interface %s does not exist!\n",
			    ifname);
		ret = -ENODEV;
		goto out;
	}

	switch (command[0]) {
	case '+':
		netdev_info(bond->dev, "Adding slave %s\n", dev->name);
		ret = bond_enslave(bond->dev, dev);
		break;

	case '-':
		netdev_info(bond->dev, "Removing slave %s\n", dev->name);
		ret = bond_release(bond->dev, dev);
		break;

	default:
		goto err_no_cmd;
	}

out:
	return ret;

err_no_cmd:
	netdev_err(bond->dev, "no command found in slaves file - use +ifname or -ifname\n");
	ret = -EPERM;
	goto out;
}
```


### bond_enslave

```c
int bond_enslave(struct net_device *bond_dev, struct net_device *slave_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);
	const struct net_device_ops *slave_ops = slave_dev->netdev_ops;
	struct slave *new_slave = NULL, *prev_slave;
	struct sockaddr addr;
	int link_reporting;
	int res = 0, i;

	if (!bond->params.use_carrier &&
	    slave_dev->ethtool_ops->get_link == NULL &&
	    slave_ops->ndo_do_ioctl == NULL) {
		netdev_warn(bond_dev, "no link monitoring support for %s\n",
			    slave_dev->name);
	}

	/* already enslaved */
	if (slave_dev->flags & IFF_SLAVE) {
		netdev_dbg(bond_dev, "Error: Device was already enslaved\n");
		return -EBUSY;
	}

	if (bond_dev == slave_dev) {
		netdev_err(bond_dev, "cannot enslave bond to itself.\n");
		return -EPERM;
	}

	/* vlan challenged mutual exclusion */
	/* no need to lock since we're protected by rtnl_lock */
	if (slave_dev->features & NETIF_F_VLAN_CHALLENGED) {
		netdev_dbg(bond_dev, "%s is NETIF_F_VLAN_CHALLENGED\n",
			   slave_dev->name);
		if (vlan_uses_dev(bond_dev)) {
			netdev_err(bond_dev, "Error: cannot enslave VLAN challenged slave %s on VLAN enabled bond %s\n",
				   slave_dev->name, bond_dev->name);
			return -EPERM;
		} else {
			netdev_warn(bond_dev, "enslaved VLAN challenged slave %s. Adding VLANs will be blocked as long as %s is part of bond %s\n",
				    slave_dev->name, slave_dev->name,
				    bond_dev->name);
		}
	} else {
		netdev_dbg(bond_dev, "%s is !NETIF_F_VLAN_CHALLENGED\n",
			   slave_dev->name);
	}

	/* Old ifenslave binaries are no longer supported.  These can
	 * be identified with moderate accuracy by the state of the slave:
	 * the current ifenslave will set the interface down prior to
	 * enslaving it; the old ifenslave will not.
	 */
	if ((slave_dev->flags & IFF_UP)) {
		netdev_err(bond_dev, "%s is up - this may be due to an out of date ifenslave\n",
			   slave_dev->name);
		res = -EPERM;
		goto err_undo_flags;
	}

	/* set bonding device ether type by slave - bonding netdevices are
	 * created with ether_setup, so when the slave type is not ARPHRD_ETHER
	 * there is a need to override some of the type dependent attribs/funcs.
	 *
	 * bond ether type mutual exclusion - don't allow slaves of dissimilar
	 * ether type (eg ARPHRD_ETHER and ARPHRD_INFINIBAND) share the same bond
	 */
	if (!bond_has_slaves(bond)) {
		if (bond_dev->type != slave_dev->type) {
			netdev_dbg(bond_dev, "change device type from %d to %d\n",
				   bond_dev->type, slave_dev->type);

			res = call_netdevice_notifiers(NETDEV_PRE_TYPE_CHANGE,
						       bond_dev);
			res = notifier_to_errno(res);
			if (res) {
				netdev_err(bond_dev, "refused to change device type\n");
				res = -EBUSY;
				goto err_undo_flags;
			}

			/* Flush unicast and multicast addresses */
			dev_uc_flush(bond_dev);
			dev_mc_flush(bond_dev);

			if (slave_dev->type != ARPHRD_ETHER)
				bond_setup_by_slave(bond_dev, slave_dev);
			else {
				ether_setup(bond_dev);
				bond_dev->priv_flags &= ~IFF_TX_SKB_SHARING;
			}

			call_netdevice_notifiers(NETDEV_POST_TYPE_CHANGE,
						 bond_dev);
		}
	} else if (bond_dev->type != slave_dev->type) {
		netdev_err(bond_dev, "%s ether type (%d) is different from other slaves (%d), can not enslave it\n",
			   slave_dev->name, slave_dev->type, bond_dev->type);
		res = -EINVAL;
		goto err_undo_flags;
	}

	if (slave_ops->ndo_set_mac_address == NULL) {
		netdev_warn(bond_dev, "The slave device specified does not support setting the MAC address\n");
		if (BOND_MODE(bond) == BOND_MODE_ACTIVEBACKUP &&
		    bond->params.fail_over_mac != BOND_FOM_ACTIVE) {
			if (!bond_has_slaves(bond)) {
				bond->params.fail_over_mac = BOND_FOM_ACTIVE;
				netdev_warn(bond_dev, "Setting fail_over_mac to active for active-backup mode\n");
			} else {
				netdev_err(bond_dev, "The slave device specified does not support setting the MAC address, but fail_over_mac is not set to active\n");
				res = -EOPNOTSUPP;
				goto err_undo_flags;
			}
		}
	}

	call_netdevice_notifiers(NETDEV_JOIN, slave_dev);

	/* If this is the first slave, then we need to set the master's hardware
	 * address to be the same as the slave's.
	 */
	if (!bond_has_slaves(bond) &&
	    bond->dev->addr_assign_type == NET_ADDR_RANDOM)
		bond_set_dev_addr(bond->dev, slave_dev);

	new_slave = bond_alloc_slave(bond);
	if (!new_slave) {
		res = -ENOMEM;
		goto err_undo_flags;
	}

	new_slave->bond = bond;
	new_slave->dev = slave_dev;
	/* Set the new_slave's queue_id to be zero.  Queue ID mapping
	 * is set via sysfs or module option if desired.
	 */
	new_slave->queue_id = 0;

	/* Save slave's original mtu and then set it to match the bond */
	new_slave->original_mtu = slave_dev->mtu;
	res = dev_set_mtu(slave_dev, bond->dev->mtu);
	if (res) {
		netdev_dbg(bond_dev, "Error %d calling dev_set_mtu\n", res);
		goto err_free;
	}

	/* Save slave's original ("permanent") mac address for modes
	 * that need it, and for restoring it upon release, and then
	 * set it to the master's address
	 */
	ether_addr_copy(new_slave->perm_hwaddr, slave_dev->dev_addr);

	if (!bond->params.fail_over_mac ||
	    BOND_MODE(bond) != BOND_MODE_ACTIVEBACKUP) {
		/* Set slave to master's mac address.  The application already
		 * set the master's mac address to that of the first slave
		 */
		memcpy(addr.sa_data, bond_dev->dev_addr, bond_dev->addr_len);
		addr.sa_family = slave_dev->type;
		res = dev_set_mac_address(slave_dev, &addr);
		if (res) {
			netdev_dbg(bond_dev, "Error %d calling set_mac_address\n", res);
			goto err_restore_mtu;
		}
	}

	/* open the slave since the application closed it */
	res = dev_open(slave_dev);
	if (res) {
		netdev_dbg(bond_dev, "Opening slave %s failed\n", slave_dev->name);
		goto err_restore_mac;
	}

	slave_dev->priv_flags |= IFF_BONDING;
	/* initialize slave stats */
	dev_get_stats(new_slave->dev, &new_slave->slave_stats);

	if (bond_is_lb(bond)) {
		/* bond_alb_init_slave() must be called before all other stages since
		 * it might fail and we do not want to have to undo everything
		 */
		res = bond_alb_init_slave(bond, new_slave);
		if (res)
			goto err_close;
	}

	/* If the mode uses primary, then the following is handled by
	 * bond_change_active_slave().
	 */
	if (!bond_uses_primary(bond)) {
		/* set promiscuity level to new slave */
		if (bond_dev->flags & IFF_PROMISC) {
			res = dev_set_promiscuity(slave_dev, 1);
			if (res)
				goto err_close;
		}

		/* set allmulti level to new slave */
		if (bond_dev->flags & IFF_ALLMULTI) {
			res = dev_set_allmulti(slave_dev, 1);
			if (res)
				goto err_close;
		}

		netif_addr_lock_bh(bond_dev);

		dev_mc_sync_multiple(slave_dev, bond_dev);
		dev_uc_sync_multiple(slave_dev, bond_dev);

		netif_addr_unlock_bh(bond_dev);
	}

	if (BOND_MODE(bond) == BOND_MODE_8023AD) {
		/* add lacpdu mc addr to mc list */
		u8 lacpdu_multicast[ETH_ALEN] = MULTICAST_LACPDU_ADDR;

		dev_mc_add(slave_dev, lacpdu_multicast);
	}

	res = vlan_vids_add_by_dev(slave_dev, bond_dev);
	if (res) {
		netdev_err(bond_dev, "Couldn't add bond vlan ids to %s\n",
			   slave_dev->name);
		goto err_close;
	}

	prev_slave = bond_last_slave(bond);

	new_slave->delay = 0;
	new_slave->link_failure_count = 0;

	bond_update_speed_duplex(new_slave);

	new_slave->last_rx = jiffies -
		(msecs_to_jiffies(bond->params.arp_interval) + 1);
	for (i = 0; i < BOND_MAX_ARP_TARGETS; i++)
		new_slave->target_last_arp_rx[i] = new_slave->last_rx;

	if (bond->params.miimon && !bond->params.use_carrier) {
		link_reporting = bond_check_dev_link(bond, slave_dev, 1);

		if ((link_reporting == -1) && !bond->params.arp_interval) {
			/* miimon is set but a bonded network driver
			 * does not support ETHTOOL/MII and
			 * arp_interval is not set.  Note: if
			 * use_carrier is enabled, we will never go
			 * here (because netif_carrier is always
			 * supported); thus, we don't need to change
			 * the messages for netif_carrier.
			 */
			netdev_warn(bond_dev, "MII and ETHTOOL support not available for interface %s, and arp_interval/arp_ip_target module parameters not specified, thus bonding will not detect link failures! see bonding.txt for details\n",
				    slave_dev->name);
		} else if (link_reporting == -1) {
			/* unable get link status using mii/ethtool */
			netdev_warn(bond_dev, "can't get link status from interface %s; the network driver associated with this interface does not support MII or ETHTOOL link status reporting, thus miimon has no effect on this interface\n",
				    slave_dev->name);
		}
	}

	/* check for initial state */
	if (bond->params.miimon) {
		if (bond_check_dev_link(bond, slave_dev, 0) == BMSR_LSTATUS) {
			if (bond->params.updelay) {
				bond_set_slave_link_state(new_slave,
							  BOND_LINK_BACK);
				new_slave->delay = bond->params.updelay;
			} else {
				bond_set_slave_link_state(new_slave,
							  BOND_LINK_UP);
			}
		} else {
			bond_set_slave_link_state(new_slave, BOND_LINK_DOWN);
		}
	} else if (bond->params.arp_interval) {
		bond_set_slave_link_state(new_slave,
					  (netif_carrier_ok(slave_dev) ?
					  BOND_LINK_UP : BOND_LINK_DOWN));
	} else {
		bond_set_slave_link_state(new_slave, BOND_LINK_UP);
	}

	if (new_slave->link != BOND_LINK_DOWN)
		new_slave->last_link_up = jiffies;
	netdev_dbg(bond_dev, "Initial state of slave_dev is BOND_LINK_%s\n",
		   new_slave->link == BOND_LINK_DOWN ? "DOWN" :
		   (new_slave->link == BOND_LINK_UP ? "UP" : "BACK"));

	if (bond_uses_primary(bond) && bond->params.primary[0]) {
		/* if there is a primary slave, remember it */
		if (strcmp(bond->params.primary, new_slave->dev->name) == 0) {
			rcu_assign_pointer(bond->primary_slave, new_slave);
			bond->force_primary = true;
		}
	}

	switch (BOND_MODE(bond)) {
	case BOND_MODE_ACTIVEBACKUP:
		bond_set_slave_inactive_flags(new_slave,
					      BOND_SLAVE_NOTIFY_NOW);
		break;
	case BOND_MODE_8023AD:
		/* in 802.3ad mode, the internal mechanism
		 * will activate the slaves in the selected
		 * aggregator
		 */
		bond_set_slave_inactive_flags(new_slave, BOND_SLAVE_NOTIFY_NOW);
		/* if this is the first slave */
		if (!prev_slave) {
			SLAVE_AD_INFO(new_slave)->id = 1;
			/* Initialize AD with the number of times that the AD timer is called in 1 second
			 * can be called only after the mac address of the bond is set
			 */
			bond_3ad_initialize(bond, 1000/AD_TIMER_INTERVAL);
		} else {
			SLAVE_AD_INFO(new_slave)->id =
				SLAVE_AD_INFO(prev_slave)->id + 1;
		}

		bond_3ad_bind_slave(new_slave);
		break;
	case BOND_MODE_TLB:
	case BOND_MODE_ALB:
		bond_set_active_slave(new_slave);
		bond_set_slave_inactive_flags(new_slave, BOND_SLAVE_NOTIFY_NOW);
		break;
	default:
		netdev_dbg(bond_dev, "This slave is always active in trunk mode\n");

		/* always active in trunk mode */
		bond_set_active_slave(new_slave);

		/* In trunking mode there is little meaning to curr_active_slave
		 * anyway (it holds no special properties of the bond device),
		 * so we can change it without calling change_active_interface()
		 */
		if (!rcu_access_pointer(bond->curr_active_slave) &&
		    new_slave->link == BOND_LINK_UP)
			rcu_assign_pointer(bond->curr_active_slave, new_slave);

		break;
	} /* switch(bond_mode) */

#ifdef CONFIG_NET_POLL_CONTROLLER
	slave_dev->npinfo = bond->dev->npinfo;
	if (slave_dev->npinfo) {
		if (slave_enable_netpoll(new_slave)) {
			netdev_info(bond_dev, "master_dev is using netpoll, but new slave device does not support netpoll\n");
			res = -EBUSY;
			goto err_detach;
		}
	}
#endif

	if (!(bond_dev->features & NETIF_F_LRO))
		dev_disable_lro(slave_dev);

	res = netdev_rx_handler_register(slave_dev, bond_handle_frame,    // 注册rx_handler函数
					 new_slave);
	if (res) {
		netdev_dbg(bond_dev, "Error %d calling netdev_rx_handler_register\n", res);
		goto err_detach;
	}

	res = bond_master_upper_dev_link(bond_dev, slave_dev, new_slave);  //slave dev 添加到bond的链表中
	if (res) {
		netdev_dbg(bond_dev, "Error %d calling bond_master_upper_dev_link\n", res);
		goto err_unregister;
	}

	res = bond_sysfs_slave_add(new_slave);
	if (res) {
		netdev_dbg(bond_dev, "Error %d calling bond_sysfs_slave_add\n", res);
		goto err_upper_unlink;
	}

	bond->slave_cnt++;
	bond_compute_features(bond);
	bond_set_carrier(bond);

	if (bond_uses_primary(bond)) {
		block_netpoll_tx();
		bond_select_active_slave(bond);
		unblock_netpoll_tx();
	}

	if (bond_mode_uses_xmit_hash(bond))
		bond_update_slave_arr(bond, NULL);

	netdev_info(bond_dev, "Enslaving %s as %s interface with %s link\n",
		    slave_dev->name,
		    bond_is_active_slave(new_slave) ? "an active" : "a backup",
		    new_slave->link != BOND_LINK_DOWN ? "an up" : "a down");

	/* enslave is successful */
	bond_queue_slave_event(new_slave);
	return 0;

/* Undo stages on error */
err_upper_unlink:
	bond_upper_dev_unlink(bond_dev, slave_dev);

err_unregister:
	netdev_rx_handler_unregister(slave_dev);

err_detach:
	if (!bond_uses_primary(bond))
		bond_hw_addr_flush(bond_dev, slave_dev);

	vlan_vids_del_by_dev(slave_dev, bond_dev);
	if (rcu_access_pointer(bond->primary_slave) == new_slave)
		RCU_INIT_POINTER(bond->primary_slave, NULL);
	if (rcu_access_pointer(bond->curr_active_slave) == new_slave) {
		block_netpoll_tx();
		bond_change_active_slave(bond, NULL);
		bond_select_active_slave(bond);
		unblock_netpoll_tx();
	}
	/* either primary_slave or curr_active_slave might've changed */
	synchronize_rcu();
	slave_disable_netpoll(new_slave);

err_close:
	slave_dev->priv_flags &= ~IFF_BONDING;
	dev_close(slave_dev);

err_restore_mac:
	if (!bond->params.fail_over_mac ||
	    BOND_MODE(bond) != BOND_MODE_ACTIVEBACKUP) {
		/* XXX TODO - fom follow mode needs to change master's
		 * MAC if this slave's MAC is in use by the bond, or at
		 * least print a warning.
		 */
		ether_addr_copy(addr.sa_data, new_slave->perm_hwaddr);
		addr.sa_family = slave_dev->type;
		dev_set_mac_address(slave_dev, &addr);
	}

err_restore_mtu:
	dev_set_mtu(slave_dev, new_slave->original_mtu);

err_free:
	bond_free_slave(new_slave);

err_undo_flags:
	/* Enslave of first slave has failed and we need to fix master's mac */
	if (!bond_has_slaves(bond) &&
	    ether_addr_equal_64bits(bond_dev->dev_addr, slave_dev->dev_addr))
		eth_hw_addr_random(bond_dev);

	return res;
}
```


## bond底层设备收包处理

```c
static rx_handler_result_t bond_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct slave *slave;
	struct bonding *bond;
	int (*recv_probe)(const struct sk_buff *, struct bonding *,
			  struct slave *);
	int ret = RX_HANDLER_ANOTHER;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return RX_HANDLER_CONSUMED;

	*pskb = skb;

	slave = bond_slave_get_rcu(skb->dev);   //得到收到报文网卡的slave
	bond = slave->bond;

	recv_probe = ACCESS_ONCE(bond->recv_probe);   //不同的mode，该函数也不同
	if (recv_probe) {
		ret = recv_probe(skb, bond, slave);   //处理arp响应报文，记录信息，为后续发送报文准备
		if (ret == RX_HANDLER_CONSUMED) {
			consume_skb(skb);
			return ret;
		}
	}

	if (bond_should_deliver_exact_match(skb, slave, bond)) {
		return RX_HANDLER_EXACT;
	}

	skb->dev = bond->dev;

	if (BOND_MODE(bond) == BOND_MODE_ALB &&
	    bond->dev->priv_flags & IFF_BRIDGE_PORT &&
	    skb->pkt_type == PACKET_HOST) {

		if (unlikely(skb_cow_head(skb,
					  skb->data - skb_mac_header(skb)))) {
			kfree_skb(skb);
			return RX_HANDLER_CONSUMED;
		}
		ether_addr_copy(eth_hdr(skb)->h_dest, bond->dev->dev_addr);   //替换报文的目的MAC地址
	}

	return ret;    //继续上送协议栈
}
```


## bond设备发包处理

```c
static netdev_tx_t bond_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bonding *bond = netdev_priv(dev);
	netdev_tx_t ret = NETDEV_TX_OK;

	/* If we risk deadlock from transmitting this in the
	 * netpoll path, tell netpoll to queue the frame for later tx
	 */
	if (unlikely(is_netpoll_tx_blocked(dev)))
		return NETDEV_TX_BUSY;

	rcu_read_lock();
	if (bond_has_slaves(bond))
		ret = __bond_start_xmit(skb, dev);
	else
		bond_tx_drop(dev, skb);
	rcu_read_unlock();

	return ret;
}

static netdev_tx_t __bond_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bonding *bond = netdev_priv(dev);

	if (bond_should_override_tx_queue(bond) &&
	    !bond_slave_override(bond, skb))
		return NETDEV_TX_OK;

	switch (BOND_MODE(bond)) {
	case BOND_MODE_ROUNDROBIN:
		return bond_xmit_roundrobin(skb, dev);
	case BOND_MODE_ACTIVEBACKUP:
		return bond_xmit_activebackup(skb, dev);
	case BOND_MODE_8023AD:
	case BOND_MODE_XOR:
		return bond_3ad_xor_xmit(skb, dev);
	case BOND_MODE_BROADCAST:
		return bond_xmit_broadcast(skb, dev);
	case BOND_MODE_ALB:
		return bond_alb_xmit(skb, dev);
	case BOND_MODE_TLB:
		return bond_tlb_xmit(skb, dev);
	default:
		/* Should never happen, mode already checked */
		netdev_err(dev, "Unknown bonding mode %d\n", BOND_MODE(bond));
		WARN_ON_ONCE(1);
		bond_tx_drop(dev, skb);
		return NETDEV_TX_OK;
	}
}
```

### bond_xmit_roundrobin(ROUNDROBIN)

```c

static int bond_xmit_roundrobin(struct sk_buff *skb, struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);
	struct iphdr *iph = ip_hdr(skb);
	struct slave *slave;
	u32 slave_id;

	/* Start with the curr_active_slave that joined the bond as the
	 * default for sending IGMP traffic.  For failover purposes one
	 * needs to maintain some consistency for the interface that will
	 * send the join/membership reports.  The curr_active_slave found
	 * will send all of this type of traffic.
	 */
	if (iph->protocol == IPPROTO_IGMP && skb->protocol == htons(ETH_P_IP)) {
		slave = rcu_dereference(bond->curr_active_slave);
		if (slave)
			bond_dev_queue_xmit(bond, skb, slave->dev);  //IGMP报文优先使用curr_active_slave
		else
			bond_xmit_slave_id(bond, skb, 0);  //否则使用0号设备
	} else {
		int slave_cnt = ACCESS_ONCE(bond->slave_cnt);  // 得到slave数量

		if (likely(slave_cnt)) {
			slave_id = bond_rr_gen_slave_id(bond);   //得到slave id
			bond_xmit_slave_id(bond, skb, slave_id % slave_cnt);
		} else {
			bond_tx_drop(bond_dev, skb);
		}
	}

	return NETDEV_TX_OK;
}


static u32 bond_rr_gen_slave_id(struct bonding *bond)
{
	u32 slave_id;
	struct reciprocal_value reciprocal_packets_per_slave;
	int packets_per_slave = bond->params.packets_per_slave;

	switch (packets_per_slave) {
	case 0:
		slave_id = prandom_u32();     // 随机
		break;
	case 1:
		slave_id = bond->rr_tx_counter;   // roundrobin
		break;
	default:
		reciprocal_packets_per_slave =
			bond->params.reciprocal_packets_per_slave;
		slave_id = reciprocal_divide(bond->rr_tx_counter,
					     reciprocal_packets_per_slave);   // 按数量轮询
		break;
	}
	bond->rr_tx_counter++;

	return slave_id;
}

static void bond_xmit_slave_id(struct bonding *bond, struct sk_buff *skb, int slave_id)
{
	struct list_head *iter;
	struct slave *slave;
	int i = slave_id;

	/* Here we start from the slave with slave_id */
	bond_for_each_slave_rcu(bond, slave, iter) {
		if (--i < 0) {
			if (bond_slave_can_tx(slave)) {
				bond_dev_queue_xmit(bond, skb, slave->dev);   //发送报文
				return;
			}
		}
	}

	/* Here we start from the first slave up to slave_id */
	i = slave_id;
	bond_for_each_slave_rcu(bond, slave, iter) {
		if (--i < 0)
			break;
		if (bond_slave_can_tx(slave)) {
			bond_dev_queue_xmit(bond, skb, slave->dev);
			return;
		}
	}
	/* no slave that can tx has been found */
	bond_tx_drop(bond->dev, skb);
}

void bond_dev_queue_xmit(struct bonding *bond, struct sk_buff *skb,
			struct net_device *slave_dev)
{
	skb->dev = slave_dev;

	BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
		     sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
	skb->queue_mapping = qdisc_skb_cb(skb)->slave_dev_queue_mapping;

	if (unlikely(netpoll_tx_running(bond->dev)))
		bond_netpoll_send_skb(bond_get_slave_by_dev(bond, slave_dev), skb);
	else
		dev_queue_xmit(skb);   //二层发送报文
}
```


### bond_3ad_xor_xmit(8023AD/XOR)

```c
static int bond_3ad_xor_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct bonding *bond = netdev_priv(dev);
	struct slave *slave;
	struct bond_up_slave *slaves;
	unsigned int count;

	slaves = rcu_dereference(bond->slave_arr);
	count = slaves ? ACCESS_ONCE(slaves->count) : 0;
	if (likely(count)) {
		slave = slaves->arr[bond_xmit_hash(bond, skb) % count];
		bond_dev_queue_xmit(bond, skb, slave->dev);
	} else {
		bond_tx_drop(dev, skb);
	}

	return NETDEV_TX_OK;
}

u32 bond_xmit_hash(struct bonding *bond, struct sk_buff *skb)
{
	struct flow_keys flow;
	u32 hash;

	if (bond->params.xmit_policy == BOND_XMIT_POLICY_LAYER2 ||
	    !bond_flow_dissect(bond, skb, &flow))
		return bond_eth_hash(skb);

	if (bond->params.xmit_policy == BOND_XMIT_POLICY_LAYER23 ||
	    bond->params.xmit_policy == BOND_XMIT_POLICY_ENCAP23)
		hash = bond_eth_hash(skb);
	else
		hash = (__force u32)flow.ports;
	hash ^= (__force u32)flow.dst ^ (__force u32)flow.src;
	hash ^= (hash >> 16);
	hash ^= (hash >> 8);

	return hash;
}

static inline u32 bond_eth_hash(struct sk_buff *skb)
{
	struct ethhdr *ep, hdr_tmp;

	ep = skb_header_pointer(skb, 0, sizeof(hdr_tmp), &hdr_tmp);
	if (ep)
		return ep->h_dest[5] ^ ep->h_source[5] ^ ep->h_proto;
	return 0;
}
```

