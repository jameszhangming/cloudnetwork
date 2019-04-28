# MACVLAN

MACVLAN是linux模拟以太网二层设备，该设备寄居在一个物理以太网网卡（也可以是其他虚拟的二层以太网网卡）上，相当于把物理以太网卡当成集线器，macvlan当成一个网卡与物理网络连通。


## 数据结构

```c
static struct rtnl_link_ops macvlan_link_ops = {
	.kind		= "macvlan",
	.setup		= macvlan_setup,
	.newlink	= macvlan_newlink,
	.dellink	= macvlan_dellink,
	.get_link_net	= macvlan_get_link_net,
};

//设备驱动
static const struct net_device_ops macvlan_netdev_ops = {
	.ndo_init		= macvlan_init,
	.ndo_uninit		= macvlan_uninit,
	.ndo_open		= macvlan_open,
	.ndo_stop		= macvlan_stop,
	.ndo_start_xmit		= macvlan_start_xmit,
	.ndo_change_mtu		= macvlan_change_mtu,
	.ndo_fix_features	= macvlan_fix_features,
	.ndo_change_rx_flags	= macvlan_change_rx_flags,
	.ndo_set_mac_address	= macvlan_set_mac_address,
	.ndo_set_rx_mode	= macvlan_set_mac_lists,
	.ndo_get_stats64	= macvlan_dev_get_stats64,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_vlan_rx_add_vid	= macvlan_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= macvlan_vlan_rx_kill_vid,
	.ndo_fdb_add		= macvlan_fdb_add,
	.ndo_fdb_del		= macvlan_fdb_del,
	.ndo_fdb_dump		= ndo_dflt_fdb_dump,
	.ndo_get_lock_subclass  = macvlan_get_nest_level,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= macvlan_dev_poll_controller,
	.ndo_netpoll_setup	= macvlan_dev_netpoll_setup,
	.ndo_netpoll_cleanup	= macvlan_dev_netpoll_cleanup,
#endif
	.ndo_get_iflink		= macvlan_dev_get_iflink,
};
```

## 模块初始化

```c
static int __init macvlan_init_module(void)
{
	int err;

	register_netdevice_notifier(&macvlan_notifier_block);

	err = macvlan_link_register(&macvlan_link_ops);  //注册link ops
	if (err < 0)
		goto err1;
	return 0;
err1:
	unregister_netdevice_notifier(&macvlan_notifier_block);
	return err;
}

int macvlan_link_register(struct rtnl_link_ops *ops)
{
	/* common fields */
	ops->priv_size		= sizeof(struct macvlan_dev);	 //设备的存储空间
	ops->validate		= macvlan_validate;
	ops->maxtype		= IFLA_MACVLAN_MAX;
	ops->policy		= macvlan_policy;
	ops->changelink		= macvlan_changelink;
	ops->get_size		= macvlan_get_size;
	ops->fill_info		= macvlan_fill_info;

	return rtnl_link_register(ops);
};
```

## macvlan设备创建

macvlan设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）  //未定义
2. rtnl_link_ops->changelink（修改父设备link信息，根据需要）  //未定义
3. rtnl_link_ops->setup（设备初始化，默认初始化）
4. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
5. dev->netdev_ops->ndo_init（设备初始化）
6. dev->netdev_ops->ndo_validate_addr（设备地址校验）
7. dev->netdev_ops->ndo_open（打开设备）

### setup(macvlan_setup)

```c
static void macvlan_setup(struct net_device *dev)
{
	macvlan_common_setup(dev);
	dev->tx_queue_len	= 0;
}

void macvlan_common_setup(struct net_device *dev)
{
	ether_setup(dev);  //通用以太网网络设备初始化

	dev->priv_flags	       &= ~IFF_TX_SKB_SHARING;
	netif_keep_dst(dev);
	dev->priv_flags	       |= IFF_UNICAST_FLT;
	dev->netdev_ops		= &macvlan_netdev_ops;   //设置驱动
	dev->destructor		= free_netdev;
	dev->header_ops		= &macvlan_hard_header_ops;	 //刷新mac头构造函数
	dev->ethtool_ops	= &macvlan_ethtool_ops;
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

### newlink(macvlan_common_newlink)

```c
static int macvlan_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[])
{
	return macvlan_common_newlink(src_net, dev, tb, data);
}

int macvlan_common_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[])
{
	struct macvlan_dev *vlan = netdev_priv(dev);
	struct macvlan_port *port;
	struct net_device *lowerdev;
	int err;
	int macmode;

	if (!tb[IFLA_LINK])
		return -EINVAL;

	lowerdev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));   //得到底层
	if (lowerdev == NULL)
		return -ENODEV;

	/* When creating macvlans or macvtaps on top of other macvlans - use
	 * the real device as the lowerdev.
	 */
	if (netif_is_macvlan(lowerdev))   //如果底层设备也是macvlan设备，那么要找到真实的父设备
		lowerdev = macvlan_dev_real_dev(lowerdev);

	if (!tb[IFLA_MTU])
		dev->mtu = lowerdev->mtu;
	else if (dev->mtu > lowerdev->mtu)
		return -EINVAL;

	if (!tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	if (!macvlan_port_exists(lowerdev)) {
		err = macvlan_port_create(lowerdev);  //创建底层设备的macvlan port设备，同时修改父设备的rx_handler函数
		if (err < 0)
			return err;
	}
	port = macvlan_port_get_rtnl(lowerdev);   //得到macvlan port设备，port设备信息保存在rx_handler_data指针

	/* Only 1 macvlan device can be created in passthru mode */
	if (port->passthru)    //如果port是直通模式，直接返回报错，第一个macvlan设备创建时，此时该状态还是false
		return -EINVAL;

	vlan->lowerdev = lowerdev;   //设置底层设备
	vlan->dev      = dev;
	vlan->port     = port;
	vlan->set_features = MACVLAN_FEATURES;
	vlan->nest_level = dev_get_nest_level(lowerdev, netif_is_macvlan) + 1;

	vlan->mode     = MACVLAN_MODE_VEPA;
	if (data && data[IFLA_MACVLAN_MODE])
		vlan->mode = nla_get_u32(data[IFLA_MACVLAN_MODE]);

	if (data && data[IFLA_MACVLAN_FLAGS])
		vlan->flags = nla_get_u16(data[IFLA_MACVLAN_FLAGS]);

	if (vlan->mode == MACVLAN_MODE_PASSTHRU) {
		if (port->count)
			return -EINVAL;
		port->passthru = true;                  //如果是passthru模式，设置该状态为true，防止再创建macvlan设备
		eth_hw_addr_inherit(dev, lowerdev);
	}

	if (data && data[IFLA_MACVLAN_MACADDR_MODE]) {
		if (vlan->mode != MACVLAN_MODE_SOURCE)
			return -EINVAL;
		macmode = nla_get_u32(data[IFLA_MACVLAN_MACADDR_MODE]);
		//source模式，当收到源mac为当前mac地址时，该设备会接收报文
		err = macvlan_changelink_sources(vlan, macmode, data);   
		if (err)
			return err;
	}

	port->count += 1;
	err = register_netdevice(dev);    //注册网络设备
	if (err < 0)
		goto destroy_port;

	dev->priv_flags |= IFF_MACVLAN;
	err = netdev_upper_dev_link(lowerdev, dev);
	if (err)
		goto unregister_netdev;

	list_add_tail_rcu(&vlan->list, &port->vlans);	 //添加到链表中
	netif_stacked_transfer_operstate(lowerdev, dev);

	return 0;

unregister_netdev:
	unregister_netdevice(dev);
destroy_port:
	port->count -= 1;
	if (!port->count)
		macvlan_port_destroy(lowerdev);

	return err;
}

static int macvlan_port_create(struct net_device *dev)
{
	struct macvlan_port *port;
	unsigned int i;
	int err;

	if (dev->type != ARPHRD_ETHER || dev->flags & IFF_LOOPBACK)
		return -EINVAL;

	if (netif_is_ipvlan_port(dev))  //不支持底层设备是vlan设备的场景
		return -EBUSY;

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (port == NULL)
		return -ENOMEM;

	port->passthru = false;
	port->dev = dev;        //指向的是底层设备
	INIT_LIST_HEAD(&port->vlans);
	for (i = 0; i < MACVLAN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&port->vlan_hash[i]);
	for (i = 0; i < MACVLAN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&port->vlan_source_hash[i]);

	skb_queue_head_init(&port->bc_queue);   //初始化广播队列
	INIT_WORK(&port->bc_work, macvlan_process_broadcast);   //广播任务处理函数

	err = netdev_rx_handler_register(dev, macvlan_handle_frame, port);   //注册底层设备的rx_handler函数
	if (err)
		kfree(port);
	else
		dev->priv_flags |= IFF_MACVLAN_PORT;
	return err;
}
```


### ndo_init(macvlan_init)

```c
static int macvlan_init(struct net_device *dev)
{
	struct macvlan_dev *vlan = netdev_priv(dev);
	const struct net_device *lowerdev = vlan->lowerdev;   //得到底层设备

	dev->state		= (dev->state & ~MACVLAN_STATE_MASK) |
				  (lowerdev->state & MACVLAN_STATE_MASK);
	dev->features 		= lowerdev->features & MACVLAN_FEATURES;
	dev->features		|= ALWAYS_ON_FEATURES;
	dev->hw_features	|= NETIF_F_LRO;
	dev->vlan_features	= lowerdev->vlan_features & MACVLAN_FEATURES;
	dev->gso_max_size	= lowerdev->gso_max_size;
	dev->hard_header_len	= lowerdev->hard_header_len;   //二层头长度和底层设备一样

	macvlan_set_lockdep_class(dev);

	vlan->pcpu_stats = netdev_alloc_pcpu_stats(struct vlan_pcpu_stats);
	if (!vlan->pcpu_stats)
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

### ndo_open(macvlan_open)

```c
static int macvlan_open(struct net_device *dev)
{
	struct macvlan_dev *vlan = netdev_priv(dev);
	struct net_device *lowerdev = vlan->lowerdev;
	int err;

	if (vlan->port->passthru) {
		if (!(vlan->flags & MACVLAN_FLAG_NOPROMISC)) {
			err = dev_set_promiscuity(lowerdev, 1);
			if (err < 0)
				goto out;
		}
		goto hash_add;
	}

	if (lowerdev->features & NETIF_F_HW_L2FW_DOFFLOAD &&
	    dev->rtnl_link_ops == &macvlan_link_ops) {
		vlan->fwd_priv =
		      lowerdev->netdev_ops->ndo_dfwd_add_station(lowerdev, dev);

		/* If we get a NULL pointer back, or if we get an error
		 * then we should just fall through to the non accelerated path
		 */
		if (IS_ERR_OR_NULL(vlan->fwd_priv)) {
			vlan->fwd_priv = NULL;
		} else
			return 0;
	}

	err = -EBUSY;
	if (macvlan_addr_busy(vlan->port, dev->dev_addr))
		goto out;
    //为底层设备添加单播的mac地址，防止底层设备丢包（底层设备不需要开启混杂模式）
	err = dev_uc_add(lowerdev, dev->dev_addr);   
	if (err < 0)
		goto out;
	if (dev->flags & IFF_ALLMULTI) {
		err = dev_set_allmulti(lowerdev, 1);
		if (err < 0)
			goto del_unicast;
	}
    //如果macvlan开始混杂模式，那么底层设备也要开启混杂模式
	if (dev->flags & IFF_PROMISC) {     
		err = dev_set_promiscuity(lowerdev, 1);
		if (err < 0)
			goto clear_multi;
	}

hash_add:
	macvlan_hash_add(vlan); //macvlan设备添加到port的hash链表中，可以进行接收或转发报文
	return 0;

clear_multi:
	dev_set_allmulti(lowerdev, -1);
del_unicast:
	dev_uc_del(lowerdev, dev->dev_addr);
out:
	if (vlan->fwd_priv) {
		lowerdev->netdev_ops->ndo_dfwd_del_station(lowerdev,
							   vlan->fwd_priv);
		vlan->fwd_priv = NULL;
	}
	return err;
}
```

## macvlan底层设备收包处理

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

### 广播报文处理

```c
static void macvlan_broadcast_enqueue(struct macvlan_port *port,
				      struct sk_buff *skb)
{
	struct sk_buff *nskb;
	int err = -ENOMEM;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		goto err;

	spin_lock(&port->bc_queue.lock);
	if (skb_queue_len(&port->bc_queue) < MACVLAN_BC_QUEUE_LEN) {
		__skb_queue_tail(&port->bc_queue, nskb);    //报文添加到广播报文队列中
		err = 0;
	}
	spin_unlock(&port->bc_queue.lock);

	if (err)
		goto free_nskb;

	schedule_work(&port->bc_work);    //触发广播报文处理线程
	return;

free_nskb:
	kfree_skb(nskb);
err:
	atomic_long_inc(&skb->dev->rx_dropped);
}

static void macvlan_process_broadcast(struct work_struct *w)
{
	struct macvlan_port *port = container_of(w, struct macvlan_port,
						 bc_work);
	struct sk_buff *skb;
	struct sk_buff_head list;

	__skb_queue_head_init(&list);

	spin_lock_bh(&port->bc_queue.lock);
	skb_queue_splice_tail_init(&port->bc_queue, &list);  //发送报文保存到list列表中，bc_queue可以继续接收
	spin_unlock_bh(&port->bc_queue.lock);

	while ((skb = __skb_dequeue(&list))) {
		const struct macvlan_dev *src = MACVLAN_SKB_CB(skb)->src;  

		rcu_read_lock();

		if (!src)  //外部发送的组播报文
			/* frame comes from an external address */
			macvlan_broadcast(skb, port, NULL,
					  MACVLAN_MODE_PRIVATE |
					  MACVLAN_MODE_VEPA    |
					  MACVLAN_MODE_PASSTHRU|
					  MACVLAN_MODE_BRIDGE);
		else if (src->mode == MACVLAN_MODE_VEPA)
			/* flood to everyone except source */
			macvlan_broadcast(skb, port, src->dev,
					  MACVLAN_MODE_VEPA |
					  MACVLAN_MODE_BRIDGE);
		else
			/*
			 * flood only to VEPA ports, bridge ports
			 * already saw the frame on the way out.
			 */
			macvlan_broadcast(skb, port, src->dev,
					  MACVLAN_MODE_VEPA);

		rcu_read_unlock();

		kfree_skb(skb);
	}
}

static void macvlan_broadcast(struct sk_buff *skb,
			      const struct macvlan_port *port,
			      struct net_device *src,
			      enum macvlan_mode mode)
{
	const struct ethhdr *eth = eth_hdr(skb);
	const struct macvlan_dev *vlan;
	struct sk_buff *nskb;
	unsigned int i;
	int err;
	unsigned int hash;

	if (skb->protocol == htons(ETH_P_PAUSE))
		return;

	for (i = 0; i < MACVLAN_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(vlan, &port->vlan_hash[i], hlist) {   //遍历设备
		    //设备发送方，不发送；模式不匹配也不发送
			if (vlan->dev == src || !(vlan->mode & mode)) 
				continue;

			hash = mc_hash(vlan, eth->h_dest);
			if (!test_bit(hash, vlan->mc_filter))
				continue;

			err = NET_RX_DROP;
			nskb = skb_clone(skb, GFP_ATOMIC);
			if (likely(nskb))
				err = macvlan_broadcast_one(     //发送报文到该设备，即该设备接收报文
					nskb, vlan, eth,
					mode == MACVLAN_MODE_BRIDGE) ?:
				      netif_rx_ni(nskb);
			macvlan_count_rx(vlan, skb->len + ETH_HLEN,
					 err == NET_RX_SUCCESS, true);
		}
	}
}
```

不同模式下收包情况如下：

| 发送设备mode | 接收设备mode | 是否可以接收 | 
| :-----:      | :-----:      | :-----:      |
| 外部         | ALL          | 接收 |
| PRIVATE      | 自己         | 接收 |
| VEPA         | VEPA         | 接收 |
| VEPA         | BRIDGE       | 接收 | 
| VEPA         | 其他         | 不接收 |
| BRIDGE       | PRIVATE      | 不接收 |
| BRIDGE       | VEPA         | 不接收 |
| BRIDGE       | BRIDGE       | 接收 |
| BRIDGE       | 其他         | 不接收 |


## macvlan发包处理

```c
static netdev_tx_t macvlan_start_xmit(struct sk_buff *skb,
				      struct net_device *dev)
{
	unsigned int len = skb->len;
	int ret;
	struct macvlan_dev *vlan = netdev_priv(dev);  //得到macvlan设备

	if (unlikely(netpoll_tx_running(dev)))
		return macvlan_netpoll_send_skb(vlan, skb);

	if (vlan->fwd_priv) {
		skb->dev = vlan->lowerdev;
		ret = dev_queue_xmit_accel(skb, vlan->fwd_priv);   //直接使用底层设备发包
	} else {
		ret = macvlan_queue_xmit(skb, dev);   //macvlan设备发包
	}

	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN)) {
		struct vlan_pcpu_stats *pcpu_stats;

		pcpu_stats = this_cpu_ptr(vlan->pcpu_stats);
		u64_stats_update_begin(&pcpu_stats->syncp);
		pcpu_stats->tx_packets++;
		pcpu_stats->tx_bytes += len;
		u64_stats_update_end(&pcpu_stats->syncp);
	} else {
		this_cpu_inc(vlan->pcpu_stats->tx_dropped);
	}
	return ret;
}

static int macvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev)
{
	const struct macvlan_dev *vlan = netdev_priv(dev);
	const struct macvlan_port *port = vlan->port;
	const struct macvlan_dev *dest;

	if (vlan->mode == MACVLAN_MODE_BRIDGE) {     //bridge模式，直接进行转发
		const struct ethhdr *eth = (void *)skb->data;

		/* send to other bridge ports directly */
		if (is_multicast_ether_addr(eth->h_dest)) {    //组播地址，直接广播发送到其他macvlan设备
			macvlan_broadcast(skb, port, dev, MACVLAN_MODE_BRIDGE);
			goto xmit_world;   //还需要从底层设备发出
		}

		dest = macvlan_hash_lookup(port, eth->h_dest);   //非组播报文，找到目标macvlan设备
		if (dest && dest->mode == MACVLAN_MODE_BRIDGE) { //目标设备存在，且目标设备也是bridge模式
			/* send to lowerdev first for its network taps */
			dev_forward_skb(vlan->lowerdev, skb);   //底层设备收包，底层设备收包后，会进入rx_handler函数进入macvlan设备收包

			return NET_XMIT_SUCCESS;   //返回
		}
	}

xmit_world:
	skb->dev = vlan->lowerdev;   //非bridge模式，直接使用底层设备发包
	return dev_queue_xmit(skb);  
}
```



