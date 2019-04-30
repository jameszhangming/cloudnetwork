# 虚拟网卡创建

虚拟网卡创建过程涉及到Link操作和网卡驱动相关的初始化过程。

## 虚拟网卡主要数据结构

网卡驱动：
```c
struct net_device_ops {
	int			(*ndo_init)(struct net_device *dev);
	void		(*ndo_uninit)(struct net_device *dev);
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	netdev_tx_t	(*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);
	u16			(*ndo_select_queue)(struct net_device *dev,
						    struct sk_buff *skb,
						    void *accel_priv,
						    select_queue_fallback_t fallback);
	void		(*ndo_change_rx_flags)(struct net_device *dev, int flags);
	//......						     
}
```

Link操作：
```c
struct rtnl_link_ops {
	struct list_head	list;

	const char		*kind;

	size_t			priv_size;
	void			(*setup)(struct net_device *dev);

	int			maxtype;
	const struct nla_policy	*policy;
	int			(*validate)(struct nlattr *tb[], struct nlattr *data[]);

	int			(*newlink)(struct net *src_net,
					   struct net_device *dev,
					   struct nlattr *tb[],
					   struct nlattr *data[]);
	//......						     
}
```

网卡收包函数：
```
typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **pskb);
```

## 创建虚拟网卡流程

```c
static int rtnl_newlink(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	const struct rtnl_link_ops *ops;
	const struct rtnl_link_ops *m_ops = NULL;
	struct net_device *dev;
	struct net_device *master_dev = NULL;
	struct ifinfomsg *ifm;
	char kind[MODULE_NAME_LEN];
	char ifname[IFNAMSIZ];
	struct nlattr *tb[IFLA_MAX+1];
	struct nlattr *linkinfo[IFLA_INFO_MAX+1];
	unsigned char name_assign_type = NET_NAME_USER;
	int err;

#ifdef CONFIG_MODULES
replay:
#endif
	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFLA_MAX, ifla_policy);
	if (err < 0)
		return err;

	if (tb[IFLA_IFNAME])
		nla_strlcpy(ifname, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		ifname[0] = '\0';

	ifm = nlmsg_data(nlh);
	if (ifm->ifi_index > 0)
		dev = __dev_get_by_index(net, ifm->ifi_index);	//设备已创建
	else {
		if (ifname[0])
			dev = __dev_get_by_name(net, ifname);
		else
			dev = NULL;
	}

	if (dev) {
		master_dev = netdev_master_upper_dev_get(dev);
		if (master_dev)
			m_ops = master_dev->rtnl_link_ops;
	}

	err = validate_linkmsg(dev, tb);
	if (err < 0)
		return err;

	if (tb[IFLA_LINKINFO]) {
		err = nla_parse_nested(linkinfo, IFLA_INFO_MAX,
				       tb[IFLA_LINKINFO], ifla_info_policy);
		if (err < 0)
			return err;
	} else
		memset(linkinfo, 0, sizeof(linkinfo));

	if (linkinfo[IFLA_INFO_KIND]) {
		nla_strlcpy(kind, linkinfo[IFLA_INFO_KIND], sizeof(kind));
		ops = rtnl_link_ops_get(kind);		//通过命令行中的type值，获取rtnl_link_ops对象
	} else {
		kind[0] = '\0';
		ops = NULL;
	}

	if (1) {
		struct nlattr *attr[ops ? ops->maxtype + 1 : 1];
		struct nlattr *slave_attr[m_ops ? m_ops->slave_maxtype + 1 : 1];
		struct nlattr **data = NULL;
		struct nlattr **slave_data = NULL;
		struct net *dest_net, *link_net = NULL;

		if (ops) {		//如果rtnl_link_ops对象存在	
			if (ops->maxtype && linkinfo[IFLA_INFO_DATA]) {
				err = nla_parse_nested(attr, ops->maxtype,
						       linkinfo[IFLA_INFO_DATA],
						       ops->policy);
				if (err < 0)
					return err;
				data = attr;
			}
			if (ops->validate) {
				err = ops->validate(tb, data);//验证参数的正确性
				if (err < 0)
					return err;
			}
		}

		if (m_ops) {
			if (m_ops->slave_maxtype &&
			    linkinfo[IFLA_INFO_SLAVE_DATA]) {
				err = nla_parse_nested(slave_attr,
						       m_ops->slave_maxtype,
						       linkinfo[IFLA_INFO_SLAVE_DATA],
						       m_ops->slave_policy);
				if (err < 0)
					return err;
				slave_data = slave_attr;
			}
			if (m_ops->slave_validate) {
				err = m_ops->slave_validate(tb, slave_data);
				if (err < 0)
					return err;
			}
		}

		if (dev) {			//设备已经创建，修改设备信息
			int status = 0;

			if (nlh->nlmsg_flags & NLM_F_EXCL)
				return -EEXIST;
			if (nlh->nlmsg_flags & NLM_F_REPLACE)
				return -EOPNOTSUPP;

			if (linkinfo[IFLA_INFO_DATA]) {
				if (!ops || ops != dev->rtnl_link_ops ||
				    !ops->changelink)
					return -EOPNOTSUPP;

				err = ops->changelink(dev, tb, data);	//调用link修改函数
				if (err < 0)
					return err;
				status |= DO_SETLINK_NOTIFY;
			}

			if (linkinfo[IFLA_INFO_SLAVE_DATA]) {
				if (!m_ops || !m_ops->slave_changelink)
					return -EOPNOTSUPP;

				err = m_ops->slave_changelink(master_dev, dev,
							      tb, slave_data);
				if (err < 0)
					return err;
				status |= DO_SETLINK_NOTIFY;
			}

			return do_setlink(skb, dev, ifm, tb, ifname, status);  
		}

		if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
			if (ifm->ifi_index == 0 && tb[IFLA_GROUP])
				return rtnl_group_changelink(skb, net,
						nla_get_u32(tb[IFLA_GROUP]),
						ifm, tb);
			return -ENODEV;
		}

		if (tb[IFLA_MAP] || tb[IFLA_MASTER] || tb[IFLA_PROTINFO])
			return -EOPNOTSUPP;

		if (!ops) {		//如果ops不存在则报错
#ifdef CONFIG_MODULES
			if (kind[0]) {
				__rtnl_unlock();
				request_module("rtnl-link-%s", kind);
				rtnl_lock();
				ops = rtnl_link_ops_get(kind);
				if (ops)
					goto replay;
			}
#endif
			return -EOPNOTSUPP;
		}

		if (!ops->setup)
			return -EOPNOTSUPP;

		if (!ifname[0]) {
			snprintf(ifname, IFNAMSIZ, "%s%%d", ops->kind);
			name_assign_type = NET_NAME_ENUM;
		}

		dest_net = rtnl_link_get_net(net, tb);
		if (IS_ERR(dest_net))
			return PTR_ERR(dest_net);

		err = -EPERM;
		if (!netlink_ns_capable(skb, dest_net->user_ns, CAP_NET_ADMIN))
			goto out;

		if (tb[IFLA_LINK_NETNSID]) {
			int id = nla_get_s32(tb[IFLA_LINK_NETNSID]);

			link_net = get_net_ns_by_id(dest_net, id);
			if (!link_net) {
				err =  -EINVAL;
				goto out;
			}
			err = -EPERM;
			if (!netlink_ns_capable(skb, link_net->user_ns, CAP_NET_ADMIN))
				goto out;
		}

		dev = rtnl_create_link(link_net ? : dest_net, ifname,		
				       name_assign_type, ops, tb);
		if (IS_ERR(dev)) {
			err = PTR_ERR(dev);
			goto out;
		}

		dev->ifindex = ifm->ifi_index;

		if (ops->newlink) {
		    //初始化设备私有属性（不同设备的对象不同，基类都是net_device）
			err = ops->newlink(link_net ? : net, dev, tb, data);	
			/* Drivers should call free_netdev() in ->destructor
			 * and unregister it on failure after registration
			 * so that device could be finally freed in rtnl_unlock.
			 */
			if (err < 0) {
				/* If device is not registered at all, free it now */
				if (dev->reg_state == NETREG_UNINITIALIZED)
					free_netdev(dev);
				goto out;
			}
		} else {
			err = register_netdevice(dev);
			if (err < 0) {
				free_netdev(dev);
				goto out;
			}
		}
		err = rtnl_configure_link(dev, ifm);    
		if (err < 0)
			goto out_unregister;
		if (link_net) {
			err = dev_change_net_namespace(dev, dest_net, ifname);
			if (err < 0)
				goto out_unregister;
		}
out:
		if (link_net)
			put_net(link_net);
		put_net(dest_net);
		return err;
out_unregister:
		if (ops->newlink) {
			LIST_HEAD(list_kill);

			ops->dellink(dev, &list_kill);
			unregister_netdevice_many(&list_kill);
		} else {
			unregister_netdevice(dev);
		}
		goto out;
	}
}

struct net_device *rtnl_create_link(struct net *net,
	const char *ifname, unsigned char name_assign_type,
	const struct rtnl_link_ops *ops, struct nlattr *tb[])
{
	int err;
	struct net_device *dev;
	unsigned int num_tx_queues = 1;
	unsigned int num_rx_queues = 1;

	if (tb[IFLA_NUM_TX_QUEUES])
		num_tx_queues = nla_get_u32(tb[IFLA_NUM_TX_QUEUES]);
	else if (ops->get_num_tx_queues)
		num_tx_queues = ops->get_num_tx_queues();

	if (tb[IFLA_NUM_RX_QUEUES])
		num_rx_queues = nla_get_u32(tb[IFLA_NUM_RX_QUEUES]);
	else if (ops->get_num_rx_queues)
		num_rx_queues = ops->get_num_rx_queues();

	err = -ENOMEM;
	//priv_size的值为虚拟网卡对象的大小，并初始化收发包队列
	dev = alloc_netdev_mqs(ops->priv_size, ifname, name_assign_type,		
			       ops->setup, num_tx_queues, num_rx_queues);		
	if (!dev)
		goto err;

	dev_net_set(dev, net);    //设置网络空间
	dev->rtnl_link_ops = ops;	//设置rtnl_link_ops对象
	dev->rtnl_link_state = RTNL_LINK_INITIALIZING;

	if (tb[IFLA_MTU])
		dev->mtu = nla_get_u32(tb[IFLA_MTU]);
	if (tb[IFLA_ADDRESS]) {
		memcpy(dev->dev_addr, nla_data(tb[IFLA_ADDRESS]),
				nla_len(tb[IFLA_ADDRESS]));
		dev->addr_assign_type = NET_ADDR_SET;
	}
	if (tb[IFLA_BROADCAST])
		memcpy(dev->broadcast, nla_data(tb[IFLA_BROADCAST]),
				nla_len(tb[IFLA_BROADCAST]));
	if (tb[IFLA_TXQLEN])
		dev->tx_queue_len = nla_get_u32(tb[IFLA_TXQLEN]);
	if (tb[IFLA_OPERSTATE])
		set_operstate(dev, nla_get_u8(tb[IFLA_OPERSTATE]));
	if (tb[IFLA_LINKMODE])
		dev->link_mode = nla_get_u8(tb[IFLA_LINKMODE]);
	if (tb[IFLA_GROUP])
		dev_set_group(dev, nla_get_u32(tb[IFLA_GROUP]));

	return dev;

err:
	return ERR_PTR(err);
}

struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
		unsigned char name_assign_type,
		void (*setup)(struct net_device *),
		unsigned int txqs, unsigned int rxqs)
{
	struct net_device *dev;
	size_t alloc_size;
	struct net_device *p;

	BUG_ON(strlen(name) >= sizeof(dev->name));

	if (txqs < 1) {
		pr_err("alloc_netdev: Unable to allocate device with zero queues\n");
		return NULL;
	}

#ifdef CONFIG_SYSFS
	if (rxqs < 1) {
		pr_err("alloc_netdev: Unable to allocate device with zero RX queues\n");
		return NULL;
	}
#endif

	alloc_size = sizeof(struct net_device);
	if (sizeof_priv) {
		/* ensure 32-byte alignment of private area */
		alloc_size = ALIGN(alloc_size, NETDEV_ALIGN);
		alloc_size += sizeof_priv;
	}
	/* ensure 32-byte alignment of whole construct */
	alloc_size += NETDEV_ALIGN - 1;

	//创建net_device对象，包含私有数据
	p = kzalloc(alloc_size, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);	
	if (!p)
		p = vzalloc(alloc_size);
	if (!p)
		return NULL;

	dev = PTR_ALIGN(p, NETDEV_ALIGN);
	dev->padded = (char *)dev - (char *)p;

	dev->pcpu_refcnt = alloc_percpu(int);
	if (!dev->pcpu_refcnt)
		goto free_dev;

	if (dev_addr_init(dev))
		goto free_pcpu;

	dev_mc_init(dev);
	dev_uc_init(dev);

	dev_net_set(dev, &init_net);

	dev->gso_max_size = GSO_MAX_SIZE;
	dev->gso_max_segs = GSO_MAX_SEGS;
	dev->gso_min_segs = 0;

	INIT_LIST_HEAD(&dev->napi_list);
	INIT_LIST_HEAD(&dev->unreg_list);
	INIT_LIST_HEAD(&dev->close_list);
	INIT_LIST_HEAD(&dev->link_watch_list);
	INIT_LIST_HEAD(&dev->adj_list.upper);
	INIT_LIST_HEAD(&dev->adj_list.lower);
	INIT_LIST_HEAD(&dev->all_adj_list.upper);
	INIT_LIST_HEAD(&dev->all_adj_list.lower);
	INIT_LIST_HEAD(&dev->ptype_all);
	INIT_LIST_HEAD(&dev->ptype_specific);
	dev->priv_flags = IFF_XMIT_DST_RELEASE | IFF_XMIT_DST_RELEASE_PERM;
	setup(dev);		//调用rtnl_link_ops对象的setup函数

	dev->num_tx_queues = txqs;
	dev->real_num_tx_queues = txqs;
	if (netif_alloc_netdev_queues(dev))
		goto free_all;

#ifdef CONFIG_SYSFS
	dev->num_rx_queues = rxqs;
	dev->real_num_rx_queues = rxqs;
	if (netif_alloc_rx_queues(dev))
		goto free_all;
#endif

	strcpy(dev->name, name);
	dev->name_assign_type = name_assign_type;
	dev->group = INIT_NETDEV_GROUP;
	if (!dev->ethtool_ops)
		dev->ethtool_ops = &default_ethtool_ops;
	return dev;

free_all:
	free_netdev(dev);
	return NULL;

free_pcpu:
	free_percpu(dev->pcpu_refcnt);
free_dev:
	netdev_freemem(dev);
	return NULL;
}

int rtnl_configure_link(struct net_device *dev, const struct ifinfomsg *ifm)
{
	unsigned int old_flags;
	int err;

	old_flags = dev->flags;
	if (ifm && (ifm->ifi_flags || ifm->ifi_change)) {
		err = __dev_change_flags(dev, rtnl_dev_combine_flags(dev, ifm));  //修改状态
		if (err < 0)
			return err;
	}

	dev->rtnl_link_state = RTNL_LINK_INITIALIZED;

	__dev_notify_flags(dev, old_flags, ~0U);
	return 0;
}

int __dev_change_flags(struct net_device *dev, unsigned int flags)
{
	unsigned int old_flags = dev->flags;
	int ret;

	ASSERT_RTNL();

	/*
	 *	Set the flags on our device.
	 */

	dev->flags = (flags & (IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
			       IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL |
			       IFF_AUTOMEDIA)) |
		     (dev->flags & (IFF_UP | IFF_VOLATILE | IFF_PROMISC |
				    IFF_ALLMULTI));

	/*
	 *	Load in the correct multicast list now the flags have changed.
	 */

	if ((old_flags ^ flags) & IFF_MULTICAST)
		dev_change_rx_flags(dev, IFF_MULTICAST);

	dev_set_rx_mode(dev);

	/*
	 *	Have we downed the interface. We handle IFF_UP ourselves
	 *	according to user attempts to set it, rather than blindly
	 *	setting it.
	 */

	ret = 0;
	if ((old_flags ^ flags) & IFF_UP)
		ret = ((old_flags & IFF_UP) ? __dev_close : __dev_open)(dev);

	if ((flags ^ dev->gflags) & IFF_PROMISC) {
		int inc = (flags & IFF_PROMISC) ? 1 : -1;
		unsigned int old_flags = dev->flags;

		dev->gflags ^= IFF_PROMISC;

		if (__dev_set_promiscuity(dev, inc, false) >= 0)
			if (dev->flags != old_flags)
				dev_set_rx_mode(dev);
	}

	/* NOTE: order of synchronization of IFF_PROMISC and IFF_ALLMULTI
	   is important. Some (broken) drivers set IFF_PROMISC, when
	   IFF_ALLMULTI is requested not asking us and not reporting.
	 */
	if ((flags ^ dev->gflags) & IFF_ALLMULTI) {
		int inc = (flags & IFF_ALLMULTI) ? 1 : -1;

		dev->gflags ^= IFF_ALLMULTI;
		__dev_set_allmulti(dev, inc, false);
	}

	return ret;
}

static int __dev_open(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int ret;

	ASSERT_RTNL();

	if (!netif_device_present(dev))
		return -ENODEV;

	/* Block netpoll from trying to do any rx path servicing.
	 * If we don't do this there is a chance ndo_poll_controller
	 * or ndo_poll may be running while we open the device
	 */
	netpoll_poll_disable(dev);

	ret = call_netdevice_notifiers(NETDEV_PRE_UP, dev);
	ret = notifier_to_errno(ret);
	if (ret)
		return ret;

	set_bit(__LINK_STATE_START, &dev->state);

	if (ops->ndo_validate_addr)
		ret = ops->ndo_validate_addr(dev);

	if (!ret && ops->ndo_open)
		ret = ops->ndo_open(dev);   //调用驱动的open函数

	netpoll_poll_enable(dev);

	if (ret)
		clear_bit(__LINK_STATE_START, &dev->state);
	else {
		dev->flags |= IFF_UP;
		dev_set_rx_mode(dev);
		dev_activate(dev);
		add_device_randomness(dev->dev_addr, dev->addr_len);
	}

	return ret;
}
```

## 创建虚拟网卡流程总结

虚拟网卡创建过程中，涉及到link接口和驱动接口调用的流程如下：

* rtnl_newlink（创建入口）
	1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）
	2. m_ops->slave_changelink（修改父设备link信息，根据需要）
	3. 如果设备已存在，调用do_setlink（修改设备），并返回
    4. rtnl_group_changelink
    5. rtnl_create_link（创建net_device设备，实际是虚拟设备对象）
		1. alloc_netdev_mqs（分配队列）
			  1. rtnl_link_ops->setup（设备初始化，默认初始化）
	6. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
		1. register_netdevice（内核注册设备）
		2. dev->netdev_ops->ndo_init（设备初始化）
	7. rtnl_configure_link
		1. __dev_change_flags(dev,flags)
			1. __dev_open(dev)
				1. dev->netdev_ops->ndo_validate_addr（设备地址校验）
				2. dev->netdev_ops->ndo_open（打开设备）

