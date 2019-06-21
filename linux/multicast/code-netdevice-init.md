# 简介

本文介绍支持组播报文的网卡初始化过程。


# in_device初始化

```c
static struct in_device *inetdev_init(struct net_device *dev)
{
	struct in_device *in_dev;
	int err = -ENOMEM;

	ASSERT_RTNL();

	in_dev = kzalloc(sizeof(*in_dev), GFP_KERNEL);
	if (!in_dev)
		goto out;
	memcpy(&in_dev->cnf, dev_net(dev)->ipv4.devconf_dflt,
			sizeof(in_dev->cnf));
	in_dev->cnf.sysctl = NULL;
	in_dev->dev = dev;
	in_dev->arp_parms = neigh_parms_alloc(dev, &arp_tbl);
	if (!in_dev->arp_parms)
		goto out_kfree;
	if (IPV4_DEVCONF(in_dev->cnf, FORWARDING))
		dev_disable_lro(dev);
	/* Reference in_dev->dev */
	dev_hold(dev);
	/* Account for reference dev->ip_ptr (below) */
	in_dev_hold(in_dev);

	err = devinet_sysctl_register(in_dev);
	if (err) {
		in_dev->dead = 1;
		in_dev_put(in_dev);
		in_dev = NULL;
		goto out;
	}
	ip_mc_init_dev(in_dev);   //初始化定时器
	if (dev->flags & IFF_UP)
		ip_mc_up(in_dev);

	/* we can receive as soon as ip_ptr is set -- do this last */
	rcu_assign_pointer(dev->ip_ptr, in_dev);
out:
	return in_dev ?: ERR_PTR(err);
out_kfree:
	kfree(in_dev);
	in_dev = NULL;
	goto out;
}
```


## ip_mc_init_dev

```c
void ip_mc_init_dev(struct in_device *in_dev)
{
	ASSERT_RTNL();

#ifdef CONFIG_IP_MULTICAST
	setup_timer(&in_dev->mr_gq_timer, igmp_gq_timer_expire,
			(unsigned long)in_dev);
	setup_timer(&in_dev->mr_ifc_timer, igmp_ifc_timer_expire,
			(unsigned long)in_dev);
	in_dev->mr_qrv = sysctl_igmp_qrv;
#endif

	spin_lock_init(&in_dev->mc_tomb_lock);
}
```


## ip_mc_up

```c
void ip_mc_up(struct in_device *in_dev)
{
	struct ip_mc_list *pmc;

	ASSERT_RTNL();

#ifdef CONFIG_IP_MULTICAST
	in_dev->mr_qrv = sysctl_igmp_qrv;
#endif
	ip_mc_inc_group(in_dev, IGMP_ALL_HOSTS);   // 自动加入224.0.0.1组播组

	for_each_pmc_rtnl(in_dev, pmc)
		igmp_group_added(pmc);
}
```


# ip_mc_inc_group

```c
void ip_mc_inc_group(struct in_device *in_dev, __be32 addr)
{
	struct ip_mc_list *im;

	ASSERT_RTNL();

	for_each_pmc_rtnl(in_dev, im) {
		if (im->multiaddr == addr) {   //该组播组已经加入
			im->users++;   //用户加一
			ip_mc_add_src(in_dev, &addr, MCAST_EXCLUDE, 0, NULL, 0);
			goto out;
		}
	}

	im = kzalloc(sizeof(*im), GFP_KERNEL);    //新建ip_mc_list对象
	if (!im)
		goto out;

	im->users = 1;
	im->interface = in_dev;
	in_dev_hold(in_dev);
	im->multiaddr = addr;
	/* initial mode is (EX, empty) */
	im->sfmode = MCAST_EXCLUDE;
	im->sfcount[MCAST_EXCLUDE] = 1;
	atomic_set(&im->refcnt, 1);
	spin_lock_init(&im->lock);
#ifdef CONFIG_IP_MULTICAST
	setup_timer(&im->timer, igmp_timer_expire, (unsigned long)im);    //启动定时器
	im->unsolicit_count = sysctl_igmp_qrv;
#endif

	im->next_rcu = in_dev->mc_list;   //把新建的ip_mc_list对象插到最前面
	in_dev->mc_count++;
	rcu_assign_pointer(in_dev->mc_list, im);

	ip_mc_hash_add(in_dev, im);   //im添加到hash桶中

#ifdef CONFIG_IP_MULTICAST
	igmpv3_del_delrec(in_dev, im->multiaddr);
#endif
	igmp_group_added(im);    //添加新组播组
	if (!in_dev->dead)
		ip_rt_multicast_event(in_dev);
out:
	return;
}
EXPORT_SYMBOL(ip_mc_inc_group);
```


## ip_mc_hash_add

```c
static void ip_mc_hash_add(struct in_device *in_dev,
			   struct ip_mc_list *im)
{
	struct ip_mc_list __rcu **mc_hash;
	u32 hash;

	mc_hash = rtnl_dereference(in_dev->mc_hash);
	if (mc_hash) {
		hash = ip_mc_hash(im);   //计算hash值
		im->next_hash = mc_hash[hash]; //构建成链表
		rcu_assign_pointer(mc_hash[hash], im);  //im添加到hash桶中
		return;
	}

	/* do not use a hash table for small number of items */
	if (in_dev->mc_count < 4)
		return;

	mc_hash = kzalloc(sizeof(struct ip_mc_list *) << MC_HASH_SZ_LOG,
			  GFP_KERNEL);
	if (!mc_hash)   //
		return;

	for_each_pmc_rtnl(in_dev, im) {
		hash = ip_mc_hash(im);
		im->next_hash = mc_hash[hash];
		RCU_INIT_POINTER(mc_hash[hash], im);
	}

	rcu_assign_pointer(in_dev->mc_hash, mc_hash);
}
```
	
	
## igmp_group_added

```c
static void igmp_group_added(struct ip_mc_list *im)
{
	struct in_device *in_dev = im->interface;

	if (im->loaded == 0) {
		im->loaded = 1;
		ip_mc_filter_add(in_dev, im->multiaddr);  //设备添加filter
	}

#ifdef CONFIG_IP_MULTICAST
	if (im->multiaddr == IGMP_ALL_HOSTS)  //如果是224.0.0.1不需要发送igmp report报文
		return;

	if (in_dev->dead)
		return;
	if (IGMP_V1_SEEN(in_dev) || IGMP_V2_SEEN(in_dev)) {
		spin_lock_bh(&im->lock);
		igmp_start_timer(im, IGMP_INITIAL_REPORT_DELAY);   //发送igmp report报文
		spin_unlock_bh(&im->lock);
		return;
	}
	/* else, v3 */

	im->crcount = in_dev->mr_qrv ?: sysctl_igmp_qrv;
	igmp_ifc_event(in_dev);
#endif
}
```


## ip_mc_filter_add

```c
static void ip_mc_filter_add(struct in_device *in_dev, __be32 addr)
{
	char buf[MAX_ADDR_LEN];
	struct net_device *dev = in_dev->dev;

	/* Checking for IFF_MULTICAST here is WRONG-WRONG-WRONG.
	   We will get multicast token leakage, when IFF_MULTICAST
	   is changed. This check should be done in ndo_set_rx_mode
	   routine. Something sort of:
	   if (dev->mc_list && dev->flags&IFF_MULTICAST) { do it; }
	   --ANK
	   */
	if (arp_mc_map(addr, buf, dev, 0) == 0)    //组播IP地址映射到MAC地址
		dev_mc_add(dev, buf);   //设备添加mac地址
}

int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);   //以太网协议走此分支，IP地址的低23位映射到MAC地址
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, dev->broadcast, haddr);
		return 0;
	case ARPHRD_IPGRE:
		ip_ipgre_mc_map(addr, dev->broadcast, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}

static inline void ip_eth_mc_map(__be32 naddr, char *buf)
{
	__u32 addr=ntohl(naddr);
	buf[0]=0x01;
	buf[1]=0x00;
	buf[2]=0x5e;
	buf[5]=addr&0xFF;
	addr>>=8;
	buf[4]=addr&0xFF;
	addr>>=8;
	buf[3]=addr&0x7F;
}
```


## dev_mc_add

```c
int dev_mc_add(struct net_device *dev, const unsigned char *addr)
{
	return __dev_mc_add(dev, addr, false);
}

static int __dev_mc_add(struct net_device *dev, const unsigned char *addr,
			bool global)
{
	int err;

	netif_addr_lock_bh(dev);
	err = __hw_addr_add_ex(&dev->mc, addr, dev->addr_len,
			       NETDEV_HW_ADDR_T_MULTICAST, global, false, 0);
	if (!err)
		__dev_set_rx_mode(dev);
	netif_addr_unlock_bh(dev);
	return err;
}
```




