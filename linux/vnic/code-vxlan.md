# VXLAN

VXLAN是当前VPC隧道网络的主流方案，本文分析linux vxlan设备的创建以及收发包流程。


## 数据结构

```c
static struct rtnl_link_ops vxlan_link_ops __read_mostly = {
	.kind		= "vxlan",
	.maxtype	= IFLA_VXLAN_MAX,
	.policy		= vxlan_policy,
	.priv_size	= sizeof(struct vxlan_dev),
	.setup		= vxlan_setup,
	.validate	= vxlan_validate,
	.newlink	= vxlan_newlink,
	.dellink	= vxlan_dellink,
	.get_size	= vxlan_get_size,
	.fill_info	= vxlan_fill_info,
	.get_link_net	= vxlan_get_link_net,
};

//设备驱动
static const struct net_device_ops vxlan_netdev_ops = {
	.ndo_init		= vxlan_init,
	.ndo_uninit		= vxlan_uninit,
	.ndo_open		= vxlan_open,
	.ndo_stop		= vxlan_stop,
	.ndo_start_xmit		= vxlan_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_set_rx_mode	= vxlan_set_multicast_list,
	.ndo_change_mtu		= vxlan_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_fdb_add		= vxlan_fdb_add,
	.ndo_fdb_del		= vxlan_fdb_delete,
	.ndo_fdb_dump		= vxlan_fdb_dump,
};
```

## 模块初始化

```c
static int __init vxlan_init_module(void)
{
	int rc;

	vxlan_wq = alloc_workqueue("vxlan", 0, 0);
	if (!vxlan_wq)
		return -ENOMEM;

	get_random_bytes(&vxlan_salt, sizeof(vxlan_salt));   //得到随机盐值

	rc = register_pernet_subsys(&vxlan_net_ops);   //注册net namespace操作
	if (rc)
		goto out1;

	rc = register_netdevice_notifier(&vxlan_notifier_block);  //注册设备注册回调函数
	if (rc)
		goto out2;

	rc = rtnl_link_register(&vxlan_link_ops);   //注册link ops
	if (rc)
		goto out3;

	return 0;
out3:
	unregister_netdevice_notifier(&vxlan_notifier_block);
out2:
	unregister_pernet_subsys(&vxlan_net_ops);
out1:
	destroy_workqueue(vxlan_wq);
	return rc;
}
```


## vxlan设备创建

macvlan设备的创建入口为rtnl_newlink函数（虚拟网卡创建入口），根据调用顺序来分析各个函数：

1. rtnl_link_ops->validate（根据type找到rtnl_link_ops，校验输入参数）
2. rtnl_link_ops->setup（设备初始化，默认初始化）
3. rtnl_link_ops->newlink（创建设备，一般会有如下两个操作）
4. dev->netdev_ops->ndo_init（设备初始化）
5. dev->netdev_ops->ndo_validate_addr（设备地址校验）
6. dev->netdev_ops->ndo_open（打开设备）


### validate(vxlan_validate)

```c
static int vxlan_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {  //检验mac地址
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			pr_debug("invalid link address (not ethernet)\n");
			return -EINVAL;
		}

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {   
			pr_debug("invalid all zero ethernet address\n");
			return -EADDRNOTAVAIL;
		}
	}

	if (!data)
		return -EINVAL;

	if (data[IFLA_VXLAN_ID]) {   //校验vxlan id
		__u32 id = nla_get_u32(data[IFLA_VXLAN_ID]);
		if (id >= VXLAN_VID_MASK)
			return -ERANGE;
	}

	if (data[IFLA_VXLAN_PORT_RANGE]) {   //校验端口范围
		const struct ifla_vxlan_port_range *p
			= nla_data(data[IFLA_VXLAN_PORT_RANGE]);

		if (ntohs(p->high) < ntohs(p->low)) {
			pr_debug("port range %u .. %u not valid\n",
				 ntohs(p->low), ntohs(p->high));
			return -EINVAL;
		}
	}

	return 0;
}
```


### setup(vxlan_setup)

```c
static void vxlan_setup(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	unsigned int h;

	eth_hw_addr_random(dev);  //mac地址随机生成
	ether_setup(dev);         //通用以太网设备属性设置
	if (vxlan->default_dst.remote_ip.sa.sa_family == AF_INET6)
		dev->needed_headroom = ETH_HLEN + VXLAN6_HEADROOM;
	else
		dev->needed_headroom = ETH_HLEN + VXLAN_HEADROOM;   // 14 + 50（VXLAN外层头）

	dev->netdev_ops = &vxlan_netdev_ops;     //设置驱动
	dev->destructor = free_netdev;
	SET_NETDEV_DEVTYPE(dev, &vxlan_type);   //设置设备类型

	dev->tx_queue_len = 0;
	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features   |= NETIF_F_RXCSUM;
	dev->features   |= NETIF_F_GSO_SOFTWARE;

	dev->vlan_features = dev->features;
	dev->features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
	dev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX;
	netif_keep_dst(dev);
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	INIT_LIST_HEAD(&vxlan->next);
	spin_lock_init(&vxlan->hash_lock);

	init_timer_deferrable(&vxlan->age_timer);
	vxlan->age_timer.function = vxlan_cleanup;
	vxlan->age_timer.data = (unsigned long) vxlan;

	vxlan->dst_port = htons(vxlan_port);	//默认目标端口为8472

	vxlan->dev = dev;

	for (h = 0; h < FDB_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vxlan->fdb_head[h]);   //初始化fdb桶
}
```

### newlink(vxlan_newlink)

```c
static int vxlan_newlink(struct net *src_net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
{
	struct vxlan_net *vn = net_generic(src_net, vxlan_net_id);
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_rdst *dst = &vxlan->default_dst;
	__u32 vni;
	int err;
	bool use_ipv6 = false;

	if (!data[IFLA_VXLAN_ID])
		return -EINVAL;

	vxlan->net = src_net;

	vni = nla_get_u32(data[IFLA_VXLAN_ID]);
	dst->remote_vni = vni;	//设置VNI值

	/* Unless IPv6 is explicitly requested, assume IPv4 */
	dst->remote_ip.sa.sa_family = AF_INET;
	if (data[IFLA_VXLAN_GROUP]) {
		dst->remote_ip.sin.sin_addr.s_addr = nla_get_in_addr(data[IFLA_VXLAN_GROUP]);	//对端IP地址
	} else if (data[IFLA_VXLAN_GROUP6]) {
		if (!IS_ENABLED(CONFIG_IPV6))
			return -EPFNOSUPPORT;

		dst->remote_ip.sin6.sin6_addr = nla_get_in6_addr(data[IFLA_VXLAN_GROUP6]);
		dst->remote_ip.sa.sa_family = AF_INET6;
		use_ipv6 = true;
	}

	if (data[IFLA_VXLAN_LOCAL]) {
		vxlan->saddr.sin.sin_addr.s_addr = nla_get_in_addr(data[IFLA_VXLAN_LOCAL]);	 //本地IP地址
		vxlan->saddr.sa.sa_family = AF_INET;
	} else if (data[IFLA_VXLAN_LOCAL6]) {
		if (!IS_ENABLED(CONFIG_IPV6))
			return -EPFNOSUPPORT;

		/* TODO: respect scope id */
		vxlan->saddr.sin6.sin6_addr = nla_get_in6_addr(data[IFLA_VXLAN_LOCAL6]);
		vxlan->saddr.sa.sa_family = AF_INET6;
		use_ipv6 = true;
	}

	if (data[IFLA_VXLAN_LINK] &&
	    (dst->remote_ifindex = nla_get_u32(data[IFLA_VXLAN_LINK]))) {   //检查底层设备存在
		struct net_device *lowerdev
			 = __dev_get_by_index(src_net, dst->remote_ifindex);

		if (!lowerdev) {
			pr_info("ifindex %d does not exist\n", dst->remote_ifindex);
			return -ENODEV;
		}

#if IS_ENABLED(CONFIG_IPV6)
		if (use_ipv6) {
			struct inet6_dev *idev = __in6_dev_get(lowerdev);
			if (idev && idev->cnf.disable_ipv6) {
				pr_info("IPv6 is disabled via sysctl\n");
				return -EPERM;
			}
			vxlan->flags |= VXLAN_F_IPV6;
		}
#endif

		if (!tb[IFLA_MTU])   //设置mtu
			dev->mtu = lowerdev->mtu - (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);

		dev->needed_headroom = lowerdev->hard_header_len +
				       (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);  //更新needed_headroom值
	} else if (use_ipv6)
		vxlan->flags |= VXLAN_F_IPV6;

	if (data[IFLA_VXLAN_TOS])
		vxlan->tos  = nla_get_u8(data[IFLA_VXLAN_TOS]);

	if (data[IFLA_VXLAN_TTL])
		vxlan->ttl = nla_get_u8(data[IFLA_VXLAN_TTL]);

	if (!data[IFLA_VXLAN_LEARNING] || nla_get_u8(data[IFLA_VXLAN_LEARNING]))  // 设置learning属性
		vxlan->flags |= VXLAN_F_LEARN;

	if (data[IFLA_VXLAN_AGEING])
		vxlan->age_interval = nla_get_u32(data[IFLA_VXLAN_AGEING]);
	else
		vxlan->age_interval = FDB_AGE_DEFAULT;

	if (data[IFLA_VXLAN_PROXY] && nla_get_u8(data[IFLA_VXLAN_PROXY]))   // 设置arp proxy属性
		vxlan->flags |= VXLAN_F_PROXY;

	if (data[IFLA_VXLAN_RSC] && nla_get_u8(data[IFLA_VXLAN_RSC]))
		vxlan->flags |= VXLAN_F_RSC;

	if (data[IFLA_VXLAN_L2MISS] && nla_get_u8(data[IFLA_VXLAN_L2MISS]))
		vxlan->flags |= VXLAN_F_L2MISS;

	if (data[IFLA_VXLAN_L3MISS] && nla_get_u8(data[IFLA_VXLAN_L3MISS]))
		vxlan->flags |= VXLAN_F_L3MISS;

	if (data[IFLA_VXLAN_LIMIT])
		vxlan->addrmax = nla_get_u32(data[IFLA_VXLAN_LIMIT]);

	if (data[IFLA_VXLAN_PORT_RANGE]) {
		const struct ifla_vxlan_port_range *p
			= nla_data(data[IFLA_VXLAN_PORT_RANGE]);
		vxlan->port_min = ntohs(p->low);
		vxlan->port_max = ntohs(p->high);
	}

	if (data[IFLA_VXLAN_PORT])
		vxlan->dst_port = nla_get_be16(data[IFLA_VXLAN_PORT]);   //设置目标端口

	if (data[IFLA_VXLAN_UDP_CSUM] && nla_get_u8(data[IFLA_VXLAN_UDP_CSUM]))
		vxlan->flags |= VXLAN_F_UDP_CSUM;

	if (data[IFLA_VXLAN_UDP_ZERO_CSUM6_TX] &&
	    nla_get_u8(data[IFLA_VXLAN_UDP_ZERO_CSUM6_TX]))
		vxlan->flags |= VXLAN_F_UDP_ZERO_CSUM6_TX;

	if (data[IFLA_VXLAN_UDP_ZERO_CSUM6_RX] &&
	    nla_get_u8(data[IFLA_VXLAN_UDP_ZERO_CSUM6_RX]))
		vxlan->flags |= VXLAN_F_UDP_ZERO_CSUM6_RX;

	if (data[IFLA_VXLAN_REMCSUM_TX] &&
	    nla_get_u8(data[IFLA_VXLAN_REMCSUM_TX]))
		vxlan->flags |= VXLAN_F_REMCSUM_TX;

	if (data[IFLA_VXLAN_REMCSUM_RX] &&
	    nla_get_u8(data[IFLA_VXLAN_REMCSUM_RX]))
		vxlan->flags |= VXLAN_F_REMCSUM_RX;

	if (data[IFLA_VXLAN_GBP])
		vxlan->flags |= VXLAN_F_GBP;

	if (data[IFLA_VXLAN_REMCSUM_NOPARTIAL])
		vxlan->flags |= VXLAN_F_REMCSUM_NOPARTIAL;

	if (vxlan_find_vni(src_net, vni, use_ipv6 ? AF_INET6 : AF_INET,
			   vxlan->dst_port, vxlan->flags)) {
		pr_info("duplicate VNI %u\n", vni);
		return -EEXIST;
	}

	dev->ethtool_ops = &vxlan_ethtool_ops;

	/* create an fdb entry for a valid default destination */
	if (!vxlan_addr_any(&vxlan->default_dst.remote_ip)) {   // 默认对端IP不为0，添加全零mac地址的fdb表项
		err = vxlan_fdb_create(vxlan, all_zeros_mac,        // 表示如果没有匹配mac时，可以发送到默认对端
				       &vxlan->default_dst.remote_ip,
				       NUD_REACHABLE|NUD_PERMANENT,
				       NLM_F_EXCL|NLM_F_CREATE,
				       vxlan->dst_port,                     //如果没设置目的端口，则使用8472
				       vxlan->default_dst.remote_vni,       //创建vxlan时设置的vni值
				       vxlan->default_dst.remote_ifindex,   //创建vxlan时的底层设备
				       NTF_SELF);
		if (err)
			return err;
	}

	err = register_netdevice(dev);   //注册设备，vxlan模块初始化时注册了回调函数，实际调用vxlan_lowerdev_event
	if (err) {
		vxlan_fdb_delete_default(vxlan);
		return err;
	}

	list_add(&vxlan->next, &vn->vxlan_list);	//添加到vxlan列表中

	return 0;
}

static int vxlan_lowerdev_event(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct vxlan_net *vn = net_generic(dev_net(dev), vxlan_net_id);

	if (event == NETDEV_UNREGISTER)
		vxlan_handle_lowerdev_unregister(vn, dev);

	return NOTIFY_DONE;
}
```


### ndo_init(vxlan_init)

```c
static int vxlan_init(struct net_device *dev)
{
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);  //初始化统计
	if (!dev->tstats)
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
static int vxlan_open(struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_sock *vs;
	int ret = 0;

	vs = vxlan_sock_add(vxlan->net, vxlan->dst_port, vxlan_rcv, NULL,
			    false, vxlan->flags);   //添加vxlan_sock如果不存在
	if (IS_ERR(vs))
		return PTR_ERR(vs);

	vxlan_vs_add_dev(vs, vxlan);   //把vxlan设备添加到vxlan_sock

	//如果已经创建socket，则不重复创建
	if (vxlan_addr_multicast(&vxlan->default_dst.remote_ip)) {     
		ret = vxlan_igmp_join(vxlan);
		if (ret == -EADDRINUSE)
			ret = 0;
		if (ret) {
			vxlan_sock_release(vs);
			return ret;
		}
	}

	if (vxlan->age_interval)
		mod_timer(&vxlan->age_timer, jiffies + FDB_AGE_INTERVAL);

	return ret;
}

struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
				  vxlan_rcv_t *rcv, void *data,
				  bool no_share, u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	bool ipv6 = flags & VXLAN_F_IPV6;

	if (!no_share) {   //默认是可共享vxlan_sock的
		spin_lock(&vn->sock_lock);
		vs = vxlan_find_sock(net, ipv6 ? AF_INET6 : AF_INET, port,
				     flags);   //根据源端口和flags查找vxlan_sock
		if (vs && vs->rcv == rcv) {
			if (!atomic_add_unless(&vs->refcnt, 1, 0))
				vs = ERR_PTR(-EBUSY);
			spin_unlock(&vn->sock_lock);
			return vs;
		}
		spin_unlock(&vn->sock_lock);
	}

	return vxlan_socket_create(net, port, rcv, data, flags);  //创建vxlan_sock
}

static struct vxlan_sock *vxlan_socket_create(struct net *net, __be16 port,
					      vxlan_rcv_t *rcv, void *data,
					      u32 flags)
{
	struct vxlan_net *vn = net_generic(net, vxlan_net_id);
	struct vxlan_sock *vs;
	struct socket *sock;
	unsigned int h;
	bool ipv6 = !!(flags & VXLAN_F_IPV6);
	struct udp_tunnel_sock_cfg tunnel_cfg;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL);   //申请vxlan_sock对象
	if (!vs)
		return ERR_PTR(-ENOMEM);

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vs->vni_list[h]);   //初始化vni链表

	INIT_WORK(&vs->del_work, vxlan_del_work);

	sock = vxlan_create_sock(net, ipv6, port, flags);  //创建内核UDP socket，并完成bind
	if (IS_ERR(sock)) {
		pr_info("Cannot bind port %d, err=%ld\n", ntohs(port),
			PTR_ERR(sock));
		kfree(vs);
		return ERR_CAST(sock);
	}

	vs->sock = sock;
	atomic_set(&vs->refcnt, 1);
	vs->rcv = rcv;
	vs->data = data;
	vs->flags = (flags & VXLAN_F_RCV_FLAGS);

	/* Initialize the vxlan udp offloads structure */
	vs->udp_offloads.port = port;
	vs->udp_offloads.callbacks.gro_receive  = vxlan_gro_receive;
	vs->udp_offloads.callbacks.gro_complete = vxlan_gro_complete;

	spin_lock(&vn->sock_lock);
	hlist_add_head_rcu(&vs->hlist, vs_head(net, port));   //添加到链表中
	vxlan_notify_add_rx_port(vs);
	spin_unlock(&vn->sock_lock);

	/* Mark socket as an encapsulation socket. */
	tunnel_cfg.sk_user_data = vs;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = vxlan_udp_encap_recv;   //udp收包流程中，会调用到此函数，进入到vxlan处理流程
	tunnel_cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(net, sock, &tunnel_cfg);	//设置到udp_sock对象中

	return vs;
}

void setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			   struct udp_tunnel_sock_cfg *cfg)
{
	struct sock *sk = sock->sk;

	/* Disable multicast loopback */
	inet_sk(sk)->mc_loop = 0;

	/* Enable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
	inet_inc_convert_csum(sk);

	rcu_assign_sk_user_data(sk, cfg->sk_user_data);   //user data为 vxlan_sock对象

	udp_sk(sk)->encap_type = cfg->encap_type;
	udp_sk(sk)->encap_rcv = cfg->encap_rcv;    //udp收包流程中，会调用到此函数，进入到vxlan处理流程
	udp_sk(sk)->encap_destroy = cfg->encap_destroy;

	udp_tunnel_encap_enable(sock);   //使能udp sock的encap配置
}
```

## vxlan底层设备收包处理

```c
static int vxlan_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct vxlan_sock *vs;
	struct vxlanhdr *vxh;
	u32 flags, vni;
	struct vxlan_metadata md = {0};

	/* Need Vxlan and inner Ethernet header to be present */
	if (!pskb_may_pull(skb, VXLAN_HLEN))	//报文长度检测
		goto error;

	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);	//得到vxlan头指针，和UDP头长度相同，所以可以这么操作
	flags = ntohl(vxh->vx_flags);	
	vni = ntohl(vxh->vx_vni);

	if (flags & VXLAN_HF_VNI) {		//发送的vxlan报文，该flag必须置1
		flags &= ~VXLAN_HF_VNI;
	} else {
		/* VNI flag always required to be set */
		goto bad_flags;
	}

	if (iptunnel_pull_header(skb, VXLAN_HLEN, htons(ETH_P_TEB)))	//报文移动到内层报文
		goto drop;
	vxh = (struct vxlanhdr *)(udp_hdr(skb) + 1);

	vs = rcu_dereference_sk_user_data(sk);   //得到vxlan sock对象
	if (!vs)
		goto drop;

	if ((flags & VXLAN_HF_RCO) && (vs->flags & VXLAN_F_REMCSUM_RX)) {  //VXLAN_HF_RCO意味着发送端的vxlan设置了VXLAN_F_REMCSUM_TX标记
		vxh = vxlan_remcsum(skb, vxh, sizeof(struct vxlanhdr), vni,	//并且报文的ip_summed == CHECKSUM_PARTIAL
				    !!(vs->flags & VXLAN_F_REMCSUM_NOPARTIAL));	//remcsum检测，检测失败丢弃该报文
		if (!vxh)
			goto drop;

		flags &= ~VXLAN_HF_RCO;		//flags去掉VXLAN_HF_RCO标记
		vni &= VXLAN_VNI_MASK;		//vni去掉低8位内容，仅剩下vni ID
	}

	/* For backwards compatibility, only allow reserved fields to be
	 * used by VXLAN extensions if explicitly requested.
	 */
	if ((flags & VXLAN_HF_GBP) && (vs->flags & VXLAN_F_GBP)) {
		struct vxlanhdr_gbp *gbp;

		gbp = (struct vxlanhdr_gbp *)vxh;
		md.gbp = ntohs(gbp->policy_id);

		if (gbp->dont_learn)
			md.gbp |= VXLAN_GBP_DONT_LEARN;

		if (gbp->policy_applied)
			md.gbp |= VXLAN_GBP_POLICY_APPLIED;

		flags &= ~VXLAN_GBP_USED_BITS;
	}

	if (flags || vni & ~VXLAN_VNI_MASK) {	//flags没有其他标记，vni低8为0
		/* If there are any unprocessed flags remaining treat
		 * this as a malformed packet. This behavior diverges from
		 * VXLAN RFC (RFC7348) which stipulates that bits in reserved
		 * in reserved fields are to be ignored. The approach here
		 * maintains compatibility with previous stack code, and also
		 * is more robust and provides a little more security in
		 * adding extensions to VXLAN.
		 */

		goto bad_flags;
	}

	md.vni = vxh->vx_vni;
	vs->rcv(vs, skb, &md);	//内核定义了vxlan_rcv，如果OVS创建vxlan端口，encap_rcv函数也是用OVS定义的
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;

bad_flags:
	netdev_dbg(skb->dev, "invalid vxlan flags=%#x vni=%#x\n",
		   ntohl(vxh->vx_flags), ntohl(vxh->vx_vni));

error:
	/* Return non vxlan pkt */
	return 1;
}

static void vxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb,
		      struct vxlan_metadata *md)
{
	struct iphdr *oip = NULL;
	struct ipv6hdr *oip6 = NULL;
	struct vxlan_dev *vxlan;
	struct pcpu_sw_netstats *stats;
	union vxlan_addr saddr;
	__u32 vni;
	int err = 0;
	union vxlan_addr *remote_ip;

	vni = ntohl(md->vni) >> 8;
	/* Is this VNI defined? */
	vxlan = vxlan_vs_find_vni(vs, vni);	  //根据vni找到vxlan设备，支持多个vxlan设备
	if (!vxlan)
		goto drop;

	remote_ip = &vxlan->default_dst.remote_ip;
	skb_reset_mac_header(skb);	
	skb_scrub_packet(skb, !net_eq(vxlan->net, dev_net(vxlan->dev)));
	skb->protocol = eth_type_trans(skb, vxlan->dev);	//解析报文protocol，同时会设置skb的dev为vxlan设备，报文移动到IP头
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);	//csum计算，netif_receive_skb要求

	/* Ignore packet loops (and multicast echo) */
	if (ether_addr_equal(eth_hdr(skb)->h_source, vxlan->dev->dev_addr))	//报文源mac等于vxlan设备的mac，丢弃报文
		goto drop;

	/* Re-examine inner Ethernet packet */
	if (remote_ip->sa.sa_family == AF_INET) {
		oip = ip_hdr(skb);
		saddr.sin.sin_addr.s_addr = oip->saddr;
		saddr.sa.sa_family = AF_INET;
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		oip6 = ipv6_hdr(skb);
		saddr.sin6.sin6_addr = oip6->saddr;
		saddr.sa.sa_family = AF_INET6;
#endif
	}

	if ((vxlan->flags & VXLAN_F_LEARN) &&
	    vxlan_snoop(skb->dev, &saddr, eth_hdr(skb)->h_source))	//vxlan fdb表学习，记录mac和ip的对应关系
		goto drop;

	skb_reset_network_header(skb);
	skb->mark = md->gbp;

	if (oip6)
		err = IP6_ECN_decapsulate(oip6, skb);
	if (oip)
		err = IP_ECN_decapsulate(oip, skb);	//内外层tos检测

	if (unlikely(err)) {
		if (log_ecn_error) {
			if (oip6)
				net_info_ratelimited("non-ECT from %pI6\n",
						     &oip6->saddr);
			if (oip)
				net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
						     &oip->saddr, oip->tos);
		}
		if (err > 1) {
			++vxlan->dev->stats.rx_frame_errors;
			++vxlan->dev->stats.rx_errors;
			goto drop;
		}
	}

	stats = this_cpu_ptr(vxlan->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);	//交给协议栈处理，skb的dev为vxlan_dev

	return;
drop:
	/* Consume bad packet */
	kfree_skb(skb);
}
```


## vxlan发包处理

```c
static netdev_tx_t vxlan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct ethhdr *eth;
	bool did_rsc = false;
	struct vxlan_rdst *rdst, *fdst = NULL;
	struct vxlan_fdb *f;

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);

	if ((vxlan->flags & VXLAN_F_PROXY)) {
		if (ntohs(eth->h_proto) == ETH_P_ARP)
			return arp_reduce(dev, skb);
#if IS_ENABLED(CONFIG_IPV6)
		else if (ntohs(eth->h_proto) == ETH_P_IPV6 &&
			 pskb_may_pull(skb, sizeof(struct ipv6hdr)
				       + sizeof(struct nd_msg)) &&
			 ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
				struct nd_msg *msg;

				msg = (struct nd_msg *)skb_transport_header(skb);
				if (msg->icmph.icmp6_code == 0 &&
				    msg->icmph.icmp6_type == NDISC_NEIGHBOUR_SOLICITATION)
					return neigh_reduce(dev, skb);
		}
		eth = eth_hdr(skb);
#endif
	}

	f = vxlan_find_mac(vxlan, eth->h_dest);  //得到目的mac地址
	did_rsc = false;

	if (f && (f->flags & NTF_ROUTER) && (vxlan->flags & VXLAN_F_RSC) &&
	    (ntohs(eth->h_proto) == ETH_P_IP ||
	     ntohs(eth->h_proto) == ETH_P_IPV6)) {
		did_rsc = route_shortcircuit(dev, skb);
		if (did_rsc)
			f = vxlan_find_mac(vxlan, eth->h_dest);  //根据目的mac查找fdb表项
	}

	if (f == NULL) {
		f = vxlan_find_mac(vxlan, all_zeros_mac);  //查找全零mac地址的fdb表项
		if (f == NULL) {   //如果未找到，则无法发送
			if ((vxlan->flags & VXLAN_F_L2MISS) &&
			    !is_multicast_ether_addr(eth->h_dest))
				vxlan_fdb_miss(vxlan, eth->h_dest);	//内层MAC地址不可达，即不知道在哪个节点上

			dev->stats.tx_dropped++;
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}

	list_for_each_entry_rcu(rdst, &f->remotes, list) {  //根据fdb的目的地，发送报文
		struct sk_buff *skb1;

		if (!fdst) {
			fdst = rdst;
			continue;
		}
		skb1 = skb_clone(skb, GFP_ATOMIC);
		if (skb1)
		    //did_srce为true，说明该报文需要经过下一跳转发才能到达目的地
			vxlan_xmit_one(skb1, dev, rdst, did_rsc);	
	}

	if (fdst)
		vxlan_xmit_one(skb, dev, fdst, did_rsc);
	else
		kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void vxlan_xmit_one(struct sk_buff *skb, struct net_device *dev,
			   struct vxlan_rdst *rdst, bool did_rsc)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct sock *sk = vxlan->vn_sock->sock->sk;
	struct rtable *rt = NULL;
	const struct iphdr *old_iph;
	struct flowi4 fl4;
	union vxlan_addr *dst;
	struct vxlan_metadata md;
	__be16 src_port = 0, dst_port;
	u32 vni;
	__be16 df = 0;
	__u8 tos, ttl;
	int err;

	dst_port = rdst->remote_port ? rdst->remote_port : vxlan->dst_port;
	vni = rdst->remote_vni;   //创建vxlan设备时指定的vni值
	dst = &rdst->remote_ip;

	if (vxlan_addr_any(dst)) {		//目的IP地址为全零
		if (did_rsc) {
			/* short-circuited back to local bridge */
			vxlan_encap_bypass(skb, vxlan, vxlan);    //发送给本地
			return;
		}
		goto drop;
	}

	old_iph = ip_hdr(skb);

	ttl = vxlan->ttl;
	if (!ttl && vxlan_addr_multicast(dst))
		ttl = 1;

	tos = vxlan->tos;
	if (tos == 1)
		tos = ip_tunnel_get_dsfield(old_iph, skb);

	src_port = udp_flow_src_port(dev_net(dev), skb, vxlan->port_min,	//获取源端口
				     vxlan->port_max, true);

	if (dst->sa.sa_family == AF_INET) {
		memset(&fl4, 0, sizeof(fl4));
		fl4.flowi4_oif = rdst->remote_ifindex;
		fl4.flowi4_tos = RT_TOS(tos);
		fl4.daddr = dst->sin.sin_addr.s_addr;
		fl4.saddr = vxlan->saddr.sin.sin_addr.s_addr;  //vxlan设备的源ip地址

		rt = ip_route_output_key(vxlan->net, &fl4);  //查找路由，vxlan设备未设置源IP时，此时会根据路由设置源IP
		if (IS_ERR(rt)) {
			netdev_dbg(dev, "no route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}

		if (rt->dst.dev == dev) {
			netdev_dbg(dev, "circular route to %pI4\n",
				   &dst->sin.sin_addr.s_addr);
			dev->stats.collisions++;
			goto rt_tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		if (rt->rt_flags & RTCF_LOCAL &&
		    !(rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			ip_rt_put(rt);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			vxlan_encap_bypass(skb, vxlan, dst_vxlan);
			return;
		}

		tos = ip_tunnel_ecn_encap(tos, old_iph, skb);
		ttl = ttl ? : ip4_dst_hoplimit(&rt->dst);
		md.vni = htonl(vni << 8);
		md.gbp = skb->mark;

		err = vxlan_xmit_skb(rt, sk, skb, fl4.saddr,
				     dst->sin.sin_addr.s_addr, tos, ttl, df,
				     src_port, dst_port, &md,
				     !net_eq(vxlan->net, dev_net(vxlan->dev)),
				     vxlan->flags);
		if (err < 0) {
			/* skb is already freed. */
			skb = NULL;
			goto rt_tx_error;
		}

		iptunnel_xmit_stats(err, &dev->stats, dev->tstats);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct dst_entry *ndst;
		struct flowi6 fl6;
		u32 flags;

		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_oif = rdst->remote_ifindex;
		fl6.daddr = dst->sin6.sin6_addr;
		fl6.saddr = vxlan->saddr.sin6.sin6_addr;
		fl6.flowi6_proto = IPPROTO_UDP;

		if (ipv6_stub->ipv6_dst_lookup(sk, &ndst, &fl6)) {
			netdev_dbg(dev, "no route to %pI6\n",
				   &dst->sin6.sin6_addr);
			dev->stats.tx_carrier_errors++;
			goto tx_error;
		}

		if (ndst->dev == dev) {
			netdev_dbg(dev, "circular route to %pI6\n",
				   &dst->sin6.sin6_addr);
			dst_release(ndst);
			dev->stats.collisions++;
			goto tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		flags = ((struct rt6_info *)ndst)->rt6i_flags;
		if (flags & RTF_LOCAL &&
		    !(flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
			struct vxlan_dev *dst_vxlan;

			dst_release(ndst);
			dst_vxlan = vxlan_find_vni(vxlan->net, vni,
						   dst->sa.sa_family, dst_port,
						   vxlan->flags);
			if (!dst_vxlan)
				goto tx_error;
			vxlan_encap_bypass(skb, vxlan, dst_vxlan);
			return;
		}

		ttl = ttl ? : ip6_dst_hoplimit(ndst);
		md.vni = htonl(vni << 8);
		md.gbp = skb->mark;

		err = vxlan6_xmit_skb(ndst, sk, skb, dev, &fl6.saddr, &fl6.daddr,
				      0, ttl, src_port, dst_port, &md,
				      !net_eq(vxlan->net, dev_net(vxlan->dev)),
				      vxlan->flags);
#endif
	}

	return;

drop:
	dev->stats.tx_dropped++;
	goto tx_free;

rt_tx_error:
	ip_rt_put(rt);
tx_error:
	dev->stats.tx_errors++;
tx_free:
	dev_kfree_skb(skb);
}

int vxlan_xmit_skb(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port,
		   struct vxlan_metadata *md, bool xnet, u32 vxflags)
{
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	bool udp_sum = !!(vxflags & VXLAN_F_UDP_CSUM);
	int type = udp_sum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
	u16 hdrlen = sizeof(struct vxlanhdr);

	if ((vxflags & VXLAN_F_REMCSUM_TX) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		int csum_start = skb_checksum_start_offset(skb);

		if (csum_start <= VXLAN_MAX_REMCSUM_START &&
		    !(csum_start & VXLAN_RCO_SHIFT_MASK) &&
		    (skb->csum_offset == offsetof(struct udphdr, check) ||
		     skb->csum_offset == offsetof(struct tcphdr, check))) {
			udp_sum = false;
			type |= SKB_GSO_TUNNEL_REMCSUM;
		}
	}

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ VXLAN_HLEN + sizeof(struct iphdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);		//扩展报文头
	if (unlikely(err)) {
		kfree_skb(skb);
		return err;
	}

	skb = vlan_hwaccel_push_inside(skb);		//如果报文有vlan，插入到报文头中
	if (WARN_ON(!skb))
		return -ENOMEM;

	skb = iptunnel_handle_offloads(skb, udp_sum, type);
	if (IS_ERR(skb))
		return PTR_ERR(skb);

	vxh = (struct vxlanhdr *) __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = md->vni;

	if (type & SKB_GSO_TUNNEL_REMCSUM) {
		u32 data = (skb_checksum_start_offset(skb) - hdrlen) >>
			   VXLAN_RCO_SHIFT;

		if (skb->csum_offset == offsetof(struct udphdr, check))
			data |= VXLAN_RCO_UDP;

		vxh->vx_vni |= htonl(data);
		vxh->vx_flags |= htonl(VXLAN_HF_RCO);

		if (!skb_is_gso(skb)) {
			skb->ip_summed = CHECKSUM_NONE;
			skb->encapsulation = 0;
		}
	}

	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);

	skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	return udp_tunnel_xmit_skb(rt, sk, skb, src, dst, tos,
				   ttl, df, src_port, dst_port, xnet,
				   !(vxflags & VXLAN_F_UDP_CSUM));
}

int udp_tunnel_xmit_skb(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
			__be32 src, __be32 dst, __u8 tos, __u8 ttl,
			__be16 df, __be16 src_port, __be16 dst_port,
			bool xnet, bool nocheck)
{
	struct udphdr *uh;

	__skb_push(skb, sizeof(*uh));		//skb增加UDP头，skb报文的headroom大小在vxlan头封装前就完成准备，线性区的空间是充足的
	skb_reset_transport_header(skb);	//重置报文（外层报文）的transport header的偏移
	uh = udp_hdr(skb);

	uh->dest = dst_port;			//设置目的端口
	uh->source = src_port;			//设置源端端口
	uh->len = htons(skb->len);		//设置UDP头中的长度，该长度包括UDP头 + vxlan头 + 用户数据（payload）

	udp_set_csum(nocheck, skb, src, dst, skb->len);		//UDP头csum计算

	return iptunnel_xmit(sk, rt, skb, src, dst, IPPROTO_UDP,	//IP层封装tunnel发送报文
			     tos, ttl, df, xnet);
}

int iptunnel_xmit(struct sock *sk, struct rtable *rt, struct sk_buff *skb,
		  __be32 src, __be32 dst, __u8 proto,
		  __u8 tos, __u8 ttl, __be16 df, bool xnet)
{
	int pkt_len = skb->len;
	struct iphdr *iph;
	int err;

	skb_scrub_packet(skb, xnet);			//清空skb相关信息

	skb_clear_hash(skb);				//清空skb hash值
	skb_dst_set(skb, &rt->dst);			//rt必须根据外层报文的IP地址及相关信息获取到的
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));	//清空skb IPCB的内容

	/* Push down and install the IP header. */
	skb_push(skb, sizeof(struct iphdr));		//skb报文添加IP头
	skb_reset_network_header(skb);			//设置IP头的偏移

	iph = ip_hdr(skb);

	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	df;			//OVS2.5默认有df标记
	iph->protocol	=	proto;			//vxlan，该协议为UDP
	iph->tos	=	tos;
	iph->daddr	=	dst;
	iph->saddr	=	src;
	iph->ttl	=	ttl;
	__ip_select_ident(dev_net(rt->dst.dev), iph,		//计算IP报文的ID值
			  skb_shinfo(skb)->gso_segs ?: 1);

	err = ip_local_out_sk(sk, skb);				//调用ip层发送函数
	if (unlikely(net_xmit_eval(err)))
		pkt_len = 0;
	return pkt_len;
}
```


## vxlan设备发包总结

vxlan外层封装信息总结：

* vxlan.vni
  * 使用vxlan设备的vni值
* udp.src_port
  * 根据创建vxlan时指定的端口范围获取
* udp.dst_port
  * 创建vxlan设备时指定的目的port，如果未指定使用8472
* ip.src_ip
  * 使用创建vxlan设备时指定的源IP，如果未设置，根据目的tunnel IP查询路由得到源IP信息（路由出口设备上的IP地址）
* ip.dst_ip
  * fdb表中根据目的MAC匹配到的dst项的IP地址
  * fdb表中根据全零MAC匹配到的dst项（多个）的IP地址，default remote IP会被放入此fdb表项
* ip.tos
  * 创建vxlan设备时指定的tos值
* mac.src_mac
  * 根据源IP得到的MAC地址
* mac.dst_mac
  * 根据目的IP得到的MAC地址
  

## vxlan设备ARP代理

```c
static int arp_reduce(struct net_device *dev, struct sk_buff *skb)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct arphdr *parp;
	u8 *arpptr, *sha;
	__be32 sip, tip;
	struct neighbour *n;

	if (dev->flags & IFF_NOARP)
		goto out;

	if (!pskb_may_pull(skb, arp_hdr_len(dev))) {
		dev->stats.tx_dropped++;
		goto out;
	}
	parp = arp_hdr(skb);

	if ((parp->ar_hrd != htons(ARPHRD_ETHER) &&
	     parp->ar_hrd != htons(ARPHRD_IEEE802)) ||
	    parp->ar_pro != htons(ETH_P_IP) ||
	    parp->ar_op != htons(ARPOP_REQUEST) ||
	    parp->ar_hln != dev->addr_len ||
	    parp->ar_pln != 4)
		goto out;
	arpptr = (u8 *)parp + sizeof(struct arphdr);
	sha = arpptr;
	arpptr += dev->addr_len;	/* sha */
	memcpy(&sip, arpptr, sizeof(sip));		//获取发送者IP
	arpptr += sizeof(sip);
	arpptr += dev->addr_len;	/* tha */
	memcpy(&tip, arpptr, sizeof(tip));		//获取目标IP

	if (ipv4_is_loopback(tip) ||	//如果目的IP是127.0.0.1或组播地址，则直接返回，相当于丢弃该报文
	    ipv4_is_multicast(tip))
		goto out;

	n = neigh_lookup(&arp_tbl, &tip, dev);	// 查找本地ARP表项

	if (n) {
		struct vxlan_fdb *f;
		struct sk_buff	*reply;

		if (!(n->nud_state & NUD_CONNECTED)) {
			neigh_release(n);
			goto out;
		}

		f = vxlan_find_mac(vxlan, n->ha);
		if (f && vxlan_addr_any(&(first_remote_rcu(f)->remote_ip))) {
			/* bridge-local neighbor */
			neigh_release(n);
			goto out;
		}

		reply = arp_create(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				n->ha, sha);

		neigh_release(n);

		if (reply == NULL)
			goto out;

		skb_reset_mac_header(reply);
		__skb_pull(reply, skb_network_offset(reply));
		reply->ip_summed = CHECKSUM_UNNECESSARY;
		reply->pkt_type = PACKET_HOST;

		if (netif_rx_ni(reply) == NET_RX_DROP)		//协议栈接收arp reply报文
			dev->stats.rx_dropped++;
	} else if (vxlan->flags & VXLAN_F_L3MISS) {
		union vxlan_addr ipa = {
			.sin.sin_addr.s_addr = tip,
			.sin.sin_family = AF_INET,
		};

		vxlan_ip_miss(dev, &ipa);     //未找到内层IP对应的MAC地址，ip miss
	}
out:
	consume_skb(skb);
	return NETDEV_TX_OK;
}
```


## vxlan设备learn机制

```c
static bool vxlan_snoop(struct net_device *dev,
			union vxlan_addr *src_ip, const u8 *src_mac)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_fdb *f;

	f = vxlan_find_mac(vxlan, src_mac);   //查询fdb表项
	if (likely(f)) {
		struct vxlan_rdst *rdst = first_remote_rcu(f);

		if (likely(vxlan_addr_equal(&rdst->remote_ip, src_ip))) 
			return false;

		/* Don't migrate static entries, drop packets */
		if (f->state & NUD_NOARP)
			return true;

		if (net_ratelimit())
			netdev_info(dev,
				    "%pM migrated from %pIS to %pIS\n",
				    src_mac, &rdst->remote_ip.sa, &src_ip->sa);

		rdst->remote_ip = *src_ip;    //修改目标IP
		f->updated = jiffies;
		vxlan_fdb_notify(vxlan, f, rdst, RTM_NEWNEIGH);   //通知更新
	} else {
		/* learned new entry */
		spin_lock(&vxlan->hash_lock);

		/* close off race between vxlan_flush and incoming packets */
		if (netif_running(dev))
			vxlan_fdb_create(vxlan, src_mac, src_ip,     //创建fdb表项
					 NUD_REACHABLE,
					 NLM_F_EXCL|NLM_F_CREATE,
					 vxlan->dst_port,                    //使用vxlan配置的目标端口
					 vxlan->default_dst.remote_vni,      //使用vxlan设备配置的vni
					 0, NTF_SELF);
		spin_unlock(&vxlan->hash_lock);
	}

	return false;
}
```
  
