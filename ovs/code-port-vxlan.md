# vxlan端口管理

内核态OVS添加/删除vxlan设备涉及到管理面的netdev设备管理和数据面的vport设备管理。


# netdev_class

vxlan设备属于vport设备，定义的是vport_class

```
TUNNEL_CLASS("vxlan", "vxlan_sys", netdev_vxlan_build_header, push_udp_header, netdev_vxlan_pop_header),

#define TUNNEL_CLASS(NAME, DPIF_PORT, BUILD_HEADER, PUSH_HEADER, POP_HEADER)   \
    { DPIF_PORT,                                                               \
        { NAME, VPORT_FUNCTIONS(get_tunnel_config,                             \
                                set_tunnel_config,                             \
                                get_netdev_tunnel_config,                      \
                                tunnel_get_status,                             \
                                BUILD_HEADER, PUSH_HEADER, POP_HEADER) }}

#define VPORT_FUNCTIONS(GET_CONFIG, SET_CONFIG,             \
                        GET_TUNNEL_CONFIG, GET_STATUS,      \
                        BUILD_HEADER,                       \
                        PUSH_HEADER, POP_HEADER)            \
    NULL,                                                   \
    netdev_vport_run,                                       \
    netdev_vport_wait,                                      \
                                                            \
    netdev_vport_alloc,                                     \
    netdev_vport_construct,                                 \
    netdev_vport_destruct,                                  \
    netdev_vport_dealloc,                                   \
    GET_CONFIG,                                             \
    SET_CONFIG,                                             \
    GET_TUNNEL_CONFIG,                                      \
    BUILD_HEADER,                                           \
    PUSH_HEADER,                                            \
    POP_HEADER,                                             \
    NULL,                       /* get_numa_id */           \
    NULL,                       /* set_multiq */            \
                                                            \
    NULL,                       /* send */                  \
    NULL,                       /* send_wait */             \
......
```


## 添加vxlan端口

```
static struct netdev *
netdev_vport_alloc(void)
{
    struct netdev_vport *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_vport_construct(struct netdev *netdev_)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev_);
    const char *type = netdev_get_type(netdev_);

    ovs_mutex_init(&dev->mutex);
    eth_addr_random(&dev->etheraddr);   //设置mac地址

    /* Add a default destination port for tunnel ports if none specified. */
    if (!strcmp(type, "geneve")) {
        dev->tnl_cfg.dst_port = htons(GENEVE_DST_PORT);
    } else if (!strcmp(type, "vxlan")) {
        dev->tnl_cfg.dst_port = htons(VXLAN_DST_PORT);    //设置目的端口
    } else if (!strcmp(type, "lisp")) {
        dev->tnl_cfg.dst_port = htons(LISP_DST_PORT);
    } else if (!strcmp(type, "stt")) {
        dev->tnl_cfg.dst_port = htons(STT_DST_PORT);
    }

    dev->tnl_cfg.dont_fragment = true;
    dev->tnl_cfg.ttl = DEFAULT_TTL;
    return 0;
}
```


## 删除vxlan端口

```
static void
netdev_vport_destruct(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);

    free(netdev->peer);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_vport_dealloc(struct netdev *netdev_)
{
    struct netdev_vport *netdev = netdev_vport_cast(netdev_);
    free(netdev);
}

```


# vport_class

```
static struct vport_ops ovs_vxlan_netdev_vport_ops = {
    .type            = OVS_VPORT_TYPE_VXLAN,
    .create            = vxlan_create,
    .destroy        = ovs_netdev_tunnel_destroy,
    .get_options        = vxlan_get_options,
    .send            = vxlan_xmit,
    .get_egress_tun_info    = vxlan_get_egress_tun_info,
};
```


## vxlan_create

```
static struct vport *vxlan_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = vxlan_tnl_create(parms);   //创建vport和vxlan设备
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct net_device *dev;
	struct vport *vport;
	struct nlattr *a;
	int err;
	struct vxlan_config conf = {
		.no_share = true,
		.flags = VXLAN_F_COLLECT_METADATA,
		/* Don't restrict the packets that can be sent by MTU */
		.mtu = IP_MAX_MTU,
	};

	if (!options) {
		err = -EINVAL;
		goto error;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		conf.dst_port = htons(nla_get_u16(a));
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	vport = ovs_vport_alloc(0, &ovs_vxlan_netdev_vport_ops, parms);   //申请vport对象
	if (IS_ERR(vport))
		return vport;

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_EXTENSION);
	if (a) {
		err = vxlan_configure_exts(vport, a, &conf);
		if (err) {
			ovs_vport_free(vport);
			goto error;
		}
	}

	rtnl_lock();
	dev = vxlan_dev_create(net, parms->name, NET_NAME_USER, &conf);  //创建vxlan设备
	if (IS_ERR(dev)) {
		rtnl_unlock();
		ovs_vport_free(vport);
		return ERR_CAST(dev);
	}

	dev_change_flags(dev, dev->flags | IFF_UP);
	rtnl_unlock();
	return vport;
error:
	return ERR_PTR(err);
}

struct net_device *rpl_vxlan_dev_create(struct net *net, const char *name,
				    u8 name_assign_type, struct vxlan_config *conf)
{
	struct nlattr *tb[IFLA_MAX+1];
	struct net_device *dev;
	int err;

	memset(&tb, 0, sizeof(tb));

	dev = rtnl_create_link(net, (char *)name, name_assign_type,   //调用内核创建vxlan设备
			       &vxlan_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = vxlan_dev_configure(net, dev, conf);   //配置vxlan设备
	if (err < 0) {
		free_netdev(dev);
		return ERR_PTR(err);
	}

	return dev;
}


static int vxlan_dev_configure(struct net *src_net, struct net_device *dev,
			       struct vxlan_config *conf)
{
	struct vxlan_net *vn = net_generic(src_net, vxlan_net_id);
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_rdst *dst = &vxlan->default_dst;
	int err;
	bool use_ipv6 = false;
	__be16 default_port = vxlan->cfg.dst_port;
	struct net_device *lowerdev = NULL;

	vxlan->net = src_net;

	dst->remote_vni = conf->vni;

	memcpy(&dst->remote_ip, &conf->remote_ip, sizeof(conf->remote_ip));    //设置对端IP地址

	/* Unless IPv6 is explicitly requested, assume IPv4 */
	if (!dst->remote_ip.sa.sa_family)
		dst->remote_ip.sa.sa_family = AF_INET;

	if (dst->remote_ip.sa.sa_family == AF_INET6 ||
	    vxlan->cfg.saddr.sa.sa_family == AF_INET6) {
		if (!IS_ENABLED(CONFIG_IPV6))
			return -EPFNOSUPPORT;
		use_ipv6 = true;
	}

	if (conf->remote_ifindex) {    //指定底层设备
		lowerdev = __dev_get_by_index(src_net, conf->remote_ifindex);
		dst->remote_ifindex = conf->remote_ifindex;

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

		if (!conf->mtu)
			dev->mtu = lowerdev->mtu - (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);  //设置mtu

		dev->needed_headroom = lowerdev->hard_header_len +
				       (use_ipv6 ? VXLAN6_HEADROOM : VXLAN_HEADROOM);   //设置header len
	} else if (use_ipv6) {
		vxlan->flags |= VXLAN_F_IPV6;
		dev->needed_headroom = ETH_HLEN + VXLAN6_HEADROOM;
	} else {
		dev->needed_headroom = ETH_HLEN + VXLAN_HEADROOM;    // VXLAN_HEADROOM为50
	}

	if (conf->mtu) {
		err = __vxlan_change_mtu(dev, lowerdev, dst, conf->mtu, false);   //vxlan设备修改mtu
		if (err)
			return err;
	}

	memcpy(&vxlan->cfg, conf, sizeof(*conf));
	if (!vxlan->cfg.dst_port)
		vxlan->cfg.dst_port = default_port;
	vxlan->flags |= conf->flags;

	if (!vxlan->cfg.age_interval)
		vxlan->cfg.age_interval = FDB_AGE_DEFAULT;

	if (vxlan_find_vni(src_net, conf->vni, use_ipv6 ? AF_INET6 : AF_INET,
			   vxlan->cfg.dst_port, vxlan->flags))
		return -EEXIST;

	dev->ethtool_ops = &vxlan_ethtool_ops;

	/* create an fdb entry for a valid default destination */
	if (!vxlan_addr_any(&vxlan->default_dst.remote_ip)) {
		err = vxlan_fdb_create(vxlan, all_zeros_mac,             //创建defaultfdb表项
				       &vxlan->default_dst.remote_ip,
				       NUD_REACHABLE|NUD_PERMANENT,
				       NLM_F_EXCL|NLM_F_CREATE,
				       vxlan->cfg.dst_port,
				       vxlan->default_dst.remote_vni,
				       vxlan->default_dst.remote_ifindex,
				       NTF_SELF);
		if (err)
			return err;
	}

	err = register_netdevice(dev);    //注册netdevice
	if (err) {
		vxlan_fdb_delete_default(vxlan);
		return err;
	}

	list_add(&vxlan->next, &vn->vxlan_list);    //vxlan添加到网络空间的链表中

	return 0;
}

struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);   //根据name找到vxlan设备
	if (!vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	if (vport->dev->flags & IFF_LOOPBACK ||
	    vport->dev->type != ARPHRD_ETHER ||
	    ovs_is_internal_dev(vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

	rtnl_lock();
	err = netdev_master_upper_dev_link(vport->dev,
					   get_dpdev(vport->dp));
	if (err)
		goto error_unlock;

	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook,     //vxlan_dev设备注册rx_handler函数
					 vport);
	if (err)
		goto error_master_upper_dev_unlink;

	dev_disable_lro(vport->dev);
	dev_set_promiscuity(vport->dev, 1);
	vport->dev->priv_flags |= IFF_OVS_DATAPATH;
	rtnl_unlock();

	return vport;

error_master_upper_dev_unlink:
	netdev_upper_dev_unlink(vport->dev, get_dpdev(vport->dp));
error_unlock:
	rtnl_unlock();
error_put:
	dev_put(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
	return ERR_PTR(err);
}
```


## ovs_netdev_tunnel_destroy

```
void ovs_netdev_tunnel_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);   //卸载设备

	/* We can be invoked by both explicit vport deletion and
	 * underlying netdev deregistration; delete the link only
	 * if it's not already shutting down.
	 */

	if (vport->dev->reg_state == NETREG_REGISTERED)
		rtnl_delete_link(vport->dev);    //删除vxlan设备

	dev_put(vport->dev);
	vport->dev = NULL;
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}

void ovs_netdev_detach_dev(struct vport *vport)
{
	ASSERT_RTNL();
	vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(vport->dev);     //解注册rx_handler函数
	netdev_upper_dev_unlink(vport->dev,
				netdev_master_upper_dev_get(vport->dev));
	dev_set_promiscuity(vport->dev, -1);         //设置为非混杂模式
}
```


## vxlan_xmit

通过vxlan设备发送报文，参考linux的vxlan设备分析。

