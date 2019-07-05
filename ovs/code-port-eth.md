# eth设备操作

内核态OVS添加/删除本地网卡设备涉及到管理面的netdev设备管理和数据面的vport设备管理。


# netdev_class

1. 添加port流程中，netdev_class的两个主要的函数时alloc和construct函数。
2. 删除port流程中，netdev_class的两个主要的函数时destruct和dealloc函数。

```
const struct netdev_class netdev_linux_class =
    NETDEV_LINUX_CLASS(
        "system",
        netdev_linux_construct,
        netdev_linux_get_stats,
        netdev_linux_get_features,
        netdev_linux_get_status);


static struct netdev *
netdev_linux_alloc(void)
{
    struct netdev_linux *netdev = xzalloc(sizeof *netdev); 
    return &netdev->up;
}

static int
netdev_linux_construct(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    int error;

    netdev_linux_common_construct(netdev);  //初始化mutex锁

    error = get_flags(&netdev->up, &netdev->ifi_flags);
    if (error == ENODEV) {
        if (netdev->up.netdev_class != &netdev_internal_class) {
            /* The device does not exist, so don't allow it to be opened. */
            return ENODEV;
        } else {
            /* "Internal" netdevs have to be created as netdev objects before
             * they exist in the kernel, because creating them in the kernel
             * happens by passing a netdev object to dpif_port_add().
             * Therefore, ignore the error. */
        }
    }

    return 0;
}

static void
netdev_linux_destruct(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);

    if (netdev->tc && netdev->tc->ops->tc_destroy) {
        netdev->tc->ops->tc_destroy(netdev->tc);
    }

    if (netdev_get_class(netdev_) == &netdev_tap_class
        && netdev->tap_fd >= 0)
    {
        close(netdev->tap_fd);
    }

    if (netdev->miimon_interval > 0) {
        atomic_count_dec(&miimon_cnt);
    }

    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_linux_dealloc(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    free(netdev);
}
```


# vport_ops

内核数据面添加eth网卡和tap设备，后端的vport_ops对应的都是ovs_netdev_vport_ops

```
static struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.send		= dev_queue_xmit,   //直接调用二层发包
};
```


## netdev_create

```
static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_alloc(0, &ovs_netdev_vport_ops, parms);   //申请vport对象
	if (IS_ERR(vport))
		return vport;

	return ovs_netdev_link(vport, parms->name);  //设备关联
}

struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids)) {
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	return vport;
}

struct vport *ovs_netdev_link(struct vport *vport, const char *name)
{
	int err;

	vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), name);  //绑定到eth设备
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

	err = netdev_rx_handler_register(vport->dev, netdev_frame_hook,    //注册rx_handler函数，dev收包后进入ovs处理
					 vport);
	if (err)
		goto error_master_upper_dev_unlink;

	dev_disable_lro(vport->dev);
	dev_set_promiscuity(vport->dev, 1);              //设置混杂模式
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


## netdev_destroy

```
static void netdev_destroy(struct vport *vport)
{
	rtnl_lock();
	if (vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);
	rtnl_unlock();

	call_rcu(&vport->rcu, vport_netdev_free);
}

void ovs_netdev_detach_dev(struct vport *vport)
{
	ASSERT_RTNL();
	vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(vport->dev);     //rx handler解注册
	netdev_upper_dev_unlink(vport->dev,
				netdev_master_upper_dev_get(vport->dev));  //空函数
	dev_set_promiscuity(vport->dev, -1);   //设置为非混杂模式
}
```

