# tap设备操作

内核态OVS添加/删除tap设备涉及到管理面的netdev设备管理和数据面的vport设备管理。


# netdev_class

1. 添加port流程中，netdev_class的两个主要的函数时alloc和construct函数。
2. 删除port流程中，netdev_class的两个主要的函数时destruct和dealloc函数。

```
const struct netdev_class netdev_tap_class =
    NETDEV_LINUX_CLASS(
        "tap",
        netdev_linux_construct_tap,
        netdev_tap_get_stats,
        netdev_linux_get_features,
        netdev_linux_get_status);
```

alloc操作同netdev_linux_class。


## netdev_linux_construct_tap

```
static int
netdev_linux_construct_tap(struct netdev *netdev_)
{
    struct netdev_linux *netdev = netdev_linux_cast(netdev_);
    static const char tap_dev[] = "/dev/net/tun";
    const char *name = netdev_->name;
    struct ifreq ifr;
    int error;

    netdev_linux_common_construct(netdev);

    /* Open tap device. */
    netdev->tap_fd = open(tap_dev, O_RDWR);   //打开tap设备
    if (netdev->tap_fd < 0) {
        error = errno;
        VLOG_WARN("opening \"%s\" failed: %s", tap_dev, ovs_strerror(error));
        return error;
    }

    /* Create tap device. */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    ovs_strzcpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(netdev->tap_fd, TUNSETIFF, &ifr) == -1) {      //创建tap设备
        VLOG_WARN("%s: creating tap device failed: %s", name,
                  ovs_strerror(errno));
        error = errno;
        goto error_close;
    }

    /* Make non-blocking. */
    error = set_nonblocking(netdev->tap_fd);
    if (error) {
        goto error_close;
    }

    return 0;

error_close:
    close(netdev->tap_fd);
    return error;
}
```


# vport_ops

tap设备的vport_ops同eth设备，即tap（注册了rx_handler函数）收包进入ovs，tap发包通过dev_queue_xmit发送报文，最终由打开tap设备socket的进程进行收包。

