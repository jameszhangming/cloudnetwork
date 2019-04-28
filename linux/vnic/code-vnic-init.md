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

虚拟网卡创建流程：

```c
rtnl_newlink //创建入口
	rtnl_link_ops->validate()      //根据type找到rtnl_link_ops，校验输入参数
	rtnl_link_ops->changelink()    //修改父设备（如果需要的话）
	do_setlink()
        rtnl_group_changelink()
        rtnl_create_link() //创建net_device设备，实际是虚拟设备对象
		alloc_netdev_mqs()
			rtnl_link_ops->setup()	//设备初始化，默认初始化
	rtnl_link_ops->newlink(dev)  //根据输入参数设置
		register_netdevice(dev)	//内核注册设备
			dev->netdev_ops->ndo_init(dev)   //设备初始化
	rtnl_configure_link(dev, ifm)
		__dev_change_flags(dev,flags)
			__dev_open(dev)
				dev->netdev_ops->ndo_validate_addr(dev) //设备地址校验
				dev->netdev_ops->ndo_open(dev)			//打开设备
```

