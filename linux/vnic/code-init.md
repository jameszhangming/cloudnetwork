# ������������

�����������������漰��Link����������������صĳ�ʼ�����̡�

## ����������Ҫ���ݽṹ

����������
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

Link������
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

�����հ�������
```
typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **pskb);
```


## ����������������

���������������̣�

```c
rtnl_newlink //�������
	rtnl_link_ops->validate()      //����type�ҵ�rtnl_link_ops��У���������
	rtnl_link_ops->changelink()    //�޸ĸ��豸�������Ҫ�Ļ���
	do_setlink()
        rtnl_group_changelink()
        rtnl_create_link() //����net_device�豸��ʵ���������豸����
		alloc_netdev_mqs()
			rtnl_link_ops->setup()	//�豸��ʼ����Ĭ�ϳ�ʼ��
	rtnl_link_ops->newlink(dev)  //���������������
		register_netdevice(dev)	//�ں�ע���豸
			dev->netdev_ops->ndo_init(dev)   //�豸��ʼ��
	rtnl_configure_link(dev, ifm)
		__dev_change_flags(dev,flags)
			__dev_open(dev)
				dev->netdev_ops->ndo_validate_addr(dev) //�豸��ַУ��
				dev->netdev_ops->ndo_open(dev)			//���豸
```

