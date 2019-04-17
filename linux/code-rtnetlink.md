# Rtnetlink

rtnetlink底层依赖netlink，提供一种基于消息的

## rtnetlink内核初始化
```c
static int __net_init rtnetlink_net_init(struct net *net)
{
	struct sock *sk;
	struct netlink_kernel_cfg cfg = {
		.groups		= RTNLGRP_MAX,
		.input		= rtnetlink_rcv,          //rtnetlink接收函数，向此socket发送消息时，最后会调用到此函数
		.cb_mutex	= &rtnl_mutex,
		.flags		= NL_CFG_F_NONROOT_RECV,
	};

	sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);  //创建内核socket，最后调用sock_create_lite(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, &sock)
	if (!sk)
		return -ENOMEM;
	net->rtnl = sk;
	return 0;
}
```


## 注册rtnetlink消息处理函数

```c
void rtnl_register(int protocol, int msgtype,
		   rtnl_doit_func doit, rtnl_dumpit_func dumpit,
		   rtnl_calcit_func calcit)
{
	if (__rtnl_register(protocol, msgtype, doit, dumpit, calcit) < 0)
		panic("Unable to register rtnetlink message handler, "
		      "protocol = %d, message type = %d\n",
		      protocol, msgtype);
}

int __rtnl_register(int protocol, int msgtype,
		    rtnl_doit_func doit, rtnl_dumpit_func dumpit,
		    rtnl_calcit_func calcit)
{
	struct rtnl_link *tab;
	int msgindex;

	BUG_ON(protocol < 0 || protocol > RTNL_FAMILY_MAX);
	msgindex = rtm_msgindex(msgtype);   //根据消息类型得到index，index唯一

	tab = rtnl_msg_handlers[protocol];
	if (tab == NULL) {
		tab = kcalloc(RTM_NR_MSGTYPES, sizeof(*tab), GFP_KERNEL);   //申请数组
		if (tab == NULL)
			return -ENOBUFS;

		rtnl_msg_handlers[protocol] = tab;
	}

	if (doit)
		tab[msgindex].doit = doit;      //注册消息处理函数

	if (dumpit)
		tab[msgindex].dumpit = dumpit;

	if (calcit)
		tab[msgindex].calcit = calcit;

	return 0;
}
```


## 内核发送rtnetlink消息

```c
void rtnl_notify(struct sk_buff *skb, struct net *net, u32 pid, u32 group,   //实际内核使用时pid为0，实际是发给自己
		 struct nlmsghdr *nlh, gfp_t flags)
{
	struct sock *rtnl = net->rtnl;   //得到发送方的sock对象，统一使用内核创建的socket
	int report = 0;

	if (nlh)
		report = nlmsg_report(nlh);

	nlmsg_notify(rtnl, skb, pid, group, report, flags);
}

int nlmsg_notify(struct sock *sk, struct sk_buff *skb, u32 portid,
		 unsigned int group, int report, gfp_t flags)
{
	int err = 0;

	if (group) {
		int exclude_portid = 0;

		if (report) {
			atomic_inc(&skb->users);
			exclude_portid = portid;
		}

		/* errors reported via destination sk->sk_err, but propagate
		 * delivery errors if NETLINK_BROADCAST_ERROR flag is set */
		err = nlmsg_multicast(sk, skb, exclude_portid, group, flags);
	}

	if (report) {
		int err2;

		err2 = nlmsg_unicast(sk, skb, portid);   //调用netlink发送消息
		if (!err || err == -ESRCH)
			err = err2;
	}

	return err;
}

static inline int nlmsg_unicast(struct sock *sk, struct sk_buff *skb, u32 portid)
{
	int err;

	err = netlink_unicast(sk, skb, portid, MSG_DONTWAIT);  //调用netlink发送消息
	if (err > 0)
		err = 0;

	return err;
}

int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 portid, int nonblock)
{
	struct sock *sk;
	int err;
	long timeo;

	skb = netlink_trim(skb, gfp_any());

	timeo = sock_sndtimeo(ssk, nonblock);
retry:
	sk = netlink_getsockbyportid(ssk, portid);		//rtnl_notify调用时，portid为0， ssk的family为PF_NETLINK
	if (IS_ERR(sk)) {
		kfree_skb(skb);
		return PTR_ERR(sk);
	}
	if (netlink_is_kernel(sk))
		return netlink_unicast_kernel(sk, skb, ssk);   //为内核socket走此分支，最后调用rtnetlink_net_init中注册的rtnetlink_rcv

	if (sk_filter(sk, skb)) {
		err = skb->len;
		kfree_skb(skb);
		sock_put(sk);
		return err;
	}

	err = netlink_attachskb(sk, skb, &timeo, ssk);
	if (err == 1)
		goto retry;
	if (err)
		return err;

	return netlink_sendskb(sk, skb);
}

static void rtnetlink_rcv(struct sk_buff *skb)
{
	rtnl_lock();
	netlink_rcv_skb(skb, &rtnetlink_rcv_msg);
	rtnl_unlock();
}

int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
						     struct nlmsghdr *))
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);   //获得netlink消息头
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
			goto ack;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto ack;

		err = cb(skb, nlh);   //调用rtnetlink_rcv_msg
		if (err == -EINTR)
			goto skip;

ack:
		if (nlh->nlmsg_flags & NLM_F_ACK || err)
			netlink_ack(skb, nlh, err);

skip:
		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len)
			msglen = skb->len;
		skb_pull(skb, msglen);
	}

	return 0;
}

static int rtnetlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	rtnl_doit_func doit;
	int sz_idx, kind;
	int family;
	int type;
	int err;

	type = nlh->nlmsg_type;        //type为nlmsghdr中的type
	if (type > RTM_MAX)
		return -EOPNOTSUPP;

	type -= RTM_BASE;

	/* All the messages must have at least 1 byte length */
	if (nlmsg_len(nlh) < sizeof(struct rtgenmsg))
		return 0;

	family = ((struct rtgenmsg *)nlmsg_data(nlh))->rtgen_family;    //nlmsghdr后为rtgenmsg头
	sz_idx = type>>2;
	kind = type&3;

	if (kind != 2 && !netlink_net_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	if (kind == 2 && nlh->nlmsg_flags&NLM_F_DUMP) {
		struct sock *rtnl;
		rtnl_dumpit_func dumpit;
		rtnl_calcit_func calcit;
		u16 min_dump_alloc = 0;

		dumpit = rtnl_get_dumpit(family, type);
		if (dumpit == NULL)
			return -EOPNOTSUPP;
		calcit = rtnl_get_calcit(family, type);
		if (calcit)
			min_dump_alloc = calcit(skb, nlh);

		__rtnl_unlock();
		rtnl = net->rtnl;
		{
			struct netlink_dump_control c = {
				.dump		= dumpit,
				.min_dump_alloc	= min_dump_alloc,
			};
			err = netlink_dump_start(rtnl, skb, nlh, &c);
		}
		rtnl_lock();
		return err;
	}

	doit = rtnl_get_doit(family, type);    //根据family和type得到消息处理函数
	if (doit == NULL)
		return -EOPNOTSUPP;

	return doit(skb, nlh);   //处理消息
}

static rtnl_doit_func rtnl_get_doit(int protocol, int msgindex)
{
	struct rtnl_link *tab;

	if (protocol <= RTNL_FAMILY_MAX)
		tab = rtnl_msg_handlers[protocol]; 
	else
		tab = NULL;

	if (tab == NULL || tab[msgindex].doit == NULL)
		tab = rtnl_msg_handlers[PF_UNSPEC];

	return tab[msgindex].doit;   //获取之前注册的处理函数
}

```

## 内核中已注册消息处理函数
```c
rtnl_register(PF_UNSPEC, RTM_NEWNEIGH, neigh_add, NULL, NULL);
rtnl_register(PF_UNSPEC, RTM_DELNEIGH, neigh_delete, NULL, NULL);
rtnl_register(PF_UNSPEC, RTM_GETNEIGH, NULL, neigh_dump_info, NULL);
rtnl_register(PF_UNSPEC, RTM_GETNEIGHTBL, NULL, neightbl_dump_info,
rtnl_register(PF_UNSPEC, RTM_SETNEIGHTBL, neightbl_set, NULL, NULL);
```

## 内核中已注册消息处理函数

* 系统已注册的消息处理，也支持扩展
* generic netlink相比rtnetlink提供了一套自定义消息解析机制
