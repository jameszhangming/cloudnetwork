# XFRM 操作

用户态命令通过netlink实现xfrm配置


## 操作注册

```c
static int __net_init xfrm_user_net_init(struct net *net)
{
	struct sock *nlsk;
	struct netlink_kernel_cfg cfg = {
		.groups	= XFRMNLGRP_MAX,
		.input	= xfrm_netlink_rcv,
	};

	nlsk = netlink_kernel_create(net, NETLINK_XFRM, &cfg);
	if (nlsk == NULL)
		return -ENOMEM;
	net->xfrm.nlsk_stash = nlsk; /* Don't set to NULL */
	rcu_assign_pointer(net->xfrm.nlsk, nlsk);
	return 0;
}
```


## 操作入口

```c
static void xfrm_netlink_rcv(struct sk_buff *skb)
{
	struct net *net = sock_net(skb->sk);

	mutex_lock(&net->xfrm.xfrm_cfg_mutex);
	netlink_rcv_skb(skb, &xfrm_user_rcv_msg);
	mutex_unlock(&net->xfrm.xfrm_cfg_mutex);
}

int netlink_rcv_skb(struct sk_buff *skb, int (*cb)(struct sk_buff *,
						     struct nlmsghdr *))
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len)
			return 0;

		/* Only requests are handled by the kernel */
		if (!(nlh->nlmsg_flags & NLM_F_REQUEST))
			goto ack;

		/* Skip control messages */
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE)
			goto ack;

		err = cb(skb, nlh);  //调用xfrm_user_rcv_msg
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


static int xfrm_user_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *attrs[XFRMA_MAX+1];
	const struct xfrm_link *link;
	int type, err;

#ifdef CONFIG_COMPAT
	if (is_compat_task())
		return -ENOTSUPP;
#endif

	type = nlh->nlmsg_type;
	if (type > XFRM_MSG_MAX)
		return -EINVAL;

	type -= XFRM_MSG_BASE;
	link = &xfrm_dispatch[type];   //操作方法

	/* All operations require privileges, even GET */
	if (!netlink_net_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	if ((type == (XFRM_MSG_GETSA - XFRM_MSG_BASE) ||
	     type == (XFRM_MSG_GETPOLICY - XFRM_MSG_BASE)) &&
	    (nlh->nlmsg_flags & NLM_F_DUMP)) {
		if (link->dump == NULL)
			return -EINVAL;

		{
			struct netlink_dump_control c = {
				.dump = link->dump,
				.done = link->done,
			};
			return netlink_dump_start(net->xfrm.nlsk, skb, nlh, &c);
		}
	}

	err = nlmsg_parse(nlh, xfrm_msg_min[type], attrs,
			  link->nla_max ? : XFRMA_MAX,
			  link->nla_pol ? : xfrma_policy);
	if (err < 0)
		return err;

	if (link->doit == NULL)
		return -EINVAL;

	return link->doit(skb, nlh, attrs);
}
```


## 操作方法定义

```c
static const struct xfrm_link {
	int (*doit)(struct sk_buff *, struct nlmsghdr *, struct nlattr **);
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	const struct nla_policy *nla_pol;
	int nla_max;
} xfrm_dispatch[XFRM_NR_MSGTYPES] = {
	[XFRM_MSG_NEWSA       - XFRM_MSG_BASE] = { .doit = xfrm_add_sa        },
	[XFRM_MSG_DELSA       - XFRM_MSG_BASE] = { .doit = xfrm_del_sa        },
	[XFRM_MSG_GETSA       - XFRM_MSG_BASE] = { .doit = xfrm_get_sa,
						   .dump = xfrm_dump_sa,
						   .done = xfrm_dump_sa_done  },
	[XFRM_MSG_NEWPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_add_policy    },
	[XFRM_MSG_DELPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_get_policy    },
	[XFRM_MSG_GETPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_get_policy,
						   .dump = xfrm_dump_policy,
						   .done = xfrm_dump_policy_done },
	[XFRM_MSG_ALLOCSPI    - XFRM_MSG_BASE] = { .doit = xfrm_alloc_userspi },
	[XFRM_MSG_ACQUIRE     - XFRM_MSG_BASE] = { .doit = xfrm_add_acquire   },
	[XFRM_MSG_EXPIRE      - XFRM_MSG_BASE] = { .doit = xfrm_add_sa_expire },
	[XFRM_MSG_UPDPOLICY   - XFRM_MSG_BASE] = { .doit = xfrm_add_policy    },
	[XFRM_MSG_UPDSA       - XFRM_MSG_BASE] = { .doit = xfrm_add_sa        },
	[XFRM_MSG_POLEXPIRE   - XFRM_MSG_BASE] = { .doit = xfrm_add_pol_expire},
	[XFRM_MSG_FLUSHSA     - XFRM_MSG_BASE] = { .doit = xfrm_flush_sa      },
	[XFRM_MSG_FLUSHPOLICY - XFRM_MSG_BASE] = { .doit = xfrm_flush_policy  },
	[XFRM_MSG_NEWAE       - XFRM_MSG_BASE] = { .doit = xfrm_new_ae  },
	[XFRM_MSG_GETAE       - XFRM_MSG_BASE] = { .doit = xfrm_get_ae  },
	[XFRM_MSG_MIGRATE     - XFRM_MSG_BASE] = { .doit = xfrm_do_migrate    },
	[XFRM_MSG_GETSADINFO  - XFRM_MSG_BASE] = { .doit = xfrm_get_sadinfo   },
	[XFRM_MSG_NEWSPDINFO  - XFRM_MSG_BASE] = { .doit = xfrm_set_spdinfo,
						   .nla_pol = xfrma_spd_policy,
						   .nla_max = XFRMA_SPD_MAX },
	[XFRM_MSG_GETSPDINFO  - XFRM_MSG_BASE] = { .doit = xfrm_get_spdinfo   },
};
```


## 添加sa

```c
static int xfrm_add_sa(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct nlattr **attrs)
{
	struct net *net = sock_net(skb->sk);
	struct xfrm_usersa_info *p = nlmsg_data(nlh); //xfrm_state 参数
	struct xfrm_state *x;
	int err;
	struct km_event c;

	err = verify_newsa_info(p, attrs);	//验证参数
	if (err)
		return err;

	x = xfrm_state_construct(net, p, attrs, &err);	//创建xfrm_state对象，并初始化
	if (!x)
		return err;

	xfrm_state_hold(x);
	if (nlh->nlmsg_type == XFRM_MSG_NEWSA)
		err = xfrm_state_add(x);     //添加xfrm_state对象
	else
		err = xfrm_state_update(x);

	xfrm_audit_state_add(x, err ? 0 : 1, true);

	if (err < 0) {
		x->km.state = XFRM_STATE_DEAD;
		__xfrm_state_put(x);
		goto out;
	}

	c.seq = nlh->nlmsg_seq;
	c.portid = nlh->nlmsg_pid;
	c.event = nlh->nlmsg_type;

	km_state_notify(x, &c);
out:
	xfrm_state_put(x);
	return err;
}
```

### xfrm_state_construct

```c
static struct xfrm_state *xfrm_state_construct(struct net *net,
					       struct xfrm_usersa_info *p,
					       struct nlattr **attrs,
					       int *errp)
{
	struct xfrm_state *x = xfrm_state_alloc(net);	//构造xfrm_state对象
	int err = -ENOMEM;

	if (!x)
		goto error_no_put;

	copy_from_user_state(x, p);		//拷贝xfrm_state部分信息

	if (attrs[XFRMA_SA_EXTRA_FLAGS])
		x->props.extra_flags = nla_get_u32(attrs[XFRMA_SA_EXTRA_FLAGS]);

	if ((err = attach_aead(&x->aead, &x->props.ealgo,
			       attrs[XFRMA_ALG_AEAD])))
		goto error;
	if ((err = attach_auth_trunc(&x->aalg, &x->props.aalgo,
				     attrs[XFRMA_ALG_AUTH_TRUNC])))
		goto error;
	if (!x->props.aalgo) {
		if ((err = attach_auth(&x->aalg, &x->props.aalgo,
				       attrs[XFRMA_ALG_AUTH])))
			goto error;
	}
	if ((err = attach_one_algo(&x->ealg, &x->props.ealgo,
				   xfrm_ealg_get_byname,
				   attrs[XFRMA_ALG_CRYPT])))
		goto error;
	if ((err = attach_one_algo(&x->calg, &x->props.calgo,
				   xfrm_calg_get_byname,
				   attrs[XFRMA_ALG_COMP])))
		goto error;

	if (attrs[XFRMA_ENCAP]) {		//设置encap属性
		x->encap = kmemdup(nla_data(attrs[XFRMA_ENCAP]),
				   sizeof(*x->encap), GFP_KERNEL);
		if (x->encap == NULL)
			goto error;
	}

	if (attrs[XFRMA_TFCPAD])
		x->tfcpad = nla_get_u32(attrs[XFRMA_TFCPAD]);

	if (attrs[XFRMA_COADDR]) {
		x->coaddr = kmemdup(nla_data(attrs[XFRMA_COADDR]),
				    sizeof(*x->coaddr), GFP_KERNEL);
		if (x->coaddr == NULL)
			goto error;
	}

	xfrm_mark_get(attrs, &x->mark);

	err = __xfrm_init_state(x, false);	//xfrm_state初始化
	if (err)
		goto error;

	if (attrs[XFRMA_SEC_CTX] &&
	    security_xfrm_state_alloc(x, nla_data(attrs[XFRMA_SEC_CTX])))
		goto error;

	if ((err = xfrm_alloc_replay_state_esn(&x->replay_esn, &x->preplay_esn,
					       attrs[XFRMA_REPLAY_ESN_VAL])))
		goto error;

	x->km.seq = p->seq;
	x->replay_maxdiff = net->xfrm.sysctl_aevent_rseqth;
	/* sysctl_xfrm_aevent_etime is in 100ms units */
	x->replay_maxage = (net->xfrm.sysctl_aevent_etime*HZ)/XFRM_AE_ETH_M;

	if ((err = xfrm_init_replay(x)))	//初始化replay
		goto error;

	/* override default values from above */
	xfrm_update_ae_params(x, attrs, 0);		//设置replay等参数值

	return x;

error:
	x->km.state = XFRM_STATE_DEAD;
	xfrm_state_put(x);
error_no_put:
	*errp = err;
	return NULL;
}

```

### xfrm_state_add

```c
int xfrm_state_add(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	struct xfrm_state *x1, *to_put;
	int family;
	int err;
	u32 mark = x->mark.v & x->mark.m;
	//IPPROTO_AH或IPPROTO_ESP或IPPROTO_COMP， 该值为1
	int use_spi = xfrm_id_proto_match(x->id.proto, IPSEC_PROTO_ANY);	

	family = x->props.family;

	to_put = NULL;

	spin_lock_bh(&net->xfrm.xfrm_state_lock);
	
	//根据目的IP、SPI、协议（AH/ESP等）、协议族来查找xfrm_state
	x1 = __xfrm_state_locate(x, use_spi, family);	
	if (x1) {
		to_put = x1;	//如果已经存在，则需要释放该xfrm_state对象
		x1 = NULL;
		err = -EEXIST;
		goto out;
	}

	if (use_spi && x->km.seq) {
		x1 = __xfrm_find_acq_byseq(net, mark, x->km.seq);	//根据目的IP和seq来
		if (x1 && ((x1->id.proto != x->id.proto) ||		//协议不同，或者目的地不同
		    !xfrm_addr_equal(&x1->id.daddr, &x->id.daddr, family))) {
			to_put = x1;	//需要释放该xfrm_state
			x1 = NULL;
		}
	}

	if (use_spi && !x1)
		x1 = __find_acq_core(net, &x->mark, family, x->props.mode,
				     x->props.reqid, x->id.proto,
				     &x->id.daddr, &x->props.saddr, 0);

	__xfrm_state_bump_genids(x);
	__xfrm_state_insert(x);
	err = 0;

out:
	spin_unlock_bh(&net->xfrm.xfrm_state_lock);

	if (x1) {
		xfrm_state_delete(x1);
		xfrm_state_put(x1);
	}

	if (to_put)
		xfrm_state_put(to_put);

	return err;
}
EXPORT_SYMBOL(xfrm_state_add);

```




