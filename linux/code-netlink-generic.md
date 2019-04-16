# Generic Netlink 

Generic Netlink是通用的用户态和内核态进行通信的机制，可以被多个应用使用，例如OVS就使用了Generic Netlink用于用户态和内核态通信

关于Netlink相关的实现已经在[Netlink](code-netlink.md)中介绍，本文仅介绍Generic Netlink相关的内容

## Generic Netlink input

genl_rcv函数说明了从用户态Generic Socket发送消息，如何被用户在内核中注册的函数接收

```c
static void genl_rcv(struct sk_buff *skb)
{
	down_read(&cb_lock);
	netlink_rcv_skb(skb, &genl_rcv_msg);
	up_read(&cb_lock);
}

static int genl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct genl_family *family;
	int err;

	family = genl_family_find_byid(nlh->nlmsg_type);	   //通过id找到family
	if (family == NULL)
		return -ENOENT;

	if (!family->parallel_ops)
		genl_lock();

	err = genl_family_rcv_msg(family, skb, nlh);

	if (!family->parallel_ops)
		genl_unlock();

	return err;
}

static int genl_family_rcv_msg(struct genl_family *family,
			       struct sk_buff *skb,
			       struct nlmsghdr *nlh)
{
	const struct genl_ops *ops;
	struct net *net = sock_net(skb->sk);
	struct genl_info info;
	struct genlmsghdr *hdr = nlmsg_data(nlh);	//直接根据skb->data+nlmsghdr头（对齐的大小）的指针 
	struct nlattr **attrbuf;
	int hdrlen, err;

	/* this family doesn't exist in this netns */
	if (!family->netnsok && !net_eq(net, &init_net))
		return -ENOENT;

	hdrlen = GENL_HDRLEN + family->hdrsize;
	if (nlh->nlmsg_len < nlmsg_msg_size(hdrlen))
		return -EINVAL;

	ops = genl_get_cmd(hdr->cmd, family);		//根据family和cmd得到方法
	if (ops == NULL)
		return -EOPNOTSUPP;

	if ((ops->flags & GENL_ADMIN_PERM) &&
	    !netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	if ((nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP) {
		int rc;

		if (ops->dumpit == NULL)
			return -EOPNOTSUPP;

		if (!family->parallel_ops) {
			struct netlink_dump_control c = {
				.module = family->module,
				/* we have const, but the netlink API doesn't */
				.data = (void *)ops,
				.dump = genl_lock_dumpit,
				.done = genl_lock_done,
			};

			genl_unlock();
			rc = __netlink_dump_start(net->genl_sock, skb, nlh, &c);
			genl_lock();

		} else {
			struct netlink_dump_control c = {
				.module = family->module,
				.dump = ops->dumpit,
				.done = ops->done,
			};

			rc = __netlink_dump_start(net->genl_sock, skb, nlh, &c);
		}

		return rc;
	}

	if (ops->doit == NULL)
		return -EOPNOTSUPP;

	if (family->maxattr && family->parallel_ops) {
		attrbuf = kmalloc((family->maxattr+1) *
					sizeof(struct nlattr *), GFP_KERNEL);
		if (attrbuf == NULL)
			return -ENOMEM;
	} else
		attrbuf = family->attrbuf;

	if (attrbuf) {
		err = nlmsg_parse(nlh, hdrlen, attrbuf, family->maxattr,	//解析参数内容
				  ops->policy);
		if (err < 0)
			goto out;
	}

	info.snd_seq = nlh->nlmsg_seq;
	info.snd_portid = NETLINK_CB(skb).portid;
	info.nlhdr = nlh;				  //netlink头
	info.genlhdr = nlmsg_data(nlh);			  //通用头
	info.userhdr = nlmsg_data(nlh) + GENL_HDRLEN;  //用户自定义的头
	info.attrs = attrbuf;
	info.dst_sk = skb->sk;
	genl_info_net_set(&info, net);
	memset(&info.user_ptr, 0, sizeof(info.user_ptr));

	if (family->pre_doit) {
		err = family->pre_doit(ops, skb, &info);
		if (err)
			goto out;
	}

	err = ops->doit(skb, &info);	//调用用户定义的方法，此时用户定义的参数均已经解析

	if (family->post_doit)
		family->post_doit(ops, skb, &info);

out:
	if (family->parallel_ops)
		kfree(attrbuf);

	return err;
}
```

## 内核注册处理函数

以OVS使用Generic Netlink为例，说明如何在内核中注册Generic Netlink Socket的处理函数

```c
//genl_family定义了一类操作的，用id来唯一标识
static struct genl_family dp_flow_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = OVS_FLOW_VERSION,
	.maxattr = OVS_FLOW_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_flow_genl_ops,   //处理函数
	.n_ops = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps = &ovs_dp_flow_multicast_group,
	.n_mcgrps = 1,
};

//定义了操作函数，根据cmd来标识
static struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};

//用来解析自定义参数，即nlmsg_parse函数
static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_MASK] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_UFID] = { .type = NLA_UNSPEC, .len = 1 },
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .type = NLA_U32 },
};

//ovs实际处理函数实例
static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;				//已经被解析完成
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_key key;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);   //可以直接使用自定义参数
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];

	/* Must have key and actions. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attr not present in new flow.");
		goto error;
	}
	if (!a[OVS_FLOW_ATTR_ACTIONS]) {
		OVS_NLERR(log, "Flow actions attr not present in new flow.");
		goto error;
	}

	/* Most of the time we need to allocate a new flow, do it before
	 * locking.
	 */
	new_flow = ovs_flow_alloc();
	if (IS_ERR(new_flow)) {
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */
	ovs_match_init(&match, &key, &mask);
	error = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto err_kfree_flow;

	ovs_flow_mask_key(&new_flow->key, &key, true, &mask);

	/* Extract flow identifier. */
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],
				       &key, log);
	if (error)
		goto err_kfree_flow;

	/* Validate actions. */
	error = ovs_nla_copy_actions(net, a[OVS_FLOW_ATTR_ACTIONS],
				     &new_flow->key, &acts, log);
	if (error) {
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,
					ufid_flags);
	if (IS_ERR(reply)) {
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	if (ovs_identifier_is_ufid(&new_flow->id))
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);
	if (!flow)
		flow = ovs_flow_tbl_lookup(&dp->table, &key);
	if (likely(!flow)) {
		rcu_assign_pointer(new_flow->sf_acts, acts);

		/* Put flow in bucket. */
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);
		if (unlikely(error)) {
			acts = NULL;
			goto err_unlock_ovs;
		}

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(new_flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();
	} else {
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		if (unlikely(info->nlhdr->nlmsg_flags & (NLM_F_CREATE
							 | NLM_F_EXCL))) {
			error = -EEXIST;
			goto err_unlock_ovs;
		}
		/* The flow identifier has to be the same for flow updates.
		 * Look for any overlapping flow.
		 */
		if (unlikely(!ovs_flow_cmp(flow, &match))) {
			if (ovs_identifier_is_key(&flow->id))
				flow = ovs_flow_tbl_lookup_exact(&dp->table,
								 &match);
			else /* UFID matches but key is different */
				flow = NULL;
			if (!flow) {
				error = -ENOENT;
				goto err_unlock_ovs;
			}
		}
		/* Update actions. */
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();

		ovs_nla_free_flow_actions_rcu(old_acts);
		ovs_flow_free(new_flow, false);
	}

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
err_kfree_flow:
	ovs_flow_free(new_flow, false);
error:
	return error;
}

## Generic Netlink Socket消息头定义

发送Generic Netlink Socket消息需要符合标准定义，其中nlmsghdr和genlmsghdr是必须的消息头，之后可以自定义消息内容

![generic-header](images/generic-header.png "generic-header")
