# flow操作

本文介绍内核态OVS流表更新操作流程。


# dpif_netlink_operate(dpif_netlink_class)

```c
static void dpif_netlink_operate(struct dpif *dpif_, struct dpif_op **ops, size_t n_ops)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    while (n_ops > 0) {
        size_t chunk = dpif_netlink_operate__(dpif, ops, n_ops);
        ops += chunk;
        n_ops -= chunk;
    }
}

static size_t dpif_netlink_operate__(struct dpif_netlink *dpif,
                       struct dpif_op **ops, size_t n_ops)
{
    enum { MAX_OPS = 50 };

    struct op_auxdata {
        struct nl_transaction txn;

        struct ofpbuf request;
        uint64_t request_stub[1024 / 8];

        struct ofpbuf reply;
        uint64_t reply_stub[1024 / 8];
    } auxes[MAX_OPS];

    struct nl_transaction *txnsp[MAX_OPS];
    size_t i;

    n_ops = MIN(n_ops, MAX_OPS);
    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_flow_get *get;
        struct dpif_netlink_flow flow;

        ofpbuf_use_stub(&aux->request,
                        aux->request_stub, sizeof aux->request_stub);
        aux->txn.request = &aux->request;

        ofpbuf_use_stub(&aux->reply, aux->reply_stub, sizeof aux->reply_stub);
        aux->txn.reply = NULL;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            dpif_netlink_init_flow_put(dpif, put, &flow);
            if (put->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            dpif_netlink_init_flow_del(dpif, del, &flow);
            if (del->stats) {
                flow.nlmsg_flags |= NLM_F_ECHO;
                aux->txn.reply = &aux->reply;
            }
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        case DPIF_OP_EXECUTE:
            /* Can't execute a packet that won't fit in a Netlink attribute. */
            if (OVS_UNLIKELY(nl_attr_oversized(
                                 dp_packet_size(op->u.execute.packet)))) {
                /* Report an error immediately if this is the first operation.
                 * Otherwise the easiest thing to do is to postpone to the next
                 * call (when this will be the first operation). */
                if (i == 0) {
                    VLOG_ERR_RL(&error_rl,
                                "dropping oversized %"PRIu32"-byte packet",
                                dp_packet_size(op->u.execute.packet));
                    op->error = ENOBUFS;
                    return 1;
                }
                n_ops = i;
            } else {
                dpif_netlink_encode_execute(dpif->dp_ifindex, &op->u.execute,
                                            &aux->request);
            }
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->u.flow_get;
            dpif_netlink_init_flow_get(dpif, get, &flow);
            aux->txn.reply = get->buffer;
            dpif_netlink_flow_to_ofpbuf(&flow, &aux->request);
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    for (i = 0; i < n_ops; i++) {
        txnsp[i] = &auxes[i].txn;
    }
    nl_transact_multiple(NETLINK_GENERIC, txnsp, n_ops);

    for (i = 0; i < n_ops; i++) {
        struct op_auxdata *aux = &auxes[i];
        struct nl_transaction *txn = &auxes[i].txn;
        struct dpif_op *op = ops[i];
        struct dpif_flow_put *put;
        struct dpif_flow_del *del;
        struct dpif_flow_get *get;

        op->error = txn->error;

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            put = &op->u.flow_put;
            if (put->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, put->stats);
                    }
                }
            }
            break;

        case DPIF_OP_FLOW_DEL:
            del = &op->u.flow_del;
            if (del->stats) {
                if (!op->error) {
                    struct dpif_netlink_flow reply;

                    op->error = dpif_netlink_flow_from_ofpbuf(&reply,
                                                              txn->reply);
                    if (!op->error) {
                        dpif_netlink_flow_get_stats(&reply, del->stats);
                    }
                }
            }
            break;

        case DPIF_OP_EXECUTE:
            break;

        case DPIF_OP_FLOW_GET:
            get = &op->u.flow_get;
            if (!op->error) {
                struct dpif_netlink_flow reply;

                op->error = dpif_netlink_flow_from_ofpbuf(&reply, txn->reply);
                if (!op->error) {
                    dpif_netlink_flow_to_dpif_flow(&dpif->dpif, get->flow,
                                                   &reply);
                }
            }
            break;

        default:
            OVS_NOT_REACHED();
        }

        ofpbuf_uninit(&aux->request);
        ofpbuf_uninit(&aux->reply);
    }

    return n_ops;
}
```


## dpif_netlink_init_flow_put

```c
static void
dpif_netlink_init_flow_put(struct dpif_netlink *dpif,
                           const struct dpif_flow_put *put,
                           struct dpif_netlink_flow *request)
{
    static const struct nlattr dummy_action;

    dpif_netlink_flow_init(request);
    request->cmd = (put->flags & DPIF_FP_CREATE
                    ? OVS_FLOW_CMD_NEW : OVS_FLOW_CMD_SET);
    request->dp_ifindex = dpif->dp_ifindex;
    request->key = put->key;
    request->key_len = put->key_len;
    request->mask = put->mask;
    request->mask_len = put->mask_len;
    dpif_netlink_flow_init_ufid(request, put->ufid, false);

    /* Ensure that OVS_FLOW_ATTR_ACTIONS will always be included. */
    request->actions = (put->actions
                        ? put->actions
                        : CONST_CAST(struct nlattr *, &dummy_action));
    request->actions_len = put->actions_len;
    if (put->flags & DPIF_FP_ZERO_STATS) {
        request->clear = true;
    }
    if (put->flags & DPIF_FP_PROBE) {
        request->probe = true;
    }
    request->nlmsg_flags = put->flags & DPIF_FP_MODIFY ? 0 : NLM_F_CREATE;
}
```


## dpif_netlink_flow_to_ofpbuf

```c
static void
dpif_netlink_flow_to_ofpbuf(const struct dpif_netlink_flow *flow,
                            struct ofpbuf *buf)
{
    struct ovs_header *ovs_header;

    nl_msg_put_genlmsghdr(buf, 0, ovs_flow_family,
                          NLM_F_REQUEST | flow->nlmsg_flags,
                          flow->cmd, OVS_FLOW_VERSION);

    ovs_header = ofpbuf_put_uninit(buf, sizeof *ovs_header);
    ovs_header->dp_ifindex = flow->dp_ifindex;

    if (flow->ufid_present) {
        nl_msg_put_unspec(buf, OVS_FLOW_ATTR_UFID, &flow->ufid,
                          sizeof flow->ufid);
    }
    if (flow->ufid_terse) {
        nl_msg_put_u32(buf, OVS_FLOW_ATTR_UFID_FLAGS,
                       OVS_UFID_F_OMIT_KEY | OVS_UFID_F_OMIT_MASK
                       | OVS_UFID_F_OMIT_ACTIONS);
    }
    if (!flow->ufid_terse || !flow->ufid_present) {
        if (flow->key_len) {
            nl_msg_put_unspec(buf, OVS_FLOW_ATTR_KEY,
                              flow->key, flow->key_len);
        }

        if (flow->mask_len) {
            nl_msg_put_unspec(buf, OVS_FLOW_ATTR_MASK,
                              flow->mask, flow->mask_len);
        }
        if (flow->actions || flow->actions_len) {
            nl_msg_put_unspec(buf, OVS_FLOW_ATTR_ACTIONS,
                              flow->actions, flow->actions_len);
        }
    }

    /* We never need to send these to the kernel. */
    ovs_assert(!flow->stats);
    ovs_assert(!flow->tcp_flags);
    ovs_assert(!flow->used);

    if (flow->clear) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_CLEAR);
    }
    if (flow->probe) {
        nl_msg_put_flag(buf, OVS_FLOW_ATTR_PROBE);
    }
}
```


## nl_transact_multiple

```c
void
nl_transact_multiple(int protocol,
                     struct nl_transaction **transactions, size_t n)
{
    struct nl_sock *sock;
    int error;

    error = nl_pool_alloc(protocol, &sock);
    if (!error) {
        nl_sock_transact_multiple(sock, transactions, n);
        nl_pool_release(sock);
    } else {
        nl_sock_record_errors__(transactions, n, error);
    }
}


static void
nl_sock_transact_multiple(struct nl_sock *sock,
                          struct nl_transaction **transactions, size_t n)
{
    int max_batch_count;
    int error;

    if (!n) {
        return;
    }

    /* In theory, every request could have a 64 kB reply.  But the default and
     * maximum socket rcvbuf size with typical Dom0 memory sizes both tend to
     * be a bit below 128 kB, so that would only allow a single message in a
     * "batch".  So we assume that replies average (at most) 4 kB, which allows
     * a good deal of batching.
     *
     * In practice, most of the requests that we batch either have no reply at
     * all or a brief reply. */
    max_batch_count = MAX(sock->rcvbuf / 4096, 1);
    max_batch_count = MIN(max_batch_count, max_iovs);

    while (n > 0) {
        size_t count, bytes;
        size_t done;

        /* Batch up to 'max_batch_count' transactions.  But cap it at about a
         * page of requests total because big skbuffs are expensive to
         * allocate in the kernel.  */
#if defined(PAGESIZE)
        enum { MAX_BATCH_BYTES = MAX(1, PAGESIZE - 512) };
#else
        enum { MAX_BATCH_BYTES = 4096 - 512 };
#endif
        bytes = transactions[0]->request->size;
        for (count = 1; count < n && count < max_batch_count; count++) {
            if (bytes + transactions[count]->request->size > MAX_BATCH_BYTES) {
                break;
            }
            bytes += transactions[count]->request->size;
        }

        error = nl_sock_transact_multiple__(sock, transactions, count, &done);
        transactions += done;
        n -= done;

        if (error == ENOBUFS) {
            VLOG_DBG_RL(&rl, "receive buffer overflow, resending request");
        } else if (error) {
            VLOG_ERR_RL(&rl, "transaction error (%s)", ovs_strerror(error));
            nl_sock_record_errors__(transactions, n, error);
            if (error != EAGAIN) {
                /* A fatal error has occurred.  Abort the rest of
                 * transactions. */
                break;
            }
        }
    }
}
```


# 内核数据面入口

数据面流表操作入口如下：

```c
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
```


## ovs_flow_cmd_new

```c
static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_key key;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
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
	new_flow = ovs_flow_alloc();    //申请sw_flow对象
	if (IS_ERR(new_flow)) {
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */
	ovs_match_init(&match, &key, &mask);           //初始化match对象，设置match的key和mask指针
	error = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],    //设置match->key和match->mask对象
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto err_kfree_flow;

	ovs_flow_mask_key(&new_flow->key, &key, true, &mask);    //生成new_flow的key值，key值通过key&mask计算得到，此时是全量的

	/* Extract flow identifier. */
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],  //得到流表的ufid，唯一标识
				       &key, log);
	if (error)
		goto err_kfree_flow;

	/* Validate actions. */
	error = ovs_nla_copy_actions(net, a[OVS_FLOW_ATTR_ACTIONS],     //拷贝actions
				     &new_flow->key, &acts, log);
	if (error) {
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,     //构造reply对象
					ufid_flags);
	if (IS_ERR(reply)) {
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);     //获得datapath
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	if (ovs_identifier_is_ufid(&new_flow->id))
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);    //查找是否有相同id的flow
	if (!flow)
		flow = ovs_flow_tbl_lookup(&dp->table, &key);     //如果根据id查找没找到，则根据sw_flow的key查找，该key值已经赋值给flow对象
	if (likely(!flow)) {                                  
		rcu_assign_pointer(new_flow->sf_acts, acts);      //仍然没有找到对应的flow，赋值actions指针

		/* Put flow in bucket. */
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);    //插入流表
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
```


### ovs_flow_alloc

```c
struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow;
	struct flow_stats *stats;
	int node;

	flow = kmem_cache_alloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	flow->sf_acts = NULL;
	flow->mask = NULL;
	flow->id.ufid_len = 0;
	flow->id.unmasked_key = NULL;
	flow->stats_last_writer = NUMA_NO_NODE;

	/* Initialize the default stat node. */
	stats = kmem_cache_alloc_node(flow_stats_cache,
				      GFP_KERNEL | __GFP_ZERO, 0);
	if (!stats)
		goto err;

	spin_lock_init(&stats->lock);

	RCU_INIT_POINTER(flow->stats[0], stats);

	for_each_node(node)
		if (node != 0)
			RCU_INIT_POINTER(flow->stats[node], NULL);

	return flow;
err:
	kmem_cache_free(flow_cache, flow);
	return ERR_PTR(-ENOMEM);
}
```


### ovs_match_init

```c
void ovs_match_init(struct sw_flow_match *match,
		    struct sw_flow_key *key,
		    struct sw_flow_mask *mask)
{
	memset(match, 0, sizeof(*match));
	match->key = key;
	match->mask = mask;

	memset(key, 0, sizeof(*key));

	if (mask) {
		memset(&mask->key, 0, sizeof(mask->key));
		mask->range.start = mask->range.end = 0;
	}
}
```


### ovs_nla_get_match

```c
int ovs_nla_get_match(struct net *net, struct sw_flow_match *match,
		      const struct nlattr *nla_key,
		      const struct nlattr *nla_mask,
		      bool log)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	const struct nlattr *encap;
	struct nlattr *newmask = NULL;
	u64 key_attrs = 0;
	u64 mask_attrs = 0;
	bool encap_valid = false;
	int err;

	err = parse_flow_nlattrs(nla_key, a, &key_attrs, log);
	if (err)
		return err;

	if ((key_attrs & (1ULL << OVS_KEY_ATTR_ETHERNET)) &&
	    (key_attrs & (1ULL << OVS_KEY_ATTR_ETHERTYPE)) &&
	    (nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]) == htons(ETH_P_8021Q))) {
		__be16 tci;

		if (!((key_attrs & (1ULL << OVS_KEY_ATTR_VLAN)) &&
		      (key_attrs & (1ULL << OVS_KEY_ATTR_ENCAP)))) {
			OVS_NLERR(log, "Invalid Vlan frame.");
			return -EINVAL;
		}

		key_attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		encap = a[OVS_KEY_ATTR_ENCAP];
		key_attrs &= ~(1ULL << OVS_KEY_ATTR_ENCAP);
		encap_valid = true;

		if (tci & htons(VLAN_TAG_PRESENT)) {
			err = parse_flow_nlattrs(encap, a, &key_attrs, log);
			if (err)
				return err;
		} else if (!tci) {
			/* Corner case for truncated 802.1Q header. */
			if (nla_len(encap)) {
				OVS_NLERR(log, "Truncated 802.1Q header has non-zero encap attribute.");
				return -EINVAL;
			}
		} else {
			OVS_NLERR(log, "Encap attr is set for non-VLAN frame");
			return  -EINVAL;
		}
	}

	err = ovs_key_from_nlattrs(net, match, key_attrs, a, false, log);     //解析key_attrs对象，设置到match->key
	if (err)
		return err;

	if (match->mask) {
		if (!nla_mask) {
			/* Create an exact match mask. We need to set to 0xff
			 * all the 'match->mask' fields that have been touched
			 * in 'match->key'. We cannot simply memset
			 * 'match->mask', because padding bytes and fields not
			 * specified in 'match->key' should be left to 0.
			 * Instead, we use a stream of netlink attributes,
			 * copied from 'key' and set to 0xff.
			 * ovs_key_from_nlattrs() will take care of filling
			 * 'match->mask' appropriately.
			 */
			newmask = kmemdup(nla_key,
					  nla_total_size(nla_len(nla_key)),
					  GFP_KERNEL);
			if (!newmask)
				return -ENOMEM;

			mask_set_nlattr(newmask, 0xff);

			/* The userspace does not send tunnel attributes that
			 * are 0, but we should not wildcard them nonetheless.
			 */
			if (match->key->tun_key.u.ipv4.dst)
				SW_FLOW_KEY_MEMSET_FIELD(match, tun_key,
							 0xff, true);

			nla_mask = newmask;
		}

		err = parse_flow_mask_nlattrs(nla_mask, a, &mask_attrs, log);
		if (err)
			goto free_newmask;

		/* Always match on tci. */
		SW_FLOW_KEY_PUT(match, eth.tci, htons(0xffff), true);

		if (mask_attrs & 1ULL << OVS_KEY_ATTR_ENCAP) {
			__be16 eth_type = 0;
			__be16 tci = 0;

			if (!encap_valid) {
				OVS_NLERR(log, "Encap mask attribute is set for non-VLAN frame.");
				err = -EINVAL;
				goto free_newmask;
			}

			mask_attrs &= ~(1ULL << OVS_KEY_ATTR_ENCAP);
			if (a[OVS_KEY_ATTR_ETHERTYPE])
				eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);

			if (eth_type == htons(0xffff)) {
				mask_attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
				encap = a[OVS_KEY_ATTR_ENCAP];
				err = parse_flow_mask_nlattrs(encap, a,
							      &mask_attrs, log);
				if (err)
					goto free_newmask;
			} else {
				OVS_NLERR(log, "VLAN frames must have an exact match on the TPID (mask=%x).",
					  ntohs(eth_type));
				err = -EINVAL;
				goto free_newmask;
			}

			if (a[OVS_KEY_ATTR_VLAN])
				tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);

			if (!(tci & htons(VLAN_TAG_PRESENT))) {
				OVS_NLERR(log, "VLAN tag present bit must have an exact match (tci_mask=%x).",
					  ntohs(tci));
				err = -EINVAL;
				goto free_newmask;
			}
		}

		err = ovs_key_from_nlattrs(net, match, mask_attrs, a, true,         //倒数第二个参数为true，将设置match->mask的内容
					   log);
		if (err)
			goto free_newmask;
	}

	if (!match_validate(match, key_attrs, mask_attrs, log))
		err = -EINVAL;

free_newmask:
	kfree(newmask);
	return err;
}


static int ovs_key_from_nlattrs(struct net *net, struct sw_flow_match *match,
				u64 attrs, const struct nlattr **a,
				bool is_mask, bool log)
{
	int err;

	err = metadata_from_nlattrs(net, match, &attrs, a, is_mask, log);
	if (err)
		return err;

	if (attrs & (1ULL << OVS_KEY_ATTR_ETHERNET)) {
		const struct ovs_key_ethernet *eth_key;

		eth_key = nla_data(a[OVS_KEY_ATTR_ETHERNET]);
		SW_FLOW_KEY_MEMCPY(match, eth.src,
				eth_key->eth_src, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, eth.dst,
				eth_key->eth_dst, ETH_ALEN, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERNET);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_VLAN)) {
		__be16 tci;

		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		if (!(tci & htons(VLAN_TAG_PRESENT))) {
			if (is_mask)
				OVS_NLERR(log, "VLAN TCI mask does not have exact match for VLAN_TAG_PRESENT bit.");
			else
				OVS_NLERR(log, "VLAN TCI does not have VLAN_TAG_PRESENT bit set.");

			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.tci, tci, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_VLAN);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ETHERTYPE)) {
		__be16 eth_type;

		eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);
		if (is_mask) {
			/* Always exact match EtherType. */
			eth_type = htons(0xffff);
		} else if (!eth_proto_is_802_3(eth_type)) {
			OVS_NLERR(log, "EtherType %x is less than min %x",
				  ntohs(eth_type), ETH_P_802_3_MIN);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.type, eth_type, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ETHERTYPE);
	} else if (!is_mask) {
		SW_FLOW_KEY_PUT(match, eth.type, htons(ETH_P_802_2), is_mask);
	}

	if (attrs & (1 << OVS_KEY_ATTR_IPV4)) {
		const struct ovs_key_ipv4 *ipv4_key;

		ipv4_key = nla_data(a[OVS_KEY_ATTR_IPV4]);
		if (!is_mask && ipv4_key->ipv4_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv4 frag type %d is out of range max %d",
				  ipv4_key->ipv4_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv4_key->ipv4_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv4_key->ipv4_tos, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv4_key->ipv4_ttl, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv4_key->ipv4_frag, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				ipv4_key->ipv4_src, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
				ipv4_key->ipv4_dst, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_IPV4);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_IPV6)) {
		const struct ovs_key_ipv6 *ipv6_key;

		ipv6_key = nla_data(a[OVS_KEY_ATTR_IPV6]);
		if (!is_mask && ipv6_key->ipv6_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv6 frag type %d is out of range max %d",
				  ipv6_key->ipv6_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}

		if (!is_mask && ipv6_key->ipv6_label & htonl(0xFFF00000)) {
			OVS_NLERR(log,
				  "Invalid IPv6 flow label value (value=%x, max=%x).",
				  ntohl(ipv6_key->ipv6_label), (1 << 20) - 1);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv6.label,
				ipv6_key->ipv6_label, is_mask);
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv6_key->ipv6_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv6_key->ipv6_tclass, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv6_key->ipv6_hlimit, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv6_key->ipv6_frag, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.src,
				ipv6_key->ipv6_src,
				sizeof(match->key->ipv6.addr.src),
				is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.dst,
				ipv6_key->ipv6_dst,
				sizeof(match->key->ipv6.addr.dst),
				is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_IPV6);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ARP)) {
		const struct ovs_key_arp *arp_key;

		arp_key = nla_data(a[OVS_KEY_ATTR_ARP]);
		if (!is_mask && (arp_key->arp_op & htons(0xff00))) {
			OVS_NLERR(log, "Unknown ARP opcode (opcode=%d).",
				  arp_key->arp_op);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				arp_key->arp_sip, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
			arp_key->arp_tip, is_mask);
		SW_FLOW_KEY_PUT(match, ip.proto,
				ntohs(arp_key->arp_op), is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.sha,
				arp_key->arp_sha, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.tha,
				arp_key->arp_tha, ETH_ALEN, is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_ARP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_MPLS)) {
		const struct ovs_key_mpls *mpls_key;

		mpls_key = nla_data(a[OVS_KEY_ATTR_MPLS]);
		SW_FLOW_KEY_PUT(match, mpls.top_lse,
				mpls_key->mpls_lse, is_mask);

		attrs &= ~(1ULL << OVS_KEY_ATTR_MPLS);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_TCP)) {
		const struct ovs_key_tcp *tcp_key;

		tcp_key = nla_data(a[OVS_KEY_ATTR_TCP]);
		SW_FLOW_KEY_PUT(match, tp.src, tcp_key->tcp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, tcp_key->tcp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_TCP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_TCP_FLAGS)) {
		SW_FLOW_KEY_PUT(match, tp.flags,
				nla_get_be16(a[OVS_KEY_ATTR_TCP_FLAGS]),
				is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_TCP_FLAGS);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_UDP)) {
		const struct ovs_key_udp *udp_key;

		udp_key = nla_data(a[OVS_KEY_ATTR_UDP]);
		SW_FLOW_KEY_PUT(match, tp.src, udp_key->udp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, udp_key->udp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_UDP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_SCTP)) {
		const struct ovs_key_sctp *sctp_key;

		sctp_key = nla_data(a[OVS_KEY_ATTR_SCTP]);
		SW_FLOW_KEY_PUT(match, tp.src, sctp_key->sctp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, sctp_key->sctp_dst, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_SCTP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ICMP)) {
		const struct ovs_key_icmp *icmp_key;

		icmp_key = nla_data(a[OVS_KEY_ATTR_ICMP]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmp_key->icmp_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmp_key->icmp_code), is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ICMP);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ICMPV6)) {
		const struct ovs_key_icmpv6 *icmpv6_key;

		icmpv6_key = nla_data(a[OVS_KEY_ATTR_ICMPV6]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmpv6_key->icmpv6_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmpv6_key->icmpv6_code), is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ICMPV6);
	}

	if (attrs & (1ULL << OVS_KEY_ATTR_ND)) {
		const struct ovs_key_nd *nd_key;

		nd_key = nla_data(a[OVS_KEY_ATTR_ND]);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.target,
			nd_key->nd_target,
			sizeof(match->key->ipv6.nd.target),
			is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.sll,
			nd_key->nd_sll, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.tll,
				nd_key->nd_tll, ETH_ALEN, is_mask);
		attrs &= ~(1ULL << OVS_KEY_ATTR_ND);
	}

	if (attrs != 0) {
		OVS_NLERR(log, "Unknown key attributes %llx",
			  (unsigned long long)attrs);
		return -EINVAL;
	}

	return 0;
}

#define SW_FLOW_KEY_PUT(match, field, value, is_mask) \
	do { \
		update_range(match, offsetof(struct sw_flow_key, field),    \      //更新range
			     sizeof((match)->key->field), is_mask);	    \
		if (is_mask)						    \
			(match)->mask->key.field = value;		    \
		else							    \
			(match)->key->field = value;		            \
	} while (0)
	
	
static void update_range(struct sw_flow_match *match,
			 size_t offset, size_t size, bool is_mask)
{
	struct sw_flow_key_range *range;
	size_t start = rounddown(offset, sizeof(long));     //取小，即覆盖更多的范围
	size_t end = roundup(offset + size, sizeof(long));  //取大，即覆盖更多的范围

	if (!is_mask)
		range = &match->range;
	else
		range = &match->mask->range;

	if (range->start == range->end) {     //初始值，两者都为0
		range->start = start;
		range->end = end;
		return;
	}

	if (range->start > start)      //start值变小
		range->start = start;

	if (range->end < end)          //end值增大
		range->end = end;
}
```


### ovs_flow_mask_key

```c
void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       bool full, const struct sw_flow_mask *mask)
{
	int start = full ? 0 : mask->range.start;
	int len = full ? sizeof *dst : range_n_bytes(&mask->range);
	const long *m = (const long *)((const u8 *)&mask->key + start);
	const long *s = (const long *)((const u8 *)src + start);
	long *d = (long *)((u8 *)dst + start);
	int i;

	/* If 'full' is true then all of 'dst' is fully initialized. Otherwise,
	 * if 'full' is false the memory outside of the 'mask->range' is left
	 * uninitialized. This can be used as an optimization when further
	 * operations on 'dst' only use contents within 'mask->range'.
	 */
	for (i = 0; i < len; i += sizeof(long))
		*d++ = *s++ & *m++;
}
```


### ovs_nla_copy_actions

```c
int ovs_nla_copy_actions(struct net *net, const struct nlattr *attr,
			 const struct sw_flow_key *key,
			 struct sw_flow_actions **sfa, bool log)
{
	int err;

	*sfa = nla_alloc_flow_actions(nla_len(attr), log);
	if (IS_ERR(*sfa))
		return PTR_ERR(*sfa);

	(*sfa)->orig_len = nla_len(attr);
	err = __ovs_nla_copy_actions(net, attr, key, 0, sfa, key->eth.type,
				     key->eth.tci, log);
	if (err)
		ovs_nla_free_flow_actions(*sfa);

	return err;
}


static int __ovs_nla_copy_actions(struct net *net, const struct nlattr *attr,
				  const struct sw_flow_key *key,
				  int depth, struct sw_flow_actions **sfa,
				  __be16 eth_type, __be16 vlan_tci, bool log)
{
	const struct nlattr *a;
	int rem, err;

	if (depth >= SAMPLE_ACTION_DEPTH)
		return -EOVERFLOW;

	nla_for_each_nested(a, attr, rem) {
		/* Expected argument lengths, (u32)-1 for variable length. */
		static const u32 action_lens[OVS_ACTION_ATTR_MAX + 1] = {
			[OVS_ACTION_ATTR_OUTPUT] = sizeof(u32),
			[OVS_ACTION_ATTR_RECIRC] = sizeof(u32),
			[OVS_ACTION_ATTR_USERSPACE] = (u32)-1,
			[OVS_ACTION_ATTR_PUSH_MPLS] = sizeof(struct ovs_action_push_mpls),
			[OVS_ACTION_ATTR_POP_MPLS] = sizeof(__be16),
			[OVS_ACTION_ATTR_PUSH_VLAN] = sizeof(struct ovs_action_push_vlan),
			[OVS_ACTION_ATTR_POP_VLAN] = 0,
			[OVS_ACTION_ATTR_SET] = (u32)-1,
			[OVS_ACTION_ATTR_SET_MASKED] = (u32)-1,
			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1,
			[OVS_ACTION_ATTR_HASH] = sizeof(struct ovs_action_hash),
			[OVS_ACTION_ATTR_CT] = (u32)-1,
		};
		const struct ovs_action_push_vlan *vlan;
		int type = nla_type(a);
		bool skip_copy;

		if (type > OVS_ACTION_ATTR_MAX ||
		    (action_lens[type] != nla_len(a) &&
		     action_lens[type] != (u32)-1))
			return -EINVAL;

		skip_copy = false;
		switch (type) {
		case OVS_ACTION_ATTR_UNSPEC:
			return -EINVAL;

		case OVS_ACTION_ATTR_USERSPACE:
			err = validate_userspace(a);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_OUTPUT:
			if (nla_get_u32(a) >= DP_MAX_PORTS)
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_HASH: {
			const struct ovs_action_hash *act_hash = nla_data(a);

			switch (act_hash->hash_alg) {
			case OVS_HASH_ALG_L4:
				break;
			default:
				return  -EINVAL;
			}

			break;
		}

		case OVS_ACTION_ATTR_POP_VLAN:
			vlan_tci = htons(0);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			vlan = nla_data(a);
			if (vlan->vlan_tpid != htons(ETH_P_8021Q))
				return -EINVAL;
			if (!(vlan->vlan_tci & htons(VLAN_TAG_PRESENT)))
				return -EINVAL;
			vlan_tci = vlan->vlan_tci;
			break;

		case OVS_ACTION_ATTR_RECIRC:
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS: {
			const struct ovs_action_push_mpls *mpls = nla_data(a);

			if (!eth_p_mpls(mpls->mpls_ethertype))
				return -EINVAL;
			/* Prohibit push MPLS other than to a white list
			 * for packets that have a known tag order.
			 */
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    (eth_type != htons(ETH_P_IP) &&
			     eth_type != htons(ETH_P_IPV6) &&
			     eth_type != htons(ETH_P_ARP) &&
			     eth_type != htons(ETH_P_RARP) &&
			     !eth_p_mpls(eth_type)))
				return -EINVAL;
			eth_type = mpls->mpls_ethertype;
			break;
		}

		case OVS_ACTION_ATTR_POP_MPLS:
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    !eth_p_mpls(eth_type))
				return -EINVAL;

			/* Disallow subsequent L2.5+ set and mpls_pop actions
			 * as there is no check here to ensure that the new
			 * eth_type is valid and thus set actions could
			 * write off the end of the packet or otherwise
			 * corrupt it.
			 *
			 * Support for these actions is planned using packet
			 * recirculation.
			 */
			eth_type = htons(0);
			break;

		case OVS_ACTION_ATTR_SET:
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, false, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, true, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = validate_and_copy_sample(net, a, key, depth, sfa,
						       eth_type, vlan_tci, log);
			if (err)
				return err;
			skip_copy = true;
			break;

		case OVS_ACTION_ATTR_CT:
			err = ovs_ct_copy_action(net, a, key, sfa, log);
			if (err)
				return err;
			skip_copy = true;
			break;

		default:
			OVS_NLERR(log, "Unknown Action type %d", type);
			return -EINVAL;
		}
		if (!skip_copy) {
			err = copy_action(a, sfa, log);
			if (err)
				return err;
		}
	}

	if (rem > 0)
		return -EINVAL;

	return 0;
}
```


### ovs_flow_tbl_lookup_ufid

```c
struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
					 const struct sw_flow_id *ufid)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ufid_ti);
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;

	hash = ufid_hash(ufid);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, ufid_table.node[ti->node_ver]) {
		if (flow->ufid_table.hash == hash &&
		    ovs_flow_cmp_ufid(flow, ufid))
			return flow;
	}
	return NULL;
}
```


### ovs_flow_tbl_lookup

```c
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct mask_array *ma = rcu_dereference_ovsl(tbl->mask_array);
	u32 __always_unused n_mask_hit;
	u32 index = 0;

	return flow_lookup(tbl, ti, ma, key, &n_mask_hit, &index);
}

static struct sw_flow *flow_lookup(struct flow_table *tbl,
				   struct table_instance *ti,
				   const struct mask_array *ma,
				   const struct sw_flow_key *key,
				   u32 *n_mask_hit,
				   u32 *index)
{
	struct sw_flow_mask *mask;
	struct sw_flow *flow;
	int i;

	if (*index < ma->max) {    //如果index的值小于mask的entry数量，说明index是有效值，基于该值获取sw_flow_mask值
		mask = rcu_dereference_ovsl(ma->masks[*index]);
		if (mask) {
			flow = masked_flow_lookup(ti, key, mask, n_mask_hit);      //使用当前mask进行检索
			if (flow)
				return flow;
		}
	}

	for (i = 0; i < ma->max; i++)  {

		if (i == *index)	//前面已查询过，所以跳过该值
			continue;

		mask = rcu_dereference_ovsl(ma->masks[i]);
		if (!mask)
			continue;

		flow = masked_flow_lookup(ti, key, mask, n_mask_hit);    //使用当前mask进行检索
		if (flow) { /* Found */
			*index = i;		//更新index指向的值，下次可以直接命中
			return flow;
		}
	}

	return NULL;
}

static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  const struct sw_flow_mask *mask,
					  u32 *n_mask_hit)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;
	struct sw_flow_key masked_key;

    ovs_flow_mask_key(&masked_key, unmasked, false, mask);    //根据mask计算出masked_key
	hash = flow_hash(&masked_key, &mask->range);              //使用masked_key和range算出hash key，即flow->key的值
	head = find_bucket(ti, hash);
	(*n_mask_hit)++;
	hlist_for_each_entry_rcu(flow, head, flow_table.node[ti->node_ver]) {
		if (flow->mask == mask && flow->flow_table.hash == hash &&    //flow使用mask与当前的mask相同
		    flow_cmp_masked_key(flow, &masked_key, &mask->range))     //比较masked_key是否匹配flow
			return flow;
	}
	return NULL;
}
```


## ovs_flow_cmd_set

```c
static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply = NULL;
	struct datapath *dp;
	struct sw_flow_actions *old_acts = NULL, *acts = NULL;
	struct sw_flow_match match;
	struct sw_flow_id sfid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	/* Extract key. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attribute not present in set flow.");
		goto error;
	}

	ufid_present = ovs_nla_get_ufid(&sfid, a[OVS_FLOW_ATTR_UFID], log);
	ovs_match_init(&match, &key, &mask);                                     //初始化match对象，设置match的key和mask指针
	error = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],             //解析消息设置match->key和match->mask对象
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto error;

	/* Validate actions. */
	if (a[OVS_FLOW_ATTR_ACTIONS]) {
		acts = get_flow_actions(net, a[OVS_FLOW_ATTR_ACTIONS], &key,        //解析得到actions
					&mask, log);
		if (IS_ERR(acts)) {
			error = PTR_ERR(acts);
			goto error;
		}

		/* Can allocate before locking if have acts. */
		reply = ovs_flow_cmd_alloc_info(acts, &sfid, info, false,           //构造reply对象
						ufid_flags);
		if (IS_ERR(reply)) {
			error = PTR_ERR(reply);
			goto err_kfree_acts;
		}
	}

	ovs_lock();
	dp = get_dp(net, ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}
	/* Check that the flow exists. */
	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &sfid);                 //根据ufid得到flow
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);               //根据match检索flow
	if (unlikely(!flow)) {
		error = -ENOENT;
		goto err_unlock_ovs;
	}

	/* Update actions, if present. */
	if (likely(acts)) {
		old_acts = ovsl_dereference(flow->sf_acts);            //得到之前的actions
		rcu_assign_pointer(flow->sf_acts, acts);               //更新actions

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
	} else {
		/* Could not alloc without acts before locking. */
		reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex,
						info, OVS_FLOW_CMD_NEW, false,
						ufid_flags);

		if (unlikely(IS_ERR(reply))) {
			error = PTR_ERR(reply);
			goto err_unlock_ovs;
		}
	}

	/* Clear stats. */
	if (a[OVS_FLOW_ATTR_CLEAR])
		ovs_flow_stats_clear(flow);
	ovs_unlock();

	if (reply)
		ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
	if (old_acts)
		ovs_nla_free_flow_actions_rcu(old_acts);

	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	ovs_nla_free_flow_actions(acts);
error:
	return error;
}
```


### ovs_flow_tbl_lookup_exact

```c
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match)
{
	struct mask_array *ma = ovsl_dereference(tbl->mask_array);     //得到mask array对象
	int i;

	/* Always called under ovs-mutex. */
	for (i = 0; i < ma->max; i++) {                     //遍历mask对象
		struct table_instance *ti = ovsl_dereference(tbl->ti);
		u32 __always_unused n_mask_hit;
		struct sw_flow_mask *mask;
		struct sw_flow *flow;

		mask = ovsl_dereference(ma->masks[i]);        //得到当前的mask
		if (!mask)
			continue;
		flow = masked_flow_lookup(ti, match->key, mask, &n_mask_hit);     //根据key和mask检索flow
		if (flow && ovs_identifier_is_key(&flow->id) &&
		    ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}
```


## ovs_flow_cmd_del

```c
static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct net *net = sock_net(skb->sk);
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow = NULL;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, NULL);                             //初始化match对象，设置match的key和mask指针
		err = ovs_nla_get_match(net, &match, a[OVS_FLOW_ATTR_KEY],      //解析消息设置match->key和match->mask对象
					NULL, log);
		if (unlikely(err))
			return err;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		err = -ENODEV;
		goto unlock;
	}

	if (unlikely(!a[OVS_FLOW_ATTR_KEY] && !ufid_present)) {
		err = ovs_flow_tbl_flush(&dp->table);
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);           //根据ufid检索到flow
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);         //根据match中的key和mask值检索到flow
	if (unlikely(!flow)) {
		err = -ENOENT;
		goto unlock;
	}

	ovs_flow_tbl_remove(&dp->table, flow);           //删除flow
	ovs_unlock();

	reply = ovs_flow_cmd_alloc_info(rcu_dereference_raw(flow->sf_acts),
					&flow->id, info, false, ufid_flags);

	if (likely(reply)) {
		if (likely(!IS_ERR(reply))) {
			rcu_read_lock();	/*To keep RCU checker happy. */
			err = ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex,
						     reply, info->snd_portid,
						     info->snd_seq, 0,
						     OVS_FLOW_CMD_DEL,
						     ufid_flags);
			rcu_read_unlock();
			BUG_ON(err < 0);
			ovs_notify(&dp_flow_genl_family, &ovs_dp_flow_multicast_group, reply, info);
		} else {
			genl_set_err(&dp_flow_genl_family, sock_net(skb->sk), 0,
				     GROUP_ID(&ovs_dp_flow_multicast_group), PTR_ERR(reply));

		}
	}

	ovs_flow_free(flow, true);
	return 0;
unlock:
	ovs_unlock();
	return err;
}
```


### ovs_flow_tbl_remove

```c
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti = ovsl_dereference(table->ti);
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&flow->flow_table.node[ti->node_ver]);    //删除flow，数据面流表查找的表
	table->count--;
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);    //删除flow，ufid的表
		table->ufid_count--;
	}

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
	flow_mask_remove(table, flow->mask);      //删除mask，如果该mask没有flow使用
}
```


# ovs_flow_tbl_insert(数据面)

```c
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

	err = flow_mask_insert(table, flow, mask);
	if (err)
		return err;
	flow_key_insert(table, flow);
	if (ovs_identifier_is_ufid(&flow->id))  
		flow_ufid_insert(table, flow);

	return 0;
}
```


## flow_mask_insert

```c
static int flow_mask_insert(struct flow_table *tbl, struct sw_flow *flow,
			    const struct sw_flow_mask *new)
{
	struct sw_flow_mask *mask;

	mask = flow_mask_find(tbl, new);     //查找mask，是否有相同的mask
	if (!mask) {
		struct mask_array *ma;
		int i;

		/* Allocate a new mask if none exsits. */
		mask = mask_alloc();           //构建mask对象
		if (!mask)
			return -ENOMEM;

		mask->key = new->key;
		mask->range = new->range;

		/* Add mask to mask-list. */
		ma = ovsl_dereference(tbl->mask_array);
		if (ma->count >= ma->max) {                  //判断mask是否达到上限
			int err;

			err = tbl_mask_array_realloc(tbl, ma->max +     //mask数组扩容
							  MASK_ARRAY_SIZE_MIN);
			if (err) {
				kfree(mask);
				return err;
			}
			ma = ovsl_dereference(tbl->mask_array);
		}

		for (i = 0; i < ma->max; i++) {
			struct sw_flow_mask *t;

			t = ovsl_dereference(ma->masks[i]);
			if (!t) {
				rcu_assign_pointer(ma->masks[i], mask);     //插入到数组中
				ma->count++;
				break;
			}
		}

	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;             //mask的用户加一
	}

	flow->mask = mask;      //设置flow的mask
	return 0;
}

static struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
					   const struct sw_flow_mask *mask)
{
	struct mask_array *ma;
	int i;

	ma = ovsl_dereference(tbl->mask_array);     //遍历mask
	for (i = 0; i < ma->max; i++) {
		struct sw_flow_mask *t;

		t = ovsl_dereference(ma->masks[i]);
		if (t && mask_equal(mask, t))          //判断mask相同
			return t;
	}

	return NULL;
}

static bool mask_equal(const struct sw_flow_mask *a,
		       const struct sw_flow_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
}
```


## flow_key_insert

```c
static void flow_key_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	flow->flow_table.hash = flow_hash(&flow->key, &flow->mask->range);    //计算flow的hash值
	ti = ovsl_dereference(table->ti);
	table_instance_insert(ti, flow);        //插入flow
	table->count++;

	/* Expand table, if necessary, to make room. */
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti, false);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets, false);

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		table->last_rehash = jiffies;
	}
}

static void table_instance_insert(struct table_instance *ti,
				  struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->flow_table.hash);     //根据hash值，得到bucket
	hlist_add_head_rcu(&flow->flow_table.node[ti->node_ver], head);   //flow添加到bucket中
}

static struct table_instance *table_instance_expand(struct table_instance *ti,
						    bool ufid)
{
	return table_instance_rehash(ti, ti->n_buckets * 2, ufid);
}

static struct table_instance *table_instance_rehash(struct table_instance *ti,
						    int n_buckets, bool ufid)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);     //申请新的table instance对象
	if (!new_ti)
		return NULL;

	flow_table_copy_flows(ti, new_ti, ufid);      //拷贝流表

	return new_ti;
}
```


## flow_ufid_insert

```c
static void flow_ufid_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti;

	flow->ufid_table.hash = ufid_hash(&flow->id);     //根据id计算hash值
	ti = ovsl_dereference(table->ufid_ti);            //得到ufid的table instance
	ufid_table_instance_insert(ti, flow);             //flow插入到该table instance中
	table->ufid_count++;

	/* Expand table, if necessary, to make room. */
	if (table->ufid_count > ti->n_buckets) {
		struct table_instance *new_ti;

		new_ti = table_instance_expand(ti, true);
		if (new_ti) {
			rcu_assign_pointer(table->ufid_ti, new_ti);
			call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		}
	}
}
```

