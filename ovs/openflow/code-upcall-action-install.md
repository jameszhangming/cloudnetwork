# upcall 流表安装

本文介绍upcall完成后，如何把流表下发到数据面。流表下发的入口为handle_upcalls函数。

调用流程：

![upcall-xlate-action-install](images/upcall-xlate-action-install.png "upcall-xlate-action-install")


# handle_upcalls

```c
static void
handle_upcalls(struct udpif *udpif, struct upcall *upcalls,
               size_t n_upcalls)
{
    struct dpif_op *opsp[UPCALL_MAX_BATCH * 2];
    struct ukey_op ops[UPCALL_MAX_BATCH * 2];
    unsigned int flow_limit;
    size_t n_ops, n_opsp, i;
    bool may_put;

    atomic_read_relaxed(&udpif->flow_limit, &flow_limit);

    may_put = udpif_get_n_flows(udpif) < flow_limit;     //检查数据面的流表数是否超过上限

    /* Handle the packets individually in order of arrival.
     *
     *   - For SLOW_CFM, SLOW_LACP, SLOW_STP, and SLOW_BFD, translation is what
     *     processes received packets for these protocols.
     *
     *   - For SLOW_CONTROLLER, translation sends the packet to the OpenFlow
     *     controller.
     *
     * The loop fills 'ops' with an array of operations to execute in the
     * datapath. */
    n_ops = 0;
    for (i = 0; i < n_upcalls; i++) {
        struct upcall *upcall = &upcalls[i];
        const struct dp_packet *packet = upcall->packet;
        struct ukey_op *op;

        if (upcall->vsp_adjusted) {
            /* This packet was received on a VLAN splinter port.  We added a
             * VLAN to the packet to make the packet resemble the flow, but the
             * actions were composed assuming that the packet contained no
             * VLAN.  So, we must remove the VLAN header from the packet before
             * trying to execute the actions. */
            if (upcall->odp_actions.size) {
                eth_pop_vlan(CONST_CAST(struct dp_packet *, upcall->packet));
            }

            /* Remove the flow vlan tags inserted by vlan splinter logic
             * to ensure megaflow masks generated match the data path flow. */
            CONST_CAST(struct flow *, upcall->flow)->vlan_tci = 0;
        }

        /* Do not install a flow into the datapath if:
         *
         *    - The datapath already has too many flows.
         *
         *    - We received this packet via some flow installed in the kernel
         *      already.
         *
         *    - Upcall was a recirculation but we do not have a reference to
         *      to the recirculation ID. */
        if (may_put && upcall->type == DPIF_UC_MISS &&
            (!upcall->recirc || upcall->have_recirc_ref)) {    //进此流程
            struct udpif_key *ukey = upcall->ukey;

            upcall->ukey_persists = true;
            op = &ops[n_ops++];

            op->ukey = ukey;
            op->dop.type = DPIF_OP_FLOW_PUT;
            op->dop.u.flow_put.flags = DPIF_FP_CREATE;
            op->dop.u.flow_put.key = ukey->key;
            op->dop.u.flow_put.key_len = ukey->key_len;
            op->dop.u.flow_put.mask = ukey->mask;
            op->dop.u.flow_put.mask_len = ukey->mask_len;
            op->dop.u.flow_put.ufid = upcall->ufid;
            op->dop.u.flow_put.stats = NULL;
            ukey_get_actions(ukey, &op->dop.u.flow_put.actions,   //ukey的actions根据upcall的put_action生成
                             &op->dop.u.flow_put.actions_len);
        }

        if (upcall->odp_actions.size) {
            op = &ops[n_ops++];
            op->ukey = NULL;
            op->dop.type = DPIF_OP_EXECUTE;
            op->dop.u.execute.packet = CONST_CAST(struct dp_packet *, packet);
            odp_key_to_pkt_metadata(upcall->key, upcall->key_len,
                                    &op->dop.u.execute.packet->md);
            op->dop.u.execute.actions = upcall->odp_actions.data;
            op->dop.u.execute.actions_len = upcall->odp_actions.size;
            op->dop.u.execute.needs_help = (upcall->xout.slow & SLOW_ACTION) != 0;
            op->dop.u.execute.probe = false;
            op->dop.u.execute.mtu = upcall->mru;
        }
    }

    /* Execute batch.
     *
     * We install ukeys before installing the flows, locking them for exclusive
     * access by this thread for the period of installation. This ensures that
     * other threads won't attempt to delete the flows as we are creating them.
     */
    n_opsp = 0;
    for (i = 0; i < n_ops; i++) {
        struct udpif_key *ukey = ops[i].ukey;

        if (ukey) {
            /* If we can't install the ukey, don't install the flow. */
            if (!ukey_install_start(udpif, ukey)) {      //ukey install，如果成功则可以安装flow
                ukey_delete__(ukey);
                ops[i].ukey = NULL;
                continue;
            }
        }
        opsp[n_opsp++] = &ops[i].dop;
    }
    dpif_operate(udpif->dpif, opsp, n_opsp);     //执行actions，执行flow插入到dp
    for (i = 0; i < n_ops; i++) {
        if (ops[i].ukey) {
            ukey_install_finish(ops[i].ukey, ops[i].dop.error);
        }
    }
}
```


## ukey_install_start

```c
static bool ukey_install_start(struct udpif *udpif, struct udpif_key *new_ukey)
    OVS_TRY_LOCK(true, new_ukey->mutex)
{
    struct umap *umap;
    struct udpif_key *old_ukey;
    uint32_t idx;
    bool locked = false;

    idx = new_ukey->hash % N_UMAPS;
    umap = &udpif->ukeys[idx];        //数组map，得到ukey对应的map
    ovs_mutex_lock(&umap->mutex);
    old_ukey = ukey_lookup(udpif, &new_ukey->ufid);
    if (old_ukey) {
        /* Uncommon case: A ukey is already installed with the same UFID. */
        if (old_ukey->key_len == new_ukey->key_len
            && !memcmp(old_ukey->key, new_ukey->key, new_ukey->key_len)) {
            COVERAGE_INC(handler_duplicate_upcall);
        } else {
            struct ds ds = DS_EMPTY_INITIALIZER;

            odp_format_ufid(&old_ukey->ufid, &ds);
            ds_put_cstr(&ds, " ");
            odp_flow_key_format(old_ukey->key, old_ukey->key_len, &ds);
            ds_put_cstr(&ds, "\n");
            odp_format_ufid(&new_ukey->ufid, &ds);
            ds_put_cstr(&ds, " ");
            odp_flow_key_format(new_ukey->key, new_ukey->key_len, &ds);

            VLOG_WARN_RL(&rl, "Conflicting ukey for flows:\n%s", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    } else {
        ovs_mutex_lock(&new_ukey->mutex);
        cmap_insert(&umap->cmap, &new_ukey->cmap_node, new_ukey->hash);    //插入到bucket中
        locked = true;
    }
    ovs_mutex_unlock(&umap->mutex);

    return locked;
}
```


## ukey_install_finish

```c
static bool
ukey_install_finish(struct udpif_key *ukey, int error)
    OVS_RELEASES(ukey->mutex)
{
    if (!error) {
        ukey_install_finish__(ukey);
    }
    ovs_mutex_unlock(&ukey->mutex);

    return !error;
}
```


# dpif_operate(安装流表)

```c
void dpif_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops)
{
    while (n_ops > 0) {
        size_t chunk;

        /* Count 'chunk', the number of ops that can be executed without
         * needing any help.  Ops that need help should be rare, so we
         * expect this to ordinarily be 'n_ops', that is, all the ops. */
        for (chunk = 0; chunk < n_ops; chunk++) {
            struct dpif_op *op = ops[chunk];

            if (op->type == DPIF_OP_EXECUTE
                && dpif_execute_needs_help(&op->u.execute)) {
                break;
            }
        }

        if (chunk) {
            /* Execute a chunk full of ops that the dpif provider can
             * handle itself, without help. */
            size_t i;

            dpif->dpif_class->operate(dpif, ops, chunk);    //批量处理，实际执行dpif_netlink_operate函数

            for (i = 0; i < chunk; i++) {
                struct dpif_op *op = ops[i];
                int error = op->error;

                switch (op->type) {
                case DPIF_OP_FLOW_PUT: {
                    struct dpif_flow_put *put = &op->u.flow_put;

                    COVERAGE_INC(dpif_flow_put);
                    log_flow_put_message(dpif, put, error);
                    if (error && put->stats) {
                        memset(put->stats, 0, sizeof *put->stats);
                    }
                    break;
                }

                case DPIF_OP_FLOW_GET: {
                    struct dpif_flow_get *get = &op->u.flow_get;

                    COVERAGE_INC(dpif_flow_get);
                    if (error) {
                        memset(get->flow, 0, sizeof *get->flow);
                    }
                    log_flow_get_message(dpif, get, error);

                    break;
                }

                case DPIF_OP_FLOW_DEL: {
                    struct dpif_flow_del *del = &op->u.flow_del;

                    COVERAGE_INC(dpif_flow_del);
                    log_flow_del_message(dpif, del, error);
                    if (error && del->stats) {
                        memset(del->stats, 0, sizeof *del->stats);
                    }
                    break;
                }

                case DPIF_OP_EXECUTE:
                    COVERAGE_INC(dpif_execute);
                    log_execute_message(dpif, &op->u.execute, false, error);
                    break;
                }
            }

            ops += chunk;
            n_ops -= chunk;
        } else {
            /* Help the dpif provider to execute one op. */
            struct dpif_op *op = ops[0];

            COVERAGE_INC(dpif_execute);
            op->error = dpif_execute_with_help(dpif, &op->u.execute);
            ops++;
            n_ops--;
        }
    }
}
```


## dpif_execute_with_help

```c
static int
dpif_execute_with_help(struct dpif *dpif, struct dpif_execute *execute)
{
    struct dpif_execute_helper_aux aux = {dpif, 0};
    struct dp_packet *pp;

    COVERAGE_INC(dpif_execute_with_help);

    pp = execute->packet;
    odp_execute_actions(&aux, &pp, 1, false, execute->actions,
                        execute->actions_len, dpif_execute_helper_cb);
    return aux.error;
}


void
odp_execute_actions(void *dp, struct dp_packet **packets, int cnt, bool steal,
                    const struct nlattr *actions, size_t actions_len,
                    odp_execute_cb dp_execute_action)
{
    const struct nlattr *a;
    unsigned int left;
    int i;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        if (requires_datapath_assistance(a)) {
            if (dp_execute_action) {
                /* Allow 'dp_execute_action' to steal the packet data if we do
                 * not need it any more. */
                bool may_steal = steal && last_action;

                dp_execute_action(dp, packets, cnt, a, may_steal);

                if (last_action) {
                    /* We do not need to free the packets. dp_execute_actions()
                     * has stolen them */
                    return;
                }
            }
            continue;
        }

        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_HASH: {
            const struct ovs_action_hash *hash_act = nl_attr_get(a);

            /* Calculate a hash value directly.  This might not match the
             * value computed by the datapath, but it is much less expensive,
             * and the current use case (bonding) does not require a strict
             * match to work properly. */
            if (hash_act->hash_alg == OVS_HASH_ALG_L4) {
                struct flow flow;
                uint32_t hash;

                for (i = 0; i < cnt; i++) {
                    flow_extract(packets[i], &flow);
                    hash = flow_hash_5tuple(&flow, hash_act->hash_basis);

                    packets[i]->md.dp_hash = hash;
                }
            } else {
                /* Assert on unknown hash algorithm.  */
                OVS_NOT_REACHED();
            }
            break;
        }

        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                eth_push_vlan(packets[i], vlan->vlan_tpid, vlan->vlan_tci);
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
            for (i = 0; i < cnt; i++) {
                eth_pop_vlan(packets[i]);
            }
            break;

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);

            for (i = 0; i < cnt; i++) {
                push_mpls(packets[i], mpls->mpls_ethertype, mpls->mpls_lse);
            }
            break;
         }

        case OVS_ACTION_ATTR_POP_MPLS:
            for (i = 0; i < cnt; i++) {
                pop_mpls(packets[i], nl_attr_get_be16(a));
            }
            break;

        case OVS_ACTION_ATTR_SET:
            for (i = 0; i < cnt; i++) {
                odp_execute_set_action(packets[i], nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SET_MASKED:
            for (i = 0; i < cnt; i++) {
                odp_execute_masked_set_action(packets[i], nl_attr_get(a));
            }
            break;

        case OVS_ACTION_ATTR_SAMPLE:
            for (i = 0; i < cnt; i++) {
                odp_execute_sample(dp, packets[i], steal && last_action, a,
                                   dp_execute_action);
            }

            if (last_action) {
                /* We do not need to free the packets. odp_execute_sample() has
                 * stolen them*/
                return;
            }
            break;

        case OVS_ACTION_ATTR_OUTPUT:
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_UNSPEC:
        case __OVS_ACTION_ATTR_MAX:
            OVS_NOT_REACHED();
        }
    }

    if (steal) {
        for (i = 0; i < cnt; i++) {
            dp_packet_delete(packets[i]);
        }
    }
}
```

