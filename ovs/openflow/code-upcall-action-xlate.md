# upcall action解析

本文介绍upcall过程中，流表查找完成后的action解析过程。

报文字段的修改，直接体现在flow对象中，后续会对比源flow和更新后的flow。

# xlate_output_action(OUTPUT)

```c
static void
xlate_output_action(struct xlate_ctx *ctx,
                    ofp_port_t port, uint16_t max_len, bool may_packet_in)
{
    ofp_port_t prev_nf_output_iface = ctx->nf_output_iface;

    ctx->nf_output_iface = NF_OUT_DROP;

    switch (port) {
    case OFPP_IN_PORT:
        compose_output_action(ctx, ctx->xin->flow.in_port.ofp_port, NULL);
        break;
    case OFPP_TABLE:
        xlate_table_action(ctx, ctx->xin->flow.in_port.ofp_port,
                           0, may_packet_in, true);
        break;
    case OFPP_NORMAL:
        xlate_normal(ctx);
        break;
    case OFPP_FLOOD:
        flood_packets(ctx,  false);
        break;
    case OFPP_ALL:
        flood_packets(ctx, true);
        break;
    case OFPP_CONTROLLER:
        execute_controller_action(ctx, max_len,
                                  (ctx->in_group ? OFPR_GROUP
                                   : ctx->in_action_set ? OFPR_ACTION_SET
                                   : OFPR_ACTION),
                                  0);
        break;
    case OFPP_NONE:
        break;
    case OFPP_LOCAL:
    default:
        if (port != ctx->xin->flow.in_port.ofp_port) {
            compose_output_action(ctx, port, NULL);
        } else {
            xlate_report(ctx, "skipping output to input port");
        }
        break;
    }

    if (prev_nf_output_iface == NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_FLOOD;
    } else if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = prev_nf_output_iface;
    } else if (prev_nf_output_iface != NF_OUT_DROP &&
               ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}
```


## xlate_normal

```c
static void
xlate_normal(struct xlate_ctx *ctx)
{
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    struct xbundle *in_xbundle;
    struct xport *in_port;
    struct mac_entry *mac;
    void *mac_port;
    uint16_t vlan;
    uint16_t vid;

    memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
    memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
    wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);

    in_xbundle = lookup_input_bundle(ctx->xbridge, flow->in_port.ofp_port,
                                     ctx->xin->packet != NULL, &in_port);
    if (!in_xbundle) {
        xlate_report(ctx, "no input bundle, dropping");
        return;
    }

    /* Drop malformed frames. */
    if (flow->dl_type == htons(ETH_TYPE_VLAN) &&
        !(flow->vlan_tci & htons(VLAN_CFI))) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet with partial "
                         "VLAN tag received on port %s",
                         ctx->xbridge->name, in_xbundle->name);
        }
        xlate_report(ctx, "partial VLAN tag, dropping");
        return;
    }

    /* Drop frames on bundles reserved for mirroring. */
    if (xbundle_mirror_out(ctx->xbridge, in_xbundle)) {
        if (ctx->xin->packet != NULL) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "bridge %s: dropping packet received on port "
                         "%s, which is reserved exclusively for mirroring",
                         ctx->xbridge->name, in_xbundle->name);
        }
        xlate_report(ctx, "input port is mirror output port, dropping");
        return;
    }

    /* Check VLAN. */
    vid = vlan_tci_to_vid(flow->vlan_tci);    //check vlan是否相符
    if (!input_vid_is_valid(vid, in_xbundle, ctx->xin->packet != NULL)) {
        xlate_report(ctx, "disallowed VLAN VID for this input port, dropping");
        return;
    }
    vlan = input_vid_to_vlan(in_xbundle, vid);

    /* Check other admissibility requirements. */
    if (in_port && !is_admissible(ctx, in_port, vlan)) {
        return;
    }

    /* Learn source MAC. */
    if (ctx->xin->may_learn) {
        update_learning_table(ctx->xbridge, flow, wc, vlan, in_xbundle);
    }
    if (ctx->xin->xcache) {
        struct xc_entry *entry;

        /* Save enough info to update mac learning table later. */
        entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NORMAL);
        entry->u.normal.ofproto = ctx->xbridge->ofproto;
        entry->u.normal.flow = xmemdup(flow, sizeof *flow);
        entry->u.normal.vlan = vlan;
    }

    /* Determine output bundle. */
    if (mcast_snooping_enabled(ctx->xbridge->ms)
        && !eth_addr_is_broadcast(flow->dl_dst)
        && eth_addr_is_multicast(flow->dl_dst)
        && is_ip_any(flow)) {
        struct mcast_snooping *ms = ctx->xbridge->ms;
        struct mcast_group *grp = NULL;

        if (is_igmp(flow)) {
            if (mcast_snooping_is_membership(flow->tp_src) ||
                mcast_snooping_is_query(flow->tp_src)) {
                if (ctx->xin->may_learn && ctx->xin->packet) {
                    update_mcast_snooping_table(ctx->xbridge, flow, vlan,
                                                in_xbundle, ctx->xin->packet);
                }
                /*
                 * IGMP packets need to take the slow path, in order to be
                 * processed for mdb updates. That will prevent expires
                 * firing off even after hosts have sent reports.
                 */
                ctx->xout->slow |= SLOW_ACTION;
            }

            if (mcast_snooping_is_membership(flow->tp_src)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                /* RFC4541: section 2.1.1, item 1: A snooping switch should
                 * forward IGMP Membership Reports only to those ports where
                 * multicast routers are attached.  Alternatively stated: a
                 * snooping switch should not forward IGMP Membership Reports
                 * to ports on which only hosts are attached.
                 * An administrative control may be provided to override this
                 * restriction, allowing the report messages to be flooded to
                 * other ports. */
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, vlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, "multicast traffic, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            }
            return;
        } else if (is_mld(flow)) {
            ctx->xout->slow |= SLOW_ACTION;
            if (ctx->xin->may_learn && ctx->xin->packet) {
                update_mcast_snooping_table(ctx->xbridge, flow, vlan,
                                            in_xbundle, ctx->xin->packet);
            }
            if (is_mld_report(flow)) {
                ovs_rwlock_rdlock(&ms->rwlock);
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                xlate_normal_mcast_send_rports(ctx, ms, in_xbundle, vlan);
                ovs_rwlock_unlock(&ms->rwlock);
            } else {
                xlate_report(ctx, "MLD query, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            }
        } else {
            if ((flow->dl_type == htons(ETH_TYPE_IP)
                 && ip_is_local_multicast(flow->nw_dst))
                || (flow->dl_type == htons(ETH_TYPE_IPV6)
                    && ipv6_is_all_hosts(&flow->ipv6_dst))) {
                /* RFC4541: section 2.1.2, item 2: Packets with a dst IP
                 * address in the 224.0.0.x range which are not IGMP must
                 * be forwarded on all ports */
                xlate_report(ctx, "RFC4541: section 2.1.2, item 2, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
                return;
            }
        }

        /* forwarding to group base ports */
        ovs_rwlock_rdlock(&ms->rwlock);
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            grp = mcast_snooping_lookup4(ms, flow->nw_dst, vlan);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            grp = mcast_snooping_lookup(ms, &flow->ipv6_dst, vlan);
        }
        if (grp) {
            xlate_normal_mcast_send_group(ctx, ms, grp, in_xbundle, vlan);
            xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, vlan);
            xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
        } else {
            if (mcast_snooping_flood_unreg(ms)) {
                xlate_report(ctx, "unregistered multicast, flooding");
                xlate_normal_flood(ctx, in_xbundle, vlan);
            } else {
                xlate_normal_mcast_send_mrouters(ctx, ms, in_xbundle, vlan);
                xlate_normal_mcast_send_fports(ctx, ms, in_xbundle, vlan);
            }
        }
        ovs_rwlock_unlock(&ms->rwlock);
    } else {
        ovs_rwlock_rdlock(&ctx->xbridge->ml->rwlock);
        mac = mac_learning_lookup(ctx->xbridge->ml, flow->dl_dst, vlan);
        mac_port = mac ? mac_entry_get_port(ctx->xbridge->ml, mac) : NULL;
        ovs_rwlock_unlock(&ctx->xbridge->ml->rwlock);

        if (mac_port) {
            struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
            struct xbundle *mac_xbundle = xbundle_lookup(xcfg, mac_port);
            if (mac_xbundle && mac_xbundle != in_xbundle) {
                xlate_report(ctx, "forwarding to learned port");
                output_normal(ctx, mac_xbundle, vlan);
            } else if (!mac_xbundle) {
                xlate_report(ctx, "learned port is unknown, dropping");
            } else {
                xlate_report(ctx, "learned port is input port, dropping");
            }
        } else {
            xlate_report(ctx, "no learned MAC for destination, flooding");
            xlate_normal_flood(ctx, in_xbundle, vlan);
        }
    }
}
```


## flood_packets

```c
static void
flood_packets(struct xlate_ctx *ctx, bool all)
{
    const struct xport *xport;

    HMAP_FOR_EACH (xport, ofp_node, &ctx->xbridge->xports) {
        if (xport->ofp_port == ctx->xin->flow.in_port.ofp_port) {
            continue;
        }

        if (all) {
            compose_output_action__(ctx, xport->ofp_port, NULL, false);
        } else if (!(xport->config & OFPUTIL_PC_NO_FLOOD)) {
            compose_output_action(ctx, xport->ofp_port, NULL);
        }
    }

    ctx->nf_output_iface = NF_OUT_FLOOD;
}
```


### compose_output_action__

```c
static void
compose_output_action__(struct xlate_ctx *ctx, ofp_port_t ofp_port,
                        const struct xlate_bond_recirc *xr, bool check_stp)
{
    const struct xport *xport = get_ofp_port(ctx->xbridge, ofp_port);
    struct flow_wildcards *wc = ctx->wc;
    struct flow *flow = &ctx->xin->flow;
    struct flow_tnl flow_tnl;
    ovs_be16 flow_vlan_tci;
    uint32_t flow_pkt_mark;
    uint8_t flow_nw_tos;
    odp_port_t out_port, odp_port;
    bool tnl_push_pop_send = false;
    uint8_t dscp;

    /* If 'struct flow' gets additional metadata, we'll need to zero it out
     * before traversing a patch port. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 35);
    memset(&flow_tnl, 0, sizeof flow_tnl);

    if (!xport) {
        xlate_report(ctx, "Nonexistent output port");
        return;
    } else if (xport->config & OFPUTIL_PC_NO_FWD) {
        xlate_report(ctx, "OFPPC_NO_FWD set, skipping output");
        return;
    } else if (check_stp) {
        if (is_stp(&ctx->base_flow)) {
            if (!xport_stp_should_forward_bpdu(xport) &&
                !xport_rstp_should_manage_bpdu(xport)) {
                if (ctx->xbridge->stp != NULL) {
                    xlate_report(ctx, "STP not in listening state, "
                            "skipping bpdu output");
                } else if (ctx->xbridge->rstp != NULL) {
                    xlate_report(ctx, "RSTP not managing BPDU in this state, "
                            "skipping bpdu output");
                }
                return;
            }
        } else if (!xport_stp_forward_state(xport) ||
                   !xport_rstp_forward_state(xport)) {
            if (ctx->xbridge->stp != NULL) {
                xlate_report(ctx, "STP not in forwarding state, "
                        "skipping output");
            } else if (ctx->xbridge->rstp != NULL) {
                xlate_report(ctx, "RSTP not in forwarding state, "
                        "skipping output");
            }
            return;
        }
    }

    if (xport->peer) {
        const struct xport *peer = xport->peer;
        struct flow old_flow = ctx->xin->flow;
        bool old_conntrack = ctx->conntracked;
        bool old_was_mpls = ctx->was_mpls;
        cls_version_t old_version = ctx->tables_version;
        struct ofpbuf old_stack = ctx->stack;
        union mf_subvalue new_stack[1024 / sizeof(union mf_subvalue)];
        struct ofpbuf old_action_set = ctx->action_set;
        uint64_t actset_stub[1024 / 8];

        ofpbuf_use_stub(&ctx->stack, new_stack, sizeof new_stack);
        ofpbuf_use_stub(&ctx->action_set, actset_stub, sizeof actset_stub);
        ctx->xbridge = peer->xbridge;
        flow->in_port.ofp_port = peer->ofp_port;
        flow->metadata = htonll(0);
        memset(&flow->tunnel, 0, sizeof flow->tunnel);
        memset(flow->regs, 0, sizeof flow->regs);
        flow->actset_output = OFPP_UNSET;
        ctx->conntracked = false;
        clear_conntrack(flow);

        /* The bridge is now known so obtain its table version. */
        ctx->tables_version
            = ofproto_dpif_get_tables_version(ctx->xbridge->ofproto);

        if (!process_special(ctx, peer) && may_receive(peer, ctx)) {
            if (xport_stp_forward_state(peer) && xport_rstp_forward_state(peer)) {
                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true);
                if (ctx->action_set.size) {
                    /* Translate action set only if not dropping the packet and
                     * not recirculating. */
                    if (!exit_recirculates(ctx)) {
                        xlate_action_set(ctx);
                    }
                }
                /* Check if need to recirculate. */
                if (exit_recirculates(ctx)) {
                    compose_recirculate_action(ctx);
                }
            } else {
                /* Forwarding is disabled by STP and RSTP.  Let OFPP_NORMAL and
                 * the learning action look at the packet, then drop it. */
                struct flow old_base_flow = ctx->base_flow;
                size_t old_size = ctx->odp_actions->size;
                mirror_mask_t old_mirrors = ctx->mirrors;

                xlate_table_action(ctx, flow->in_port.ofp_port, 0, true, true);
                ctx->mirrors = old_mirrors;
                ctx->base_flow = old_base_flow;
                ctx->odp_actions->size = old_size;

                /* Undo changes that may have been done for recirculation. */
                if (exit_recirculates(ctx)) {
                    ctx->action_set.size = ctx->recirc_action_offset;
                    ctx->recirc_action_offset = -1;
                    ctx->last_unroll_offset = -1;
                }
            }
        }

        ctx->xin->flow = old_flow;
        ctx->xbridge = xport->xbridge;
        ofpbuf_uninit(&ctx->action_set);
        ctx->action_set = old_action_set;
        ofpbuf_uninit(&ctx->stack);
        ctx->stack = old_stack;

        /* Restore calling bridge's lookup version. */
        ctx->tables_version = old_version;

        /* The peer bridge popping MPLS should have no effect on the original
         * bridge. */
        ctx->was_mpls = old_was_mpls;

        /* The peer bridge's conntrack execution should have no effect on the
         * original bridge. */
        ctx->conntracked = old_conntrack;

        /* The fact that the peer bridge exits (for any reason) does not mean
         * that the original bridge should exit.  Specifically, if the peer
         * bridge recirculates (which typically modifies the packet), the
         * original bridge must continue processing with the original, not the
         * recirculated packet! */
        ctx->exit = false;

        /* Peer bridge errors do not propagate back. */
        ctx->error = XLATE_OK;

        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
            netdev_vport_inc_rx(peer->netdev, ctx->xin->resubmit_stats);
            if (peer->bfd) {
                bfd_account_rx(peer->bfd, ctx->xin->resubmit_stats);
            }
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
            entry->u.dev.tx = netdev_ref(xport->netdev);
            entry->u.dev.rx = netdev_ref(peer->netdev);
            entry->u.dev.bfd = bfd_ref(peer->bfd);
        }
        return;
    }

    flow_vlan_tci = flow->vlan_tci;
    flow_pkt_mark = flow->pkt_mark;
    flow_nw_tos = flow->nw_tos;

    if (count_skb_priorities(xport)) {
        memset(&wc->masks.skb_priority, 0xff, sizeof wc->masks.skb_priority);
        if (dscp_from_skb_priority(xport, flow->skb_priority, &dscp)) {
            wc->masks.nw_tos |= IP_DSCP_MASK;
            flow->nw_tos &= ~IP_DSCP_MASK;
            flow->nw_tos |= dscp;
        }
    }

    if (xport->is_tunnel) {
        struct in6_addr dst;
         /* Save tunnel metadata so that changes made due to
          * the Logical (tunnel) Port are not visible for any further
          * matches, while explicit set actions on tunnel metadata are.
          */
        flow_tnl = flow->tunnel;
        odp_port = tnl_port_send(xport->ofport, flow, ctx->wc);
        if (odp_port == ODPP_NONE) {
            xlate_report(ctx, "Tunneling decided against output");
            goto out; /* restore flow_nw_tos */
        }
        dst = flow_tnl_dst(&flow->tunnel);
        if (ipv6_addr_equals(&dst, &ctx->orig_tunnel_ipv6_dst)) {
            xlate_report(ctx, "Not tunneling to our own address");
            goto out; /* restore flow_nw_tos */
        }
        if (ctx->xin->resubmit_stats) {
            netdev_vport_inc_tx(xport->netdev, ctx->xin->resubmit_stats);
        }
        if (ctx->xin->xcache) {
            struct xc_entry *entry;

            entry = xlate_cache_add_entry(ctx->xin->xcache, XC_NETDEV);
            entry->u.dev.tx = netdev_ref(xport->netdev);
        }
        out_port = odp_port;
        if (ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {
            xlate_report(ctx, "output to native tunnel");
            tnl_push_pop_send = true;
        } else {
            xlate_report(ctx, "output to kernel tunnel");
            commit_odp_tunnel_action(flow, &ctx->base_flow, ctx->odp_actions);
            flow->tunnel = flow_tnl; /* Restore tunnel metadata */
        }
    } else {
        odp_port = xport->odp_port;
        out_port = odp_port;
        if (ofproto_has_vlan_splinters(ctx->xbridge->ofproto)) {
            ofp_port_t vlandev_port;

            wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
            vlandev_port = vsp_realdev_to_vlandev(ctx->xbridge->ofproto,
                                                  ofp_port, flow->vlan_tci);
            if (vlandev_port != ofp_port) {
                out_port = ofp_port_to_odp_port(ctx->xbridge, vlandev_port);
                flow->vlan_tci = htons(0);
            }
        }
    }

    if (out_port != ODPP_NONE) {
        xlate_commit_actions(ctx);

        if (xr) {
            struct ovs_action_hash *act_hash;

            /* Hash action. */
            act_hash = nl_msg_put_unspec_uninit(ctx->odp_actions,
                                                OVS_ACTION_ATTR_HASH,
                                                sizeof *act_hash);
            act_hash->hash_alg = xr->hash_alg;
            act_hash->hash_basis = xr->hash_basis;

            /* Recirc action. */
            nl_msg_put_u32(ctx->odp_actions, OVS_ACTION_ATTR_RECIRC,
                           xr->recirc_id);
        } else {

            if (tnl_push_pop_send) {
                build_tunnel_send(ctx, xport, flow, odp_port);
                flow->tunnel = flow_tnl; /* Restore tunnel metadata */
            } else {
                odp_port_t odp_tnl_port = ODPP_NONE;

                /* XXX: Write better Filter for tunnel port. We can use inport
                * int tunnel-port flow to avoid these checks completely. */
                if (ofp_port == OFPP_LOCAL &&
                    ovs_native_tunneling_is_on(ctx->xbridge->ofproto)) {

                    odp_tnl_port = tnl_port_map_lookup(flow, wc);
                }

                if (odp_tnl_port != ODPP_NONE) {
                    nl_msg_put_odp_port(ctx->odp_actions,
                                        OVS_ACTION_ATTR_TUNNEL_POP,
                                        odp_tnl_port);
                } else {
                    /* Tunnel push-pop action is not compatible with
                     * IPFIX action. */
                    compose_ipfix_action(ctx, out_port);
                    nl_msg_put_odp_port(ctx->odp_actions,
                                        OVS_ACTION_ATTR_OUTPUT,
                                        out_port);
               }
           }
        }

        ctx->sflow_odp_port = odp_port;
        ctx->sflow_n_outputs++;
        ctx->nf_output_iface = ofp_port;
    }

    if (mbridge_has_mirrors(ctx->xbridge->mbridge) && xport->xbundle) {
        mirror_packet(ctx, xport->xbundle,
                      xbundle_mirror_dst(xport->xbundle->xbridge,
                                         xport->xbundle));
    }

 out:
    /* Restore flow */
    flow->vlan_tci = flow_vlan_tci;
    flow->pkt_mark = flow_pkt_mark;
    flow->nw_tos = flow_nw_tos;
}
```


## execute_controller_action

```c
static void
execute_controller_action(struct xlate_ctx *ctx, int len,
                          enum ofp_packet_in_reason reason,
                          uint16_t controller_id)
{
    struct ofproto_packet_in *pin;
    struct dp_packet *packet;

    ctx->xout->slow |= SLOW_CONTROLLER;
    xlate_commit_actions(ctx);
    if (!ctx->xin->packet) {
        return;
    }

    packet = dp_packet_clone(ctx->xin->packet);

    odp_execute_actions(NULL, &packet, 1, false,
                        ctx->odp_actions->data, ctx->odp_actions->size, NULL);

    pin = xmalloc(sizeof *pin);
    pin->up.packet_len = dp_packet_size(packet);
    pin->up.packet = dp_packet_steal_data(packet);
    pin->up.reason = reason;
    pin->up.table_id = ctx->table_id;
    pin->up.cookie = ctx->rule_cookie;

    flow_get_metadata(&ctx->xin->flow, &pin->up.flow_metadata);

    pin->controller_id = controller_id;
    pin->send_len = len;
    /* If a rule is a table-miss rule then this is
     * a table-miss handled by a table-miss rule.
     *
     * Else, if rule is internal and has a controller action,
     * the later being implied by the rule being processed here,
     * then this is a table-miss handled without a table-miss rule.
     *
     * Otherwise this is not a table-miss. */
    pin->miss_type = OFPROTO_PACKET_IN_NO_MISS;
    if (ctx->rule) {
        if (rule_dpif_is_table_miss(ctx->rule)) {
            pin->miss_type = OFPROTO_PACKET_IN_MISS_FLOW;
        } else if (rule_dpif_is_internal(ctx->rule)) {
            pin->miss_type = OFPROTO_PACKET_IN_MISS_WITHOUT_FLOW;
        }
    }
    ofproto_dpif_send_packet_in(ctx->xbridge->ofproto, pin);
    dp_packet_delete(packet);
}
```


# xlate_group_action(GROUP)

```c
static bool
xlate_group_action(struct xlate_ctx *ctx, uint32_t group_id)
{
    if (xlate_resubmit_resource_check(ctx)) {
        struct group_dpif *group;
        bool got_group;

        got_group = group_dpif_lookup(ctx->xbridge->ofproto, group_id, &group);
        if (got_group) {
            xlate_group_action__(ctx, group);
        } else {
            return true;
        }
    }

    return false;
}
```


# xlate_enqueue_action(ENQUEUE)

```c
static void
xlate_enqueue_action(struct xlate_ctx *ctx,
                     const struct ofpact_enqueue *enqueue)
{
    ofp_port_t ofp_port = enqueue->port;
    uint32_t queue_id = enqueue->queue;
    uint32_t flow_priority, priority;
    int error;

    /* Translate queue to priority. */
    error = dpif_queue_to_priority(ctx->xbridge->dpif, queue_id, &priority);
    if (error) {
        /* Fall back to ordinary output action. */
        xlate_output_action(ctx, enqueue->port, 0, false);
        return;
    }

    /* Check output port. */
    if (ofp_port == OFPP_IN_PORT) {
        ofp_port = ctx->xin->flow.in_port.ofp_port;
    } else if (ofp_port == ctx->xin->flow.in_port.ofp_port) {
        return;
    }

    /* Add datapath actions. */
    flow_priority = ctx->xin->flow.skb_priority;
    ctx->xin->flow.skb_priority = priority;
    compose_output_action(ctx, ofp_port, NULL);
    ctx->xin->flow.skb_priority = flow_priority;

    /* Update NetFlow output port. */
    if (ctx->nf_output_iface == NF_OUT_DROP) {
        ctx->nf_output_iface = ofp_port;
    } else if (ctx->nf_output_iface != NF_OUT_FLOOD) {
        ctx->nf_output_iface = NF_OUT_MULTI;
    }
}
```