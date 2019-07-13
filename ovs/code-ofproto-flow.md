# ofproto流表操作

本文介绍openflow流表操作的流程。

主要数据结构：

![ofproto-flow-class](images/ofproto-flow-class.png "ofproto-flow-class")

调用流程：

![ofproto-flow-flow](images/ofproto-flow-flow.png "ofproto-flow-flow")


# 调用入口

bridge_reconfigure->bridge_run__->ofproto_run

```c
int
ofproto_run(struct ofproto *p)
{
    int error;
    uint64_t new_seq;

    error = p->ofproto_class->run(p);
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: run failed (%s)", p->name, ovs_strerror(error));
    }

    run_rule_executes(p);

    /* Restore the eviction group heap invariant occasionally. */
    if (p->eviction_group_timer < time_msec()) {
        size_t i;

        p->eviction_group_timer = time_msec() + 1000;

        for (i = 0; i < p->n_tables; i++) {
            struct oftable *table = &p->tables[i];
            struct eviction_group *evg;
            struct rule *rule;

            if (!table->eviction) {
                continue;
            }

            if (table->n_flows > 100000) {
                static struct vlog_rate_limit count_rl =
                    VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&count_rl, "Table %"PRIuSIZE" has an excessive"
                             " number of rules: %d", i, table->n_flows);
            }

            ovs_mutex_lock(&ofproto_mutex);
            CLS_FOR_EACH (rule, cr, &table->cls) {
                if (rule->idle_timeout || rule->hard_timeout) {
                    if (!rule->eviction_group) {
                        eviction_group_add_rule(rule);
                    } else {
                        heap_raw_change(&rule->evg_node,
                                        rule_eviction_priority(p, rule));
                    }
                }
            }

            HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
                heap_rebuild(&evg->rules);
            }
            ovs_mutex_unlock(&ofproto_mutex);
        }
    }

    if (p->ofproto_class->port_poll) {
        char *devname;

        while ((error = p->ofproto_class->port_poll(p, &devname)) != EAGAIN) {
            process_port_change(p, error, devname);
        }
    }

    new_seq = seq_read(connectivity_seq_get());
    if (new_seq != p->change_seq) {
        struct sset devnames;
        const char *devname;
        struct ofport *ofport;

        /* Update OpenFlow port status for any port whose netdev has changed.
         *
         * Refreshing a given 'ofport' can cause an arbitrary ofport to be
         * destroyed, so it's not safe to update ports directly from the
         * HMAP_FOR_EACH loop, or even to use HMAP_FOR_EACH_SAFE.  Instead, we
         * need this two-phase approach. */
        sset_init(&devnames);
        HMAP_FOR_EACH (ofport, hmap_node, &p->ports) {
            uint64_t port_change_seq;

            port_change_seq = netdev_get_change_seq(ofport->netdev);
            if (ofport->change_seq != port_change_seq) {
                ofport->change_seq = port_change_seq;
                sset_add(&devnames, netdev_get_name(ofport->netdev));
            }
        }
        SSET_FOR_EACH (devname, &devnames) {
            update_port(p, devname);
        }
        sset_destroy(&devnames);

        p->change_seq = new_seq;
    }

    connmgr_run(p->connmgr, handle_openflow);     //执行openflow操作

    return error;
}

void
connmgr_run(struct connmgr *mgr,
            void (*handle_openflow)(struct ofconn *,
                                    const struct ofpbuf *ofp_msg))
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofconn *ofconn, *next_ofconn;
    struct ofservice *ofservice;
    size_t i;

    if (mgr->in_band) {
        if (!in_band_run(mgr->in_band)) {
            in_band_destroy(mgr->in_band);
            mgr->in_band = NULL;
        }
    }

    LIST_FOR_EACH_SAFE (ofconn, next_ofconn, node, &mgr->all_conns) {
        ofconn_run(ofconn, handle_openflow);    //处理openflow流表操作
    }
    ofmonitor_run(mgr);

    /* Fail-open maintenance.  Do this after processing the ofconns since
     * fail-open checks the status of the controller rconn. */
    if (mgr->fail_open) {
        fail_open_run(mgr->fail_open);
    }

    HMAP_FOR_EACH (ofservice, node, &mgr->services) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(ofservice->pvconn, &vconn);
        if (!retval) {
            struct rconn *rconn;
            char *name;

            /* Passing default value for creation of the rconn */
            rconn = rconn_create(ofservice->probe_interval, 0, ofservice->dscp,
                                 vconn_get_allowed_versions(vconn));
            name = ofconn_make_name(mgr, vconn_get_name(vconn));
            rconn_connect_unreliably(rconn, vconn, name);
            free(name);

            ovs_mutex_lock(&ofproto_mutex);
            ofconn = ofconn_create(mgr, rconn, OFCONN_SERVICE,
                                   ofservice->enable_async_msgs);
            ovs_mutex_unlock(&ofproto_mutex);

            ofconn_set_rate_limit(ofconn, ofservice->rate_limit,
                                  ofservice->burst_limit);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", ovs_strerror(retval));
        }
    }

    for (i = 0; i < mgr->n_snoops; i++) {
        struct vconn *vconn;
        int retval;

        retval = pvconn_accept(mgr->snoops[i], &vconn);
        if (!retval) {
            add_snooper(mgr, vconn);
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(&rl, "accept failed (%s)", ovs_strerror(retval));
        }
    }
}


static void
ofconn_run(struct ofconn *ofconn,
           void (*handle_openflow)(struct ofconn *,
                                   const struct ofpbuf *ofp_msg))
{
    struct connmgr *mgr = ofconn->connmgr;
    size_t i;

    for (i = 0; i < N_SCHEDULERS; i++) {
        struct ovs_list txq;

        pinsched_run(ofconn->schedulers[i], &txq);
        do_send_packet_ins(ofconn, &txq);
    }

    rconn_run(ofconn->rconn);

    /* Limit the number of iterations to avoid starving other tasks. */
    for (i = 0; i < 50 && ofconn_may_recv(ofconn); i++) {
        struct ofpbuf *of_msg = rconn_recv(ofconn->rconn);
        if (!of_msg) {
            break;
        }

        if (mgr->fail_open) {
            fail_open_maybe_recover(mgr->fail_open);
        }

        handle_openflow(ofconn, of_msg);     //处理openflow协议消息
        ofpbuf_delete(of_msg);
    }

    if (time_msec() >= ofconn->next_op_report) {
        ofconn_log_flow_mods(ofconn);
    }

    ovs_mutex_lock(&ofproto_mutex);
    if (!rconn_is_alive(ofconn->rconn)) {
        ofconn_destroy(ofconn);
    } else if (!rconn_is_connected(ofconn->rconn)) {
        ofconn_flush(ofconn);
    }
    ovs_mutex_unlock(&ofproto_mutex);
}
```


# handle_openflow

```c
static void
handle_openflow(struct ofconn *ofconn, const struct ofpbuf *ofp_msg)
    OVS_EXCLUDED(ofproto_mutex)
{
    enum ofperr error = handle_openflow__(ofconn, ofp_msg);

    if (error) {
        ofconn_send_error(ofconn, ofp_msg->data, error);
    }
    COVERAGE_INC(ofproto_recv_openflow);
}

static enum ofperr
handle_openflow__(struct ofconn *ofconn, const struct ofpbuf *msg)
    OVS_EXCLUDED(ofproto_mutex)
{
    const struct ofp_header *oh = msg->data;
    enum ofptype type;
    enum ofperr error;

    error = ofptype_decode(&type, oh);
    if (error) {
        return error;
    }
    if (oh->version >= OFP13_VERSION && ofpmsg_is_stat_request(oh)
        && ofpmp_more(oh)) {
        /* We have no buffer implementation for multipart requests.
         * Report overflow for requests which consists of multiple
         * messages. */
        return OFPERR_OFPBRC_MULTIPART_BUFFER_OVERFLOW;
    }

    switch (type) {
        /* OpenFlow requests. */
    case OFPTYPE_ECHO_REQUEST:
        return handle_echo_request(ofconn, oh);

    case OFPTYPE_FEATURES_REQUEST:
        return handle_features_request(ofconn, oh);

    case OFPTYPE_GET_CONFIG_REQUEST:
        return handle_get_config_request(ofconn, oh);

    case OFPTYPE_SET_CONFIG:
        return handle_set_config(ofconn, oh);

    case OFPTYPE_PACKET_OUT:
        return handle_packet_out(ofconn, oh);

    case OFPTYPE_PORT_MOD:
        return handle_port_mod(ofconn, oh);

    case OFPTYPE_FLOW_MOD:
        return handle_flow_mod(ofconn, oh);

    case OFPTYPE_GROUP_MOD:
        return handle_group_mod(ofconn, oh);

    case OFPTYPE_TABLE_MOD:
        return handle_table_mod(ofconn, oh);

    case OFPTYPE_METER_MOD:
        return handle_meter_mod(ofconn, oh);

    case OFPTYPE_BARRIER_REQUEST:
        return handle_barrier_request(ofconn, oh);

    case OFPTYPE_ROLE_REQUEST:
        return handle_role_request(ofconn, oh);

        /* OpenFlow replies. */
    case OFPTYPE_ECHO_REPLY:
        return 0;

        /* Nicira extension requests. */
    case OFPTYPE_FLOW_MOD_TABLE_ID:
        return handle_nxt_flow_mod_table_id(ofconn, oh);

    case OFPTYPE_SET_FLOW_FORMAT:
        return handle_nxt_set_flow_format(ofconn, oh);

    case OFPTYPE_SET_PACKET_IN_FORMAT:
        return handle_nxt_set_packet_in_format(ofconn, oh);

    case OFPTYPE_SET_CONTROLLER_ID:
        return handle_nxt_set_controller_id(ofconn, oh);

    case OFPTYPE_FLOW_AGE:
        /* Nothing to do. */
        return 0;

    case OFPTYPE_FLOW_MONITOR_CANCEL:
        return handle_flow_monitor_cancel(ofconn, oh);

    case OFPTYPE_SET_ASYNC_CONFIG:
        return handle_nxt_set_async_config(ofconn, oh);

    case OFPTYPE_GET_ASYNC_REQUEST:
        return handle_nxt_get_async_request(ofconn, oh);

        /* Statistics requests. */
    case OFPTYPE_DESC_STATS_REQUEST:
        return handle_desc_stats_request(ofconn, oh);

    case OFPTYPE_FLOW_STATS_REQUEST:
        return handle_flow_stats_request(ofconn, oh);

    case OFPTYPE_AGGREGATE_STATS_REQUEST:
        return handle_aggregate_stats_request(ofconn, oh);

    case OFPTYPE_TABLE_STATS_REQUEST:
        return handle_table_stats_request(ofconn, oh);

    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
        return handle_table_features_request(ofconn, oh);

    case OFPTYPE_TABLE_DESC_REQUEST:
        return handle_table_desc_request(ofconn, oh);

    case OFPTYPE_PORT_STATS_REQUEST:
        return handle_port_stats_request(ofconn, oh);

    case OFPTYPE_QUEUE_STATS_REQUEST:
        return handle_queue_stats_request(ofconn, oh);

    case OFPTYPE_PORT_DESC_STATS_REQUEST:
        return handle_port_desc_stats_request(ofconn, oh);

    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
        return handle_flow_monitor_request(ofconn, oh);

    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
        return handle_meter_request(ofconn, oh, type);

    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
        return handle_meter_features_request(ofconn, oh);

    case OFPTYPE_GROUP_STATS_REQUEST:
        return handle_group_stats_request(ofconn, oh);

    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
        return handle_group_desc_stats_request(ofconn, oh);

    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
        return handle_group_features_stats_request(ofconn, oh);

    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
        return handle_queue_get_config_request(ofconn, oh);

    case OFPTYPE_BUNDLE_CONTROL:
        return handle_bundle_control(ofconn, oh);

    case OFPTYPE_BUNDLE_ADD_MESSAGE:
        return handle_bundle_add(ofconn, oh);

    case OFPTYPE_NXT_TLV_TABLE_MOD:
        return handle_tlv_table_mod(ofconn, oh);

    case OFPTYPE_NXT_TLV_TABLE_REQUEST:
        return handle_tlv_table_request(ofconn, oh);

    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_FLOW_REMOVED:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_GROUP_STATS_REPLY:
    case OFPTYPE_GROUP_DESC_STATS_REPLY:
    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
    case OFPTYPE_METER_STATS_REPLY:
    case OFPTYPE_METER_CONFIG_STATS_REPLY:
    case OFPTYPE_METER_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_DESC_REPLY:
    case OFPTYPE_ROLE_STATUS:
    case OFPTYPE_REQUESTFORWARD:
    case OFPTYPE_NXT_TLV_TABLE_REPLY:
    default:
        if (ofpmsg_is_stat_request(oh)) {
            return OFPERR_OFPBRC_BAD_STAT;
        } else {
            return OFPERR_OFPBRC_BAD_TYPE;
        }
    }
}
```


# handle_flow_mod

```c
static enum ofperr
handle_flow_mod(struct ofconn *ofconn, const struct ofp_header *oh)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct ofproto *ofproto = ofconn_get_ofproto(ofconn);
    struct ofproto_flow_mod ofm;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts;
    enum ofperr error;

    error = reject_slave_controller(ofconn);
    if (error) {
        goto exit;
    }

    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    error = ofputil_decode_flow_mod(&ofm.fm, oh, ofconn_get_protocol(ofconn),
                                    &ofpacts,
                                    u16_to_ofp(ofproto->max_ports),
                                    ofproto->n_tables);
    if (!error) {
        error = ofproto_check_ofpacts(ofproto, ofm.fm.ofpacts,
                                      ofm.fm.ofpacts_len);
    }
    if (!error) {
        struct flow_mod_requester req;

        req.ofconn = ofconn;
        req.request = oh;
        error = handle_flow_mod__(ofproto, &ofm, &req);
    }
    if (error) {
        goto exit_free_ofpacts;
    }

    ofconn_report_flow_mod(ofconn, ofm.fm.command);

exit_free_ofpacts:
    ofpbuf_uninit(&ofpacts);
exit:
    return error;
}

static enum ofperr
handle_flow_mod__(struct ofproto *ofproto, struct ofproto_flow_mod *ofm,
                  const struct flow_mod_requester *req)
    OVS_EXCLUDED(ofproto_mutex)
{
    enum ofperr error;

    ovs_mutex_lock(&ofproto_mutex);
    ofm->version = ofproto->tables_version + 1;
    error = ofproto_flow_mod_start(ofproto, ofm);
    if (!error) {
        ofproto_bump_tables_version(ofproto);
        ofproto_flow_mod_finish(ofproto, ofm, req);
    }
    ofmonitor_flush(ofproto->connmgr);
    ovs_mutex_unlock(&ofproto_mutex);

    run_rule_executes(ofproto);
    return error;
}
```


## ofputil_decode_flow_mod

解析openflow消息

```c
enum ofperr
ofputil_decode_flow_mod(struct ofputil_flow_mod *fm,
                        const struct ofp_header *oh,
                        enum ofputil_protocol protocol,
                        struct ofpbuf *ofpacts,
                        ofp_port_t max_port, uint8_t max_table)
{
    ovs_be16 raw_flags;
    enum ofperr error;
    struct ofpbuf b;
    enum ofpraw raw;

    /* Ignored for non-delete actions */
    fm->delete_reason = OFPRR_DELETE;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    raw = ofpraw_pull_assert(&b);
    if (raw == OFPRAW_OFPT11_FLOW_MOD) {
        /* Standard OpenFlow 1.1+ flow_mod. */
        const struct ofp11_flow_mod *ofm;

        ofm = ofpbuf_pull(&b, sizeof *ofm);

        error = ofputil_pull_ofp11_match(&b, &fm->match, NULL);
        if (error) {
            return error;
        }

        /* Translate the message. */
        fm->priority = ntohs(ofm->priority);
        if (ofm->command == OFPFC_ADD
            || (oh->version == OFP11_VERSION
                && (ofm->command == OFPFC_MODIFY ||
                    ofm->command == OFPFC_MODIFY_STRICT)
                && ofm->cookie_mask == htonll(0))) {
            /* In OpenFlow 1.1 only, a "modify" or "modify-strict" that does
             * not match on the cookie is treated as an "add" if there is no
             * match. */
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
        } else {
            fm->cookie = ofm->cookie;
            fm->cookie_mask = ofm->cookie_mask;
            fm->new_cookie = OVS_BE64_MAX;
        }
        fm->modify_cookie = false;
        fm->command = ofm->command;

        /* Get table ID.
         *
         * OF1.1 entirely forbids table_id == OFPTT_ALL.
         * OF1.2+ allows table_id == OFPTT_ALL only for deletes. */
        fm->table_id = ofm->table_id;
        if (fm->table_id == OFPTT_ALL
            && (oh->version == OFP11_VERSION
                || (ofm->command != OFPFC_DELETE &&
                    ofm->command != OFPFC_DELETE_STRICT))) {
            return OFPERR_OFPFMFC_BAD_TABLE_ID;
        }

        fm->idle_timeout = ntohs(ofm->idle_timeout);
        fm->hard_timeout = ntohs(ofm->hard_timeout);
        if (oh->version >= OFP14_VERSION && ofm->command == OFPFC_ADD) {
            fm->importance = ntohs(ofm->importance);
        } else {
            fm->importance = 0;
        }
        fm->buffer_id = ntohl(ofm->buffer_id);
        error = ofputil_port_from_ofp11(ofm->out_port, &fm->out_port);
        if (error) {
            return error;
        }

        fm->out_group = (ofm->command == OFPFC_DELETE ||
                         ofm->command == OFPFC_DELETE_STRICT
                         ? ntohl(ofm->out_group)
                         : OFPG_ANY);
        raw_flags = ofm->flags;
    } else {
        uint16_t command;

        if (raw == OFPRAW_OFPT10_FLOW_MOD) {
            /* Standard OpenFlow 1.0 flow_mod. */
            const struct ofp10_flow_mod *ofm;

            /* Get the ofp10_flow_mod. */
            ofm = ofpbuf_pull(&b, sizeof *ofm);

            /* Translate the rule. */
            ofputil_match_from_ofp10_match(&ofm->match, &fm->match);
            ofputil_normalize_match(&fm->match);

            /* OpenFlow 1.0 says that exact-match rules have to have the
             * highest possible priority. */
            fm->priority = (ofm->match.wildcards & htonl(OFPFW10_ALL)
                            ? ntohs(ofm->priority)
                            : UINT16_MAX);

            /* Translate the message. */
            command = ntohs(ofm->command);
            fm->cookie = htonll(0);
            fm->cookie_mask = htonll(0);
            fm->new_cookie = ofm->cookie;
            fm->idle_timeout = ntohs(ofm->idle_timeout);
            fm->hard_timeout = ntohs(ofm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(ofm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(ofm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = ofm->flags;
        } else if (raw == OFPRAW_NXT_FLOW_MOD) {
            /* Nicira extended flow_mod. */
            const struct nx_flow_mod *nfm;

            /* Dissect the message. */
            nfm = ofpbuf_pull(&b, sizeof *nfm);
            error = nx_pull_match(&b, ntohs(nfm->match_len),
                                  &fm->match, &fm->cookie, &fm->cookie_mask);
            if (error) {
                return error;
            }

            /* Translate the message. */
            command = ntohs(nfm->command);
            if ((command & 0xff) == OFPFC_ADD && fm->cookie_mask) {
                /* Flow additions may only set a new cookie, not match an
                 * existing cookie. */
                return OFPERR_NXBRC_NXM_INVALID;
            }
            fm->priority = ntohs(nfm->priority);
            fm->new_cookie = nfm->cookie;
            fm->idle_timeout = ntohs(nfm->idle_timeout);
            fm->hard_timeout = ntohs(nfm->hard_timeout);
            fm->importance = 0;
            fm->buffer_id = ntohl(nfm->buffer_id);
            fm->out_port = u16_to_ofp(ntohs(nfm->out_port));
            fm->out_group = OFPG_ANY;
            raw_flags = nfm->flags;
        } else {
            OVS_NOT_REACHED();
        }

        fm->modify_cookie = fm->new_cookie != OVS_BE64_MAX;
        if (protocol & OFPUTIL_P_TID) {
            fm->command = command & 0xff;
            fm->table_id = command >> 8;
        } else {
            if (command > 0xff) {
                VLOG_WARN_RL(&bad_ofmsg_rl, "flow_mod has explicit table_id "
                             "but flow_mod_table_id extension is not enabled");
            }
            fm->command = command;
            fm->table_id = 0xff;
        }
    }

    if (fm->command > OFPFC_DELETE_STRICT) {
        return OFPERR_OFPFMFC_BAD_COMMAND;
    }

    error = ofpacts_pull_openflow_instructions(&b, b.size,
                                               oh->version, ofpacts);
    if (error) {
        return error;
    }
    fm->ofpacts = ofpacts->data;
    fm->ofpacts_len = ofpacts->size;

    error = ofputil_decode_flow_mod_flags(raw_flags, fm->command,
                                          oh->version, &fm->flags);
    if (error) {
        return error;
    }

    if (fm->flags & OFPUTIL_FF_EMERG) {
        /* We do not support the OpenFlow 1.0 emergency flow cache, which
         * is not required in OpenFlow 1.0.1 and removed from OpenFlow 1.1.
         *
         * OpenFlow 1.0 specifies the error code to use when idle_timeout
         * or hard_timeout is nonzero.  Otherwise, there is no good error
         * code, so just state that the flow table is full. */
        return (fm->hard_timeout || fm->idle_timeout
                ? OFPERR_OFPFMFC_BAD_EMERG_TIMEOUT
                : OFPERR_OFPFMFC_TABLE_FULL);
    }

    return ofpacts_check_consistency(fm->ofpacts, fm->ofpacts_len,
                                     &fm->match.flow, max_port,
                                     fm->table_id, max_table, protocol);
}
```


### ofputil_pull_ofp11_match

```c
enum ofperr
ofputil_pull_ofp11_match(struct ofpbuf *buf, struct match *match,
                         uint16_t *padded_match_len)
{
    struct ofp11_match_header *omh = buf->data;
    uint16_t match_len;

    if (buf->size < sizeof *omh) {
        return OFPERR_OFPBMC_BAD_LEN;
    }

    match_len = ntohs(omh->length);

    switch (ntohs(omh->type)) {
    case OFPMT_STANDARD: {
        struct ofp11_match *om;

        if (match_len != sizeof *om || buf->size < sizeof *om) {
            return OFPERR_OFPBMC_BAD_LEN;
        }
        om = ofpbuf_pull(buf, sizeof *om);
        if (padded_match_len) {
            *padded_match_len = match_len;
        }
        return ofputil_match_from_ofp11_match(om, match);
    }

    case OFPMT_OXM:
        if (padded_match_len) {
            *padded_match_len = ROUND_UP(match_len, 8);
        }
        return oxm_pull_match(buf, match);

    default:
        return OFPERR_OFPBMC_BAD_TYPE;
    }
}

enum ofperr
ofputil_match_from_ofp11_match(const struct ofp11_match *ofmatch,
                               struct match *match)
{
    uint16_t wc = ntohl(ofmatch->wildcards);
    bool ipv4, arp, rarp;

    match_init_catchall(match);

    if (!(wc & OFPFW11_IN_PORT)) {
        ofp_port_t ofp_port;
        enum ofperr error;

        error = ofputil_port_from_ofp11(ofmatch->in_port, &ofp_port);
        if (error) {
            return OFPERR_OFPBMC_BAD_VALUE;
        }
        match_set_in_port(match, ofp_port);
    }

    match_set_dl_src_masked(match, ofmatch->dl_src,
                            eth_addr_invert(ofmatch->dl_src_mask));
    match_set_dl_dst_masked(match, ofmatch->dl_dst,
                            eth_addr_invert(ofmatch->dl_dst_mask));

    if (!(wc & OFPFW11_DL_VLAN)) {
        if (ofmatch->dl_vlan == htons(OFPVID11_NONE)) {
            /* Match only packets without a VLAN tag. */
            match->flow.vlan_tci = htons(0);
            match->wc.masks.vlan_tci = OVS_BE16_MAX;
        } else {
            if (ofmatch->dl_vlan == htons(OFPVID11_ANY)) {
                /* Match any packet with a VLAN tag regardless of VID. */
                match->flow.vlan_tci = htons(VLAN_CFI);
                match->wc.masks.vlan_tci = htons(VLAN_CFI);
            } else if (ntohs(ofmatch->dl_vlan) < 4096) {
                /* Match only packets with the specified VLAN VID. */
                match->flow.vlan_tci = htons(VLAN_CFI) | ofmatch->dl_vlan;
                match->wc.masks.vlan_tci = htons(VLAN_CFI | VLAN_VID_MASK);
            } else {
                /* Invalid VID. */
                return OFPERR_OFPBMC_BAD_VALUE;
            }

            if (!(wc & OFPFW11_DL_VLAN_PCP)) {
                if (ofmatch->dl_vlan_pcp <= 7) {
                    match->flow.vlan_tci |= htons(ofmatch->dl_vlan_pcp
                                                  << VLAN_PCP_SHIFT);
                    match->wc.masks.vlan_tci |= htons(VLAN_PCP_MASK);
                } else {
                    /* Invalid PCP. */
                    return OFPERR_OFPBMC_BAD_VALUE;
                }
            }
        }
    }

    if (!(wc & OFPFW11_DL_TYPE)) {
        match_set_dl_type(match,
                          ofputil_dl_type_from_openflow(ofmatch->dl_type));
    }

    ipv4 = match->flow.dl_type == htons(ETH_TYPE_IP);
    arp = match->flow.dl_type == htons(ETH_TYPE_ARP);
    rarp = match->flow.dl_type == htons(ETH_TYPE_RARP);

    if (ipv4 && !(wc & OFPFW11_NW_TOS)) {
        if (ofmatch->nw_tos & ~IP_DSCP_MASK) {
            /* Invalid TOS. */
            return OFPERR_OFPBMC_BAD_VALUE;
        }

        match_set_nw_dscp(match, ofmatch->nw_tos);
    }

    if (ipv4 || arp || rarp) {
        if (!(wc & OFPFW11_NW_PROTO)) {
            match_set_nw_proto(match, ofmatch->nw_proto);
        }
        match_set_nw_src_masked(match, ofmatch->nw_src, ~ofmatch->nw_src_mask);
        match_set_nw_dst_masked(match, ofmatch->nw_dst, ~ofmatch->nw_dst_mask);
    }

#define OFPFW11_TP_ALL (OFPFW11_TP_SRC | OFPFW11_TP_DST)
    if (ipv4 && (wc & OFPFW11_TP_ALL) != OFPFW11_TP_ALL) {
        switch (match->flow.nw_proto) {
        case IPPROTO_ICMP:
            /* "A.2.3 Flow Match Structures" in OF1.1 says:
             *
             *    The tp_src and tp_dst fields will be ignored unless the
             *    network protocol specified is as TCP, UDP or SCTP.
             *
             * but I'm pretty sure we should support ICMP too, otherwise
             * that's a regression from OF1.0. */
            if (!(wc & OFPFW11_TP_SRC)) {
                uint16_t icmp_type = ntohs(ofmatch->tp_src);
                if (icmp_type < 0x100) {
                    match_set_icmp_type(match, icmp_type);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            if (!(wc & OFPFW11_TP_DST)) {
                uint16_t icmp_code = ntohs(ofmatch->tp_dst);
                if (icmp_code < 0x100) {
                    match_set_icmp_code(match, icmp_code);
                } else {
                    return OFPERR_OFPBMC_BAD_FIELD;
                }
            }
            break;

        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            if (!(wc & (OFPFW11_TP_SRC))) {
                match_set_tp_src(match, ofmatch->tp_src);
            }
            if (!(wc & (OFPFW11_TP_DST))) {
                match_set_tp_dst(match, ofmatch->tp_dst);
            }
            break;

        default:
            /* OF1.1 says explicitly to ignore this. */
            break;
        }
    }

    if (eth_type_mpls(match->flow.dl_type)) {
        if (!(wc & OFPFW11_MPLS_LABEL)) {
            match_set_mpls_label(match, 0, ofmatch->mpls_label);
        }
        if (!(wc & OFPFW11_MPLS_TC)) {
            match_set_mpls_tc(match, 0, ofmatch->mpls_tc);
        }
    }

    match_set_metadata_masked(match, ofmatch->metadata,
                              ~ofmatch->metadata_mask);

    return 0;
}
```


### ofputil_port_from_ofp11

```c
enum ofperr
ofputil_port_from_ofp11(ovs_be32 ofp11_port, ofp_port_t *ofp10_port)
{
    uint32_t ofp11_port_h = ntohl(ofp11_port);

    if (ofp11_port_h < ofp_to_u16(OFPP_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h);
        return 0;
    } else if (ofp11_port_h >= ofp11_to_u32(OFPP11_MAX)) {
        *ofp10_port = u16_to_ofp(ofp11_port_h - OFPP11_OFFSET);
        return 0;
    } else {
        *ofp10_port = OFPP_NONE;
        VLOG_WARN_RL(&bad_ofmsg_rl, "port %"PRIu32" is outside the supported "
                     "range 0 through %d or 0x%"PRIx32" through 0x%"PRIx32,
                     ofp11_port_h, ofp_to_u16(OFPP_MAX) - 1,
                     ofp11_to_u32(OFPP11_MAX), UINT32_MAX);
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
}
```

### ofpacts_pull_openflow_instructions

```c
enum ofperr
ofpacts_pull_openflow_instructions(struct ofpbuf *openflow,
                                   unsigned int instructions_len,
                                   enum ofp_version version,
                                   struct ofpbuf *ofpacts)
{
    const struct ofp11_instruction *instructions;
    const struct ofp11_instruction *insts[N_OVS_INSTRUCTIONS];
    enum ofperr error;

    if (version == OFP10_VERSION) {
        return ofpacts_pull_openflow_actions__(openflow, instructions_len,
                                               version,
                                               (1u << N_OVS_INSTRUCTIONS) - 1,
                                               ofpacts, 0);
    }

    ofpbuf_clear(ofpacts);

    if (instructions_len % OFP11_INSTRUCTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u is not a "
                     "multiple of %d",
                     instructions_len, OFP11_INSTRUCTION_ALIGN);
        error = OFPERR_OFPBIC_BAD_LEN;
        goto exit;
    }

    instructions = ofpbuf_try_pull(openflow, instructions_len);
    if (instructions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u exceeds "
                     "remaining message length (%"PRIu32")",
                     instructions_len, openflow->size);
        error = OFPERR_OFPBIC_BAD_LEN;
        goto exit;
    }

    error = decode_openflow11_instructions(
        instructions, instructions_len / OFP11_INSTRUCTION_ALIGN,
        insts);
    if (error) {
        goto exit;
    }

    if (insts[OVSINST_OFPIT13_METER]) {
        const struct ofp13_instruction_meter *oim;
        struct ofpact_meter *om;

        oim = ALIGNED_CAST(const struct ofp13_instruction_meter *,
                           insts[OVSINST_OFPIT13_METER]);

        om = ofpact_put_METER(ofpacts);
        om->meter_id = ntohl(oim->meter_id);
    }
    if (insts[OVSINST_OFPIT11_APPLY_ACTIONS]) {
        const struct ofp_action_header *actions;
        size_t actions_len;

        get_actions_from_instruction(insts[OVSINST_OFPIT11_APPLY_ACTIONS],
                                     &actions, &actions_len);
        error = ofpacts_decode(actions, actions_len, version, ofpacts);
        if (error) {
            goto exit;
        }
    }
    if (insts[OVSINST_OFPIT11_CLEAR_ACTIONS]) {
        instruction_get_OFPIT11_CLEAR_ACTIONS(
            insts[OVSINST_OFPIT11_CLEAR_ACTIONS]);
        ofpact_put_CLEAR_ACTIONS(ofpacts);
    }
    if (insts[OVSINST_OFPIT11_WRITE_ACTIONS]) {
        struct ofpact_nest *on;
        const struct ofp_action_header *actions;
        size_t actions_len;
        size_t start;

        ofpact_pad(ofpacts);
        start = ofpacts->size;
        ofpact_put(ofpacts, OFPACT_WRITE_ACTIONS,
                   offsetof(struct ofpact_nest, actions));
        get_actions_from_instruction(insts[OVSINST_OFPIT11_WRITE_ACTIONS],
                                     &actions, &actions_len);
        error = ofpacts_decode_for_action_set(actions, actions_len,
                                              version, ofpacts);
        if (error) {
            goto exit;
        }
        on = ofpbuf_at_assert(ofpacts, start, sizeof *on);
        on->ofpact.len = ofpacts->size - start;
    }
    if (insts[OVSINST_OFPIT11_WRITE_METADATA]) {
        const struct ofp11_instruction_write_metadata *oiwm;
        struct ofpact_metadata *om;

        oiwm = ALIGNED_CAST(const struct ofp11_instruction_write_metadata *,
                            insts[OVSINST_OFPIT11_WRITE_METADATA]);

        om = ofpact_put_WRITE_METADATA(ofpacts);
        om->metadata = oiwm->metadata;
        om->mask = oiwm->metadata_mask;
    }
    if (insts[OVSINST_OFPIT11_GOTO_TABLE]) {
        const struct ofp11_instruction_goto_table *oigt;
        struct ofpact_goto_table *ogt;

        oigt = instruction_get_OFPIT11_GOTO_TABLE(
            insts[OVSINST_OFPIT11_GOTO_TABLE]);
        ogt = ofpact_put_GOTO_TABLE(ofpacts);
        ogt->table_id = oigt->table_id;
    }

    ofpact_pad(ofpacts);

    error = ofpacts_verify(ofpacts->data, ofpacts->size,
                           (1u << N_OVS_INSTRUCTIONS) - 1, 0);
exit:
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
}
```


### ofputil_decode_flow_mod_flags

```c
static enum ofperr
ofputil_decode_flow_mod_flags(ovs_be16 raw_flags_,
                              enum ofp_flow_mod_command command,
                              enum ofp_version version,
                              enum ofputil_flow_mod_flags *flagsp)
{
    uint16_t raw_flags = ntohs(raw_flags_);
    const struct ofputil_flow_mod_flag *f;

    *flagsp = 0;
    for (f = ofputil_flow_mod_flags; f->raw_flag; f++) {
        if (raw_flags & f->raw_flag
            && version >= f->min_version
            && (!f->max_version || version <= f->max_version)) {
            raw_flags &= ~f->raw_flag;
            *flagsp |= f->flag;
        }
    }

    /* In OF1.0 and OF1.1, "add" always resets counters, and other commands
     * never do.
     *
     * In OF1.2 and later, OFPFF12_RESET_COUNTS controls whether each command
     * resets counters. */
    if ((version == OFP10_VERSION || version == OFP11_VERSION)
        && command == OFPFC_ADD) {
        *flagsp |= OFPUTIL_FF_RESET_COUNTS;
    }

    return raw_flags ? OFPERR_OFPFMFC_BAD_FLAGS : 0;
}
```


## ofproto_flow_mod_start

```c
static enum ofperr
ofproto_flow_mod_start(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    switch (ofm->fm.command) {
    case OFPFC_ADD:
        return add_flow_start(ofproto, ofm);
        /* , &be->old_rules.stub[0],
           &be->new_rules.stub[0]); */
    case OFPFC_MODIFY:
        return modify_flows_start_loose(ofproto, ofm);
    case OFPFC_MODIFY_STRICT:
        return modify_flow_start_strict(ofproto, ofm);
    case OFPFC_DELETE:
        return delete_flows_start_loose(ofproto, ofm);

    case OFPFC_DELETE_STRICT:
        return delete_flow_start_strict(ofproto, ofm);
    }

    return OFPERR_OFPFMFC_BAD_COMMAND;
}
```


##  ofproto_flow_mod_finish

```c
static void
ofproto_flow_mod_finish(struct ofproto *ofproto,
                        struct ofproto_flow_mod *ofm,
                        const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    switch (ofm->fm.command) {
    case OFPFC_ADD:
        add_flow_finish(ofproto, ofm, req);
        break;

    case OFPFC_MODIFY:
    case OFPFC_MODIFY_STRICT:
        modify_flows_finish(ofproto, ofm, req);
        break;

    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT:
        delete_flows_finish(ofproto, ofm, req);
        break;

    default:
        break;
    }
}
```


# 添加流表

```c
static enum ofperr
add_flow_start(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule **old_rule = &ofm->old_rules.stub[0];
    struct rule **new_rule = &ofm->new_rules.stub[0];
    struct oftable *table;
    struct cls_rule cr;
    struct rule *rule;
    uint8_t table_id;
    struct cls_conjunction *conjs;
    size_t n_conjs;
    enum ofperr error;

    if (!check_table_id(ofproto, fm->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
        return error;
    }

    /* Pick table. */
    if (fm->table_id == 0xff) {    //255号table用来自动选择table
        if (ofproto->ofproto_class->rule_choose_table) {
            error = ofproto->ofproto_class->rule_choose_table(ofproto,
                                                              &fm->match,
                                                              &table_id);
            if (error) {
                return error;
            }
            ovs_assert(table_id < ofproto->n_tables);
        } else {
            table_id = 0;
        }
    } else if (fm->table_id < ofproto->n_tables) {    //正常情况下使用流表中table id值
        table_id = fm->table_id;
    } else {
        return OFPERR_OFPBRC_BAD_TABLE_ID;
    }

    table = &ofproto->tables[table_id];     //得到table
    if (table->flags & OFTABLE_READONLY
        && !(fm->flags & OFPUTIL_FF_NO_READONLY)) {
        return OFPERR_OFPBRC_EPERM;
    }

    if (!(fm->flags & OFPUTIL_FF_HIDDEN_FIELDS)
        && !match_has_default_hidden_fields(&fm->match)) {
        VLOG_WARN_RL(&rl, "%s: (add_flow) only internal flows can set "
                     "non-default values to hidden fields", ofproto->name);
        return OFPERR_OFPBRC_EPERM;
    }

    cls_rule_init(&cr, &fm->match, fm->priority);      //初始化cls_rule对象

    /* Check for the existence of an identical rule.
     * This will not return rules earlier marked for removal. */
    rule = rule_from_cls_rule(classifier_find_rule_exactly(&table->cls, &cr,     //遍历流表，得到和cls_rule对应的表项，精确匹配
                                                           ofm->version));
    *old_rule = rule;
    if (!rule) {             //未检索到对应的cls_rule表项
        /* Check for overlap, if requested. */
        if (fm->flags & OFPUTIL_FF_CHECK_OVERLAP
            && classifier_rule_overlaps(&table->cls, &cr, ofm->version)) {      //检查cls_rule是否和流表中有冲突，通过和mask计算后匹配
            cls_rule_destroy(&cr);
            return OFPERR_OFPFMFC_OVERLAP;
        }

        /* If necessary, evict an existing rule to clear out space. */
        if (table->n_flows >= table->max_flows) {
            if (!choose_rule_to_evict(table, &rule)) {
                error = OFPERR_OFPFMFC_TABLE_FULL;
                cls_rule_destroy(&cr);
                return error;
            }
            eviction_group_remove_rule(rule);     //删除rule
            /* Marks '*old_rule' as an evicted rule rather than replaced rule.
             */
            fm->delete_reason = OFPRR_EVICTION;
            *old_rule = rule;
        }
    } else {
        fm->modify_cookie = true;
    }

    /* Allocate new rule. */
    error = replace_rule_create(ofproto, fm, &cr, table - ofproto->tables,
                                rule, new_rule);
    if (error) {
        return error;
    }

    get_conjunctions(fm, &conjs, &n_conjs);
    replace_rule_start(ofproto, ofm->version, rule, *new_rule, conjs, n_conjs);
    free(conjs);

    return 0;
}
```


## cls_rule_init

```c
void
cls_rule_init(struct cls_rule *rule, const struct match *match, int priority)
{
    cls_rule_init__(rule, priority);
    minimatch_init(CONST_CAST(struct minimatch *, &rule->match), match);
}

void
minimatch_init(struct minimatch *dst, const struct match *src)
{
    struct miniflow tmp;

    miniflow_map_init(&tmp, &src->wc.masks);
    /* Allocate two consecutive miniflows. */
    miniflow_alloc(dst->flows, 2, &tmp);
    miniflow_init(dst->flow, &src->flow);
    minimask_init(dst->mask, &src->wc);
}

void
miniflow_map_init(struct miniflow *flow, const struct flow *src)
{
    /* Initialize map, counting the number of nonzero elements. */
    flowmap_init(&flow->map);
    for (size_t i = 0; i < FLOW_U64S; i++) {
        if (flow_u64_value(src, i)) {              //非零设置1
            flowmap_set(&flow->map, i, 1);
        }
    }
}

size_t
miniflow_alloc(struct miniflow *dsts[], size_t n, const struct miniflow *src)
{
    size_t n_values = miniflow_n_values(src);
    size_t data_size = MINIFLOW_VALUES_SIZE(n_values);
    struct miniflow *dst = xmalloc(n * (sizeof *src + data_size));   //minimatch的成员为union，但是数据结构是相同的，只是区分了名字和用途
    size_t i;

    COVERAGE_INC(miniflow_malloc);

    for (i = 0; i < n; i++) {
        *dst = *src;   /* Copy maps. */
        dsts[i] = dst;
        dst += 1;      /* Just past the maps. */
        dst = (struct miniflow *)((uint64_t *)dst + n_values); /* Skip data. */
    }
    return data_size;
}

void
miniflow_init(struct miniflow *dst, const struct flow *src)
{
    uint64_t *dst_u64 = miniflow_values(dst);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, dst->map) {   
        *dst_u64++ = flow_u64_value(src, idx);
    }
}

void
minimask_init(struct minimask *mask, const struct flow_wildcards *wc)
{
    miniflow_init(&mask->masks, &wc->masks);
}
```


## classifier_find_rule_exactly

```c
const struct cls_rule *
classifier_find_rule_exactly(const struct classifier *cls,
                             const struct cls_rule *target,
                             cls_version_t version)
{
    const struct cls_match *head, *rule;
    const struct cls_subtable *subtable;

    subtable = find_subtable(cls, target->match.mask);
    if (!subtable) {
        return NULL;
    }

    head = find_equal(subtable, target->match.flow,
                      miniflow_hash_in_minimask(target->match.flow,
                                                target->match.mask, 0));
    if (!head) {
        return NULL;
    }
    CLS_MATCH_FOR_EACH (rule, head) {       //遍历cls_match链表
        if (rule->priority < target->priority) {
            break; /* Not found. */
        }
        if (rule->priority == target->priority
            && cls_match_visible_in_version(rule, version)) {
            return rule->cls_rule;
        }
    }
    return NULL;
}

static inline uint32_t
miniflow_hash_in_minimask(const struct miniflow *flow,
                          const struct minimask *mask, uint32_t basis)
{
    const uint64_t *mask_values = miniflow_get_values(&mask->masks);     //得到miniflow的数据区
    const uint64_t *p = mask_values;
    uint32_t hash = basis;
    uint64_t value;

    MINIFLOW_FOR_EACH_IN_FLOWMAP(value, flow, mask->masks.map) {    //miniflow和mask的值计算出hash值
        hash = hash_add64(hash, value & *p++);
    }

    return hash_finish(hash, (p - mask_values) * 8);
}

static struct cls_match *
find_equal(const struct cls_subtable *subtable, const struct miniflow *flow,
           uint32_t hash)
{
    struct cls_match *head;

    CMAP_FOR_EACH_WITH_HASH (head, cmap_node, hash, &subtable->rules) {   //遍历subtable的cls_match，相同的miniflow在同一个cls_match链表中
        if (miniflow_equal(&head->flow, flow)) {     //flow相同。 不同flow，配合mask后可能有相同的结果，此处不区分
            return head;
        }
    }
    return NULL;
}
```


## classifier_rule_overlaps

```c
bool
classifier_rule_overlaps(const struct classifier *cls,
                         const struct cls_rule *target, cls_version_t version)
{
    struct cls_subtable *subtable;

    /* Iterate subtables in the descending max priority order. */
    PVECTOR_FOR_EACH_PRIORITY (subtable, target->priority - 1, 2,
                               sizeof(struct cls_subtable), &cls->subtables) {
        struct {
            struct minimask mask;
            uint64_t storage[FLOW_U64S];
        } m;
        const struct cls_rule *rule;

        minimask_combine(&m.mask, target->match.mask, &subtable->mask,
                         m.storage);

        RCULIST_FOR_EACH (rule, node, &subtable->rules_list) {
            if (rule->priority == target->priority
                && miniflow_equal_in_minimask(target->match.flow,
                                              rule->match.flow, &m.mask)
                && cls_match_visible_in_version(rule->cls_match, version)) {
                return true;
            }
        }
    }
    return false;
}
```


## choose_rule_to_evict

```c
static bool
choose_rule_to_evict(struct oftable *table, struct rule **rulep)
    OVS_REQUIRES(ofproto_mutex)
{
    struct eviction_group *evg;

    *rulep = NULL;
    if (!table->eviction) {
        return false;
    }

    /* In the common case, the outer and inner loops here will each be entered
     * exactly once:
     *
     *   - The inner loop normally "return"s in its first iteration.  If the
     *     eviction group has any evictable rules, then it always returns in
     *     some iteration.
     *
     *   - The outer loop only iterates more than once if the largest eviction
     *     group has no evictable rules.
     *
     *   - The outer loop can exit only if table's 'max_flows' is all filled up
     *     by unevictable rules. */
    HEAP_FOR_EACH (evg, size_node, &table->eviction_groups_by_size) {
        struct rule *rule;

        HEAP_FOR_EACH (rule, evg_node, &evg->rules) {
            *rulep = rule;
            return true;
        }
    }

    return false;
}
```


## eviction_group_remove_rule

```c
static void
eviction_group_remove_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rule->eviction_group) {
        struct oftable *table = &rule->ofproto->tables[rule->table_id];
        struct eviction_group *evg = rule->eviction_group;

        rule->eviction_group = NULL;
        heap_remove(&evg->rules, &rule->evg_node);
        if (heap_is_empty(&evg->rules)) {
            eviction_group_destroy(table, evg);
        } else {
            eviction_group_resized(table, evg);
        }
    }
}
```


## replace_rule_create

```c
static enum ofperr
replace_rule_create(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                    struct cls_rule *cr, uint8_t table_id,
                    struct rule *old_rule, struct rule **new_rule)
{
    struct rule *rule;
    enum ofperr error;

    /* Allocate new rule. */
    rule = ofproto->ofproto_class->rule_alloc();   //申请rule对象，实际调用ofproto_dpif_class的rule_alloc
    if (!rule) {
        cls_rule_destroy(cr);
        VLOG_WARN_RL(&rl, "%s: failed to allocate a rule.", ofproto->name);
        return OFPERR_OFPFMFC_UNKNOWN;
    }

    /* Initialize base state. */
    *CONST_CAST(struct ofproto **, &rule->ofproto) = ofproto;
    cls_rule_move(CONST_CAST(struct cls_rule *, &rule->cr), cr);   //复制rule->cr.minimatch的flow和mask
    ovs_refcount_init(&rule->ref_count);///
    rule->flow_cookie = fm->new_cookie;
    rule->created = rule->modified = time_msec();    //设置创建和修改为当前时间

    ovs_mutex_init(&rule->mutex);
    ovs_mutex_lock(&rule->mutex);
    rule->idle_timeout = fm->idle_timeout;
    rule->hard_timeout = fm->hard_timeout;
    *CONST_CAST(uint16_t *, &rule->importance) = fm->importance;
    rule->removed_reason = OVS_OFPRR_NONE;

    *CONST_CAST(uint8_t *, &rule->table_id) = table_id;
    rule->flags = fm->flags & OFPUTIL_FF_STATE;
    *CONST_CAST(const struct rule_actions **, &rule->actions)
        = rule_actions_create(fm->ofpacts, fm->ofpacts_len);
    list_init(&rule->meter_list_node);
    rule->eviction_group = NULL;
    list_init(&rule->expirable);
    rule->monitor_flags = 0;
    rule->add_seqno = 0;
    rule->modify_seqno = 0;

    /* Copy values from old rule for modify semantics. */
    if (old_rule && fm->delete_reason != OFPRR_EVICTION) {
        bool change_cookie = (fm->modify_cookie
                              && fm->new_cookie != OVS_BE64_MAX
                              && fm->new_cookie != old_rule->flow_cookie);

        ovs_mutex_lock(&old_rule->mutex);
        if (fm->command != OFPFC_ADD) {
            rule->idle_timeout = old_rule->idle_timeout;
            rule->hard_timeout = old_rule->hard_timeout;
            *CONST_CAST(uint16_t *, &rule->importance) = old_rule->importance;
            rule->flags = old_rule->flags;
            rule->created = old_rule->created;
        }
        if (!change_cookie) {
            rule->flow_cookie = old_rule->flow_cookie;
        }
        ovs_mutex_unlock(&old_rule->mutex);
    }
    ovs_mutex_unlock(&rule->mutex);

    /* Construct rule, initializing derived state. */
    error = ofproto->ofproto_class->rule_construct(rule);
    if (error) {
        ofproto_rule_destroy__(rule);
        return error;
    }

    rule->removed = true;   /* Not yet in ofproto data structures. */

    *new_rule = rule;
    return 0;
}
```


### rule_alloc(ofproto_dpif_class)

```c
static struct rule *
rule_alloc(void)
{
    struct rule_dpif *rule = xzalloc(sizeof *rule);     //实际分配rule_dpif对象
    return &rule->up;
}
```


### rule_construct(ofproto_dpif_class)

```c
static enum ofperr
rule_construct(struct rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);
    int error;

    error = rule_check(rule_);
    if (error) {
        return error;
    }

    ovs_mutex_init_adaptive(&rule->stats_mutex);
    rule->stats.n_packets = 0;
    rule->stats.n_bytes = 0;
    rule->stats.used = rule->up.modified;
    rule->recirc_id = 0;
    rule->new_rule = NULL;

    return 0;
}
```


## replace_rule_start

```c
static void
replace_rule_start(struct ofproto *ofproto, cls_version_t version,
                   struct rule *old_rule, struct rule *new_rule,
                   struct cls_conjunction *conjs, size_t n_conjs)
{
    struct oftable *table = &ofproto->tables[new_rule->table_id];

    /* 'old_rule' may be either an evicted rule or replaced rule. */
    if (old_rule) {
        /* Mark the old rule for removal in the next version. */
        cls_rule_make_invisible_in_version(&old_rule->cr, version);
    } else {
        table->n_flows++;    //流表数加一
    }
    /* Insert flow to the classifier, so that later flow_mods may relate
     * to it.  This is reversible, in case later errors require this to
     * be reverted. */
    ofproto_rule_insert__(ofproto, new_rule);   //插入rule
    /* Make the new rule visible for classifier lookups only from the next
     * version. */
    classifier_insert(&table->cls, &new_rule->cr, version, conjs, n_conjs);
}
```


### ofproto_rule_insert__

```c
static void
ofproto_rule_insert__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct rule_actions *actions = rule_get_actions(rule);

    ovs_assert(rule->removed);

    if (rule->hard_timeout || rule->idle_timeout) {
        list_insert(&ofproto->expirable, &rule->expirable);
    }
    cookies_insert(ofproto, rule);
    eviction_group_add_rule(rule);
    if (actions->has_meter) {
        meter_insert_rule(rule);
    }
    rule->removed = false;
}

static void
eviction_group_add_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofproto *ofproto = rule->ofproto;
    struct oftable *table = &ofproto->tables[rule->table_id];
    bool has_timeout;

    /* Timeouts may be modified only when holding 'ofproto_mutex'.  We have it
     * so no additional protection is needed. */
    has_timeout = rule->hard_timeout || rule->idle_timeout;

    if (table->eviction && has_timeout) {
        struct eviction_group *evg;

        evg = eviction_group_find(table, eviction_group_hash_rule(rule));

        rule->eviction_group = evg;
        heap_insert(&evg->rules, &rule->evg_node,             //rule添加到evg group中
                    rule_eviction_priority(ofproto, rule));
        eviction_group_resized(table, evg);
    }
}

static struct eviction_group *
eviction_group_find(struct oftable *table, uint32_t id)
    OVS_REQUIRES(ofproto_mutex)
{
    struct eviction_group *evg;

    HMAP_FOR_EACH_WITH_HASH (evg, id_node, id, &table->eviction_groups_by_id) {   //查到则返回
        return evg;
    }

    evg = xmalloc(sizeof *evg);     //未找到，则创建evg
    hmap_insert(&table->eviction_groups_by_id, &evg->id_node, id);
    heap_insert(&table->eviction_groups_by_size, &evg->size_node,
                eviction_group_priority(0));
    heap_init(&evg->rules);

    return evg;
}

static void
meter_insert_rule(struct rule *rule)
{
    const struct rule_actions *a = rule_get_actions(rule);
    uint32_t meter_id = ofpacts_get_meter(a->ofpacts, a->ofpacts_len);  //根据action计算meter id
    struct meter *meter = rule->ofproto->meters[meter_id];    //根据meter id得到meter对象

    list_insert(&meter->rules, &rule->meter_list_node);    //rule添加到该meter中
}
```


### classifier_insert

```c
void
classifier_insert(struct classifier *cls, const struct cls_rule *rule,
                  cls_version_t version, const struct cls_conjunction conj[],
                  size_t n_conj)
{
    const struct cls_rule *displaced_rule
        = classifier_replace(cls, rule, version, conj, n_conj);
    ovs_assert(!displaced_rule);
}

const struct cls_rule *
classifier_replace(struct classifier *cls, const struct cls_rule *rule,
                   cls_version_t version,
                   const struct cls_conjunction *conjs, size_t n_conjs)
{
    struct cls_match *new;
    struct cls_subtable *subtable;
    uint32_t ihash[CLS_MAX_INDICES];
    struct cls_match *head;
    unsigned int mask_offset;
    size_t n_rules = 0;
    uint32_t basis;
    uint32_t hash;
    unsigned int i;

    /* 'new' is initially invisible to lookups. */
    new = cls_match_alloc(rule, version, conjs, n_conjs);    //创建cls match

    CONST_CAST(struct cls_rule *, rule)->cls_match = new;    //建立rule 和match的关联关系

    subtable = find_subtable(cls, rule->match.mask);         //找到mask相同的subtable
    if (!subtable) {
        subtable = insert_subtable(cls, rule->match.mask);   //创建subtable，添加到cls对象的map中
    }

    /* Compute hashes in segments. */
    basis = 0;
    mask_offset = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                        &mask_offset, &basis);
    }
    hash = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                &mask_offset, &basis);

    head = find_equal(subtable, rule->match.flow, hash);     //根据flow检索cls_match
    if (!head) {
        /* Add rule to tries.
         *
         * Concurrent readers might miss seeing the rule until this update,
         * which might require being fixed up by revalidation later. */
        for (i = 0; i < cls->n_tries; i++) {
            if (subtable->trie_plen[i]) {
                trie_insert(&cls->tries[i], rule, subtable->trie_plen[i]);
            }
        }

        /* Add rule to ports trie. */
        if (subtable->ports_mask_len) {
            /* We mask the value to be inserted to always have the wildcarded
             * bits in known (zero) state, so we can include them in comparison
             * and they will always match (== their original value does not
             * matter). */
            ovs_be32 masked_ports = minimatch_get_ports(&rule->match);

            trie_insert_prefix(&subtable->ports_trie, &masked_ports,
                               subtable->ports_mask_len);
        }

        /* Add new node to segment indices.
         *
         * Readers may find the rule in the indices before the rule is visible
         * in the subtables 'rules' map.  This may result in us losing the
         * opportunity to quit lookups earlier, resulting in sub-optimal
         * wildcarding.  This will be fixed later by revalidation (always
         * scheduled after flow table changes). */
        for (i = 0; i < subtable->n_indices; i++) {
            cmap_insert(&subtable->indices[i], &new->index_nodes[i], ihash[i]);   //match添加到subtable中
        }
        n_rules = cmap_insert(&subtable->rules, &new->cmap_node, hash);      //match添加到subtable中
    } else {   /* Equal rules exist in the classifier already. */
        struct cls_match *prev, *iter;

        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority.  Insert after rules marked invisible
         * in any version of the same priority. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, prev, head) {
            if (rule->priority > iter->priority
                || (rule->priority == iter->priority
                    && !cls_match_is_eventually_invisible(iter))) {
                break;
            }
        }

        /* Replace 'iter' with 'new' or insert 'new' between 'prev' and
         * 'iter'. */
        if (iter) {
            struct cls_rule *old;

            if (rule->priority == iter->priority) {
                cls_match_replace(prev, iter, new);
                old = CONST_CAST(struct cls_rule *, iter->cls_rule);
            } else {
                cls_match_insert(prev, iter, new);
                old = NULL;
            }

            /* Replace the existing head in data structures, if rule is the new
             * head. */
            if (iter == head) {
                subtable_replace_head_rule(cls, subtable, head, new, hash,
                                           ihash);
            }

            if (old) {
                struct cls_conjunction_set *conj_set;

                conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                                &iter->conj_set);
                if (conj_set) {
                    ovsrcu_postpone(free, conj_set);
                }

                ovsrcu_postpone(cls_match_free_cb, iter);
                old->cls_match = NULL;

                /* No change in subtable's max priority or max count. */

                /* Make 'new' visible to lookups in the appropriate version. */
                cls_match_set_remove_version(new, CLS_NOT_REMOVED_VERSION);

                /* Make rule visible to iterators (immediately). */
                rculist_replace(CONST_CAST(struct rculist *, &rule->node),
                                &old->node);

                /* Return displaced rule.  Caller is responsible for keeping it
                 * around until all threads quiesce. */
                return old;
            }
        } else {
            /* 'new' is new node after 'prev' */
            cls_match_insert(prev, iter, new);
        }
    }

    /* Make 'new' visible to lookups in the appropriate version. */
    cls_match_set_remove_version(new, CLS_NOT_REMOVED_VERSION);

    /* Make rule visible to iterators (immediately). */
    rculist_push_back(&subtable->rules_list,
                      CONST_CAST(struct rculist *, &rule->node));

    /* Rule was added, not replaced.  Update 'subtable's 'max_priority' and
     * 'max_count', if necessary.
     *
     * The rule was already inserted, but concurrent readers may not see the
     * rule yet as the subtables vector is not updated yet.  This will have to
     * be fixed by revalidation later. */
    if (n_rules == 1) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_insert(&cls->subtables, subtable, rule->priority);
    } else if (rule->priority == subtable->max_priority) {
        ++subtable->max_count;
    } else if (rule->priority > subtable->max_priority) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_change_priority(&cls->subtables, subtable, rule->priority);
    }

    /* Nothing was replaced. */
    cls->n_rules++;

    if (cls->publish) {
        pvector_publish(&cls->subtables);
    }

    return NULL;
}
```


## add_flow_finish

```c
static void
add_flow_finish(struct ofproto *ofproto, struct ofproto_flow_mod *ofm,
                const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule *old_rule = ofm->old_rules.stub[0];
    struct rule *new_rule = ofm->new_rules.stub[0];
    struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);

    replace_rule_finish(ofproto, fm, req, old_rule, new_rule, &dead_cookies);    //添加rule
    learned_cookies_flush(ofproto, &dead_cookies);

    if (old_rule) {
        ovsrcu_postpone(remove_rule_rcu, old_rule);
    } else {
        if (minimask_get_vid_mask(new_rule->cr.match.mask) == VLAN_VID_MASK) {
            if (ofproto->vlan_bitmap) {
                uint16_t vid = miniflow_get_vid(new_rule->cr.match.flow);

                if (!bitmap_is_set(ofproto->vlan_bitmap, vid)) {
                    bitmap_set1(ofproto->vlan_bitmap, vid);
                    ofproto->vlans_changed = true;
                }
            } else {
                ofproto->vlans_changed = true;
            }
        }

        ofmonitor_report(ofproto->connmgr, new_rule, NXFME_ADDED, 0,
                         req ? req->ofconn : NULL,
                         req ? req->request->xid : 0, NULL);
    }

    send_buffered_packet(req, fm->buffer_id, new_rule);
}
```


### replace_rule_finish

```c
static void
replace_rule_finish(struct ofproto *ofproto, struct ofputil_flow_mod *fm,
                    const struct flow_mod_requester *req,
                    struct rule *old_rule, struct rule *new_rule,
                    struct ovs_list *dead_cookies)
    OVS_REQUIRES(ofproto_mutex)
{
    bool forward_stats = !(fm->flags & OFPUTIL_FF_RESET_COUNTS);
    struct rule *replaced_rule;

    replaced_rule = fm->delete_reason != OFPRR_EVICTION ? old_rule : NULL;

    /* Insert the new flow to the ofproto provider.  A non-NULL 'replaced_rule'
     * is a duplicate rule the 'new_rule' is replacing.  The provider should
     * link the stats from the old rule to the new one if 'forward_stats' is
     * 'true'.  The 'replaced_rule' will be deleted right after this call. */
    ofproto->ofproto_class->rule_insert(new_rule, replaced_rule,                  //rule添加
                                        forward_stats);
    learned_cookies_inc(ofproto, rule_get_actions(new_rule));

    if (old_rule) {
        const struct rule_actions *old_actions = rule_get_actions(old_rule);

        /* Remove the old rule from data structures.  Removal from the
         * classifier and the deletion of the rule is RCU postponed by the
         * caller. */
        ofproto_rule_remove__(ofproto, old_rule);
        learned_cookies_dec(ofproto, old_actions, dead_cookies);

        if (replaced_rule) {
            enum nx_flow_update_event event = fm->command == OFPFC_ADD
                ? NXFME_ADDED : NXFME_MODIFIED;

            bool change_cookie = (fm->modify_cookie
                                  && fm->new_cookie != OVS_BE64_MAX
                                  && fm->new_cookie != old_rule->flow_cookie);

            bool change_actions = !ofpacts_equal(fm->ofpacts,
                                                 fm->ofpacts_len,
                                                 old_actions->ofpacts,
                                                 old_actions->ofpacts_len);

            if (event != NXFME_MODIFIED || change_actions || change_cookie) {
                ofmonitor_report(ofproto->connmgr, new_rule, event, 0,
                                 req ? req->ofconn : NULL,
                                 req ? req->request->xid : 0,
                                 change_actions ? old_actions : NULL);
            }
        } else {
            /* XXX: This is slight duplication with delete_flows_finish__() */

            old_rule->removed_reason = OFPRR_EVICTION;

            ofmonitor_report(ofproto->connmgr, old_rule, NXFME_DELETED,
                             OFPRR_EVICTION,
                             req ? req->ofconn : NULL,
                             req ? req->request->xid : 0, NULL);
        }
    }
}

static void rule_insert(struct rule *rule_, struct rule *old_rule_, bool forward_stats)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_dpif *rule = rule_dpif_cast(rule_);

    if (old_rule_ && forward_stats) {
        struct rule_dpif *old_rule = rule_dpif_cast(old_rule_);

        ovs_assert(!old_rule->new_rule);

        /* Take a reference to the new rule, and refer all stats updates from
         * the old rule to the new rule. */
        rule_dpif_ref(rule);

        ovs_mutex_lock(&old_rule->stats_mutex);
        ovs_mutex_lock(&rule->stats_mutex);
        old_rule->new_rule = rule;       /* Forward future stats. */
        rule->stats = old_rule->stats;   /* Transfer stats to the new rule. */
        ovs_mutex_unlock(&rule->stats_mutex);
        ovs_mutex_unlock(&old_rule->stats_mutex);
    }

    complete_operation(rule);
}

static void ofproto_rule_remove__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    ovs_assert(!rule->removed);

    cookies_remove(ofproto, rule);

    eviction_group_remove_rule(rule);         //eviction group删除rule
    if (!list_is_empty(&rule->expirable)) {
        list_remove(&rule->expirable);
    }
    if (!list_is_empty(&rule->meter_list_node)) {
        list_remove(&rule->meter_list_node);
        list_init(&rule->meter_list_node);
    }

    rule->removed = true;
}

static void
eviction_group_remove_rule(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rule->eviction_group) {
        struct oftable *table = &rule->ofproto->tables[rule->table_id];
        struct eviction_group *evg = rule->eviction_group;

        rule->eviction_group = NULL;
        heap_remove(&evg->rules, &rule->evg_node);
        if (heap_is_empty(&evg->rules)) {
            eviction_group_destroy(table, evg);
        } else {
            eviction_group_resized(table, evg);
        }
    }
}
```


# 修改流表(loose)

```c
static enum ofperr
modify_flows_start_loose(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *old_rules = &ofm->old_rules;
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0, CLS_MAX_VERSION,
                       fm->cookie, fm->cookie_mask, OFPP_ANY, OFPG_ANY);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_loose(ofproto, &criteria, old_rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        error = modify_flows_start__(ofproto, ofm);
    }

    if (error) {
        rule_collection_destroy(old_rules);
    }
    return error;
}

static enum ofperr
modify_flows_start__(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *old_rules = &ofm->old_rules;
    struct rule_collection *new_rules = &ofm->new_rules;
    enum ofperr error;

    rule_collection_init(new_rules);

    if (old_rules->n > 0) {
        struct cls_conjunction *conjs;
        size_t n_conjs;
        size_t i;

        /* Create a new 'modified' rule for each old rule. */
        for (i = 0; i < old_rules->n; i++) {
            struct rule *old_rule = old_rules->rules[i];
            struct rule *new_rule;
            struct cls_rule cr;

            cls_rule_clone(&cr, &old_rule->cr);   //克隆cls rule
            error = replace_rule_create(ofproto, fm, &cr, old_rule->table_id,    //申请rule_dpif，用于添加到流表中
                                        old_rule, &new_rule);
            if (!error) {
                rule_collection_add(new_rules, new_rule);
            } else {
                rule_collection_unref(new_rules);
                rule_collection_destroy(new_rules);
                return error;
            }
        }
        ovs_assert(new_rules->n == old_rules->n);

        get_conjunctions(fm, &conjs, &n_conjs);
        for (i = 0; i < old_rules->n; i++) {
            replace_rule_start(ofproto, ofm->version, old_rules->rules[i],    //添加cls rule
                               new_rules->rules[i], conjs, n_conjs);
        }
        free(conjs);
    } else if (!(fm->cookie_mask != htonll(0)
                 || fm->new_cookie == OVS_BE64_MAX)) {
        /* No match, add a new flow. */
        error = add_flow_start(ofproto, ofm);            //没有匹配，相当于新建
        if (!error) {
            ovs_assert(fm->delete_reason == OFPRR_EVICTION
                       || !old_rules->rules[0]);
        }
        new_rules->n = 1;
    } else {
        error = 0;
    }

    return error;
}
```


## rule_criteria_init

```c
static void
rule_criteria_init(struct rule_criteria *criteria, uint8_t table_id,
                   const struct match *match, int priority,
                   cls_version_t version, ovs_be64 cookie,
                   ovs_be64 cookie_mask, ofp_port_t out_port,
                   uint32_t out_group)
{
    criteria->table_id = table_id;
    cls_rule_init(&criteria->cr, match, priority);    //初始化cls rule
    criteria->version = version;
    criteria->cookie = cookie;
    criteria->cookie_mask = cookie_mask;
    criteria->out_port = out_port;
    criteria->out_group = out_group;

    /* We ordinarily want to skip hidden rules, but there has to be a way for
     * code internal to OVS to modify and delete them, so if the criteria
     * specify a priority that can only be for a hidden flow, then allow hidden
     * rules to be selected.  (This doesn't allow OpenFlow clients to meddle
     * with hidden flows because OpenFlow uses only a 16-bit field to specify
     * priority.) */
    criteria->include_hidden = priority > UINT16_MAX;

    /* We assume that the criteria are being used to collect flows for reading
     * but not modification.  Thus, we should collect read-only flows. */
    criteria->include_readonly = true;
}
```


## collect_rules_loose

```c
static enum ofperr
collect_rules_loose(struct ofproto *ofproto,
                    const struct rule_criteria *criteria,
                    struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    enum ofperr error = 0;
    size_t n_readonly = 0;

    rule_collection_init(rules);

    if (!check_table_id(ofproto, criteria->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_is_loose_match(&rule->cr, &criteria->cr.match)) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {    //得到table
            struct rule *rule;

            CLS_FOR_EACH_TARGET (rule, cr, &table->cls, &criteria->cr,    //遍历cls中的rule
                                 criteria->version) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    }

exit:
    if (!error && !rules->n && n_readonly) {
        /* We didn't find any rules to modify.  We did find some read-only
         * rules that we're not allowed to modify, so report that. */
        error = OFPERR_OFPBRC_EPERM;
    }
    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}

bool
cls_rule_is_loose_match(const struct cls_rule *rule,
                        const struct minimatch *criteria)
{
    return (!minimask_has_extra(rule->match.mask, criteria->mask)
            && miniflow_equal_in_minimask(rule->match.flow, criteria->flow,
                                          criteria->mask));
}
```


## modify_flows_finish

```c
static void
modify_flows_finish(struct ofproto *ofproto, struct ofproto_flow_mod *ofm,
                    const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *old_rules = &ofm->old_rules;
    struct rule_collection *new_rules = &ofm->new_rules;

    if (old_rules->n == 0 && new_rules->n == 1) {
        add_flow_finish(ofproto, ofm, req);
    } else if (old_rules->n > 0) {
        struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);

        ovs_assert(new_rules->n == old_rules->n);

        for (size_t i = 0; i < old_rules->n; i++) {
            replace_rule_finish(ofproto, fm, req, old_rules->rules[i],
                                new_rules->rules[i], &dead_cookies);
        }
        learned_cookies_flush(ofproto, &dead_cookies);
        rule_collection_remove_postponed(old_rules);

        send_buffered_packet(req, fm->buffer_id, new_rules->rules[0]);
        rule_collection_destroy(new_rules);
    }
}
```


# 修改流表(strict)


```c
static enum ofperr modify_flow_start_strict(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *old_rules = &ofm->old_rules;
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       CLS_MAX_VERSION, fm->cookie, fm->cookie_mask, OFPP_ANY,
                       OFPG_ANY);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_strict(ofproto, &criteria, old_rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        /* collect_rules_strict() can return max 1 rule. */
        error = modify_flows_start__(ofproto, ofm);
    }

    if (error) {
        rule_collection_destroy(old_rules);
    }
    return error;
}
```


## collect_rules_strict

```c
static enum ofperr
collect_rules_strict(struct ofproto *ofproto,
                     const struct rule_criteria *criteria,
                     struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    struct oftable *table;
    size_t n_readonly = 0;
    enum ofperr error = 0;

    rule_collection_init(rules);

    if (!check_table_id(ofproto, criteria->table_id)) {
        error = OFPERR_OFPBRC_BAD_TABLE_ID;
        goto exit;
    }

    if (criteria->cookie_mask == OVS_BE64_MAX) {
        struct rule *rule;

        HINDEX_FOR_EACH_WITH_HASH (rule, cookie_node,
                                   hash_cookie(criteria->cookie),
                                   &ofproto->cookies) {
            if (cls_rule_equal(&rule->cr, &criteria->cr)) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    } else {
        FOR_EACH_MATCHING_TABLE (table, criteria->table_id, ofproto) {
            struct rule *rule;

            rule = rule_from_cls_rule(classifier_find_rule_exactly(
                                          &table->cls, &criteria->cr,
                                          criteria->version));
            if (rule) {
                collect_rule(rule, criteria, rules, &n_readonly);
            }
        }
    }

exit:
    if (!error && !rules->n && n_readonly) {
        /* We didn't find any rules to modify.  We did find some read-only
         * rules that we're not allowed to modify, so report that. */
        error = OFPERR_OFPBRC_EPERM;
    }
    if (error) {
        rule_collection_destroy(rules);
    }
    return error;
}
```


# 删除流表(loose)

```c
static enum ofperr delete_flows_start_loose(struct ofproto *ofproto, struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *rules = &ofm->old_rules;
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, 0, CLS_MAX_VERSION,
                       fm->cookie, fm->cookie_mask, fm->out_port,
                       fm->out_group);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_loose(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        delete_flows_start__(ofproto, ofm->version, rules);
    }

    return error;
}

static void delete_flows_start__(struct ofproto *ofproto, cls_version_t version,
                     const struct rule_collection *rules)
    OVS_REQUIRES(ofproto_mutex)
{
    for (size_t i = 0; i < rules->n; i++) {
        struct rule *rule = rules->rules[i];
        struct oftable *table = &ofproto->tables[rule->table_id];

        table->n_flows--;
        cls_rule_make_invisible_in_version(&rule->cr, version);
    }
}
```


## delete_flows_finish

```c
static void delete_flows_finish(struct ofproto *ofproto,
                    struct ofproto_flow_mod *ofm,
                    const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    delete_flows_finish__(ofproto, &ofm->old_rules, ofm->fm.delete_reason,
                          req);
}

static void
delete_flows_finish__(struct ofproto *ofproto,
                      struct rule_collection *rules,
                      enum ofp_flow_removed_reason reason,
                      const struct flow_mod_requester *req)
    OVS_REQUIRES(ofproto_mutex)
{
    if (rules->n) {
        struct ovs_list dead_cookies = OVS_LIST_INITIALIZER(&dead_cookies);

        for (size_t i = 0; i < rules->n; i++) {
            struct rule *rule = rules->rules[i];

            /* This value will be used to send the flow removed message right
             * before the rule is actually destroyed. */
            rule->removed_reason = reason;

            ofmonitor_report(ofproto->connmgr, rule, NXFME_DELETED, reason,
                             req ? req->ofconn : NULL,
                             req ? req->request->xid : 0, NULL);
            ofproto_rule_remove__(ofproto, rule);
            learned_cookies_dec(ofproto, rule_get_actions(rule),
                                &dead_cookies);
        }
        rule_collection_remove_postponed(rules);

        learned_cookies_flush(ofproto, &dead_cookies);
    }
}
```


# 删除流表(strict)

```c
static enum ofperr
delete_flow_start_strict(struct ofproto *ofproto,
                         struct ofproto_flow_mod *ofm)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct ofputil_flow_mod *fm = &ofm->fm;
    struct rule_collection *rules = &ofm->old_rules;
    struct rule_criteria criteria;
    enum ofperr error;

    rule_criteria_init(&criteria, fm->table_id, &fm->match, fm->priority,
                       CLS_MAX_VERSION, fm->cookie, fm->cookie_mask,
                       fm->out_port, fm->out_group);
    rule_criteria_require_rw(&criteria,
                             (fm->flags & OFPUTIL_FF_NO_READONLY) != 0);
    error = collect_rules_strict(ofproto, &criteria, rules);
    rule_criteria_destroy(&criteria);

    if (!error) {
        delete_flows_start__(ofproto, ofm->version, rules);
    }

    return error;
}
```


