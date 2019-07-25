# xbridge

xbridge/xbundle/xport用于xlate，在bridge_reconfigure函数处理完bridge和port之后，调用bridge_run__函数实现xbridge/xbundle/xport对象构建。

数据结构如下：

![xbridge](images/xbridge.png "xbridge")

```c
static void
bridge_run__(void)
{
    struct bridge *br;
    struct sset types;
    const char *type;

    /* Let each datapath type do the work that it needs to do. */
    sset_init(&types);
    ofproto_enumerate_types(&types);    //只有openflow一种类型
    SSET_FOR_EACH (type, &types) {
        ofproto_type_run(type);         //调用type run方法
    }
    sset_destroy(&types);

    /* Let each bridge do the work that it needs to do. */
    HMAP_FOR_EACH (br, node, &all_bridges) {
        ofproto_run(br->ofproto);
    }
}

int
ofproto_type_run(const char *datapath_type)
{
    const struct ofproto_class *class;
    int error;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);

    error = class->type_run ? class->type_run(datapath_type) : 0;     //实际调用ofproto_dpif_class的type_run函数
    if (error && error != EAGAIN) {
        VLOG_ERR_RL(&rl, "%s: type_run failed (%s)",
                    datapath_type, ovs_strerror(error));
    }
    return error;
}
```


# type_run(ofproto_dpif_class)

```c
static int
type_run(const char *type)
{
    struct dpif_backer *backer;

    backer = shash_find_data(&all_dpif_backers, type);
    if (!backer) {
        /* This is not necessarily a problem, since backers are only
         * created on demand. */
        return 0;
    }


    if (dpif_run(backer->dpif)) {    //刷新upcall channel
        backer->need_revalidate = REV_RECONFIGURE;
    }

    udpif_run(backer->udpif);

    /* If vswitchd started with other_config:flow_restore_wait set as "true",
     * and the configuration has now changed to "false", enable receiving
     * packets from the datapath. */
    if (!backer->recv_set_enable && !ofproto_get_flow_restore_wait()) {
        int error;

        backer->recv_set_enable = true;

        error = dpif_recv_set(backer->dpif, backer->recv_set_enable);
        if (error) {
            VLOG_ERR("Failed to enable receiving packets in dpif.");
            return error;
        }
        dpif_flow_flush(backer->dpif);
        backer->need_revalidate = REV_RECONFIGURE;
    }

    if (backer->recv_set_enable) {
        udpif_set_threads(backer->udpif, n_handlers, n_revalidators);   //启动upcall和revalidator线程
    }

    dpif_poll_threads_set(backer->dpif, n_dpdk_rxqs, pmd_cpu_mask); 

    if (backer->need_revalidate) {
        struct ofproto_dpif *ofproto;
        struct simap_node *node;
        struct simap tmp_backers;

        /* Handle tunnel garbage collection. */
        simap_init(&tmp_backers);
        simap_swap(&backer->tnl_backers, &tmp_backers);

        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            struct ofport_dpif *iter;

            if (backer != ofproto->backer) {
                continue;
            }

            HMAP_FOR_EACH (iter, up.hmap_node, &ofproto->up.ports) {
                char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
                const char *dp_port;

                if (!iter->is_tunnel) {
                    continue;
                }

                dp_port = netdev_vport_get_dpif_port(iter->up.netdev,
                                                     namebuf, sizeof namebuf);
                node = simap_find(&tmp_backers, dp_port);
                if (node) {
                    simap_put(&backer->tnl_backers, dp_port, node->data);
                    simap_delete(&tmp_backers, node);
                    node = simap_find(&backer->tnl_backers, dp_port);
                } else {
                    node = simap_find(&backer->tnl_backers, dp_port);
                    if (!node) {
                        odp_port_t odp_port = ODPP_NONE;

                        if (!dpif_port_add(backer->dpif, iter->up.netdev,
                                           &odp_port)) {
                            simap_put(&backer->tnl_backers, dp_port,
                                      odp_to_u32(odp_port));
                            node = simap_find(&backer->tnl_backers, dp_port);
                        }
                    }
                }

                iter->odp_port = node ? u32_to_odp(node->data) : ODPP_NONE;
                if (tnl_port_reconfigure(iter, iter->up.netdev,
                                         iter->odp_port,
                                         ovs_native_tunneling_is_on(ofproto), dp_port)) {
                    backer->need_revalidate = REV_RECONFIGURE;
                }
            }
        }

        SIMAP_FOR_EACH (node, &tmp_backers) {
            dpif_port_del(backer->dpif, u32_to_odp(node->data));
        }
        simap_destroy(&tmp_backers);

        switch (backer->need_revalidate) {
        case REV_RECONFIGURE:    COVERAGE_INC(rev_reconfigure);    break;
        case REV_STP:            COVERAGE_INC(rev_stp);            break;
        case REV_RSTP:           COVERAGE_INC(rev_rstp);           break;
        case REV_BOND:           COVERAGE_INC(rev_bond);           break;
        case REV_PORT_TOGGLED:   COVERAGE_INC(rev_port_toggled);   break;
        case REV_FLOW_TABLE:     COVERAGE_INC(rev_flow_table);     break;
        case REV_MAC_LEARNING:   COVERAGE_INC(rev_mac_learning);   break;
        case REV_MCAST_SNOOPING: COVERAGE_INC(rev_mcast_snooping); break;
        }
        backer->need_revalidate = 0;

        HMAP_FOR_EACH (ofproto, all_ofproto_dpifs_node, &all_ofproto_dpifs) {
            struct ofport_dpif *ofport;
            struct ofbundle *bundle;

            if (ofproto->backer != backer) {
                continue;
            }

            xlate_txn_start();
            xlate_ofproto_set(ofproto, ofproto->up.name,                     //创建xbridge
                              ofproto->backer->dpif, ofproto->ml,
                              ofproto->stp, ofproto->rstp, ofproto->ms,
                              ofproto->mbridge, ofproto->sflow, ofproto->ipfix,
                              ofproto->netflow,
                              ofproto->up.forward_bpdu,
                              connmgr_has_in_band(ofproto->up.connmgr),
                              &ofproto->backer->support);

            HMAP_FOR_EACH (bundle, hmap_node, &ofproto->bundles) {             //创建xbundle
                xlate_bundle_set(ofproto, bundle, bundle->name,
                                 bundle->vlan_mode, bundle->vlan,
                                 bundle->trunks, bundle->use_priority_tags,
                                 bundle->bond, bundle->lacp,
                                 bundle->floodable);
            }

            HMAP_FOR_EACH (ofport, up.hmap_node, &ofproto->up.ports) {
                int stp_port = ofport->stp_port
                    ? stp_port_no(ofport->stp_port)
                    : -1;
                xlate_ofport_set(ofproto, ofport->bundle, ofport,              //创建xport
                                 ofport->up.ofp_port, ofport->odp_port,
                                 ofport->up.netdev, ofport->cfm, ofport->bfd,
                                 ofport->lldp, ofport->peer, stp_port,
                                 ofport->rstp_port, ofport->qdscp,
                                 ofport->n_qdscp, ofport->up.pp.config,
                                 ofport->up.pp.state, ofport->is_tunnel,
                                 ofport->may_enable);
            }
            xlate_txn_commit();
        }

        udpif_revalidate(backer->udpif);    //重新validate
    }

    process_dpif_port_changes(backer);

    return 0;
}
```


# xlate_ofproto_set(创建xbridge)

```c
void
xlate_ofproto_set(struct ofproto_dpif *ofproto, const char *name,
                  struct dpif *dpif,
                  const struct mac_learning *ml, struct stp *stp,
                  struct rstp *rstp, const struct mcast_snooping *ms,
                  const struct mbridge *mbridge,
                  const struct dpif_sflow *sflow,
                  const struct dpif_ipfix *ipfix,
                  const struct netflow *netflow,
                  bool forward_bpdu, bool has_in_band,
                  const struct dpif_backer_support *support)
{
    struct xbridge *xbridge;

    ovs_assert(new_xcfg);

    xbridge = xbridge_lookup(new_xcfg, ofproto);    //查找xbridge
    if (!xbridge) {
        xbridge = xzalloc(sizeof *xbridge);
        xbridge->ofproto = ofproto;

        xlate_xbridge_init(new_xcfg, xbridge);      //初始化xbridge
    }

    free(xbridge->name);
    xbridge->name = xstrdup(name);

    xlate_xbridge_set(xbridge, dpif, ml, stp, rstp, ms, mbridge, sflow, ipfix,   //xbridge设置
                      netflow, forward_bpdu, has_in_band, support);
}

static struct xbridge *
xbridge_lookup(struct xlate_cfg *xcfg, const struct ofproto_dpif *ofproto)
{
    struct hmap *xbridges;
    struct xbridge *xbridge;

    if (!ofproto || !xcfg) {
        return NULL;
    }

    xbridges = &xcfg->xbridges;

    HMAP_FOR_EACH_IN_BUCKET (xbridge, hmap_node, hash_pointer(ofproto, 0),
                             xbridges) {
        if (xbridge->ofproto == ofproto) {
            return xbridge;
        }
    }
    return NULL;
}

static void
xlate_xbridge_init(struct xlate_cfg *xcfg, struct xbridge *xbridge)
{
    list_init(&xbridge->xbundles);
    hmap_init(&xbridge->xports);
    hmap_insert(&xcfg->xbridges, &xbridge->hmap_node,
                hash_pointer(xbridge->ofproto, 0));
}

static void
xlate_xbridge_set(struct xbridge *xbridge,
                  struct dpif *dpif,
                  const struct mac_learning *ml, struct stp *stp,
                  struct rstp *rstp, const struct mcast_snooping *ms,
                  const struct mbridge *mbridge,
                  const struct dpif_sflow *sflow,
                  const struct dpif_ipfix *ipfix,
                  const struct netflow *netflow,
                  bool forward_bpdu, bool has_in_band,
                  const struct dpif_backer_support *support)
{
    if (xbridge->ml != ml) {
        mac_learning_unref(xbridge->ml);
        xbridge->ml = mac_learning_ref(ml);
    }

    if (xbridge->ms != ms) {
        mcast_snooping_unref(xbridge->ms);
        xbridge->ms = mcast_snooping_ref(ms);
    }

    if (xbridge->mbridge != mbridge) {
        mbridge_unref(xbridge->mbridge);
        xbridge->mbridge = mbridge_ref(mbridge);
    }

    if (xbridge->sflow != sflow) {
        dpif_sflow_unref(xbridge->sflow);
        xbridge->sflow = dpif_sflow_ref(sflow);
    }

    if (xbridge->ipfix != ipfix) {
        dpif_ipfix_unref(xbridge->ipfix);
        xbridge->ipfix = dpif_ipfix_ref(ipfix);
    }

    if (xbridge->stp != stp) {
        stp_unref(xbridge->stp);
        xbridge->stp = stp_ref(stp);
    }

    if (xbridge->rstp != rstp) {
        rstp_unref(xbridge->rstp);
        xbridge->rstp = rstp_ref(rstp);
    }

    if (xbridge->netflow != netflow) {
        netflow_unref(xbridge->netflow);
        xbridge->netflow = netflow_ref(netflow);
    }

    xbridge->dpif = dpif;
    xbridge->forward_bpdu = forward_bpdu;
    xbridge->has_in_band = has_in_band;
    xbridge->support = *support;
}
```


# xlate_bundle_set(创建xbundle)

```c
void
xlate_bundle_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 const char *name, enum port_vlan_mode vlan_mode, int vlan,
                 unsigned long *trunks, bool use_priority_tags,
                 const struct bond *bond, const struct lacp *lacp,
                 bool floodable)
{
    struct xbundle *xbundle;

    ovs_assert(new_xcfg);

    xbundle = xbundle_lookup(new_xcfg, ofbundle);
    if (!xbundle) {
        xbundle = xzalloc(sizeof *xbundle);
        xbundle->ofbundle = ofbundle;
        xbundle->xbridge = xbridge_lookup(new_xcfg, ofproto);

        xlate_xbundle_init(new_xcfg, xbundle);
    }

    free(xbundle->name);
    xbundle->name = xstrdup(name);

    xlate_xbundle_set(xbundle, vlan_mode, vlan, trunks,
                      use_priority_tags, bond, lacp, floodable);
}

static void
xlate_xbundle_init(struct xlate_cfg *xcfg, struct xbundle *xbundle)
{
    list_init(&xbundle->xports);
    list_insert(&xbundle->xbridge->xbundles, &xbundle->list_node);
    hmap_insert(&xcfg->xbundles, &xbundle->hmap_node,
                hash_pointer(xbundle->ofbundle, 0));
}

static void
xlate_xbundle_set(struct xbundle *xbundle,
                  enum port_vlan_mode vlan_mode, int vlan,
                  unsigned long *trunks, bool use_priority_tags,
                  const struct bond *bond, const struct lacp *lacp,
                  bool floodable)
{
    ovs_assert(xbundle->xbridge);

    xbundle->vlan_mode = vlan_mode;
    xbundle->vlan = vlan;
    xbundle->trunks = trunks;
    xbundle->use_priority_tags = use_priority_tags;
    xbundle->floodable = floodable;

    if (xbundle->bond != bond) {
        bond_unref(xbundle->bond);
        xbundle->bond = bond_ref(bond);
    }

    if (xbundle->lacp != lacp) {
        lacp_unref(xbundle->lacp);
        xbundle->lacp = lacp_ref(lacp);
    }
}
```


# xlate_ofport_set(创建xport)

```c

void
xlate_ofport_set(struct ofproto_dpif *ofproto, struct ofbundle *ofbundle,
                 struct ofport_dpif *ofport, ofp_port_t ofp_port,
                 odp_port_t odp_port, const struct netdev *netdev,
                 const struct cfm *cfm, const struct bfd *bfd,
                 const struct lldp *lldp, struct ofport_dpif *peer,
                 int stp_port_no, const struct rstp_port *rstp_port,
                 const struct ofproto_port_queue *qdscp_list, size_t n_qdscp,
                 enum ofputil_port_config config,
                 enum ofputil_port_state state, bool is_tunnel,
                 bool may_enable)
{
    size_t i;
    struct xport *xport;

    ovs_assert(new_xcfg);

    xport = xport_lookup(new_xcfg, ofport);
    if (!xport) {
        xport = xzalloc(sizeof *xport);
        xport->ofport = ofport;
        xport->xbridge = xbridge_lookup(new_xcfg, ofproto);
        xport->ofp_port = ofp_port;

        xlate_xport_init(new_xcfg, xport);
    }

    ovs_assert(xport->ofp_port == ofp_port);

    xlate_xport_set(xport, odp_port, netdev, cfm, bfd, lldp,
                    stp_port_no, rstp_port, config, state, is_tunnel,
                    may_enable);

    if (xport->peer) {
        xport->peer->peer = NULL;
    }
    xport->peer = xport_lookup(new_xcfg, peer);
    if (xport->peer) {
        xport->peer->peer = xport;
    }

    if (xport->xbundle) {
        list_remove(&xport->bundle_node);
    }
    xport->xbundle = xbundle_lookup(new_xcfg, ofbundle);
    if (xport->xbundle) {
        list_insert(&xport->xbundle->xports, &xport->bundle_node);
    }

    clear_skb_priorities(xport);
    for (i = 0; i < n_qdscp; i++) {
        struct skb_priority_to_dscp *pdscp;
        uint32_t skb_priority;

        if (dpif_queue_to_priority(xport->xbridge->dpif, qdscp_list[i].queue,
                                   &skb_priority)) {
            continue;
        }

        pdscp = xmalloc(sizeof *pdscp);
        pdscp->skb_priority = skb_priority;
        pdscp->dscp = (qdscp_list[i].dscp << 2) & IP_DSCP_MASK;
        hmap_insert(&xport->skb_priorities, &pdscp->hmap_node,
                    hash_int(pdscp->skb_priority, 0));
    }
}

static void
xlate_xport_init(struct xlate_cfg *xcfg, struct xport *xport)
{
    hmap_init(&xport->skb_priorities);
    hmap_insert(&xcfg->xports, &xport->hmap_node,
                hash_pointer(xport->ofport, 0));
    hmap_insert(&xport->xbridge->xports, &xport->ofp_node,
                hash_ofp_port(xport->ofp_port));
}

static void
xlate_xport_set(struct xport *xport, odp_port_t odp_port,
                const struct netdev *netdev, const struct cfm *cfm,
                const struct bfd *bfd, const struct lldp *lldp, int stp_port_no,
                const struct rstp_port* rstp_port,
                enum ofputil_port_config config, enum ofputil_port_state state,
                bool is_tunnel, bool may_enable)
{
    xport->config = config;
    xport->state = state;
    xport->stp_port_no = stp_port_no;
    xport->is_tunnel = is_tunnel;
    xport->may_enable = may_enable;
    xport->odp_port = odp_port;

    if (xport->rstp_port != rstp_port) {
        rstp_port_unref(xport->rstp_port);
        xport->rstp_port = rstp_port_ref(rstp_port);
    }

    if (xport->cfm != cfm) {
        cfm_unref(xport->cfm);
        xport->cfm = cfm_ref(cfm);
    }

    if (xport->bfd != bfd) {
        bfd_unref(xport->bfd);
        xport->bfd = bfd_ref(bfd);
    }

    if (xport->lldp != lldp) {
        lldp_unref(xport->lldp);
        xport->lldp = lldp_ref(lldp);
    }

    if (xport->netdev != netdev) {
        netdev_close(xport->netdev);
        xport->netdev = netdev_ref(netdev);
    }
}
```

