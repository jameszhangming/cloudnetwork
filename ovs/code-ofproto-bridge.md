# ofproto bridge

本文介绍openflow交换机的bridge操作，有两个调用入口：

* bridge_delete_ofprotos函数
  * 调用ofproto_delete删除of bridge
* bridge_reconfigure函数
  * 调用ofproto_create创建of bridge
  

# ofproto_create

```c
int
ofproto_create(const char *datapath_name, const char *datapath_type,
               struct ofproto **ofprotop)
{
    const struct ofproto_class *class;
    struct ofproto *ofproto;
    int error;
    int i;

    *ofprotop = NULL;

    datapath_type = ofproto_normalize_type(datapath_type);
    class = ofproto_class_find__(datapath_type);            //openflow class
    if (!class) {
        VLOG_WARN("could not create datapath %s of unknown type %s",
                  datapath_name, datapath_type);
        return EAFNOSUPPORT;
    }

    ofproto = class->alloc();    //申请of bridge对象
    if (!ofproto) {
        VLOG_ERR("failed to allocate datapath %s of type %s",
                 datapath_name, datapath_type);
        return ENOMEM;
    }

    /* Initialize. */
    ovs_mutex_lock(&ofproto_mutex);
    memset(ofproto, 0, sizeof *ofproto);
    ofproto->ofproto_class = class;
    ofproto->name = xstrdup(datapath_name);
    ofproto->type = xstrdup(datapath_type);
    hmap_insert(&all_ofprotos, &ofproto->hmap_node,
                hash_string(ofproto->name, 0));
    ofproto->datapath_id = 0;
    ofproto->forward_bpdu = false;
    ofproto->fallback_dpid = pick_fallback_dpid();   //根据随机（4byte固定）mac地址生成dpid
    ofproto->mfr_desc = NULL;
    ofproto->hw_desc = NULL;
    ofproto->sw_desc = NULL;
    ofproto->serial_desc = NULL;
    ofproto->dp_desc = NULL;
    ofproto->frag_handling = OFPC_FRAG_NORMAL;
    hmap_init(&ofproto->ports);
    hmap_init(&ofproto->ofport_usage);
    shash_init(&ofproto->port_by_name);
    simap_init(&ofproto->ofp_requests);
    ofproto->max_ports = ofp_to_u16(OFPP_MAX);
    ofproto->eviction_group_timer = LLONG_MIN;
    ofproto->tables = NULL;
    ofproto->n_tables = 0;
    ofproto->tables_version = CLS_MIN_VERSION;
    hindex_init(&ofproto->cookies);
    hmap_init(&ofproto->learned_cookies);
    list_init(&ofproto->expirable);
    ofproto->connmgr = connmgr_create(ofproto, datapath_name, datapath_name);
    guarded_list_init(&ofproto->rule_executes);
    ofproto->vlan_bitmap = NULL;
    ofproto->vlans_changed = false;
    ofproto->min_mtu = INT_MAX;
    ovs_rwlock_init(&ofproto->groups_rwlock);
    hmap_init(&ofproto->groups);
    ovs_mutex_unlock(&ofproto_mutex);
    ofproto->ogf.types = 0xf;
    ofproto->ogf.capabilities = OFPGFC_CHAINING | OFPGFC_SELECT_LIVENESS |
                                OFPGFC_SELECT_WEIGHT;
    for (i = 0; i < 4; i++) {
        ofproto->ogf.max_groups[i] = OFPG_MAX;
        ofproto->ogf.ofpacts[i] = (UINT64_C(1) << N_OFPACTS) - 1;
    }
    tun_metadata_init();

    error = ofproto->ofproto_class->construct(ofproto);    //of bridge配置
    if (error) {
        VLOG_ERR("failed to open datapath %s: %s",
                 datapath_name, ovs_strerror(error));
        connmgr_destroy(ofproto->connmgr);
        ofproto_destroy__(ofproto);
        return error;
    }

    /* Check that hidden tables, if any, are at the end. */
    ovs_assert(ofproto->n_tables);
    for (i = 0; i + 1 < ofproto->n_tables; i++) {
        enum oftable_flags flags = ofproto->tables[i].flags;
        enum oftable_flags next_flags = ofproto->tables[i + 1].flags;

        ovs_assert(!(flags & OFTABLE_HIDDEN) || next_flags & OFTABLE_HIDDEN);
    }

    ofproto->datapath_id = pick_datapath_id(ofproto); 
    init_ports(ofproto);    //初始化端口

    /* Initialize meters table. */
    if (ofproto->ofproto_class->meter_get_features) {
        ofproto->ofproto_class->meter_get_features(ofproto,
                                                   &ofproto->meter_features);
    } else {
        memset(&ofproto->meter_features, 0, sizeof ofproto->meter_features);
    }
    ofproto->meters = xzalloc((ofproto->meter_features.max_meters + 1)    //分配meters空间
                              * sizeof(struct meter *));

    /* Set the initial tables version. */
    ofproto_bump_tables_version(ofproto);

    *ofprotop = ofproto;    //保存到bridge->ofproto指针
    return 0;
}

static uint64_t
pick_datapath_id(const struct ofproto *ofproto)
{
    const struct ofport *port;

    port = ofproto_get_port(ofproto, OFPP_LOCAL);  //得到local port
    if (port) {
        struct eth_addr ea;
        int error;

        error = netdev_get_etheraddr(port->netdev, &ea);
        if (!error) {
            return eth_addr_to_uint64(ea);    //得到mac地址
        }
        VLOG_WARN("%s: could not get MAC address for %s (%s)",
                  ofproto->name, netdev_get_name(port->netdev),
                  ovs_strerror(error));
    }
    return ofproto->fallback_dpid;
}
```


## construct(ofproto_dpif_class)

```
static int
construct(struct ofproto *ofproto_)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct shash_node *node, *next;
    int error;

    /* Tunnel module can get used right after the udpif threads are running. */
    ofproto_tunnel_init();

    error = open_dpif_backer(ofproto->up.type, &ofproto->backer);   //打开后端
    if (error) {
        return error;
    }

    atomic_init(&ofproto->tables_version, CLS_MIN_VERSION);
    ofproto->netflow = NULL;
    ofproto->sflow = NULL;
    ofproto->ipfix = NULL;
    ofproto->stp = NULL;
    ofproto->rstp = NULL;
    ofproto->dump_seq = 0;
    hmap_init(&ofproto->bundles);
    ofproto->ml = mac_learning_create(MAC_ENTRY_DEFAULT_IDLE_TIME);
    ofproto->ms = NULL;
    ofproto->mbridge = mbridge_create();    //创建mirror bridge
    ofproto->has_bonded_bundles = false;
    ofproto->lacp_enabled = false;
    ovs_mutex_init_adaptive(&ofproto->stats_mutex);
    ovs_mutex_init(&ofproto->vsp_mutex);

    guarded_list_init(&ofproto->pins);

    hmap_init(&ofproto->vlandev_map);
    hmap_init(&ofproto->realdev_vid_map);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    sset_init(&ofproto->port_poll_set);
    ofproto->port_poll_errno = 0;
    ofproto->change_seq = 0;
    ofproto->pins_seq = seq_create();
    ofproto->pins_seqno = seq_read(ofproto->pins_seq);


    SHASH_FOR_EACH_SAFE (node, next, &init_ofp_ports) {
        struct iface_hint *iface_hint = node->data;

        if (!strcmp(iface_hint->br_name, ofproto->up.name)) {
            /* Check if the datapath already has this port. */
            if (dpif_port_exists(ofproto->backer->dpif, node->name)) {
                sset_add(&ofproto->ports, node->name);
            }

            free(iface_hint->br_name);
            free(iface_hint->br_type);
            free(iface_hint);
            shash_delete(&init_ofp_ports, node);
        }
    }

    hmap_insert(&all_ofproto_dpifs, &ofproto->all_ofproto_dpifs_node,
                hash_string(ofproto->up.name, 0));
    memset(&ofproto->stats, 0, sizeof ofproto->stats);

    ofproto_init_tables(ofproto_, N_TABLES);   //初始化of tables
    error = add_internal_flows(ofproto);   

    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

    return error;
}
```


## open_dpif_backer

```
static int
open_dpif_backer(const char *type, struct dpif_backer **backerp)
{
    struct dpif_backer *backer;
    struct dpif_port_dump port_dump;
    struct dpif_port port;
    struct shash_node *node;
    struct ovs_list garbage_list;
    struct odp_garbage *garbage;

    struct sset names;
    char *backer_name;
    const char *name;
    int error;

    recirc_init();

    backer = shash_find_data(&all_dpif_backers, type);     //管理层已存在，此时dp层肯定存在
    if (backer) {
        backer->refcount++;   //backer已经存在，则使用该backer
        *backerp = backer;
        return 0;
    }

    backer_name = xasprintf("ovs-%s", type);   //backer根据类型已经确定，一共有两类system和netdev

    /* Remove any existing datapaths, since we assume we're the only
     * userspace controlling the datapath. */
    sset_init(&names);
    dp_enumerate_names(type, &names);    //遍历所有的dp，按照type来分共两种dp
    SSET_FOR_EACH(name, &names) {
        struct dpif *old_dpif;

        /* Don't remove our backer if it exists. */
        if (!strcmp(name, backer_name)) {    //管理层重启过，但是dp还在运行
            continue;
        }

        if (dpif_open(name, type, &old_dpif)) {    //不会走到此分支
            VLOG_WARN("couldn't open old datapath %s to remove it", name);
        } else {
            dpif_delete(old_dpif);
            dpif_close(old_dpif);
        }
    }
    sset_destroy(&names);

    backer = xmalloc(sizeof *backer);    //申请backer空间

    error = dpif_create_and_open(backer_name, type, &backer->dpif);   //创建dpif
    free(backer_name);
    if (error) {
        VLOG_ERR("failed to open datapath of type %s: %s", type,
                 ovs_strerror(error));
        free(backer);
        return error;
    }
    backer->udpif = udpif_create(backer, backer->dpif);  //初始化upcall dpif

    backer->type = xstrdup(type);
    backer->refcount = 1;
    hmap_init(&backer->odp_to_ofport_map);
    ovs_rwlock_init(&backer->odp_to_ofport_lock);
    backer->need_revalidate = 0;
    simap_init(&backer->tnl_backers);
    backer->recv_set_enable = !ofproto_get_flow_restore_wait();
    *backerp = backer;

    if (backer->recv_set_enable) {
        dpif_flow_flush(backer->dpif);   //删除流表
    }

    /* Loop through the ports already on the datapath and remove any
     * that we don't need anymore. */
    list_init(&garbage_list);
    dpif_port_dump_start(&port_dump, backer->dpif);
    while (dpif_port_dump_next(&port_dump, &port)) {
        node = shash_find(&init_ofp_ports, port.name);
        if (!node && strcmp(port.name, dpif_base_name(backer->dpif))) {
            garbage = xmalloc(sizeof *garbage);
            garbage->odp_port = port.port_no;
            list_push_front(&garbage_list, &garbage->list_node);
        }
    }
    dpif_port_dump_done(&port_dump);

    LIST_FOR_EACH_POP (garbage, list_node, &garbage_list) {
        dpif_port_del(backer->dpif, garbage->odp_port);
        free(garbage);
    }

    shash_add(&all_dpif_backers, type, backer);

    check_support(backer);
    atomic_count_init(&backer->tnl_count, 0);

    error = dpif_recv_set(backer->dpif, backer->recv_set_enable);     //调用dpif_netlink的recv_set函数
    if (error) {
        VLOG_ERR("failed to listen on datapath of type %s: %s",
                 type, ovs_strerror(error));
        close_dpif_backer(backer);
        return error;
    }

    if (backer->recv_set_enable) {
        udpif_set_threads(backer->udpif, n_handlers, n_revalidators);    //启动upcall线程和revalidate线程
    }

    /* This check fails if performed before udpif threads have been set,
     * as the kernel module checks that the 'pid' in userspace action
     * is non-zero. */
    backer->support.variable_length_userdata
        = check_variable_length_userdata(backer);
    backer->dp_version_string = dpif_get_dp_version(backer->dpif);

    return error;
}
```

遍历dp名字，共两种：system:dpif_netlink_class 内核态,  netdev:dpif_netdev_class DPDK

```
int
dp_enumerate_names(const char *type, struct sset *names)
{
    struct registered_dpif_class *registered_class;
    const struct dpif_class *dpif_class;
    int error;

    dp_initialize();
    sset_clear(names);

    registered_class = dp_class_lookup(type);   // system:dpif_netlink_class 内核态,  netdev:dpif_netdev_class DPDK
    if (!registered_class) {
        VLOG_WARN("could not enumerate unknown type: %s", type);
        return EAFNOSUPPORT;
    }

    dpif_class = registered_class->dpif_class;
    error = (dpif_class->enumerate
             ? dpif_class->enumerate(names, dpif_class)
             : 0);
    if (error) {
        VLOG_WARN("failed to enumerate %s datapaths: %s", dpif_class->type,
                   ovs_strerror(error));
    }
    dp_class_unref(registered_class);

    return error;
}
```

创建后端并打开：

```
int
dpif_create_and_open(const char *name, const char *type, struct dpif **dpifp)
{
    int error;

    error = dpif_create(name, type, dpifp);
    if (error == EEXIST || error == EBUSY) {
        error = dpif_open(name, type, dpifp);
        if (error) {
            VLOG_WARN("datapath %s already exists but cannot be opened: %s",
                      name, ovs_strerror(error));
        }
    } else if (error) {
        VLOG_WARN("failed to create datapath %s: %s",
                  name, ovs_strerror(error));
    }
    return error;
}

int
dpif_create(const char *name, const char *type, struct dpif **dpifp)
{
    return do_open(name, type, true, dpifp);
}

static int
do_open(const char *name, const char *type, bool create, struct dpif **dpifp)
{
    struct dpif *dpif = NULL;
    int error;
    struct registered_dpif_class *registered_class;

    dp_initialize();

    type = dpif_normalize_type(type);
    registered_class = dp_class_lookup(type);
    if (!registered_class) {
        VLOG_WARN("could not create datapath %s of unknown type %s", name,
                  type);
        error = EAFNOSUPPORT;
        goto exit;
    }

    error = registered_class->dpif_class->open(registered_class->dpif_class,    //实际调用dpif_netlink_open函数
                                               name, create, &dpif);
    if (!error) {
        ovs_assert(dpif->dpif_class == registered_class->dpif_class);
    } else {
        dp_class_unref(registered_class);
    }

exit:
    *dpifp = error ? NULL : dpif;
    return error;
}

static int
dpif_netlink_open(const struct dpif_class *class OVS_UNUSED, const char *name,
                  bool create, struct dpif **dpifp)
{
    struct dpif_netlink_dp dp_request, dp;
    struct ofpbuf *buf;
    uint32_t upcall_pid;
    int error;

    error = dpif_netlink_init();
    if (error) {
        return error;
    }

    /* Create or look up datapath. */
    dpif_netlink_dp_init(&dp_request);
    if (create) {
        dp_request.cmd = OVS_DP_CMD_NEW;
        upcall_pid = 0;
        dp_request.upcall_pid = &upcall_pid;
    } else {
        /* Use OVS_DP_CMD_SET to report user features */
        dp_request.cmd = OVS_DP_CMD_SET;
    }
    dp_request.name = name;
    dp_request.user_features |= OVS_DP_F_UNALIGNED;
    dp_request.user_features |= OVS_DP_F_VPORT_PIDS;
    error = dpif_netlink_dp_transact(&dp_request, &dp, &buf);   //发送netlink 报文给内核创建dp
    if (error) {
        return error;
    }

    error = open_dpif(&dp, dpifp);
    ofpbuf_delete(buf);
    return error;
}
```

初始化upcall：

```
struct udpif *
udpif_create(struct dpif_backer *backer, struct dpif *dpif)
{
    struct udpif *udpif = xzalloc(sizeof *udpif);

    udpif->dpif = dpif;
    udpif->backer = backer;
    atomic_init(&udpif->flow_limit, MIN(ofproto_flow_limit, 10000));
    udpif->reval_seq = seq_create();
    udpif->dump_seq = seq_create();
    latch_init(&udpif->exit_latch);
    latch_init(&udpif->pause_latch);
    list_push_back(&all_udpifs, &udpif->list_node);
    atomic_init(&udpif->enable_ufid, false);
    atomic_init(&udpif->n_flows, 0);
    atomic_init(&udpif->n_flows_timestamp, LLONG_MIN);
    ovs_mutex_init(&udpif->n_flows_mutex);
    udpif->ukeys = xmalloc(N_UMAPS * sizeof *udpif->ukeys);
    for (int i = 0; i < N_UMAPS; i++) {
        cmap_init(&udpif->ukeys[i].cmap);
        ovs_mutex_init(&udpif->ukeys[i].mutex);
    }

    dpif_register_upcall_cb(dpif, upcall_cb, udpif);       //注册upcall回调函数
    dpif_register_dp_purge_cb(dpif, dp_purge_cb, udpif);   //注册purge回调函数

    return udpif;
}
```


## add_internal_flows

```
static int
add_internal_flows(struct ofproto_dpif *ofproto)
{
    struct ofpact_controller *controller;
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts;
    struct rule *unused_rulep OVS_UNUSED;
    struct match match;
    int error;
    int id;

    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    id = 1;

    controller = ofpact_put_CONTROLLER(&ofpacts);
    controller->max_len = UINT16_MAX;
    controller->controller_id = 0;
    controller->reason = OFPR_NO_MATCH;
    ofpact_pad(&ofpacts);

    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->miss_rule);
    if (error) {
        return error;
    }

    ofpbuf_clear(&ofpacts);
    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->no_packet_in_rule);
    if (error) {
        return error;
    }

    error = add_internal_miss_flow(ofproto, id++, &ofpacts,
                                   &ofproto->drop_frags_rule);
    if (error) {
        return error;
    }

    /* Drop any run away non-recirc rule lookups. Recirc_id has to be
     * zero when reaching this rule.
     *
     * (priority=2), recirc_id=0, actions=drop
     */
    ofpbuf_clear(&ofpacts);
    match_init_catchall(&match);
    match_set_recirc_id(&match, 0);
    error = ofproto_dpif_add_internal_flow(ofproto, &match, 2, 0, &ofpacts,
                                           &unused_rulep);
    return error;
}

static int
add_internal_miss_flow(struct ofproto_dpif *ofproto, int id,
                  const struct ofpbuf *ofpacts, struct rule_dpif **rulep)
{
    struct match match;
    int error;
    struct rule *rule;

    match_init_catchall(&match);
    match_set_reg(&match, 0, id);

    error = ofproto_dpif_add_internal_flow(ofproto, &match, 0, 0, ofpacts,
                                           &rule);
    *rulep = error ? NULL : rule_dpif_cast(rule);

    return error;
}

int
ofproto_dpif_add_internal_flow(struct ofproto_dpif *ofproto,
                               const struct match *match, int priority,
                               uint16_t idle_timeout,
                               const struct ofpbuf *ofpacts,
                               struct rule **rulep)
{
    struct ofproto_flow_mod ofm;
    struct rule_dpif *rule;
    int error;

    ofm.fm.match = *match;
    ofm.fm.priority = priority;
    ofm.fm.new_cookie = htonll(0);
    ofm.fm.cookie = htonll(0);
    ofm.fm.cookie_mask = htonll(0);
    ofm.fm.modify_cookie = false;
    ofm.fm.table_id = TBL_INTERNAL;
    ofm.fm.command = OFPFC_ADD;
    ofm.fm.idle_timeout = idle_timeout;
    ofm.fm.hard_timeout = 0;
    ofm.fm.importance = 0;
    ofm.fm.buffer_id = 0;
    ofm.fm.out_port = 0;
    ofm.fm.flags = OFPUTIL_FF_HIDDEN_FIELDS | OFPUTIL_FF_NO_READONLY;
    ofm.fm.ofpacts = ofpacts->data;
    ofm.fm.ofpacts_len = ofpacts->size;
    ofm.fm.delete_reason = OVS_OFPRR_NONE;

    error = ofproto_flow_mod(&ofproto->up, &ofm);
    if (error) {
        VLOG_ERR_RL(&rl, "failed to add internal flow (%s)",
                    ofperr_to_string(error));
        *rulep = NULL;
        return error;
    }

    rule = rule_dpif_lookup_in_table(ofproto,
                                     ofproto_dpif_get_tables_version(ofproto),
                                     TBL_INTERNAL, &ofm.fm.match.flow,
                                     &ofm.fm.match.wc);
    if (rule) {
        *rulep = &rule->up;
    } else {
        OVS_NOT_REACHED();
    }
    return 0;
}
```


## ovs_dp_cmd_new(内核态)

```
static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	struct ovs_net *ovs_net;
	int err, i;

	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME] || !a[OVS_DP_ATTR_UPCALL_PID])
		goto err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);    //申请dp空间
	if (dp == NULL)
		goto err_free_reply;

	ovs_dp_set_net(dp, sock_net(skb->sk));   //设置网络空间

	/* Allocate table. */
	err = ovs_flow_tbl_init(&dp->table);     //初始化流表
	if (err)
		goto err_free_dp;

	dp->stats_percpu = netdev_alloc_pcpu_stats(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dp->ports) {
		err = -ENOMEM;
		goto err_destroy_percpu;
	}

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&dp->ports[i]);

	/* Set up our datapath device. */
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	ovs_dp_change(dp, a);

	/* So far only local changes have been made, now need the lock. */
	ovs_lock();

	vport = new_vport(&parms);   //创建internal port
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		if (err == -EEXIST) {
			/* An outdated user space instance that does not understand
			 * the concept of user_features has attempted to create a new
			 * datapath and is likely to reuse it. Drop all user features.
			 */
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
				ovs_dp_reset_user_features(skb, info);
		}

		goto err_destroy_ports_array;
	}

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_net = net_generic(ovs_dp_get_net(dp), ovs_net_id);
	list_add_tail_rcu(&dp->list_node, &ovs_net->dps);        //dp添加到网络空间

	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_destroy_ports_array:
	ovs_unlock();
	kfree(dp->ports);
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
	kfree(dp);
err_free_reply:
	kfree_skb(reply);
err:
	return err;
}
```


# ofproto_delete

```c
int
ofproto_delete(const char *name, const char *type)
{
    const struct ofproto_class *class = ofproto_class_find__(type);   //实际调用ofproto_dpif_class的del函数
    return (!class ? EAFNOSUPPORT
            : !class->del ? EACCES
            : class->del(type, name));
}

// ofproto_dpif_class->del函数
static int
del(const char *type, const char *name)
{
    struct dpif *dpif;
    int error;

    error = dpif_open(name, type, &dpif);   //调用do_open打开dpif
    if (!error) {
        error = dpif_delete(dpif);   //删除dpif
        dpif_close(dpif);
    }
    return error;
}

int
dpif_delete(struct dpif *dpif)
{
    int error;

    COVERAGE_INC(dpif_destroy);

    error = dpif->dpif_class->destroy(dpif);   //实际调用dpif_netlink_destroy
    log_operation(dpif, "delete", error);
    return error;
}
```


## dpif_netlink_destroy

```c
static int
dpif_netlink_destroy(struct dpif *dpif_)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    struct dpif_netlink_dp dp;

    dpif_netlink_dp_init(&dp);
    dp.cmd = OVS_DP_CMD_DEL;
    dp.dp_ifindex = dpif->dp_ifindex;
    return dpif_netlink_dp_transact(&dp, NULL, NULL);   //调用内核删除dp
}
```


## ovs_dp_cmd_del

```c
static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_DEL);
	BUG_ON(err < 0);

	__dp_destroy(dp);
	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, &ovs_dp_datapath_multicast_group, reply, info);
	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

static void __dp_destroy(struct datapath *dp)
{
	int i;

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;

		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (vport->port_no != OVSP_LOCAL)
				ovs_dp_detach_port(vport);
	}

	list_del_rcu(&dp->list_node);

	/* OVSP_LOCAL is datapath internal port. We need to make sure that
	 * all ports in datapath are destroyed first before freeing datapath.
	 */
	ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));  //删除local internal port

	/* RCU destroy the flow table */
	call_rcu(&dp->rcu, destroy_dp_rcu);
}
```
