# bridge操作

本文介绍内核态OVS添加/删除bridge操作。

bridge操作的总入口是bridge_reconfigure函数。


# bridge_reconfigure

```c
static void
bridge_reconfigure(const struct ovsrec_open_vswitch *ovs_cfg)
{
    unsigned long int *splinter_vlans;
    struct sockaddr_in *managers;
    struct bridge *br, *next;
    int sflow_bridge_number;
    size_t n_managers;

    COVERAGE_INC(bridge_reconfigure);

    ofproto_set_flow_limit(smap_get_int(&ovs_cfg->other_config, "flow-limit",
                                        OFPROTO_FLOW_LIMIT_DEFAULT));
    ofproto_set_max_idle(smap_get_int(&ovs_cfg->other_config, "max-idle",
                                      OFPROTO_MAX_IDLE_DEFAULT));
    ofproto_set_n_dpdk_rxqs(smap_get_int(&ovs_cfg->other_config,
                                         "n-dpdk-rxqs", 0));
    ofproto_set_cpu_mask(smap_get(&ovs_cfg->other_config, "pmd-cpu-mask"));

    ofproto_set_threads(
        smap_get_int(&ovs_cfg->other_config, "n-handler-threads", 0),
        smap_get_int(&ovs_cfg->other_config, "n-revalidator-threads", 0));

    /* Destroy "struct bridge"s, "struct port"s, and "struct iface"s according
     * to 'ovs_cfg', with only very minimal configuration otherwise.
     *
     * This is mostly an update to bridge data structures. Nothing is pushed
     * down to ofproto or lower layers. */
    add_del_bridges(ovs_cfg);
    splinter_vlans = collect_splinter_vlans(ovs_cfg);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_collect_wanted_ports(br, splinter_vlans, &br->wanted_ports);
        bridge_del_ports(br, &br->wanted_ports);      //删除端口
    }
    free(splinter_vlans);

    /* Start pushing configuration changes down to the ofproto layer:
     *
     *   - Delete ofprotos that are no longer configured.
     *
     *   - Delete ports that are no longer configured.
     *
     *   - Reconfigure existing ports to their desired configurations, or
     *     delete them if not possible.
     *
     * We have to do all the deletions before we can do any additions, because
     * the ports to be added might require resources that will be freed up by
     * deletions (they might especially overlap in name). */
    bridge_delete_ofprotos();
    HMAP_FOR_EACH (br, node, &all_bridges) {
        if (br->ofproto) {
            bridge_delete_or_reconfigure_ports(br);     //of层删除或重置端口
        }
    }

    /* Finish pushing configuration changes to the ofproto layer:
     *
     *     - Create ofprotos that are missing.
     *
     *     - Add ports that are missing. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        if (!br->ofproto) {
            int error;

            error = ofproto_create(br->name, br->type, &br->ofproto);   //构建of bridge
            if (error) {
                VLOG_ERR("failed to create bridge %s: %s", br->name,
                         ovs_strerror(error));
                shash_destroy(&br->wanted_ports);
                bridge_destroy(br, true);
            } else {
                /* Trigger storing datapath version. */
                seq_change(connectivity_seq_get());
            }
        }
    }
    HMAP_FOR_EACH (br, node, &all_bridges) {
        bridge_add_ports(br, &br->wanted_ports);     //添加端口
        shash_destroy(&br->wanted_ports);
    }

    reconfigure_system_stats(ovs_cfg);

    /* Complete the configuration. */
    sflow_bridge_number = 0;
    collect_in_band_managers(ovs_cfg, &managers, &n_managers);
    HMAP_FOR_EACH (br, node, &all_bridges) {
        struct port *port;

        /* We need the datapath ID early to allow LACP ports to use it as the
         * default system ID. */
        bridge_configure_datapath_id(br);

        HMAP_FOR_EACH (port, hmap_node, &br->ports) {
            struct iface *iface;

            port_configure(port);

            LIST_FOR_EACH (iface, port_elem, &port->ifaces) {
                iface_set_ofport(iface->cfg, iface->ofp_port);
                /* Clear eventual previous errors */
                ovsrec_interface_set_error(iface->cfg, NULL);
                iface_configure_cfm(iface);
                iface_configure_qos(iface, port->cfg->qos);
                iface_set_mac(br, port, iface);
                ofproto_port_set_bfd(br->ofproto, iface->ofp_port,
                                     &iface->cfg->bfd);
                ofproto_port_set_lldp(br->ofproto, iface->ofp_port,
                                      &iface->cfg->lldp);
            }
        }
        bridge_configure_mirrors(br);
        bridge_configure_forward_bpdu(br);
        bridge_configure_mac_table(br);
        bridge_configure_mcast_snooping(br);
        bridge_configure_remotes(br, managers, n_managers);
        bridge_configure_netflow(br);
        bridge_configure_sflow(br, &sflow_bridge_number);
        bridge_configure_ipfix(br);
        bridge_configure_spanning_tree(br);
        bridge_configure_tables(br);
        bridge_configure_dp_desc(br);
        bridge_configure_aa(br);
    }
    free(managers);

    /* The ofproto-dpif provider does some final reconfiguration in its
     * ->type_run() function.  We have to call it before notifying the database
     * client that reconfiguration is complete, otherwise there is a very
     * narrow race window in which e.g. ofproto/trace will not recognize the
     * new configuration (sometimes this causes unit test failures). */
    bridge_run__();
}
```


# add_del_bridges

```
static void
add_del_bridges(const struct ovsrec_open_vswitch *cfg)
{
    struct bridge *br, *next;
    struct shash_node *node;
    struct shash new_br;
    size_t i;

    /* Collect new bridges' names and types. */
    shash_init(&new_br);
    for (i = 0; i < cfg->n_bridges; i++) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        if (strchr(br_cfg->name, '/')) {
            /* Prevent remote ovsdb-server users from accessing arbitrary
             * directories, e.g. consider a bridge named "../../../etc/". */
            VLOG_WARN_RL(&rl, "ignoring bridge with invalid name \"%s\"",
                         br_cfg->name);
        } else if (!shash_add_once(&new_br, br_cfg->name, br_cfg)) {
            VLOG_WARN_RL(&rl, "bridge %s specified twice", br_cfg->name);
        }
    }

    /* Get rid of deleted bridges or those whose types have changed.
     * Update 'cfg' of bridges that still exist. */
    HMAP_FOR_EACH_SAFE (br, next, node, &all_bridges) {
        br->cfg = shash_find_data(&new_br, br->name);
        if (!br->cfg || strcmp(br->type, ofproto_normalize_type(
                                   br->cfg->datapath_type))) {
            bridge_destroy(br, true);    //删除bridge
        }
    }

    /* Add new bridges. */
    SHASH_FOR_EACH(node, &new_br) {
        const struct ovsrec_bridge *br_cfg = node->data;
        struct bridge *br = bridge_lookup(br_cfg->name);
        if (!br) {
            bridge_create(br_cfg);    //添加bridge
        }
    }

    shash_destroy(&new_br);
}
```


## bridge_destroy

```
static void
bridge_destroy(struct bridge *br, bool del)
{
    if (br) {
        struct mirror *mirror, *next_mirror;
        struct port *port, *next_port;

        HMAP_FOR_EACH_SAFE (port, next_port, hmap_node, &br->ports) {   //删除port
            port_destroy(port);
        }
        HMAP_FOR_EACH_SAFE (mirror, next_mirror, hmap_node, &br->mirrors) {   //删除mirror
            mirror_destroy(mirror);
        }

        hmap_remove(&all_bridges, &br->node);
        ofproto_destroy(br->ofproto, del);
        hmap_destroy(&br->ifaces);
        hmap_destroy(&br->ports);
        hmap_destroy(&br->iface_by_name);
        hmap_destroy(&br->mirrors);
        hmap_destroy(&br->mappings);
        free(br->name);
        free(br->type);
        free(br);
    }
}

static void
port_destroy(struct port *port)
{
    if (port) {
        struct bridge *br = port->bridge;
        struct iface *iface, *next;

        if (br->ofproto) {
            ofproto_bundle_unregister(br->ofproto, port);
        }

        LIST_FOR_EACH_SAFE (iface, next, port_elem, &port->ifaces) {
            iface_destroy__(iface);
        }

        hmap_remove(&br->ports, &port->hmap_node);
        free(port->name);
        free(port);
    }
}
```


## bridge_create

```
static void
bridge_create(const struct ovsrec_bridge *br_cfg)
{
    struct bridge *br;

    ovs_assert(!bridge_lookup(br_cfg->name));
    br = xzalloc(sizeof *br);    //创建bridge对象

    br->name = xstrdup(br_cfg->name);
    br->type = xstrdup(ofproto_normalize_type(br_cfg->datapath_type));
    br->cfg = br_cfg;

    /* Derive the default Ethernet address from the bridge's UUID.  This should
     * be unique and it will be stable between ovs-vswitchd runs.  */
    memcpy(&br->default_ea, &br_cfg->header_.uuid, ETH_ADDR_LEN);   //以UUID设置为mac地址
    eth_addr_mark_random(&br->default_ea);   //设置为非组播mac地址

    hmap_init(&br->ports);
    hmap_init(&br->ifaces);
    hmap_init(&br->iface_by_name);
    hmap_init(&br->mirrors);

    hmap_init(&br->mappings);
    hmap_insert(&all_bridges, &br->node, hash_string(br->name, 0));
}
```

