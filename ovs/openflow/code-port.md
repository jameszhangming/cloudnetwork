# ofproto port操作

本文介绍openflow交换机的port添加和删除操作，openflow port的操作入口为：

* ofproto_port_add 添加端口
* ofproto_port_del 删除端口
* ofproto_port_unregister 解注册，消除ofport相关配置


# ofproto_port_add

```
int
ofproto_port_add(struct ofproto *ofproto, struct netdev *netdev,
                 ofp_port_t *ofp_portp)
{
    ofp_port_t ofp_port = ofp_portp ? *ofp_portp : OFPP_NONE;
    int error;

    error = ofproto->ofproto_class->port_add(ofproto, netdev);  //只有ofproto_dpif_class类型
    if (!error) {
        const char *netdev_name = netdev_get_name(netdev);

        simap_put(&ofproto->ofp_requests, netdev_name,
                  ofp_to_u16(ofp_port));
        error = update_port(ofproto, netdev_name);   //更新ofport，如果已存在则会删除，如果不存在则创建ofport
    }
    if (ofp_portp) {
        *ofp_portp = OFPP_NONE;
        if (!error) {
            struct ofproto_port ofproto_port;

            error = ofproto_port_query_by_name(ofproto,
                                               netdev_get_name(netdev),
                                               &ofproto_port);
            if (!error) {
                *ofp_portp = ofproto_port.ofp_port;
                ofproto_port_destroy(&ofproto_port);
            }
        }
    }
    return error;
}
```


## port_add(ofproto_dpif_class)

```c
static int
port_add(struct ofproto *ofproto_, struct netdev *netdev)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    const char *devname = netdev_get_name(netdev);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;

    if (netdev_vport_is_patch(netdev)) {
        sset_add(&ofproto->ghost_ports, netdev_get_name(netdev));
        return 0;
    }

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (!dpif_port_exists(ofproto->backer->dpif, dp_port_name)) {
        odp_port_t port_no = ODPP_NONE;
        int error;

        error = dpif_port_add(ofproto->backer->dpif, netdev, &port_no);
        if (error) {
            return error;
        }
        if (netdev_get_tunnel_config(netdev)) {
            simap_put(&ofproto->backer->tnl_backers,
                      dp_port_name, odp_to_u32(port_no));
        }
    }

    if (netdev_get_tunnel_config(netdev)) {
        sset_add(&ofproto->ghost_ports, devname);
    } else {
        sset_add(&ofproto->ports, devname);
    }
    return 0;
}

int
dpif_port_add(struct dpif *dpif, struct netdev *netdev, odp_port_t *port_nop)
{
    const char *netdev_name = netdev_get_name(netdev);
    odp_port_t port_no = ODPP_NONE;
    int error;

    COVERAGE_INC(dpif_port_add);

    if (port_nop) {
        port_no = *port_nop;
    }

	//添加端口，dpdk的dpif_class为dpif_netdev_class，内核态的为dpif_netlink_class
    error = dpif->dpif_class->port_add(dpif, netdev, &port_no);   
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: added %s as port %"PRIu32,
                    dpif_name(dpif), netdev_name, port_no);
    } else {
        VLOG_WARN_RL(&error_rl, "%s: failed to add %s as port: %s",
                     dpif_name(dpif), netdev_name, ovs_strerror(error));
        port_no = ODPP_NONE;
    }
    if (port_nop) {
        *port_nop = port_no;
    }
    return error;
}
```


## update_port

```c
static int
update_port(struct ofproto *ofproto, const char *name)
{
    struct ofproto_port ofproto_port;
    struct ofputil_phy_port pp;
    struct netdev *netdev;
    struct ofport *port;
    int error = 0;

    COVERAGE_INC(ofproto_update_port);

    /* Fetch 'name''s location and properties from the datapath. */
    netdev = (!ofproto_port_query_by_name(ofproto, name, &ofproto_port)
              ? ofport_open(ofproto, &ofproto_port, &pp)
              : NULL);

    if (netdev) {
        port = ofproto_get_port(ofproto, ofproto_port.ofp_port);
        if (port && !strcmp(netdev_get_name(port->netdev), name)) {
            struct netdev *old_netdev = port->netdev;

            /* 'name' hasn't changed location.  Any properties changed? */
            if (!ofport_equal(&port->pp, &pp)) {
                ofport_modified(port, &pp);
            }

            update_mtu(ofproto, port);

            /* Install the newly opened netdev in case it has changed.
             * Don't close the old netdev yet in case port_modified has to
             * remove a retained reference to it.*/
            port->netdev = netdev;
            port->change_seq = netdev_get_change_seq(netdev);

            if (port->ofproto->ofproto_class->port_modified) {      //更新ofport
                port->ofproto->ofproto_class->port_modified(port);
            }

            netdev_close(old_netdev);
        } else {
            /* If 'port' is nonnull then its name differs from 'name' and thus
             * we should delete it.  If we think there's a port named 'name'
             * then its port number must be wrong now so delete it too. */
            if (port) {
                ofport_remove(port);
            }
            ofport_remove_with_name(ofproto, name);
            error = ofport_install(ofproto, netdev, &pp);
        }
    } else {
        /* Any port named 'name' is gone now. */
        ofport_remove_with_name(ofproto, name);
    }
    ofproto_port_destroy(&ofproto_port);

    return error;
}
```


### port_modified(ofproto_dpif_class)

```c
static void
port_modified(struct ofport *port_)
{
    struct ofport_dpif *port = ofport_dpif_cast(port_);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dp_port_name;
    struct netdev *netdev = port->up.netdev;

    if (port->bundle && port->bundle->bond) {
        bond_slave_set_netdev(port->bundle->bond, port, netdev);
    }

    if (port->cfm) {
        cfm_set_netdev(port->cfm, netdev);
    }

    if (port->bfd) {
        bfd_set_netdev(port->bfd, netdev);
    }

    ofproto_dpif_monitor_port_update(port, port->bfd, port->cfm,
                                     port->lldp, &port->up.pp.hw_addr);

    dp_port_name = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);

    if (port->is_tunnel) {
        struct ofproto_dpif *ofproto = ofproto_dpif_cast(port->up.ofproto);

        if (tnl_port_reconfigure(port, netdev, port->odp_port,
                                 ovs_native_tunneling_is_on(ofproto),
                                 dp_port_name)) {
            ofproto->backer->need_revalidate = REV_RECONFIGURE;
        }
    }

    ofport_update_peer(port);
}
```


# ofproto_port_del

```c
int
ofproto_port_del(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(ofproto, ofp_port);
    const char *name = ofport ? netdev_get_name(ofport->netdev) : "<unknown>";
    struct simap_node *ofp_request_node;
    int error;

    ofp_request_node = simap_find(&ofproto->ofp_requests, name);
    if (ofp_request_node) {
        simap_delete(&ofproto->ofp_requests, ofp_request_node);
    }

    error = ofproto->ofproto_class->port_del(ofproto, ofp_port);   //只有ofproto_dpif_class类型
    if (!error && ofport) {
        /* 'name' is the netdev's name and update_port() is going to close the
         * netdev.  Just in case update_port() refers to 'name' after it
         * destroys 'ofport', make a copy of it around the update_port()
         * call. */
        char *devname = xstrdup(name);
        update_port(ofproto, devname);
        free(devname);
    }
    return error;
}
```

## port_del(ofproto_dpif_class)

```c
static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct ofproto_dpif *ofproto = ofproto_dpif_cast(ofproto_);
    struct ofport_dpif *ofport = ofp_port_to_ofport(ofproto, ofp_port);
    int error = 0;

    if (!ofport) {
        return 0;
    }

    sset_find_and_delete(&ofproto->ghost_ports,
                         netdev_get_name(ofport->up.netdev));
    ofproto->backer->need_revalidate = REV_RECONFIGURE;
    if (!ofport->is_tunnel && !netdev_vport_is_patch(ofport->up.netdev)) {
        error = dpif_port_del(ofproto->backer->dpif, ofport->odp_port);
        if (!error) {
            /* The caller is going to close ofport->up.netdev.  If this is a
             * bonded port, then the bond is using that netdev, so remove it
             * from the bond.  The client will need to reconfigure everything
             * after deleting ports, so then the slave will get re-added. */
            bundle_remove(&ofport->up);
        }
    }
    return error;
}

int
dpif_port_del(struct dpif *dpif, odp_port_t port_no)
{
    int error;

    COVERAGE_INC(dpif_port_del);

    error = dpif->dpif_class->port_del(dpif, port_no);    //分dpdk和内核态两种模式
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: port_del(%"PRIu32")",
                    dpif_name(dpif), port_no);
    } else {
        log_operation(dpif, "port_del", error);
    }
    return error;
}
```


# ofproto_port_unregister

```c
void
ofproto_port_unregister(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    struct ofport *port = ofproto_get_port(ofproto, ofp_port);
    if (port) {
        if (port->ofproto->ofproto_class->set_realdev) {
            port->ofproto->ofproto_class->set_realdev(port, 0, 0);
        }
        if (port->ofproto->ofproto_class->set_stp_port) {
            port->ofproto->ofproto_class->set_stp_port(port, NULL);
        }
        if (port->ofproto->ofproto_class->set_rstp_port) {
            port->ofproto->ofproto_class->set_rstp_port(port, NULL);
        }
        if (port->ofproto->ofproto_class->set_cfm) {
            port->ofproto->ofproto_class->set_cfm(port, NULL);
        }
        if (port->ofproto->ofproto_class->bundle_remove) {
            port->ofproto->ofproto_class->bundle_remove(port);
        }
    }
}
```
