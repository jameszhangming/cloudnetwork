# upcall整体流程

内核OVS数据面出现流表不能匹配时，会upcall到OVSD进行流表匹配，匹配成功后将下发流表到数据面。

upcall整体流程：

![upcall-flow](images/upcall-flow.png "upcall-flow")


# ovs_dp_process_packet（数据面）

数据面在ovs_dp_process_packet处理函数中，如果当前报文未在流表中匹配到时，会调用ovs_dp_upcall发送upcall请求。

```c
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
{
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct dp_stats_percpu *stats;
	u64 *stats_counter;
	u32 n_mask_hit;

	stats = this_cpu_ptr(dp->stats_percpu);

	/* Look up flow. */
	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, skb_get_hash(skb),	//查询转发表
					 &n_mask_hit);
	if (unlikely(!flow)) {		          //如果没有查到流表，则上送的upcall线程处理
		struct dp_upcall_info upcall;
		int error;

		memset(&upcall, 0, sizeof(upcall));
		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.portid = ovs_vport_find_upcall_portid(p, skb);    //得到vport处理upcall的线程
		upcall.mru = OVS_CB(skb)->mru;
		error = ovs_dp_upcall(dp, skb, key, &upcall);
		if (unlikely(error))
			kfree_skb(skb);
		else
			consume_skb(skb);
		stats_counter = &stats->n_missed;	//丢包统计加一
		goto out;
	}

	ovs_flow_stats_update(flow, key->tp.flags, skb);
	sf_acts = rcu_dereference(flow->sf_acts);		//获取action
	ovs_execute_actions(dp, skb, sf_acts, key);		//对报文执行action

	stats_counter = &stats->n_hit;

out:
	/* Update datapath statistics. */
	u64_stats_update_begin(&stats->syncp);
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
	u64_stats_update_end(&stats->syncp);
}
```


## ovs_vport_find_upcall_portid

```c
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);   //根据报文得到hash值
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}
```


## ovs_dp_upcall

```c
int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct sw_flow_key *key,
		  const struct dp_upcall_info *upcall_info)
{
	struct dp_stats_percpu *stats;
	int err;

	if (upcall_info->portid == 0) {
		err = -ENOTCONN;
		goto err;
	}

	if (!skb_is_gso(skb))
		err = queue_userspace_packet(dp, skb, key, upcall_info);    //发送到用户态进程
	else
		err = queue_gso_packets(dp, skb, key, upcall_info);
	if (err)
		goto err;

	return 0;

err:
	stats = this_cpu_ptr(dp->stats_percpu);

	u64_stats_update_begin(&stats->syncp);
	stats->n_lost++;
	u64_stats_update_end(&stats->syncp);

	return err;
}
```


### queue_userspace_packet

```c
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb = NULL; /* to be queued to userspace */
	struct nlattr *nla;
	struct genl_info info = {
#ifdef HAVE_GENLMSG_NEW_UNICAST
		.dst_sk = ovs_dp_get_net(dp)->genl_sock,
#endif
		.snd_portid = upcall_info->portid,
	};
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (skb_vlan_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = vlan_insert_tag_set_proto(nskb, nskb->vlan_proto, skb_vlan_tag_get(nskb));
		if (!nskb)
			return -ENOMEM;

		vlan_set_tci(nskb, 0);

		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	len = upcall_msg_size(upcall_info, hlen);
	user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	err = ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);
	BUG_ON(err);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));


	if (upcall_info->egress_tun_info) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_EGRESS_TUN_KEY);
		err = ovs_nla_put_egress_tunnel_key(user_skb,
						    upcall_info->egress_tun_info,
						    upcall_info->egress_tun_opts);
		BUG_ON(err);
		nla_nest_end(user_skb, nla);
	}

	if (upcall_info->actions_len) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_ACTIONS);
		err = ovs_nla_put_actions(upcall_info->actions,
					  upcall_info->actions_len,
					  user_skb);
		if (!err)
			nla_nest_end(user_skb, nla);
		else
			nla_nest_cancel(user_skb, nla);
	}

	/* Add OVS_PACKET_ATTR_MRU */
	if (upcall_info->mru) {
		if (nla_put_u16(user_skb, OVS_PACKET_ATTR_MRU,
				upcall_info->mru)) {
			err = -ENOBUFS;
			goto out;
		}
		pad_packet(dp, user_skb);
	}

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy()
	 */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len);

	err = skb_zerocopy(user_skb, skb, skb->len, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	pad_packet(dp, user_skb);

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);    //发送netlink消息
	user_skb = NULL;
out:
	if (err)
		skb_tx_error(skb);
	kfree_skb(user_skb);
	kfree_skb(nskb);
	return err;
}
```


# upcall线程管理


## udpif_set_threads(启动线程)

```
void
udpif_set_threads(struct udpif *udpif, size_t n_handlers,
                  size_t n_revalidators)
{
    ovs_assert(udpif);
    ovs_assert(n_handlers && n_revalidators);

    ovsrcu_quiesce_start();
    if (udpif->n_handlers != n_handlers
        || udpif->n_revalidators != n_revalidators) {
        udpif_stop_threads(udpif);
    }

    if (!udpif->handlers && !udpif->revalidators) {    //两个值未设置说明线程未启动
        int error;

        error = dpif_handlers_set(udpif->dpif, n_handlers);
        if (error) {
            VLOG_ERR("failed to configure handlers in dpif %s: %s",
                     dpif_name(udpif->dpif), ovs_strerror(error));
            return;
        }

        udpif_start_threads(udpif, n_handlers, n_revalidators);  //启动线程
    }
    ovsrcu_quiesce_end();
}

static void
udpif_start_threads(struct udpif *udpif, size_t n_handlers,
                    size_t n_revalidators)
{
    if (udpif && n_handlers && n_revalidators) {
        size_t i;
        bool enable_ufid;

        udpif->n_handlers = n_handlers;
        udpif->n_revalidators = n_revalidators;

        udpif->handlers = xzalloc(udpif->n_handlers * sizeof *udpif->handlers);   //创建handler对象
        for (i = 0; i < udpif->n_handlers; i++) {
            struct handler *handler = &udpif->handlers[i];

            handler->udpif = udpif;
            handler->handler_id = i;
            handler->thread = ovs_thread_create(
                "handler", udpif_upcall_handler, handler);    //每个handler对应一个upcall线程
        }

        enable_ufid = ofproto_dpif_get_enable_ufid(udpif->backer);
        atomic_init(&udpif->enable_ufid, enable_ufid);
        dpif_enable_upcall(udpif->dpif);    //使能upcall，内核态未定义此函数

        ovs_barrier_init(&udpif->reval_barrier, udpif->n_revalidators);
        ovs_barrier_init(&udpif->pause_barrier, udpif->n_revalidators + 1);
        udpif->reval_exit = false;
        udpif->pause = false;
        udpif->revalidators = xzalloc(udpif->n_revalidators
                                      * sizeof *udpif->revalidators);    //创建revalicator对象
        for (i = 0; i < udpif->n_revalidators; i++) {
            struct revalidator *revalidator = &udpif->revalidators[i];

            revalidator->udpif = udpif;
            revalidator->thread = ovs_thread_create(
                "revalidator", udpif_revalidator, revalidator);     //启动revalidator线程
        }
    }
}
```


## udpif_synchronize

```c
void
udpif_synchronize(struct udpif *udpif)
{
    /* This is stronger than necessary.  It would be sufficient to ensure
     * (somehow) that each handler and revalidator thread had passed through
     * its main loop once. */
    size_t n_handlers = udpif->n_handlers;
    size_t n_revalidators = udpif->n_revalidators;

    ovsrcu_quiesce_start();
    udpif_stop_threads(udpif);    //停止upcall线程和revalidator线程
    udpif_start_threads(udpif, n_handlers, n_revalidators);   //启动upcall线程和revalidator线程
    ovsrcu_quiesce_end();
}
```


## udpif_flush

```c
void
udpif_flush(struct udpif *udpif)
{
    size_t n_handlers, n_revalidators;

    n_handlers = udpif->n_handlers;
    n_revalidators = udpif->n_revalidators;

    ovsrcu_quiesce_start();

    udpif_stop_threads(udpif);  //停止upcall线程和revalidator线程
    dpif_flow_flush(udpif->dpif);   //清除所有flow
    udpif_start_threads(udpif, n_handlers, n_revalidators);  //启动upcall线程和revalidator线程

    ovsrcu_quiesce_end();
}
```


# upcall线程处理函数

```c
static void *
udpif_upcall_handler(void *arg)
{
    struct handler *handler = arg;
    struct udpif *udpif = handler->udpif;

    while (!latch_is_set(&handler->udpif->exit_latch)) {
        if (recv_upcalls(handler)) {  //接收upcall并处理
            poll_immediate_wake();    //不阻塞，说明还有upcall需要处理
        } else {
		    //阻塞在netlink接收上，handler和dpif_handler对应，监听相同handler_id的sock
            dpif_recv_wait(udpif->dpif, handler->handler_id);  
            latch_wait(&udpif->exit_latch);
        }
        poll_block();   //poll阻塞
    }

    return NULL;
}
```


## poll机制

当接收到upcall并处理时，调用poll_immediate_wake函数：

```c
#define poll_immediate_wake() poll_immediate_wake_at(OVS_SOURCE_LOCATOR)

void
poll_immediate_wake_at(const char *where)
{
    poll_timer_wait_at(0, where);
}

void
poll_timer_wait_at(long long int msec, const char *where)
{
    long long int now = time_msec();
    long long int when;

    if (msec <= 0) {
        /* Wake up immediately. */
        when = LLONG_MIN;
    } else if ((unsigned long long int) now + msec <= LLONG_MAX) {
        /* Normal case. */
        when = now + msec;
    } else {
        /* now + msec would overflow. */
        when = LLONG_MAX;
    }

    poll_timer_wait_until_at(when, where);
}

void
poll_timer_wait_until_at(long long int when, const char *where)
{
    struct poll_loop *loop = poll_loop();
    if (when < loop->timeout_when) {
        loop->timeout_when = when;
        loop->timeout_where = where;
    }
}

static struct poll_loop *
poll_loop(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static pthread_key_t key;
    struct poll_loop *loop;

    if (ovsthread_once_start(&once)) {
        xpthread_key_create(&key, free_poll_loop);
        ovsthread_once_done(&once);
    }

    loop = pthread_getspecific(key);   //从当前线程获取
    if (!loop) {
        loop = xzalloc(sizeof *loop);
        hmap_init(&loop->poll_nodes);
        xpthread_setspecific(key, loop);   //设置到当前线程
    }
    return loop;
}
````

当未接收到upcall时，调用dpif_recv_wait等待

```c
void
dpif_recv_wait(struct dpif *dpif, uint32_t handler_id)
{
    if (dpif->dpif_class->recv_wait) {
        dpif->dpif_class->recv_wait(dpif, handler_id);    //内核态实际调用 dpif_netlink_recv_wait函数
    }
}

static void
dpif_netlink_recv_wait(struct dpif *dpif_, uint32_t handler_id)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);

    fat_rwlock_rdlock(&dpif->upcall_lock);
    dpif_netlink_recv_wait__(dpif, handler_id);
    fat_rwlock_unlock(&dpif->upcall_lock);
}

static void
dpif_netlink_recv_wait__(struct dpif_netlink *dpif, uint32_t handler_id)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
#ifdef _WIN32
    uint32_t i;
    struct dpif_windows_vport_sock *sock_pool =
        dpif->handlers[handler_id].vport_sock_pool;

    /* Only one handler is supported currently. */
    if (handler_id >= 1) {
        return;
    }

    for (i = 0; i < VPORT_SOCK_POOL_SIZE; i++) {
        nl_sock_wait(sock_pool[i].nl_sock, POLLIN); 
    }
#else
    if (dpif->handlers && handler_id < dpif->n_handlers) {
        struct dpif_handler *handler = &dpif->handlers[handler_id];

        poll_fd_wait(handler->epoll_fd, POLLIN);    //poll等待
    }
#endif
}

#define poll_fd_wait(fd, events) poll_fd_wait_at(fd, events, OVS_SOURCE_LOCATOR)

void
poll_fd_wait_at(int fd, short int events, const char *where)
{
    poll_create_node(fd, 0, events, where);
}

static void
poll_create_node(int fd, HANDLE wevent, short int events, const char *where)
{
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;

    COVERAGE_INC(poll_create_node);

    /* Both 'fd' and 'wevent' cannot be set. */
    ovs_assert(!fd != !wevent);

    /* Check for duplicate.  If found, "or" the events. */
    node = find_poll_node(loop, fd, wevent);
    if (node) {
        node->pollfd.events |= events;
    } else {
        node = xzalloc(sizeof *node);
        hmap_insert(&loop->poll_nodes, &node->hmap_node,
                    hash_2words(fd, (uint32_t)wevent));
        node->pollfd.fd = fd;
        node->pollfd.events = events;
#ifdef _WIN32
        if (!wevent) {
            wevent = CreateEvent(NULL, FALSE, FALSE, NULL);
        }
#endif
        node->wevent = wevent;
        node->where = where;
    }
}
```

每执行一次循环，会调用poll_block函数阻塞

```c
void
poll_block(void)
{
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;
    struct pollfd *pollfds;
    HANDLE *wevents = NULL;
    int elapsed;
    int retval;
    int i;

    /* Register fatal signal events before actually doing any real work for
     * poll_block. */
    fatal_signal_wait();

    if (loop->timeout_when == LLONG_MIN) {
        COVERAGE_INC(poll_zero_timeout);
    }

    timewarp_run();
    pollfds = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *pollfds);

#ifdef _WIN32
    wevents = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *wevents);
#endif

    /* Populate with all the fds and events. */
    i = 0;
    HMAP_FOR_EACH (node, hmap_node, &loop->poll_nodes) {
        pollfds[i] = node->pollfd;
#ifdef _WIN32
        wevents[i] = node->wevent;
        if (node->pollfd.fd && node->wevent) {
            short int wsa_events = 0;
            if (node->pollfd.events & POLLIN) {
                wsa_events |= FD_READ | FD_ACCEPT | FD_CLOSE;
            }
            if (node->pollfd.events & POLLOUT) {
                wsa_events |= FD_WRITE | FD_CONNECT | FD_CLOSE;
            }
            WSAEventSelect(node->pollfd.fd, node->wevent, wsa_events);
        }
#endif
        i++;
    }

    retval = time_poll(pollfds, hmap_count(&loop->poll_nodes), wevents,
                       loop->timeout_when, &elapsed);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "poll: %s", ovs_strerror(-retval));
    } else if (!retval) {
        log_wakeup(loop->timeout_where, NULL, elapsed);
    } else if (get_cpu_usage() > 50 || VLOG_IS_DBG_ENABLED()) {
        i = 0;
        HMAP_FOR_EACH (node, hmap_node, &loop->poll_nodes) {
            if (pollfds[i].revents) {
                log_wakeup(node->where, &pollfds[i], 0);
            }
            i++;
        }
    }

    free_poll_nodes(loop);
    loop->timeout_when = LLONG_MAX;
    loop->timeout_where = NULL;
    free(pollfds);
    free(wevents);

    /* Handle any pending signals before doing anything else. */
    fatal_signal_run();

    seq_woke();
}

int
time_poll(struct pollfd *pollfds, int n_pollfds, HANDLE *handles OVS_UNUSED,
          long long int timeout_when, int *elapsed)
{
    long long int *last_wakeup = last_wakeup_get();
    long long int start;
    bool quiescent;
    int retval = 0;

    time_init();
    coverage_clear();
    coverage_run();
    if (*last_wakeup && !thread_is_pmd()) {
        log_poll_interval(*last_wakeup);
    }
    start = time_msec();

    timeout_when = MIN(timeout_when, deadline);
    quiescent = ovsrcu_is_quiescent();

    for (;;) {
        long long int now = time_msec();
        int time_left;

        if (now >= timeout_when) {
            time_left = 0;
        } else if ((unsigned long long int) timeout_when - now > INT_MAX) {
            time_left = INT_MAX;
        } else {
            time_left = timeout_when - now;
        }

        if (!quiescent) {
            if (!time_left) {
                ovsrcu_quiesce();
            } else {
                ovsrcu_quiesce_start();
            }
        }

#ifndef _WIN32
        retval = poll(pollfds, n_pollfds, time_left);    //执行poll，直到超时或者指定的事件发生
        if (retval < 0) {
            retval = -errno;
        }
#else
        if (n_pollfds > MAXIMUM_WAIT_OBJECTS) {
            VLOG_ERR("Cannot handle more than maximum wait objects\n");
        } else if (n_pollfds != 0) {
            retval = WaitForMultipleObjects(n_pollfds, handles, FALSE,
                                            time_left);
        }
        if (retval < 0) {
            /* XXX This will be replace by a win error to errno
               conversion function */
            retval = -WSAGetLastError();
            retval = -EINVAL;
        }
#endif

        if (!quiescent && time_left) {
            ovsrcu_quiesce_end();
        }

        if (deadline <= time_msec()) {
#ifndef _WIN32
            fatal_signal_handler(SIGALRM);
#else
            VLOG_ERR("wake up from WaitForMultipleObjects after deadline");
            fatal_signal_handler(SIGTERM);
#endif
            if (retval < 0) {
                retval = 0;
            }
            break;
        }

        if (retval != -EINTR) {
            break;
        }
    }
    *last_wakeup = time_msec();
    refresh_rusage();
    *elapsed = *last_wakeup - start;
    return retval;
}
```


## recv_upcalls

```c
static size_t
recv_upcalls(struct handler *handler)
{
    struct udpif *udpif = handler->udpif;
    uint64_t recv_stubs[UPCALL_MAX_BATCH][512 / 8];
    struct ofpbuf recv_bufs[UPCALL_MAX_BATCH];
    struct dpif_upcall dupcalls[UPCALL_MAX_BATCH];
    struct upcall upcalls[UPCALL_MAX_BATCH];
    struct flow flows[UPCALL_MAX_BATCH];
    size_t n_upcalls, i;

    n_upcalls = 0;
    while (n_upcalls < UPCALL_MAX_BATCH) {
        struct ofpbuf *recv_buf = &recv_bufs[n_upcalls];
        struct dpif_upcall *dupcall = &dupcalls[n_upcalls];
        struct upcall *upcall = &upcalls[n_upcalls];
        struct flow *flow = &flows[n_upcalls];
        unsigned int mru;
        int error;

        ofpbuf_use_stub(recv_buf, recv_stubs[n_upcalls],
                        sizeof recv_stubs[n_upcalls]);
        if (dpif_recv(udpif->dpif, handler->handler_id, dupcall, recv_buf)) {    //接收upcall报文
            ofpbuf_uninit(recv_buf);
            break;
        }

        if (odp_flow_key_to_flow(dupcall->key, dupcall->key_len, flow)   //key转化为flow
            == ODP_FIT_ERROR) {
            goto free_dupcall;
        }

        if (dupcall->mru) {
            mru = nl_attr_get_u16(dupcall->mru);
        } else {
            mru = 0;
        }

        error = upcall_receive(upcall, udpif->backer, &dupcall->packet,      //初始化upcall，查找of交换机
                               dupcall->type, dupcall->userdata, flow, mru,
                               &dupcall->ufid, PMD_ID_NULL);
        if (error) {
            if (error == ENODEV) {
                /* Received packet on datapath port for which we couldn't
                 * associate an ofproto.  This can happen if a port is removed
                 * while traffic is being received.  Print a rate-limited
                 * message in case it happens frequently. */
                dpif_flow_put(udpif->dpif, DPIF_FP_CREATE, dupcall->key,
                              dupcall->key_len, NULL, 0, NULL, 0,
                              &dupcall->ufid, PMD_ID_NULL, NULL);
                VLOG_INFO_RL(&rl, "received packet on unassociated datapath "
                             "port %"PRIu32, flow->in_port.odp_port);
            }
            goto free_dupcall;
        }

        upcall->key = dupcall->key;             //报文的key
        upcall->key_len = dupcall->key_len;
        upcall->ufid = &dupcall->ufid;

        upcall->out_tun_key = dupcall->out_tun_key;
        upcall->actions = dupcall->actions;

        if (vsp_adjust_flow(upcall->ofproto, flow, &dupcall->packet)) {
            upcall->vsp_adjusted = true;
        }

        pkt_metadata_from_flow(&dupcall->packet.md, flow);
        flow_extract(&dupcall->packet, flow);	//生成flow

        error = process_upcall(udpif, upcall,
                               &upcall->odp_actions, &upcall->wc);   //用户态流表查找
        if (error) {
            goto cleanup;
        }

        n_upcalls++;
        continue;

cleanup:
        upcall_uninit(upcall);
free_dupcall:
        dp_packet_uninit(&dupcall->packet);
        ofpbuf_uninit(recv_buf);
    }

    if (n_upcalls) {
        handle_upcalls(handler->udpif, upcalls, n_upcalls);   //处理upcall结果，例如添加流表
        for (i = 0; i < n_upcalls; i++) {
            dp_packet_uninit(&dupcalls[i].packet);
            ofpbuf_uninit(&recv_bufs[i]);
            upcall_uninit(&upcalls[i]);
        }
    }

    return n_upcalls;
}
```


### dpif_recv(接收upcall)

```c
int
dpif_recv(struct dpif *dpif, uint32_t handler_id, struct dpif_upcall *upcall,
          struct ofpbuf *buf)
{
    int error = EAGAIN;

    if (dpif->dpif_class->recv) {
        error = dpif->dpif_class->recv(dpif, handler_id, upcall, buf);   //内核态实际调用dpif_netlink_recv
        if (!error) {
            dpif_print_packet(dpif, upcall);
        } else if (error != EAGAIN) {
            log_operation(dpif, "recv", error);
        }
    }
    return error;
}

static int
dpif_netlink_recv(struct dpif *dpif_, uint32_t handler_id,
                  struct dpif_upcall *upcall, struct ofpbuf *buf)
{
    struct dpif_netlink *dpif = dpif_netlink_cast(dpif_);
    int error;

    fat_rwlock_rdlock(&dpif->upcall_lock);
#ifdef _WIN32
    error = dpif_netlink_recv_windows(dpif, handler_id, upcall, buf);
#else
    error = dpif_netlink_recv__(dpif, handler_id, upcall, buf);
#endif
    fat_rwlock_unlock(&dpif->upcall_lock);

    return error;
}

static int
dpif_netlink_recv__(struct dpif_netlink *dpif, uint32_t handler_id,
                    struct dpif_upcall *upcall, struct ofpbuf *buf)
    OVS_REQ_RDLOCK(dpif->upcall_lock)
{
    struct dpif_handler *handler;
    int read_tries = 0;

    if (!dpif->handlers || handler_id >= dpif->n_handlers) {
        return EAGAIN;
    }

    handler = &dpif->handlers[handler_id];
    if (handler->event_offset >= handler->n_events) {
        int retval;

        handler->event_offset = handler->n_events = 0;

        do {
            retval = epoll_wait(handler->epoll_fd, handler->epoll_events,   //等待upcall消息
                                dpif->uc_array_size, 0);
        } while (retval < 0 && errno == EINTR);

        if (retval < 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "epoll_wait failed (%s)", ovs_strerror(errno));
        } else if (retval > 0) {
            handler->n_events = retval;
        }
    }

    while (handler->event_offset < handler->n_events) {
        int idx = handler->epoll_events[handler->event_offset].data.u32;
        struct dpif_channel *ch = &dpif->handlers[handler_id].channels[idx];

        handler->event_offset++;

        for (;;) {
            int dp_ifindex;
            int error;

            if (++read_tries > 50) {
                return EAGAIN;
            }

            error = nl_sock_recv(ch->sock, buf, false);            //接收upcall报文
            if (error == ENOBUFS) {
                /* ENOBUFS typically means that we've received so many
                 * packets that the buffer overflowed.  Try again
                 * immediately because there's almost certainly a packet
                 * waiting for us. */
                report_loss(dpif, ch, idx, handler_id);
                continue;
            }

            ch->last_poll = time_msec();
            if (error) {
                if (error == EAGAIN) {
                    break;
                }
                return error;
            }

            error = parse_odp_packet(dpif, buf, upcall, &dp_ifindex);    //解析报文
            if (!error && dp_ifindex == dpif->dp_ifindex) {
                return 0;
            } else if (error) {
                return error;
            }
        }
    }

    return EAGAIN;
}

static int
parse_odp_packet(const struct dpif_netlink *dpif, struct ofpbuf *buf,
                 struct dpif_upcall *upcall, int *dp_ifindex)
{
    static const struct nl_policy ovs_packet_policy[] = {
        /* Always present. */
        [OVS_PACKET_ATTR_PACKET] = { .type = NL_A_UNSPEC,
                                     .min_len = ETH_HEADER_LEN },
        [OVS_PACKET_ATTR_KEY] = { .type = NL_A_NESTED },

        /* OVS_PACKET_CMD_ACTION only. */
        [OVS_PACKET_ATTR_USERDATA] = { .type = NL_A_UNSPEC, .optional = true },
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_ACTIONS] = { .type = NL_A_NESTED, .optional = true },
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = true }
    };

    struct ovs_header *ovs_header;
    struct nlattr *a[ARRAY_SIZE(ovs_packet_policy)];
    struct nlmsghdr *nlmsg;
    struct genlmsghdr *genl;
    struct ofpbuf b;
    int type;

    ofpbuf_use_const(&b, buf->data, buf->size);

    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    ovs_header = ofpbuf_try_pull(&b, sizeof *ovs_header);
    if (!nlmsg || !genl || !ovs_header
        || nlmsg->nlmsg_type != ovs_packet_family
        || !nl_policy_parse(&b, 0, ovs_packet_policy, a,
                            ARRAY_SIZE(ovs_packet_policy))) {
        return EINVAL;
    }

    type = (genl->cmd == OVS_PACKET_CMD_MISS ? DPIF_UC_MISS
            : genl->cmd == OVS_PACKET_CMD_ACTION ? DPIF_UC_ACTION
            : -1);
    if (type < 0) {
        return EINVAL;
    }

    /* (Re)set ALL fields of '*upcall' on successful return. */
    upcall->type = type;
    upcall->key = CONST_CAST(struct nlattr *,
                             nl_attr_get(a[OVS_PACKET_ATTR_KEY]));
    upcall->key_len = nl_attr_get_size(a[OVS_PACKET_ATTR_KEY]);
    dpif_flow_hash(&dpif->dpif, upcall->key, upcall->key_len, &upcall->ufid);
    upcall->userdata = a[OVS_PACKET_ATTR_USERDATA];
    upcall->out_tun_key = a[OVS_PACKET_ATTR_EGRESS_TUN_KEY];
    upcall->actions = a[OVS_PACKET_ATTR_ACTIONS];
    upcall->mru = a[OVS_PACKET_ATTR_MRU];

    /* Allow overwriting the netlink attribute header without reallocating. */
    dp_packet_use_stub(&upcall->packet,
                    CONST_CAST(struct nlattr *,
                               nl_attr_get(a[OVS_PACKET_ATTR_PACKET])) - 1,
                    nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]) +
                    sizeof(struct nlattr));
    dp_packet_set_data(&upcall->packet,
                    (char *)dp_packet_data(&upcall->packet) + sizeof(struct nlattr));
    dp_packet_set_size(&upcall->packet, nl_attr_get_size(a[OVS_PACKET_ATTR_PACKET]));

    *dp_ifindex = ovs_header->dp_ifindex;

    return 0;
}
```


### upcall_receive

```c
static int
upcall_receive(struct upcall *upcall, const struct dpif_backer *backer,
               const struct dp_packet *packet, enum dpif_upcall_type type,
               const struct nlattr *userdata, const struct flow *flow,
               const unsigned int mru,
               const ovs_u128 *ufid, const unsigned pmd_id)
{
    int error;

    error = xlate_lookup(backer, flow, &upcall->ofproto, &upcall->ipfix,    //查找流表
                         &upcall->sflow, NULL, &upcall->in_port);
    if (error) {
        return error;
    }

    upcall->recirc = NULL;
    upcall->have_recirc_ref = false;
    upcall->flow = flow;
    upcall->packet = packet;
    upcall->ufid = ufid;
    upcall->pmd_id = pmd_id;
    upcall->type = type;
    upcall->userdata = userdata;
    ofpbuf_use_stub(&upcall->odp_actions, upcall->odp_actions_stub,
                    sizeof upcall->odp_actions_stub);
    ofpbuf_init(&upcall->put_actions, 0);

    upcall->xout_initialized = false;
    upcall->vsp_adjusted = false;
    upcall->ukey_persists = false;

    upcall->ukey = NULL;
    upcall->key = NULL;
    upcall->key_len = 0;
    upcall->mru = mru;

    upcall->out_tun_key = NULL;
    upcall->actions = NULL;

    return 0;
}

int
xlate_lookup(const struct dpif_backer *backer, const struct flow *flow,
             struct ofproto_dpif **ofprotop, struct dpif_ipfix **ipfix,
             struct dpif_sflow **sflow, struct netflow **netflow,
             ofp_port_t *ofp_in_port)
{
    struct ofproto_dpif *ofproto;
    const struct xport *xport;

    ofproto = xlate_lookup_ofproto_(backer, flow, ofp_in_port, &xport);   //通过flow中的inport找到ofproto_dpif对象

    if (!ofproto) {
        return ENODEV;
    }

    if (ofprotop) {
        *ofprotop = ofproto;
    }

    if (ipfix) {
        *ipfix = xport ? xport->xbridge->ipfix : NULL;
    }

    if (sflow) {
        *sflow = xport ? xport->xbridge->sflow : NULL;
    }

    if (netflow) {
        *netflow = xport ? xport->xbridge->netflow : NULL;
    }

    return 0;
}

static struct ofproto_dpif *
xlate_lookup_ofproto_(const struct dpif_backer *backer, const struct flow *flow,
                      ofp_port_t *ofp_in_port, const struct xport **xportp)
{
    struct xlate_cfg *xcfg = ovsrcu_get(struct xlate_cfg *, &xcfgp);
    const struct xport *xport;

    xport = xport_lookup(xcfg, tnl_port_should_receive(flow)
                         ? tnl_port_receive(flow)
                         : odp_port_to_ofport(backer, flow->in_port.odp_port));
    if (OVS_UNLIKELY(!xport)) {
        return NULL;
    }
    *xportp = xport;
    if (ofp_in_port) {
        *ofp_in_port = xport->ofp_port;
    }
    return xport->xbridge->ofproto;
}

static struct xport *
xport_lookup(struct xlate_cfg *xcfg, const struct ofport_dpif *ofport)
{
    struct hmap *xports;
    struct xport *xport;

    if (!ofport || !xcfg) {
        return NULL;
    }

    xports = &xcfg->xports;

    HMAP_FOR_EACH_IN_BUCKET (xport, hmap_node, hash_pointer(ofport, 0),
                             xports) {
        if (xport->ofport == ofport) {
            return xport;
        }
    }
    return NULL;
}
```


# upcall sock监听

当数据面出现upcall时，根据报文入端口的ids中选择一个id作为upcall的线程， 根据skb计算hash来选择哪个id：

1. dpif_netlink_port_add__函数中会创建netlink sock，并并且调用vport_add_channels， 添加netlink sock到epoll监听中；
2. dpif_netlink_recv__中调用epoll_wait阻塞在所有的upcall socket上；

```c
static int
dpif_netlink_port_add__(struct dpif_netlink *dpif, struct netdev *netdev,
                        odp_port_t *port_nop)
    OVS_REQ_WRLOCK(dpif->upcall_lock)
{
    const struct netdev_tunnel_config *tnl_cfg;
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *name = netdev_vport_get_dpif_port(netdev,
                                                  namebuf, sizeof namebuf);
    const char *type = netdev_get_type(netdev);
    struct dpif_netlink_vport request, reply;
    struct ofpbuf *buf;
    uint64_t options_stub[64 / 8];
    struct ofpbuf options;
    struct nl_sock **socksp = NULL;
    uint32_t *upcall_pids;
    int error = 0;

    if (dpif->handlers) {
        socksp = vport_create_socksp(dpif, &error);
        if (!socksp) {
            return error;
        }
    }

    dpif_netlink_vport_init(&request);
    request.cmd = OVS_VPORT_CMD_NEW;
    request.dp_ifindex = dpif->dp_ifindex;
    request.type = netdev_to_ovs_vport_type(netdev);
    if (request.type == OVS_VPORT_TYPE_UNSPEC) {
        VLOG_WARN_RL(&error_rl, "%s: cannot create port `%s' because it has "
                     "unsupported type `%s'",
                     dpif_name(&dpif->dpif), name, type);
        vport_del_socksp(dpif, socksp);
        return EINVAL;
    }
    request.name = name;

    if (request.type == OVS_VPORT_TYPE_NETDEV) {
#ifdef _WIN32
        /* XXX : Map appropiate Windows handle */
#else
        netdev_linux_ethtool_set_flag(netdev, ETH_FLAG_LRO, "LRO", false);
#endif
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg && (tnl_cfg->dst_port != 0 || tnl_cfg->exts)) {
        ofpbuf_use_stack(&options, options_stub, sizeof options_stub);
        if (tnl_cfg->dst_port) {
            nl_msg_put_u16(&options, OVS_TUNNEL_ATTR_DST_PORT,
                           ntohs(tnl_cfg->dst_port));
        }
        if (tnl_cfg->exts) {
            size_t ext_ofs;
            int i;

            ext_ofs = nl_msg_start_nested(&options, OVS_TUNNEL_ATTR_EXTENSION);
            for (i = 0; i < 32; i++) {
                if (tnl_cfg->exts & (1 << i)) {
                    nl_msg_put_flag(&options, i);
                }
            }
            nl_msg_end_nested(&options, ext_ofs);
        }
        request.options = options.data;
        request.options_len = options.size;
    }

    request.port_no = *port_nop;
    upcall_pids = vport_socksp_to_pids(socksp, dpif->n_handlers);
    request.n_upcall_pids = socksp ? dpif->n_handlers : 1;
    request.upcall_pids = upcall_pids;

    error = dpif_netlink_vport_transact(&request, &reply, &buf);
    if (!error) {
        *port_nop = reply.port_no;
    } else {
        if (error == EBUSY && *port_nop != ODPP_NONE) {
            VLOG_INFO("%s: requested port %"PRIu32" is in use",
                      dpif_name(&dpif->dpif), *port_nop);
        }

        vport_del_socksp(dpif, socksp);
        goto exit;
    }

    if (socksp) {
        error = vport_add_channels(dpif, *port_nop, socksp);
        if (error) {
            VLOG_INFO("%s: could not add channel for port %s",
                      dpif_name(&dpif->dpif), name);

            /* Delete the port. */
            dpif_netlink_vport_init(&request);
            request.cmd = OVS_VPORT_CMD_DEL;
            request.dp_ifindex = dpif->dp_ifindex;
            request.port_no = *port_nop;
            dpif_netlink_vport_transact(&request, NULL, NULL);
            vport_del_socksp(dpif, socksp);
            goto exit;
        }
    }
    free(socksp);

exit:
    ofpbuf_delete(buf);
    free(upcall_pids);

    return error;
}
```


## vport_add_channels

```c
static int
vport_add_channels(struct dpif_netlink *dpif, odp_port_t port_no,
                   struct nl_sock **socksp)
{
    struct epoll_event event;
    uint32_t port_idx = odp_to_u32(port_no);
    size_t i, j;
    int error;

    if (dpif->handlers == NULL) {
        return 0;
    }

    /* We assume that the datapath densely chooses port numbers, which can
     * therefore be used as an index into 'channels' and 'epoll_events' of
     * 'dpif->handler'. */
    if (port_idx >= dpif->uc_array_size) {
        uint32_t new_size = port_idx + 1;

        if (new_size > MAX_PORTS) {
            VLOG_WARN_RL(&error_rl, "%s: datapath port %"PRIu32" too big",
                         dpif_name(&dpif->dpif), port_no);
            return EFBIG;
        }

        for (i = 0; i < dpif->n_handlers; i++) {
            struct dpif_handler *handler = &dpif->handlers[i];

            handler->channels = xrealloc(handler->channels,
                                         new_size * sizeof *handler->channels);

            for (j = dpif->uc_array_size; j < new_size; j++) {
                handler->channels[j].sock = NULL;
            }

            handler->epoll_events = xrealloc(handler->epoll_events,
                new_size * sizeof *handler->epoll_events);

        }
        dpif->uc_array_size = new_size;
    }

    memset(&event, 0, sizeof event);
    event.events = EPOLLIN;
    event.data.u32 = port_idx;

    for (i = 0; i < dpif->n_handlers; i++) {
        struct dpif_handler *handler = &dpif->handlers[i];

#ifndef _WIN32
        if (epoll_ctl(handler->epoll_fd, EPOLL_CTL_ADD, nl_sock_fd(socksp[i]),     //添加到epoll监听中
                      &event) < 0) {
            error = errno;
            goto error;
        }
#endif
        dpif->handlers[i].channels[port_idx].sock = socksp[i];
        dpif->handlers[i].channels[port_idx].last_poll = LLONG_MIN;
    }

    return 0;

error:
    for (j = 0; j < i; j++) {
#ifndef _WIN32
        epoll_ctl(dpif->handlers[j].epoll_fd, EPOLL_CTL_DEL,
                  nl_sock_fd(socksp[j]), NULL);
#endif
        dpif->handlers[j].channels[port_idx].sock = NULL;
    }

    return error;
}
```