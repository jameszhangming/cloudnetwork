# Eth端口管理

本文介绍DPDK OVS添加物理网卡的流程，以及物理网卡端口的收发包流程。

Port操作流程：

![port-progress](images/port-progress.png "port-progress")


# 添加Eth端口

在DPDK OVS添加Eth端口时，最终会调用dpdk_class定义的方法。

```c
static const struct netdev_class dpdk_class =
    NETDEV_DPDK_CLASS(
        "dpdk",
        NULL,
        netdev_dpdk_construct,
        netdev_dpdk_destruct,
        netdev_dpdk_set_multiq,
        netdev_dpdk_eth_send,
        netdev_dpdk_get_carrier,
        netdev_dpdk_get_stats,
        netdev_dpdk_get_features,
        netdev_dpdk_get_status,
        netdev_dpdk_rxq_recv);
```

## netdev_dpdk_alloc

```c
static struct netdev * netdev_dpdk_alloc(void)
{
    struct netdev_dpdk *netdev = dpdk_rte_mzalloc(sizeof *netdev);
    return &netdev->up;
}
```


## netdev_dpdk_construct

```c
static int netdev_dpdk_construct(struct netdev *netdev)
{
    unsigned int port_no;
    int err;

    if (rte_eal_init_ret) {
        return rte_eal_init_ret;
    }

    /* Names always start with "dpdk" */
    err = dpdk_dev_parse_name(netdev->name, "dpdk", &port_no);   //netdev名字为dpdkXXX
    if (err) {
        return err;
    }

    ovs_mutex_lock(&dpdk_mutex);
    err = netdev_dpdk_init(netdev, port_no, DPDK_DEV_ETH);    //netdev设备初始化
    ovs_mutex_unlock(&dpdk_mutex);
    return err;
}

static int dpdk_dev_parse_name(const char dev_name[], const char prefix[],
                    unsigned int *port_no)
{
    const char *cport;

    if (strncmp(dev_name, prefix, strlen(prefix))) {
        return ENODEV;
    }

    cport = dev_name + strlen(prefix);
    *port_no = strtol(cport, NULL, 0); /* string must be null terminated */
    return 0;
}

static int netdev_dpdk_init(struct netdev *netdev_, unsigned int port_no,
                 enum dpdk_dev_type type)
    OVS_REQUIRES(dpdk_mutex)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    int sid;
    int err = 0;

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);

    rte_spinlock_init(&netdev->stats_lock);

    /* If the 'sid' is negative, it means that the kernel fails
     * to obtain the pci numa info.  In that situation, always
     * use 'SOCKET0'. */
    if (type == DPDK_DEV_ETH) {
        sid = rte_eth_dev_socket_id(port_no);   //获取port的socket id
    } else {
        sid = rte_lcore_to_socket_id(rte_get_master_lcore());
    }

    netdev->socket_id = sid < 0 ? SOCKET0 : sid;      //该值等同于numa值，查询numa值返回该值
    netdev->port_id = port_no;
    netdev->type = type;
    netdev->flags = 0;
    netdev->mtu = ETHER_MTU;
    netdev->max_packet_len = MTU_TO_MAX_LEN(netdev->mtu);

    netdev->dpdk_mp = dpdk_mp_get(netdev->socket_id, netdev->mtu);
    if (!netdev->dpdk_mp) {
        err = ENOMEM;
        goto unlock;
    }

    netdev_->n_txq = NR_QUEUE;
    netdev_->n_rxq = NR_QUEUE;
    netdev->real_n_txq = NR_QUEUE;

    if (type == DPDK_DEV_ETH) {
        netdev_dpdk_alloc_txq(netdev, NR_QUEUE);   //创建发包队列
        err = dpdk_eth_dev_init(netdev);           //设置eth设备
        if (err) {
            goto unlock;
        }
    } else {
        netdev_dpdk_alloc_txq(netdev, OVS_VHOST_MAX_QUEUE_NUM);
    }

    list_push_back(&dpdk_list, &netdev->list_node);

unlock:
    if (err) {
        rte_free(netdev->tx_q);
    }
    ovs_mutex_unlock(&netdev->mutex);
    return err;
}
```


### netdev_dpdk_alloc_txq

```c
static void netdev_dpdk_alloc_txq(struct netdev_dpdk *netdev, unsigned int n_txqs)
{
    unsigned i;

    netdev->tx_q = dpdk_rte_mzalloc(n_txqs * sizeof *netdev->tx_q);
    for (i = 0; i < n_txqs; i++) {
        int numa_id = ovs_numa_get_numa_id(i);

        if (!netdev->txq_needs_locking) {
            /* Each index is considered as a cpu core id, since there should
             * be one tx queue for each cpu core.  If the corresponding core
             * is not on the same numa node as 'netdev', flags the
             * 'flush_tx'. */
            netdev->tx_q[i].flush_tx = netdev->socket_id == numa_id;
        } else {
            /* Queues are shared among CPUs. Always flush */
            netdev->tx_q[i].flush_tx = true;
        }

        /* Initialize map for vhost devices. */
        netdev->tx_q[i].map = -1;
        rte_spinlock_init(&netdev->tx_q[i].tx_lock);
    }
}
```


### dpdk_eth_dev_init

```c
static int dpdk_eth_dev_init(struct netdev_dpdk *dev) OVS_REQUIRES(dpdk_mutex)
{
    struct rte_pktmbuf_pool_private *mbp_priv;
    struct rte_eth_dev_info info;
    struct ether_addr eth_addr;
    int diag;
    int n_rxq, n_txq;

    if (dev->port_id < 0 || dev->port_id >= rte_eth_dev_count()) {
        return ENODEV;
    }

    rte_eth_dev_info_get(dev->port_id, &info);

    n_rxq = MIN(info.max_rx_queues, dev->up.n_rxq);
    n_txq = MIN(info.max_tx_queues, dev->up.n_txq);

    diag = dpdk_eth_dev_queue_setup(dev, n_rxq, n_txq);
    if (diag) {
        VLOG_ERR("Interface %s(rxq:%d txq:%d) configure error: %s",
                 dev->up.name, n_rxq, n_txq, rte_strerror(-diag));
        return -diag;
    }

    diag = rte_eth_dev_start(dev->port_id);     //设备启动
    if (diag) {
        VLOG_ERR("Interface %s start error: %s", dev->up.name,
                 rte_strerror(-diag));
        return -diag;
    }

    rte_eth_promiscuous_enable(dev->port_id);     //使能混杂模式
    rte_eth_allmulticast_enable(dev->port_id);    //使能组播

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "Port %d: "ETH_ADDR_FMT"",
                    dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));

    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    rte_eth_link_get_nowait(dev->port_id, &dev->link);

    mbp_priv = rte_mempool_get_priv(dev->dpdk_mp->mp);
    dev->buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;

    dev->flags = NETDEV_UP | NETDEV_PROMISC;
    return 0;
}

static int dpdk_eth_dev_queue_setup(struct netdev_dpdk *dev, int n_rxq, int n_txq)
{
    int diag = 0;
    int i;

    /* A device may report more queues than it makes available (this has
     * been observed for Intel xl710, which reserves some of them for
     * SRIOV):  rte_eth_*_queue_setup will fail if a queue is not
     * available.  When this happens we can retry the configuration
     * and request less queues */
    while (n_rxq && n_txq) {
        if (diag) {
            VLOG_INFO("Retrying setup with (rxq:%d txq:%d)", n_rxq, n_txq);
        }

        diag = rte_eth_dev_configure(dev->port_id, n_rxq, n_txq, &port_conf);
        if (diag) {
            break;
        }

        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(dev->port_id, i, NIC_PORT_TX_Q_SIZE,    //发包队列设置
                                          dev->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s txq(%d) setup error: %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_txq) {
            /* Retry with less tx queues */
            n_txq = i;
            continue;
        }

        for (i = 0; i < n_rxq; i++) {
            diag = rte_eth_rx_queue_setup(dev->port_id, i, NIC_PORT_RX_Q_SIZE,    //收包队列设置
                                          dev->socket_id, NULL,
                                          dev->dpdk_mp->mp);
            if (diag) {
                VLOG_INFO("Interface %s rxq(%d) setup error: %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }

        if (i != n_rxq) {
            /* Retry with less rx queues */
            n_rxq = i;
            continue;
        }

        dev->up.n_rxq = n_rxq;
        dev->real_n_txq = n_txq;

        return 0;
    }

    return diag;
}

```


## netdev_dpdk_get_numa_id

```c
static int netdev_dpdk_get_numa_id(const struct netdev *netdev_)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);

    return netdev->socket_id;
}
```


## netdev_dpdk_set_multiq

```c
static int
netdev_dpdk_set_multiq(struct netdev *netdev_, unsigned int n_txq,
                       unsigned int n_rxq)
{
    struct netdev_dpdk *netdev = netdev_dpdk_cast(netdev_);
    int err = 0;
    int old_rxq, old_txq;

    if (netdev->up.n_txq == n_txq && netdev->up.n_rxq == n_rxq) {
        return err;
    }

    ovs_mutex_lock(&dpdk_mutex);
    ovs_mutex_lock(&netdev->mutex);

    rte_eth_dev_stop(netdev->port_id);

    old_txq = netdev->up.n_txq;
    old_rxq = netdev->up.n_rxq;
    netdev->up.n_txq = n_txq;
    netdev->up.n_rxq = n_rxq;

    rte_free(netdev->tx_q);
    err = dpdk_eth_dev_init(netdev);
    netdev_dpdk_alloc_txq(netdev, netdev->real_n_txq);
    if (err) {
        /* If there has been an error, it means that the requested queues
         * have not been created.  Restore the old numbers. */
        netdev->up.n_txq = old_txq;
        netdev->up.n_rxq = old_rxq;
    }

    netdev->txq_needs_locking = netdev->real_n_txq != netdev->up.n_txq;

    ovs_mutex_unlock(&netdev->mutex);
    ovs_mutex_unlock(&dpdk_mutex);

    return err;
}
```


## netdev_dpdk_rxq_alloc

```c
static struct netdev_rxq * netdev_dpdk_rxq_alloc(void)
{
    struct netdev_rxq_dpdk *rx = dpdk_rte_mzalloc(sizeof *rx);

    return &rx->up;
}
```


## netdev_dpdk_rxq_construct

```c
static int
netdev_dpdk_rxq_construct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq_);
    struct netdev_dpdk *netdev = netdev_dpdk_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    rx->port_id = netdev->port_id;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}
```


# Eth端口发包

物理网卡发包

```c
static int netdev_dpdk_eth_send(struct netdev *netdev, int qid,
                     struct dp_packet **pkts, int cnt, bool may_steal)
{
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);

    netdev_dpdk_send__(dev, qid, pkts, cnt, may_steal);
    return 0;
}

static inline void
netdev_dpdk_send__(struct netdev_dpdk *dev, int qid,
                   struct dp_packet **pkts, int cnt, bool may_steal)
{
    int i;

    if (OVS_UNLIKELY(dev->txq_needs_locking)) {
        qid = qid % dev->real_n_txq;
        rte_spinlock_lock(&dev->tx_q[qid].tx_lock);
    }

    if (OVS_UNLIKELY(!may_steal ||
                     pkts[0]->source != DPBUF_DPDK)) {
        struct netdev *netdev = &dev->up;

        dpdk_do_tx_copy(netdev, qid, pkts, cnt);

        if (may_steal) {
            for (i = 0; i < cnt; i++) {
                dp_packet_delete(pkts[i]);
            }
        }
    } else {
        int next_tx_idx = 0;
        int dropped = 0;

        for (i = 0; i < cnt; i++) {
            int size = dp_packet_size(pkts[i]);

            if (OVS_UNLIKELY(size > dev->max_packet_len)) {
                if (next_tx_idx != i) {
                    dpdk_queue_pkts(dev, qid,
                                    (struct rte_mbuf **)&pkts[next_tx_idx],
                                    i-next_tx_idx);
                }

                VLOG_WARN_RL(&rl, "Too big size %d max_packet_len %d",
                             (int)size , dev->max_packet_len);

                dp_packet_delete(pkts[i]);
                dropped++;
                next_tx_idx = i + 1;
            }
        }
        if (next_tx_idx != cnt) {
           dpdk_queue_pkts(dev, qid,
                            (struct rte_mbuf **)&pkts[next_tx_idx],
                            cnt-next_tx_idx);
        }

        if (OVS_UNLIKELY(dropped)) {
            rte_spinlock_lock(&dev->stats_lock);
            dev->stats.tx_dropped += dropped;
            rte_spinlock_unlock(&dev->stats_lock);
        }
    }

    if (OVS_UNLIKELY(dev->txq_needs_locking)) {
        rte_spinlock_unlock(&dev->tx_q[qid].tx_lock);
    }
}

static inline void
dpdk_queue_flush(struct netdev_dpdk *dev, int qid)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];

    if (txq->count == 0) {    //判断是否有报文待发送
        return;
    }
    dpdk_queue_flush__(dev, qid);   //触发发包
}
```


## dpdk_do_tx_copy

```c
static void
dpdk_do_tx_copy(struct netdev *netdev, int qid, struct dp_packet **pkts,
                int cnt)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    struct rte_mbuf *mbufs[PKT_ARRAY_SIZE];
    int dropped = 0;
    int newcnt = 0;
    int i;

    /* If we are on a non pmd thread we have to use the mempool mutex, because
     * every non pmd thread shares the same mempool cache */

    if (!dpdk_thread_is_pmd()) {
        ovs_mutex_lock(&nonpmd_mempool_mutex);
    }

    for (i = 0; i < cnt; i++) {
        int size = dp_packet_size(pkts[i]);

        if (OVS_UNLIKELY(size > dev->max_packet_len)) {
            VLOG_WARN_RL(&rl, "Too big size %d max_packet_len %d",
                         (int)size , dev->max_packet_len);

            dropped++;
            continue;
        }

        mbufs[newcnt] = rte_pktmbuf_alloc(dev->dpdk_mp->mp);

        if (!mbufs[newcnt]) {
            dropped += cnt - i;
            break;
        }

        /* We have to do a copy for now */
        memcpy(rte_pktmbuf_mtod(mbufs[newcnt], void *), dp_packet_data(pkts[i]), size);

        rte_pktmbuf_data_len(mbufs[newcnt]) = size;
        rte_pktmbuf_pkt_len(mbufs[newcnt]) = size;

        newcnt++;
    }

    if (OVS_UNLIKELY(dropped)) {
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += dropped;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    if (dev->type == DPDK_DEV_VHOST) {
        __netdev_dpdk_vhost_send(netdev, qid, (struct dp_packet **) mbufs, newcnt, true);
    } else {
        dpdk_queue_pkts(dev, qid, mbufs, newcnt);    //拷贝到发包队列
        dpdk_queue_flush(dev, qid);    //触发发包
    }

    if (!dpdk_thread_is_pmd()) {
        ovs_mutex_unlock(&nonpmd_mempool_mutex);
    }
}
```


## dpdk_queue_pkts

```c
inline static void dpdk_queue_pkts(struct netdev_dpdk *dev, int qid,
               struct rte_mbuf **pkts, int cnt)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];
    uint64_t diff_tsc;

    int i = 0;

    while (i < cnt) {
        int freeslots = MAX_TX_QUEUE_LEN - txq->count;
        int tocopy = MIN(freeslots, cnt-i);

        memcpy(&txq->burst_pkts[txq->count], &pkts[i],
               tocopy * sizeof (struct rte_mbuf *));

        txq->count += tocopy;
        i += tocopy;

        if (txq->count == MAX_TX_QUEUE_LEN || txq->flush_tx) {
            dpdk_queue_flush__(dev, qid);     //网卡设备发包
        }
        diff_tsc = rte_get_timer_cycles() - txq->tsc;
        if (diff_tsc >= DRAIN_TSC) {
            dpdk_queue_flush__(dev, qid);    //网卡设备发包
        }
    }
}
```


### dpdk_queue_flush__

```c
static inline void dpdk_queue_flush__(struct netdev_dpdk *dev, int qid)
{
    struct dpdk_tx_queue *txq = &dev->tx_q[qid];
    uint32_t nb_tx = 0;

    while (nb_tx != txq->count) {
        uint32_t ret;

        ret = rte_eth_tx_burst(dev->port_id, qid, txq->burst_pkts + nb_tx,   //调用DPDK方法库发包
                               txq->count - nb_tx);
        if (!ret) {
            break;
        }

        nb_tx += ret;
    }

    if (OVS_UNLIKELY(nb_tx != txq->count)) {
        /* free buffers, which we couldn't transmit, one at a time (each
         * packet could come from a different mempool) */
        int i;

        for (i = nb_tx; i < txq->count; i++) {
            rte_pktmbuf_free_seg(txq->burst_pkts[i]);
        }
        rte_spinlock_lock(&dev->stats_lock);
        dev->stats.tx_dropped += txq->count-nb_tx;
        rte_spinlock_unlock(&dev->stats_lock);
    }

    txq->count = 0;
    txq->tsc = rte_get_timer_cycles();
}
```



# Eth端口收包

DPDK eth设备队列收包方法

```c
static int
netdev_dpdk_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet **packets,
                     int *c)
{
    struct netdev_rxq_dpdk *rx = netdev_rxq_dpdk_cast(rxq_);
    struct netdev *netdev = rx->up.netdev;
    struct netdev_dpdk *dev = netdev_dpdk_cast(netdev);
    int nb_rx;

    /* There is only one tx queue for this core.  Do not flush other
     * queues.
     * Do not flush tx queue which is shared among CPUs
     * since it is always flushed */
    if (rxq_->queue_id == rte_lcore_id() &&
        OVS_LIKELY(!dev->txq_needs_locking)) {
        dpdk_queue_flush(dev, rxq_->queue_id);
    }

    nb_rx = rte_eth_rx_burst(rx->port_id, rxq_->queue_id,    //调用DPDK方法库收包
                             (struct rte_mbuf **) packets,
                             NETDEV_MAX_BURST);
    if (!nb_rx) {
        return EAGAIN;
    }

    *c = nb_rx;

    return 0;
}
```

