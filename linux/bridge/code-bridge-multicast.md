# bridge multicast报文处理

本文分析bridge的组播报文收包处理流程。


## mdb操作入口

```c
void br_mdb_init(void)
{
	rtnl_register(PF_BRIDGE, RTM_GETMDB, NULL, br_mdb_dump, NULL);
	rtnl_register(PF_BRIDGE, RTM_NEWMDB, br_mdb_add, NULL, NULL);
	rtnl_register(PF_BRIDGE, RTM_DELMDB, br_mdb_del, NULL, NULL);
}
```


### br_mdb_add

```c
static int br_mdb_add(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct br_mdb_entry *entry;
	struct net_device *dev;
	struct net_bridge *br;
	int err;

	err = br_mdb_parse(skb, nlh, &dev, &entry);
	if (err < 0)
		return err;

	br = netdev_priv(dev);

	err = __br_mdb_add(net, br, entry);
	if (!err)
		__br_mdb_notify(dev, entry, RTM_NEWMDB);
	return err;
}

static int __br_mdb_add(struct net *net, struct net_bridge *br,
			struct br_mdb_entry *entry)
{
	struct br_ip ip;
	struct net_device *dev;
	struct net_bridge_port *p;
	int ret;

	if (!netif_running(br->dev) || br->multicast_disabled)
		return -EINVAL;

	dev = __dev_get_by_index(net, entry->ifindex);
	if (!dev)
		return -ENODEV;

	p = br_port_get_rtnl(dev);
	if (!p || p->br != br || p->state == BR_STATE_DISABLED)
		return -EINVAL;

	memset(&ip, 0, sizeof(ip));
	ip.proto = entry->addr.proto;
	if (ip.proto == htons(ETH_P_IP))
		ip.u.ip4 = entry->addr.u.ip4;
#if IS_ENABLED(CONFIG_IPV6)
	else
		ip.u.ip6 = entry->addr.u.ip6;
#endif

	spin_lock_bh(&br->multicast_lock);
	ret = br_mdb_add_group(br, p, &ip, entry->state);
	spin_unlock_bh(&br->multicast_lock);
	return ret;
}

static int br_mdb_add_group(struct net_bridge *br, struct net_bridge_port *port,
			    struct br_ip *group, unsigned char state)
{
	struct net_bridge_mdb_entry *mp;
	struct net_bridge_port_group *p;
	struct net_bridge_port_group __rcu **pp;
	struct net_bridge_mdb_htable *mdb;
	int err;

	mdb = mlock_dereference(br->mdb, br);
	mp = br_mdb_ip_get(mdb, group);
	if (!mp) {
		mp = br_multicast_new_group(br, port, group);
		err = PTR_ERR(mp);
		if (IS_ERR(mp))
			return err;
	}

	for (pp = &mp->ports;
	     (p = mlock_dereference(*pp, br)) != NULL;
	     pp = &p->next) {
		if (p->port == port)
			return -EEXIST;
		if ((unsigned long)p->port < (unsigned long)port)
			break;
	}

	p = br_multicast_new_port_group(port, group, *pp, state);
	if (unlikely(!p))
		return -ENOMEM;
	rcu_assign_pointer(*pp, p);

	return 0;
}

struct net_bridge_mdb_entry *br_multicast_new_group(struct net_bridge *br,
	struct net_bridge_port *port, struct br_ip *group)
{
	struct net_bridge_mdb_htable *mdb;
	struct net_bridge_mdb_entry *mp;
	int hash;
	int err;

	mdb = rcu_dereference_protected(br->mdb, 1);
	if (!mdb) {
		err = br_mdb_rehash(&br->mdb, BR_HASH_SIZE, 0);
		if (err)
			return ERR_PTR(err);
		goto rehash;
	}

	hash = br_ip_hash(mdb, group);
	mp = br_multicast_get_group(br, port, group, hash);
	switch (PTR_ERR(mp)) {
	case 0:
		break;

	case -EAGAIN:
rehash:
		mdb = rcu_dereference_protected(br->mdb, 1);
		hash = br_ip_hash(mdb, group);
		break;

	default:
		goto out;
	}

	mp = kzalloc(sizeof(*mp), GFP_ATOMIC);
	if (unlikely(!mp))
		return ERR_PTR(-ENOMEM);

	mp->br = br;
	mp->addr = *group;
	setup_timer(&mp->timer, br_multicast_group_expired,
		    (unsigned long)mp);

	hlist_add_head_rcu(&mp->hlist[mdb->ver], &mdb->mhash[hash]);
	mdb->size++;

out:
	return mp;
}

struct net_bridge_port_group *br_multicast_new_port_group(
			struct net_bridge_port *port,
			struct br_ip *group,
			struct net_bridge_port_group __rcu *next,
			unsigned char state)
{
	struct net_bridge_port_group *p;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (unlikely(!p))
		return NULL;

	p->addr = *group;
	p->port = port;
	p->state = state;
	rcu_assign_pointer(p->next, next);
	hlist_add_head(&p->mglist, &port->mglist);
	setup_timer(&p->timer, br_multicast_port_group_expired,
		    (unsigned long)p);
	return p;
}
```


## 组播报文收包入口

```c
int br_handle_frame_finish(struct sock *sk, struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;  //得到目的mac
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);  //得到port对象
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_mdb_entry *mdst;
	struct sk_buff *skb2;
	bool unicast = true;
	u16 vid = 0;

	if (!p || p->state == BR_STATE_DISABLED)   //判断port状态
		goto drop;

	if (!br_allowed_ingress(p->br, nbp_get_vlan_info(p), skb, &vid))  //判断vlan
		goto out;

	/* insert into forwarding database after filtering to avoid spoofing */
	br = p->br;
	if (p->flags & BR_LEARNING)
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, false);  //更新bridge的fdb表

	if (!is_broadcast_ether_addr(dest) && is_multicast_ether_addr(dest) &&
	    br_multicast_rcv(br, p, skb, vid))   //组播报文接收，处理igmp报文
		goto drop;

	if (p->state == BR_STATE_LEARNING)  //只是learning状态，则丢弃报文
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;

	/* The packet skb2 goes to the local host (NULL to skip). */
	skb2 = NULL;

	if (br->dev->flags & IFF_PROMISC)
		skb2 = skb;

	dst = NULL;

	if (IS_ENABLED(CONFIG_INET) && skb->protocol == htons(ETH_P_ARP))   //arp报文处理
		br_do_proxy_arp(skb, br, vid, p);

	if (is_broadcast_ether_addr(dest)) {   //广播报文
		skb2 = skb;
		unicast = false;
	} else if (is_multicast_ether_addr(dest)) {   //组播报文
		mdst = br_mdb_get(br, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(br, eth_hdr(skb))) {
			if ((mdst && mdst->mglist) ||
			    br_multicast_is_router(br))
				skb2 = skb;
			br_multicast_forward(mdst, skb, skb2);  //组播报文发送
			skb = NULL;
			if (!skb2)
				goto out;
		} else
			skb2 = skb;

		unicast = false;
		br->dev->stats.multicast++;
	} else if ((dst = __br_fdb_get(br, dest, vid)) &&
			dst->is_local) {
		skb2 = skb;
		/* Do not forward the packet since it's local. */
		skb = NULL;
	}

	if (skb) {
		if (dst) {
			dst->used = jiffies;
			br_forward(dst->dst, skb, skb2);   //发送到目的端口，dst找到，但是dst非local
		} else
			br_flood_forward(br, skb, skb2, unicast);  //flood到其他端口，组播和广播
	}

	if (skb2) 
		return br_pass_frame_up(skb2);   //单播发送到本地的端口

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}
```

### br_multicast_rcv

```c
int br_multicast_rcv(struct net_bridge *br, struct net_bridge_port *port,
		     struct sk_buff *skb, u16 vid)
{
	BR_INPUT_SKB_CB(skb)->igmp = 0;
	BR_INPUT_SKB_CB(skb)->mrouters_only = 0;

	if (br->multicast_disabled)
		return 0;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return br_multicast_ipv4_rcv(br, port, skb, vid);
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		return br_multicast_ipv6_rcv(br, port, skb, vid);
#endif
	}

	return 0;
}

static int br_multicast_ipv4_rcv(struct net_bridge *br,
				 struct net_bridge_port *port,
				 struct sk_buff *skb,
				 u16 vid)
{
	struct sk_buff *skb2 = skb;
	const struct iphdr *iph;
	struct igmphdr *ih;
	unsigned int len;
	unsigned int offset;
	int err;

	/* We treat OOM as packet loss for now. */
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return -EINVAL;

	iph = ip_hdr(skb);

	if (iph->ihl < 5 || iph->version != 4)
		return -EINVAL;

	if (!pskb_may_pull(skb, ip_hdrlen(skb)))
		return -EINVAL;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		return -EINVAL;

	if (iph->protocol != IPPROTO_IGMP) {   //非IGMP协议报文
		if (!ipv4_is_local_multicast(iph->daddr))   //非本地组播地址
			BR_INPUT_SKB_CB(skb)->mrouters_only = 1;
		return 0;
	}

	len = ntohs(iph->tot_len);
	if (skb->len < len || len < ip_hdrlen(skb))
		return -EINVAL;

	if (skb->len > len) {
		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (!skb2)
			return -ENOMEM;

		err = pskb_trim_rcsum(skb2, len);
		if (err)
			goto err_out;
	}

	len -= ip_hdrlen(skb2);
	offset = skb_network_offset(skb2) + ip_hdrlen(skb2);
	__skb_pull(skb2, offset);
	skb_reset_transport_header(skb2);

	err = -EINVAL;
	if (!pskb_may_pull(skb2, sizeof(*ih)))
		goto out;

	switch (skb2->ip_summed) {
	case CHECKSUM_COMPLETE:
		if (!csum_fold(skb2->csum))
			break;
		/* fall through */
	case CHECKSUM_NONE:
		skb2->csum = 0;
		if (skb_checksum_complete(skb2))
			goto out;
	}

	err = 0;

	BR_INPUT_SKB_CB(skb)->igmp = 1;
	ih = igmp_hdr(skb2);

	switch (ih->type) {
	case IGMP_HOST_MEMBERSHIP_REPORT:
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		BR_INPUT_SKB_CB(skb)->mrouters_only = 1;
		err = br_ip4_multicast_add_group(br, port, ih->group, vid);
		break;
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		err = br_ip4_multicast_igmp3_report(br, port, skb2, vid);
		break;
	case IGMP_HOST_MEMBERSHIP_QUERY:
		err = br_ip4_multicast_query(br, port, skb2, vid);
		break;
	case IGMP_HOST_LEAVE_MESSAGE:
		br_ip4_multicast_leave_group(br, port, ih->group, vid);
		break;
	}

out:
	__skb_push(skb2, offset);
err_out:
	if (skb2 != skb)
		kfree_skb(skb2);
	return err;
}

static int br_ip4_multicast_add_group(struct net_bridge *br,
				      struct net_bridge_port *port,
				      __be32 group,
				      __u16 vid)
{
	struct br_ip br_group;

	if (ipv4_is_local_multicast(group))
		return 0;

	br_group.u.ip4 = group;
	br_group.proto = htons(ETH_P_IP);
	br_group.vid = vid;

	return br_multicast_add_group(br, port, &br_group);
}

static int br_multicast_add_group(struct net_bridge *br,
				  struct net_bridge_port *port,
				  struct br_ip *group)
{
	struct net_bridge_mdb_entry *mp;
	struct net_bridge_port_group *p;
	struct net_bridge_port_group __rcu **pp;
	unsigned long now = jiffies;
	int err;

	spin_lock(&br->multicast_lock);
	if (!netif_running(br->dev) ||
	    (port && port->state == BR_STATE_DISABLED))
		goto out;

	mp = br_multicast_new_group(br, port, group);
	err = PTR_ERR(mp);
	if (IS_ERR(mp))
		goto err;

	if (!port) {
		mp->mglist = true;
		mod_timer(&mp->timer, now + br->multicast_membership_interval);
		goto out;
	}

	for (pp = &mp->ports;
	     (p = mlock_dereference(*pp, br)) != NULL;
	     pp = &p->next) {
		if (p->port == port)
			goto found;
		if ((unsigned long)p->port < (unsigned long)port)
			break;
	}

	p = br_multicast_new_port_group(port, group, *pp, MDB_TEMPORARY);
	if (unlikely(!p))
		goto err;
	rcu_assign_pointer(*pp, p);
	br_mdb_notify(br->dev, port, group, RTM_NEWMDB);

found:
	mod_timer(&p->timer, now + br->multicast_membership_interval);
out:
	err = 0;

err:
	spin_unlock(&br->multicast_lock);
	return err;
}
```


### br_mdb_get

```c
struct net_bridge_mdb_entry *br_mdb_get(struct net_bridge *br,
					struct sk_buff *skb, u16 vid)
{
	struct net_bridge_mdb_htable *mdb = rcu_dereference(br->mdb);   //得到mdb hash table
	struct br_ip ip;

	if (br->multicast_disabled)   //关闭组播报文
		return NULL;

	if (BR_INPUT_SKB_CB(skb)->igmp)   //此时该值为0
		return NULL;

	ip.proto = skb->protocol;    //协议号
	ip.vid = vid;    //vid

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ip.u.ip4 = ip_hdr(skb)->daddr;   //设置目的IP
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		ip.u.ip6 = ipv6_hdr(skb)->daddr;
		break;
#endif
	default:
		return NULL;
	}

	return br_mdb_ip_get(mdb, &ip);
}

struct net_bridge_mdb_entry *br_mdb_ip_get(struct net_bridge_mdb_htable *mdb,
					   struct br_ip *dst)
{
	if (!mdb)
		return NULL;

	return __br_mdb_ip_get(mdb, dst, br_ip_hash(mdb, dst));
}

static struct net_bridge_mdb_entry *__br_mdb_ip_get(
	struct net_bridge_mdb_htable *mdb, struct br_ip *dst, int hash)
{
	struct net_bridge_mdb_entry *mp;

	hlist_for_each_entry_rcu(mp, &mdb->mhash[hash], hlist[mdb->ver]) {
		if (br_ip_equal(&mp->addr, dst))
			return mp;
	}

	return NULL;
}
```


### br_multicast_forward

```c
void br_multicast_forward(struct net_bridge_mdb_entry *mdst,
			  struct sk_buff *skb, struct sk_buff *skb2)
{
	br_multicast_flood(mdst, skb, skb2, __br_forward);
}

static void br_multicast_flood(struct net_bridge_mdb_entry *mdst,
			       struct sk_buff *skb, struct sk_buff *skb0,
			       void (*__packet_hook)(
					const struct net_bridge_port *p,
					struct sk_buff *skb))
{
	struct net_device *dev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *prev = NULL;
	struct net_bridge_port_group *p;
	struct hlist_node *rp;

	rp = rcu_dereference(hlist_first_rcu(&br->router_list));
	p = mdst ? rcu_dereference(mdst->ports) : NULL;
	while (p || rp) {
		struct net_bridge_port *port, *lport, *rport;

		lport = p ? p->port : NULL;
		rport = rp ? hlist_entry(rp, struct net_bridge_port, rlist) :
			     NULL;

		port = (unsigned long)lport > (unsigned long)rport ?
		       lport : rport;

		prev = maybe_deliver(prev, port, skb, __packet_hook);
		if (IS_ERR(prev))
			goto out;

		if ((unsigned long)lport >= (unsigned long)port)
			p = rcu_dereference(p->next);
		if ((unsigned long)rport >= (unsigned long)port)
			rp = rcu_dereference(hlist_next_rcu(rp));
	}

	if (!prev)
		goto out;

	if (skb0)
		deliver_clone(prev, skb, __packet_hook);
	else
		__packet_hook(prev, skb);
	return;

out:
	if (!skb0)
		kfree_skb(skb);
}

static struct net_bridge_port *maybe_deliver(
	struct net_bridge_port *prev, struct net_bridge_port *p,
	struct sk_buff *skb,
	void (*__packet_hook)(const struct net_bridge_port *p,
			      struct sk_buff *skb))
{
	int err;

	if (!should_deliver(p, skb))
		return prev;

	if (!prev)
		goto out;

	err = deliver_clone(prev, skb, __packet_hook);
	if (err)
		return ERR_PTR(err);

out:
	return p;
}
```


### br_pass_frame_up

```c
static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);
	struct pcpu_sw_netstats *brstats = this_cpu_ptr(br->stats);
	struct net_port_vlans *pv;

	u64_stats_update_begin(&brstats->syncp);
	brstats->rx_packets++;
	brstats->rx_bytes += skb->len;
	u64_stats_update_end(&brstats->syncp);

	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc modue when someone
	 * may be running packet capture.
	 */
	pv = br_get_vlan_info(br);
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(br, pv, skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	indev = skb->dev;
	skb->dev = brdev;
	skb = br_handle_vlan(br, pv, skb);
	if (!skb)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, NULL, skb,
		       indev, NULL,
		       netif_receive_skb_sk);   //协议栈本地收包
}
```


## 组播报文发包入口

```c
netdev_tx_t br_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct net_bridge *br = netdev_priv(dev);
    const unsigned char *dest = skb->data;
    struct net_bridge_fdb_entry *dst;
    struct net_bridge_mdb_entry *mdst;
    struct pcpu_sw_netstats *brstats = this_cpu_ptr(br->stats);
    const struct nf_br_ops *nf_ops;
    u16 vid = 0;

    rcu_read_lock();
    nf_ops = rcu_dereference(nf_br_ops);
    if (nf_ops && nf_ops->br_dev_xmit_hook(skb)) {
        rcu_read_unlock();
        return NETDEV_TX_OK;
    }

    u64_stats_update_begin(&brstats->syncp);
    brstats->tx_packets++;
    brstats->tx_bytes += skb->len;
    u64_stats_update_end(&brstats->syncp);

    BR_INPUT_SKB_CB(skb)->brdev = dev;

    skb_reset_mac_header(skb);  //设置mac头指针
    skb_pull(skb, ETH_HLEN);    //剥除mac头

    if (!br_allowed_ingress(br, br_get_vlan_info(br), skb, &vid))  //检查vlan
        goto out;

    if (is_broadcast_ether_addr(dest))
        br_flood_deliver(br, skb, false);   //广播报文
    else if (is_multicast_ether_addr(dest)) {
        if (unlikely(netpoll_tx_running(dev))) {
            br_flood_deliver(br, skb, false);
            goto out;
        }
        if (br_multicast_rcv(br, NULL, skb, vid)) {   //igmp报文处理
            kfree_skb(skb);
            goto out;
        }

        mdst = br_mdb_get(br, skb, vid);   //得到组播记录
        if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
            br_multicast_querier_exists(br, eth_hdr(skb)))
            br_multicast_deliver(mdst, skb);  //按组播转发报文
        else
            br_flood_deliver(br, skb, false);  //flood报文
    } else if ((dst = __br_fdb_get(br, dest, vid)) != NULL)
        br_deliver(dst->dst, skb);
    else
        br_flood_deliver(br, skb, true);

out:
    rcu_read_unlock();
    return NETDEV_TX_OK;
}
```
