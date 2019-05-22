# bridge 收包处理

本文分析linux bridge收发包处理流程。


## 收包入口函数

```c
rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;  //得到报文的目的mac地址
	br_should_route_hook_t *rhook;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source)) //不允许组播mac地址以及全零mac地址
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

	p = br_port_get_rcu(skb->dev);  //port对象指针保存在rx_handler_data

	if (unlikely(is_link_local_ether_addr(dest))) {		//本地mac地址01-80-C2-00-00-**
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5]))
				goto forward;
			break;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		default:
			/* Allow selective forwarding for most other protocols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* Deliver packet to local host only */
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN, NULL, skb,
			    skb->dev, NULL, br_handle_local_finish)) {
			return RX_HANDLER_CONSUMED; /* consumed by filter */
		} else {
			*pskb = skb;
			return RX_HANDLER_PASS;	/* continue processing */
		}
	}

forward:
	switch (p->state) {
	case BR_STATE_FORWARDING:
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook) {
			if ((*rhook)(skb)) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:
		if (ether_addr_equal(p->br->dev->dev_addr, dest))  //目的MAC是否为br的host接口
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(NFPROTO_BRIDGE, NF_BR_PRE_ROUTING, NULL, skb,  //netfilter处理
			skb->dev, NULL,
			br_handle_frame_finish);  
		break;
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLER_CONSUMED;
}
```


### br_handle_frame_finish

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
	    br_multicast_rcv(br, p, skb, vid))   //组播报文接收
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

### br_allowed_ingress

```C
bool br_allowed_ingress(struct net_bridge *br, struct net_port_vlans *v,
			struct sk_buff *skb, u16 *vid)
{
	bool tagged;
	__be16 proto;

	/* If VLAN filtering is disabled on the bridge, all packets are
	 * permitted.
	 */
	if (!br->vlan_enabled) {  //未开启vlan模式，所有报文都接受
		BR_INPUT_SKB_CB(skb)->vlan_filtered = false;
		return true;
	}

	/* If there are no vlan in the permitted list, all packets are
	 * rejected.
	 */
	if (!v)  //端口无vlan信息，则丢弃报文
		goto drop;

	BR_INPUT_SKB_CB(skb)->vlan_filtered = true;
	proto = br->vlan_proto;  //bridge的vlan协议

	/* If vlan tx offload is disabled on bridge device and frame was
	 * sent from vlan device on the bridge device, it does not have
	 * HW accelerated vlan tag.
	 */
	if (unlikely(!skb_vlan_tag_present(skb) &&
		     skb->protocol == proto)) {
		skb = skb_vlan_untag(skb);
		if (unlikely(!skb))
			return false;
	}

	if (!br_vlan_get_tag(skb, vid)) {  //得到skb的vlan id值
		/* Tagged frame */
		if (skb->vlan_proto != proto) {  //如果vlan协议不同
			/* Protocol-mismatch, empty out vlan_tci for new tag */
			skb_push(skb, ETH_HLEN);  //跳过mac头
			skb = vlan_insert_tag_set_proto(skb, skb->vlan_proto,  //插入vlan头
							skb_vlan_tag_get(skb));
			if (unlikely(!skb))
				return false;

			skb_pull(skb, ETH_HLEN);
			skb_reset_mac_len(skb);
			*vid = 0;
			tagged = false;
		} else {
			tagged = true;
		}
	} else {
		/* Untagged frame */
		tagged = false;
	}

	if (!*vid) {   //skb非vlan报文
		u16 pvid = br_get_pvid(v);  //得到端口的pvid

		/* Frame had a tag with VID 0 or did not have a tag.
		 * See if pvid is set on this port.  That tells us which
		 * vlan untagged or priority-tagged traffic belongs to.
		 */
		if (!pvid)
			goto drop;

		/* PVID is set on this port.  Any untagged or priority-tagged
		 * ingress frame is considered to belong to this vlan.
		 */
		*vid = pvid;
		if (likely(!tagged))
			/* Untagged Frame. */
			__vlan_hwaccel_put_tag(skb, proto, pvid);
		else
			/* Priority-tagged Frame.
			 * At this point, We know that skb->vlan_tci had
			 * VLAN_TAG_PRESENT bit and its VID field was 0x000.
			 * We update only VID field and preserve PCP field.
			 */
			skb->vlan_tci |= pvid;

		return true;
	}

	/* Frame had a valid vlan tag.  See if vlan is allowed */
	if (test_bit(*vid, v->vlan_bitmap))   //判断vlan是否支持
		return true;
drop:
	kfree_skb(skb);
	return false;
}
```


### br_forward

```c
void br_forward(const struct net_bridge_port *to, struct sk_buff *skb, struct sk_buff *skb0)
{
	if (should_deliver(to, skb)) {  //判断目的端口状态
		if (skb0)
			deliver_clone(to, skb, __br_forward);   //克隆报文，调用__br_forward发送报文
		else
			__br_forward(to, skb);
		return;
	}

	if (!skb0)
		kfree_skb(skb);
}

static void __br_forward(const struct net_bridge_port *to, struct sk_buff *skb)
{
	struct net_device *indev;

	if (skb_warn_if_lro(skb)) {
		kfree_skb(skb);
		return;
	}

	skb = br_handle_vlan(to->br, nbp_get_vlan_info(to), skb);
	if (!skb)
		return;

	indev = skb->dev;
	skb->dev = to->dev;
	skb_forward_csum(skb);

	NF_HOOK(NFPROTO_BRIDGE, NF_BR_FORWARD, NULL, skb,
		indev, skb->dev,
		br_forward_finish);
}

int br_forward_finish(struct sock *sk, struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_POST_ROUTING, sk, skb,
		       NULL, skb->dev,
		       br_dev_queue_push_xmit);

}

int br_dev_queue_push_xmit(struct sock *sk, struct sk_buff *skb)
{
	if (!is_skb_forwardable(skb->dev, skb)) {
		kfree_skb(skb);
	} else {
		skb_push(skb, ETH_HLEN);    //添加mac头
		br_drop_fake_rtable(skb);
		skb_sender_cpu_clear(skb);
		dev_queue_xmit(skb);        //二层发送报文
	}

	return 0;
}
```


### br_flood_forward

```c
void br_flood_forward(struct net_bridge *br, struct sk_buff *skb,
		      struct sk_buff *skb2, bool unicast)
{
	br_flood(br, skb, skb2, __br_forward, unicast);
}

static void br_flood(struct net_bridge *br, struct sk_buff *skb,
		     struct sk_buff *skb0,
		     void (*__packet_hook)(const struct net_bridge_port *p,
					   struct sk_buff *skb),
		     bool unicast)
{
	struct net_bridge_port *p;
	struct net_bridge_port *prev;

	prev = NULL;

	list_for_each_entry_rcu(p, &br->port_list, list) {    //遍历所有port
		/* Do not flood unicast traffic to ports that turn it off */
		if (unicast && !(p->flags & BR_FLOOD))   //端口支持flood
			continue;

		/* Do not flood to ports that enable proxy ARP */
		if (p->flags & BR_PROXYARP) 
			continue;
		if ((p->flags & BR_PROXYARP_WIFI) &&
		    BR_INPUT_SKB_CB(skb)->proxyarp_replied)
			continue;

		prev = maybe_deliver(prev, p, skb, __packet_hook);    //调用__br_forward发送报文
		if (IS_ERR(prev))
			goto out;
	}

	if (!prev)
		goto out;

	if (skb0)
		deliver_clone(prev, skb, __packet_hook);  //调用__br_forward发送报文
	else
		__packet_hook(prev, skb);  //调用__br_forward发送报文
	return;

out:
	if (!skb0)
		kfree_skb(skb);
}
```


## bridge网卡设备的发包流程

每个bridge设备都对应一个虚拟网卡设备，向该网卡设备发包会进入到bridge的转流程

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
		if (br_multicast_rcv(br, NULL, skb, vid)) {
			kfree_skb(skb);
			goto out;
		}

		mdst = br_mdb_get(br, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(br, eth_hdr(skb)))
			br_multicast_deliver(mdst, skb);
		else
			br_flood_deliver(br, skb, false);
	} else if ((dst = __br_fdb_get(br, dest, vid)) != NULL)
		br_deliver(dst->dst, skb);
	else
		br_flood_deliver(br, skb, true);

out:
	rcu_read_unlock();
	return NETDEV_TX_OK;
}
```

###  br_flood_deliver

```c
void br_flood_deliver(struct net_bridge *br, struct sk_buff *skb, bool unicast)
{
	br_flood(br, skb, NULL, __br_deliver, unicast);
}
```

### br_deliver

```c
void br_deliver(const struct net_bridge_port *to, struct sk_buff *skb)
{
	if (to && should_deliver(to, skb)) {
		__br_deliver(to, skb);
		return;
	}

	kfree_skb(skb);
}

static void __br_deliver(const struct net_bridge_port *to, struct sk_buff *skb)
{
	skb = br_handle_vlan(to->br, nbp_get_vlan_info(to), skb);
	if (!skb)
		return;

	skb->dev = to->dev;

	if (unlikely(netpoll_tx_running(to->br->dev))) {
		if (!is_skb_forwardable(skb->dev, skb))
			kfree_skb(skb);
		else {
			skb_push(skb, ETH_HLEN);
			br_netpoll_send_skb(to, skb);
		}
		return;
	}

	NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_OUT, NULL, skb,
		NULL, skb->dev,
		br_forward_finish);
}

int br_forward_finish(struct sock *sk, struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_POST_ROUTING, sk, skb,
		       NULL, skb->dev,
		       br_dev_queue_push_xmit);

}
```