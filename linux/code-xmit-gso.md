# GSO

GSO(Generic Segmentation Offload): GSO是协议栈是否推迟分段，在发送到网卡之前判断网卡是否支持TSO，如果网卡支持TSO则让网卡分段，否则协议栈分完段再交给驱动。 如果TSO开启，GSO会自动开启。

以下是TSO和GSO的组合关系：

* GSO开启，TSO开启: 协议栈推迟分段，并直接传递大数据包到网卡，让网卡自动分段
* GSO开启，TSO关闭: 协议栈推迟分段，在最后发送到网卡前才执行分段
* GSO关闭，TSO开启: 同GSO开启， TSO开启
* GSO关闭，TSO关闭: 不推迟分段，在tcp_sendmsg中直接发送MSS大小的数据包


## 数据结构

```c
static struct packet_offload ip_packet_offload __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.callbacks = {
		.gso_segment = inet_gso_segment,
		.gro_receive = inet_gro_receive,
		.gro_complete = inet_gro_complete,
	},
};

static const struct net_offload tcpv4_offload = {
	.callbacks = {
		.gso_segment	=	tcp4_gso_segment,
		.gro_receive	=	tcp4_gro_receive,
		.gro_complete	=	tcp4_gro_complete,
	},
};
```


## GSO 入口函数

GSO发生报文发送给设备驱动前，如下为调用栈：

```bash
dev_queue_xmit->dev_queue_xmit_sk->__dev_queue_xmit->
    validate_xmit_skb->dev_hard_start_xmit
    __dev_xmit_skb->sch_direct_xmit->validate_xmit_skb_list->validate_xmit_skb->dev_hard_start_xmit
```

validate_xmit_skb函数就检查设备的feature，然后判断是否需要报文分段。

```c
static struct sk_buff *validate_xmit_skb(struct sk_buff *skb, struct net_device *dev)
{
	netdev_features_t features;

	if (skb->next)		//validate_xmit_skb_list调用的场景，此条件不成立
		return skb;

	features = netif_skb_features(skb);		//获取设备的features
	skb = validate_xmit_vlan(skb, features);
	if (unlikely(!skb))
		goto out_null;
    
	// 判断报文是否需要GSO分段
	// 判断features是否包含skb->gso_type
	if (netif_needs_gso(skb, features)) {	
		struct sk_buff *segs;

		segs = skb_gso_segment(skb, features);	//报文GSO分段
		if (IS_ERR(segs)) {
			goto out_kfree_skb;
		} else if (segs) {
			consume_skb(skb);
			skb = segs;
		}
	} else {
		if (skb_needs_linearize(skb, features) &&
		    __skb_linearize(skb))
			goto out_kfree_skb;

		/* If packet is not checksummed and device does not
		 * support checksumming for this protocol, complete
		 * checksumming here.
		 */
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			if (skb->encapsulation)
				skb_set_inner_transport_header(skb,
							       skb_checksum_start_offset(skb));
			else
				skb_set_transport_header(skb,
							 skb_checksum_start_offset(skb));
			if (!(features & NETIF_F_ALL_CSUM) &&
			    skb_checksum_help(skb))
				goto out_kfree_skb;
		}
	}

	return skb;

out_kfree_skb:
	kfree_skb(skb);
out_null:
	return NULL;
}
```


### 判断是否需要GSO分段

```c
static inline bool netif_needs_gso(struct sk_buff *skb,
				   netdev_features_t features)
{
    //skb 为gso报文，且feature不包含skb->gso_type 
	//或者skb_ipsummed不为CHECKSUM_PARTIAL和CHECKSUM_UNNECESSARY
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||   
                                                                   
		unlikely((skb->ip_summed != CHECKSUM_PARTIAL) &&
			 (skb->ip_summed != CHECKSUM_UNNECESSARY)));
}

static inline bool skb_gso_ok(struct sk_buff *skb, netdev_features_t features)
{
    //feature包含gso_type 并且skb没有frag_list或者feature包含NETIF_F_FRAGLIST
	return net_gso_ok(features, skb_shinfo(skb)->gso_type) &&	
	       (!skb_has_frag_list(skb) || (features & NETIF_F_FRAGLIST));
}

static inline bool net_gso_ok(netdev_features_t features, int gso_type)
{
	netdev_features_t feature = gso_type << NETIF_F_GSO_SHIFT;

	/* check flags correspondence */
	BUILD_BUG_ON(SKB_GSO_TCPV4   != (NETIF_F_TSO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP     != (NETIF_F_UFO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_DODGY   != (NETIF_F_GSO_ROBUST >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TCP_ECN != (NETIF_F_TSO_ECN >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TCPV6   != (NETIF_F_TSO6 >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_FCOE    != (NETIF_F_FSO >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_GRE     != (NETIF_F_GSO_GRE >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_GRE_CSUM != (NETIF_F_GSO_GRE_CSUM >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_IPIP    != (NETIF_F_GSO_IPIP >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_SIT     != (NETIF_F_GSO_SIT >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP_TUNNEL != (NETIF_F_GSO_UDP_TUNNEL >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_UDP_TUNNEL_CSUM != (NETIF_F_GSO_UDP_TUNNEL_CSUM >> NETIF_F_GSO_SHIFT));
	BUILD_BUG_ON(SKB_GSO_TUNNEL_REMCSUM != (NETIF_F_GSO_TUNNEL_REMCSUM >> NETIF_F_GSO_SHIFT));

	return (features & feature) == feature;
}
```


## 报文GSO分段（MAC层）

```c
static inline
struct sk_buff *skb_gso_segment(struct sk_buff *skb, netdev_features_t features)
{
	return __skb_gso_segment(skb, features, true);
}

struct sk_buff *__skb_gso_segment(struct sk_buff *skb,
				  netdev_features_t features, bool tx_path)
{
	if (unlikely(skb_needs_check(skb, tx_path))) {	// 判断等于 skb->ip_summed != CHECKSUM_PARTIAL
		int err;

		skb_warn_bad_offload(skb);	//打印告警信息，说明GSO报文skb->ip_summed == CHECKSUM_PARTIAL

		err = skb_cow_head(skb, 0);	//如果skb是克隆，则需要重新分配线性区
		if (err < 0)
			return ERR_PTR(err);
	}

	SKB_GSO_CB(skb)->mac_offset = skb_headroom(skb);	//设置mac_offset， 用于skb_segment分段拷贝外层报文
	SKB_GSO_CB(skb)->encap_level = 0;	//encap_level为零，说明是最外层的报文

	skb_reset_mac_header(skb);	//重置mac header
	skb_reset_mac_len(skb);		//重置mac len

	return skb_mac_gso_segment(skb, features);
}

struct sk_buff *skb_mac_gso_segment(struct sk_buff *skb,
				    netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EPROTONOSUPPORT);
	struct packet_offload *ptype;
	int vlan_depth = skb->mac_len;
	__be16 type = skb_network_protocol(skb, &vlan_depth);	//得到skb协议

	if (unlikely(!type))
		return ERR_PTR(-EINVAL);

	__skb_pull(skb, vlan_depth);	//skb data指针移动到IP头

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, &offload_base, list) {
		if (ptype->type == type && ptype->callbacks.gso_segment) {
			segs = ptype->callbacks.gso_segment(skb, features);	//调用IP层的GSO segment函数
			break;
		}
	}
	rcu_read_unlock();

	__skb_push(skb, skb->data - skb_mac_header(skb));	//skb data指针移动到MAC头

	return segs;
}
```

## 报文GSO分段（IP层）

```c
static struct sk_buff *inet_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	const struct net_offload *ops;
	unsigned int offset = 0;
	bool udpfrag, encap;
	struct iphdr *iph;
	int proto;
	int nhoff;
	int ihl;
	int id;

	if (unlikely(skb_shinfo(skb)->gso_type &
		     ~(SKB_GSO_TCPV4 |
		       SKB_GSO_UDP |
		       SKB_GSO_DODGY |
		       SKB_GSO_TCP_ECN |
		       SKB_GSO_GRE |
		       SKB_GSO_GRE_CSUM |
		       SKB_GSO_IPIP |
		       SKB_GSO_SIT |
		       SKB_GSO_TCPV6 |
		       SKB_GSO_UDP_TUNNEL |
		       SKB_GSO_UDP_TUNNEL_CSUM |
		       SKB_GSO_TUNNEL_REMCSUM |
		       0)))
		goto out;

	skb_reset_network_header(skb);
	nhoff = skb_network_header(skb) - skb_mac_header(skb);	//根据network header和mac header得到IP头相对MAC的偏移
	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))	//检测skb是否可以移动到L4头？
		goto out;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;		//得到IP包头的实际长度，基于此可以得到L4的首地址
	if (ihl < sizeof(*iph))
		goto out;

	id = ntohs(iph->id);
	proto = iph->protocol;		//L4层协议类型

	/* Warning: after this point, iph might be no longer valid */
	if (unlikely(!pskb_may_pull(skb, ihl)))	//检测skb是否可以移动到L4头？
		goto out;
	__skb_pull(skb, ihl);		//报文data指针移动到传输层

	encap = SKB_GSO_CB(skb)->encap_level > 0;
	if (encap)
		features &= skb->dev->hw_enc_features;		//如果encap，那么feature与hw_enc_features取交集
	SKB_GSO_CB(skb)->encap_level += ihl;	//用来标示是否为内层报文

	skb_reset_transport_header(skb);	//设置transport header值

	segs = ERR_PTR(-EPROTONOSUPPORT);

	if (skb->encapsulation &&
	    skb_shinfo(skb)->gso_type & (SKB_GSO_SIT|SKB_GSO_IPIP))
		udpfrag = proto == IPPROTO_UDP && encap;
	else
		udpfrag = proto == IPPROTO_UDP && !skb->encapsulation;		//vxlan封装报文走此分支，此时udpfrag为false

	ops = rcu_dereference(inet_offloads[proto]);
	if (likely(ops && ops->callbacks.gso_segment))
		segs = ops->callbacks.gso_segment(skb, features);	//UDP或TCP的分段函数

	if (IS_ERR_OR_NULL(segs))
		goto out;

	skb = segs;
	do {
		iph = (struct iphdr *)(skb_mac_header(skb) + nhoff);	//根据分段报文的mac header 和 IP偏移
		if (udpfrag) {				//ip分片报文
			iph->id = htons(id);
			iph->frag_off = htons(offset >> 3);	//设置ip头的frag_off值
			if (skb->next)
				iph->frag_off |= htons(IP_MF);	//后面还有报文，需要设置more frag标记
			offset += skb->len - nhoff - ihl;	//计算offset值，下一个报文需要使用
		} else {
			iph->id = htons(id++);		//每个报文为完整的IP报文
		}
		iph->tot_len = htons(skb->len - nhoff);
		ip_send_check(iph);				//计算ip头 csum值
		if (encap)		//如果encap值非空，说明当前处于内层报文中，所以需要设置inner heaer值
			skb_reset_inner_headers(skb);
		skb->network_header = (u8 *)iph - skb->head;	//设置network header
	} while ((skb = skb->next));

out:
	return segs;
}

```


## 报文GSO分段（TCP）

```c
static struct sk_buff *tcp4_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		return ERR_PTR(-EINVAL);

	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {	
		const struct iphdr *iph = ip_hdr(skb);
		struct tcphdr *th = tcp_hdr(skb);	//ip层报文保证了transport header值

		/* Set up checksum pseudo header, usually expect stack to
		 * have done this already.
		 */

		th->check = 0;
		skb->ip_summed = CHECKSUM_PARTIAL;
		__tcp_v4_send_check(skb, iph->saddr, iph->daddr);	//计算伪头check值
	}

	return tcp_gso_segment(skb, features);	//TCP GSO分段
}

void __tcp_v4_send_check(struct sk_buff *skb, __be32 saddr, __be32 daddr)
{
	struct tcphdr *th = tcp_hdr(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);	//计算伪头check值
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		th->check = tcp_v4_check(skb->len, saddr, daddr,
					 csum_partial(th,
						      th->doff << 2,
						      skb->csum));
	}
}

struct sk_buff *tcp_gso_segment(struct sk_buff *skb,
				netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	unsigned int sum_truesize = 0;
	struct tcphdr *th;
	unsigned int thlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int mss;
	struct sk_buff *gso_skb = skb;
	__sum16 newcheck;
	bool ooo_okay, copy_destructor;

	th = tcp_hdr(skb);
	thlen = th->doff * 4;		//得到tcp头的长度
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))	//检测报文长度
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);		//skb移动到用户数据区（payload）

	mss = tcp_skb_mss(skb);		//得到mss值
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;

		if (unlikely(type &
			     ~(SKB_GSO_TCPV4 |
			       SKB_GSO_DODGY |
			       SKB_GSO_TCP_ECN |
			       SKB_GSO_TCPV6 |
			       SKB_GSO_GRE |
			       SKB_GSO_GRE_CSUM |
			       SKB_GSO_IPIP |
			       SKB_GSO_SIT |
			       SKB_GSO_UDP_TUNNEL |
			       SKB_GSO_UDP_TUNNEL_CSUM |
			       SKB_GSO_TUNNEL_REMCSUM |
			       0) ||
			     !(type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))))
			goto out;

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss); //如果报文来源不可信，则重新计算segs，返回

		segs = NULL;
		goto out;
	}

	copy_destructor = gso_skb->destructor == tcp_wfree;
	ooo_okay = gso_skb->ooo_okay;
	/* All segments but the first should have ooo_okay cleared */
	skb->ooo_okay = 0;

	segs = skb_segment(skb, features);	//调用payload根据mss值分段
	if (IS_ERR(segs))
		goto out;

	/* Only first segment might have ooo_okay set */
	segs->ooo_okay = ooo_okay;

	delta = htonl(oldlen + (thlen + mss));	//TCP头+mss - 原始报文，该值为负值

	skb = segs;
	th = tcp_hdr(skb);	//skb_segment分段后，可以直接从skb中获取tcp头， skb_segment或udp4_ufo_fragment保证
	seq = ntohl(th->seq);

	if (unlikely(skb_shinfo(gso_skb)->tx_flags & SKBTX_SW_TSTAMP))
		tcp_gso_tstamp(segs, skb_shinfo(gso_skb)->tskey, seq, mss);

	newcheck = ~csum_fold((__force __wsum)((__force u32)th->check +	//第一个报文基于原先值，根据delta快速计算
					       (__force u32)delta));

	do {	//刷新分段后报文的TCP头设置
		th->fin = th->psh = 0;
		th->check = newcheck;

		if (skb->ip_summed != CHECKSUM_PARTIAL)	   
			th->check = gso_make_checksum(skb, ~th->check);	 //重新计算check值

		seq += mss;
		if (copy_destructor) {
			skb->destructor = gso_skb->destructor;
			skb->sk = gso_skb->sk;
			sum_truesize += skb->truesize;
		}
		skb = skb->next;
		th = tcp_hdr(skb);

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	/* Following permits TCP Small Queues to work well with GSO :
	 * The callback to TCP stack will be called at the time last frag
	 * is freed at TX completion, and not right now when gso_skb
	 * is freed by GSO engine
	 */
	if (copy_destructor) {
		swap(gso_skb->sk, skb->sk);
		swap(gso_skb->destructor, skb->destructor);
		sum_truesize += skb->truesize;
		atomic_add(sum_truesize - gso_skb->truesize,
			   &skb->sk->sk_wmem_alloc);
	}

	delta = htonl(oldlen + (skb_tail_pointer(skb) -
				skb_transport_header(skb)) +	//最后一个报文的delta值不同
		      skb->data_len);
	th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				(__force u32)delta));
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		th->check = gso_make_checksum(skb, ~th->check);	//重新计算check值
out:
	return segs;
}

struct sk_buff *skb_segment(struct sk_buff *head_skb,
			    netdev_features_t features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *list_skb = skb_shinfo(head_skb)->frag_list;
	skb_frag_t *frag = skb_shinfo(head_skb)->frags;	
	unsigned int mss = skb_shinfo(head_skb)->gso_size;
	unsigned int doffset = head_skb->data - skb_mac_header(head_skb);  //得到内层报头的长度
	struct sk_buff *frag_skb = head_skb;
	unsigned int offset = doffset;
	unsigned int tnl_hlen = skb_tnl_header_len(head_skb);	//得到外层报头的长度，非封装报文该值为0， 是支持封装报文GSO的基础
	unsigned int headroom;
	unsigned int len;
	__be16 proto;
	bool csum;
	int sg = !!(features & NETIF_F_SG);	//是否支持SG
	int nfrags = skb_shinfo(head_skb)->nr_frags;
	int err = -ENOMEM;
	int i = 0;
	int pos;
	int dummy;

	__skb_push(head_skb, doffset);		//报文移到内层报文的mac头
	proto = skb_network_protocol(head_skb, &dummy);	//报文协议类型
	if (unlikely(!proto))
		return ERR_PTR(-EINVAL);

	csum = !head_skb->encap_hdr_csum &&
	    !!can_checksum_protocol(features, proto);

	headroom = skb_headroom(head_skb);	//得到报文的headroom大小
	pos = skb_headlen(head_skb);		//报文线性区长度

	do {
		struct sk_buff *nskb;
		skb_frag_t *nskb_frag;
		int hsize;
		int size;

		len = head_skb->len - offset;	//计算报文待拷贝的长度，不包括包头
		if (len > mss)			
			len = mss;		//len超过mss，则只能拷贝mss长度

		hsize = skb_headlen(head_skb) - offset;	//待拷贝的线性区长度
		if (hsize < 0)
			hsize = 0;
		if (hsize > len || !sg)
			hsize = len;

		if (!hsize && i >= nfrags && skb_headlen(list_skb) &&	//frag_list中还有数据
		    (skb_headlen(list_skb) == len || sg)) {
			BUG_ON(skb_headlen(list_skb) > len);	//frag_list中的skb线性区长度不超过len，即mss值

			i = 0;
			nfrags = skb_shinfo(list_skb)->nr_frags;
			frag = skb_shinfo(list_skb)->frags;
			frag_skb = list_skb;
			pos += skb_headlen(list_skb);	//增加线性区长度

			while (pos < offset + len) {	//只能拷贝len长度
				BUG_ON(i >= nfrags);

				size = skb_frag_size(frag);
				if (pos + size > offset + len)
					break;

				i++;
				pos += size;		//增加frag的长度
				frag++;
			}

			nskb = skb_clone(list_skb, GFP_ATOMIC);	//克隆报文，该报文包含完整的数据，需要裁剪
			list_skb = list_skb->next;

			if (unlikely(!nskb))
				goto err;

			if (unlikely(pskb_trim(nskb, len))) {	//裁剪报文到len长度
				kfree_skb(nskb);
				goto err;
			}

			hsize = skb_end_offset(nskb);
			if (skb_cow_head(nskb, doffset + headroom)) {	//扩展head，以容得下外层报头
				kfree_skb(nskb);
				goto err;
			}

			nskb->truesize += skb_end_offset(nskb) - hsize;	//truesize值刷新
			skb_release_head_state(nskb);
			__skb_push(nskb, doffset);	//skb移动到内层报文的mac头
		} else {
			nskb = __alloc_skb(hsize + doffset + headroom,	//skb的frag还未使用完，采用新申请skb的方式
					   GFP_ATOMIC, skb_alloc_rx_flag(head_skb),
					   NUMA_NO_NODE);

			if (unlikely(!nskb))
				goto err;

			skb_reserve(nskb, headroom);	//skb预留headroom长度
			__skb_put(nskb, doffset);	//线性区扩展内层报头长度
		}

		if (segs)
			tail->next = nskb;
		else
			segs = nskb;
		tail = nskb;

		__copy_skb_header(nskb, head_skb);	//拷贝skb的相关信息，包括header都拷贝了

		skb_headers_offset_update(nskb, skb_headroom(nskb) - headroom);	//由于headroom变化，刷新header值
		skb_reset_mac_len(nskb);	//重置mac len值

		skb_copy_from_linear_data_offset(head_skb, -tnl_hlen,	//拷贝外两层报头（如果封装的话）
						 nskb->data - tnl_hlen,
						 doffset + tnl_hlen);

		if (nskb->len == len + doffset)		//对于使用frag_list场景，满足条件；拷贝frag场景不满足
			goto perform_csum_check;

		if (!sg && !nskb->remcsum_offload) {
			nskb->ip_summed = CHECKSUM_NONE;
			nskb->csum = skb_copy_and_csum_bits(head_skb, offset,	//计算cusm值
							    skb_put(nskb, len),
							    len, 0);
			SKB_GSO_CB(nskb)->csum_start =
			    skb_headroom(nskb) + doffset;	//相当于数据区到head的offset
			continue;
		}

		nskb_frag = skb_shinfo(nskb)->frags;

		skb_copy_from_linear_data_offset(head_skb, offset,	//拷贝线性区数据
						 skb_put(nskb, hsize), hsize);

		skb_shinfo(nskb)->tx_flags = skb_shinfo(head_skb)->tx_flags &
			SKBTX_SHARED_FRAG;

		while (pos < offset + len) {	
			if (i >= nfrags) {
				BUG_ON(skb_headlen(list_skb));

				i = 0;
				nfrags = skb_shinfo(list_skb)->nr_frags;
				frag = skb_shinfo(list_skb)->frags;
				frag_skb = list_skb;

				BUG_ON(!nfrags);

				list_skb = list_skb->next;	//frag_list场景，取下一个skb
			}

			if (unlikely(skb_shinfo(nskb)->nr_frags >=
				     MAX_SKB_FRAGS)) {
				net_warn_ratelimited(
					"skb_segment: too many frags: %u %u\n",
					pos, mss);
				goto err;
			}

			if (unlikely(skb_orphan_frags(frag_skb, GFP_ATOMIC)))
				goto err;

			*nskb_frag = *frag;	//frag_list的逻辑和frag的逻辑合并在了一起，增加了复杂度
			__skb_frag_ref(nskb_frag);
			size = skb_frag_size(nskb_frag);

			if (pos < offset) {
				nskb_frag->page_offset += offset - pos;
				skb_frag_size_sub(nskb_frag, offset - pos);  //frag分拆
			}

			skb_shinfo(nskb)->nr_frags++;

			if (pos + size <= offset + len) {
				i++;
				frag++;
				pos += size;
			} else {
				skb_frag_size_sub(nskb_frag, pos + size - (offset + len));	//frag分拆
				goto skip_fraglist;
			}

			nskb_frag++;
		}

skip_fraglist:
		nskb->data_len = len - hsize;
		nskb->len += nskb->data_len;
		nskb->truesize += nskb->data_len;

perform_csum_check:
		if (!csum && !nskb->remcsum_offload) {	//如果设置csum且未设置remcsum，软件计算内层报文的csum
			nskb->csum = skb_checksum(nskb, doffset,
						  nskb->len - doffset, 0);	//计算csum值
			nskb->ip_summed = CHECKSUM_NONE;
			SKB_GSO_CB(nskb)->csum_start =
			    skb_headroom(nskb) + doffset;
		}
	} while ((offset += len) < head_skb->len);

	/* Some callers want to get the end of the list.
	 * Put it in segs->prev to avoid walking the list.
	 * (see validate_xmit_skb_list() for example)
	 */
	segs->prev = tail;

	/* Following permits correct backpressure, for protocols
	 * using skb_set_owner_w().
	 * Idea is to tranfert ownership from head_skb to last segment.
	 */
	if (head_skb->destructor == sock_wfree) {
		swap(tail->truesize, head_skb->truesize);
		swap(tail->destructor, head_skb->destructor);
		swap(tail->sk, head_skb->sk);
	}
	return segs;

err:
	kfree_skb_list(segs);
	return ERR_PTR(err);
}
```

## 报文GSO分段（UDP）

```c
static struct sk_buff *udp4_ufo_fragment(struct sk_buff *skb,
					 netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	unsigned int mss;
	__wsum csum;
	struct udphdr *uh;
	struct iphdr *iph;

	if (skb->encapsulation &&
	    (skb_shinfo(skb)->gso_type &
	     (SKB_GSO_UDP_TUNNEL|SKB_GSO_UDP_TUNNEL_CSUM))) {		
		segs = skb_udp_tunnel_segment(skb, features, false);	//封装报文的GSO分段，可以基于内层报文进行GSO分段
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto out;

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {		
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;

		if (unlikely(type & ~(SKB_GSO_UDP | SKB_GSO_DODGY |
				      SKB_GSO_UDP_TUNNEL |
				      SKB_GSO_UDP_TUNNEL_CSUM |
				      SKB_GSO_TUNNEL_REMCSUM |
				      SKB_GSO_IPIP |
				      SKB_GSO_GRE | SKB_GSO_GRE_CSUM) ||
			     !(type & (SKB_GSO_UDP))))
			goto out;

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss); //如果报文来源不可信，则重新计算segs，返回

		segs = NULL;
		goto out;
	}

	/* Do software UFO. Complete and fill in the UDP checksum as
	 * HW cannot do checksum of UDP packets sent as multiple
	 * IP fragments.
	 */

	uh = udp_hdr(skb);
	iph = ip_hdr(skb);

	uh->check = 0;
	csum = skb_checksum(skb, 0, skb->len, 0);	//计算csum值
	uh->check = udp_v4_check(skb->len, iph->saddr, iph->daddr, csum);	//计算udp头的check值
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

	skb->ip_summed = CHECKSUM_NONE;

	/* Fragment the skb. IP headers of the fragments are updated in
	 * inet_gso_segment()
	 */
	segs = skb_segment(skb, features);	//报文根据mss进行分段，因为包含UDP头，所以分段的结果是IP分片报文
out:
	return segs;
}

struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb,
				       netdev_features_t features,
				       bool is_ipv6)
{
	__be16 protocol = skb->protocol;
	const struct net_offload **offloads;
	const struct net_offload *ops;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
					     netdev_features_t features);

	rcu_read_lock();

	switch (skb->inner_protocol_type) {	//vxlan封装时，该值为ENCAP_TYPE_ETHER
	case ENCAP_TYPE_ETHER:
		protocol = skb->inner_protocol;
		gso_inner_segment = skb_mac_gso_segment;  //vxlan封装，内层报文为完整的报文（二层、三层、四层），继续从mac开始分段
		break;
	case ENCAP_TYPE_IPPROTO:
		offloads = is_ipv6 ? inet6_offloads : inet_offloads;
		ops = rcu_dereference(offloads[skb->inner_ipproto]);
		if (!ops || !ops->callbacks.gso_segment)
			goto out_unlock;
		gso_inner_segment = ops->callbacks.gso_segment;		//调用4层协议的GSO分段能力，GRE/IPIP等等
		break;
	default:
		goto out_unlock;
	}

	segs = __skb_udp_tunnel_segment(skb, features, gso_inner_segment,	//upd封装报文GSO分段
					protocol, is_ipv6);

out_unlock:
	rcu_read_unlock();

	return segs;
}

static struct sk_buff *__skb_udp_tunnel_segment(struct sk_buff *skb,
	netdev_features_t features,
	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb,
					     netdev_features_t features),
	__be16 new_protocol, bool is_ipv6)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	u16 mac_offset = skb->mac_header;
	int mac_len = skb->mac_len;
	int tnl_hlen = skb_inner_mac_header(skb) - skb_transport_header(skb);	//vxlan头长度 UDP + vxlan，
	__be16 protocol = skb->protocol;
	netdev_features_t enc_features;
	int udp_offset, outer_hlen;
	unsigned int oldlen;
	bool need_csum = !!(skb_shinfo(skb)->gso_type &		//是否标记csum计算
			    SKB_GSO_UDP_TUNNEL_CSUM);
	bool remcsum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_TUNNEL_REMCSUM);	//是否标记remcsum计算
	bool offload_csum = false, dont_encap = (need_csum || remcsum);

	oldlen = (u16)~skb->len;

	if (unlikely(!pskb_may_pull(skb, tnl_hlen)))
		goto out;

	skb->encapsulation = 0;
	__skb_pull(skb, tnl_hlen);	//报文移动到内层报文的MAC头
	skb_reset_mac_header(skb);	//设置skb的mac header
	skb_set_network_header(skb, skb_inner_network_offset(skb));  //设置skb的 ip header
	skb->mac_len = skb_inner_network_offset(skb);	//设置skb mac len
	skb->protocol = new_protocol;		//设置skb protocol，至此skb已经切换到内层，可以继续进行GSO分段
	skb->encap_hdr_csum = need_csum;
	skb->remcsum_offload = remcsum;		

	/* Try to offload checksum if possible */
	offload_csum = !!(need_csum &&
			  (skb->dev->features &
			   (is_ipv6 ? NETIF_F_V6_CSUM : NETIF_F_V4_CSUM)));	//硬件支持csum计算

	/* segment inner packet. */
	enc_features = skb->dev->hw_enc_features & features;
	segs = gso_inner_segment(skb, enc_features);	//如果是vxlan报文，则重新开始mac层的GSO分段
	if (IS_ERR_OR_NULL(segs)) {
		skb_gso_error_unwind(skb, protocol, tnl_hlen, mac_offset,
				     mac_len);
		goto out;
	}

	outer_hlen = skb_tnl_header_len(skb);	//计算外层报文的长度
	udp_offset = outer_hlen - tnl_hlen;	//外层UDP头的偏移
	skb = segs;				//此时skb指向内层报文的mac头位置
	do {
		struct udphdr *uh;
		int len;
		__be32 delta;

		if (dont_encap) {
			skb->encapsulation = 0;
			skb->ip_summed = CHECKSUM_NONE;
		} else {
			/* Only set up inner headers if we might be offloading
			 * inner checksum.
			 */				//csum或remcsum设置时，进此分支
			skb_reset_inner_headers(skb);	//此时skb指向内层报文，可以建立inner header值
			skb->encapsulation = 1;
		}

		skb->mac_len = mac_len;
		skb->protocol = protocol;

		skb_push(skb, outer_hlen);	//skb移到外层报文的mac头
		skb_reset_mac_header(skb);	//设置mac header
		skb_set_network_header(skb, mac_len);	//设置network header，ip层需要
		skb_set_transport_header(skb, udp_offset);	//设置transport header
		len = skb->len - udp_offset;
		uh = udp_hdr(skb);	//找到UDP头很重要，GSO分段后，有些数据需要刷新，包括长度等
		uh->len = htons(len);

		if (!need_csum)		//如果csum未开启，UDP头的check值不需要刷新和设置
			continue;

		delta = htonl(oldlen + len);

		uh->check = ~csum_fold((__force __wsum)		//gso分段后，UDP伪首部的长度字段变化，需要刷新check
				       ((__force u32)uh->check +
					(__force u32)delta));
		if (offload_csum) {
			skb->ip_summed = CHECKSUM_PARTIAL;	
			skb->csum_start = skb_transport_header(skb) - skb->head; //重新计算csum值，gso分段后位置更新了
			skb->csum_offset = offsetof(struct udphdr, check);
		} else if (remcsum) {
			/* Need to calculate checksum from scratch,
			 * inner checksums are never when doing
			 * remote_checksum_offload.
			 */

			skb->csum = skb_checksum(skb, udp_offset,	//如果设置了remcsum，则软件计算csum值，完整计算整个报文
						 skb->len - udp_offset,
						 0);
			uh->check = csum_fold(skb->csum);		
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		} else {
			uh->check = gso_make_checksum(skb, ~uh->check); //软件计算csum值，根据内层报文的csum值进行计算

			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		}
	} while ((skb = skb->next));
out:
	return segs;
}
```


