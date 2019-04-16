# CT��NATЭͬ����

֮ǰһֱ�и����ʣ�������SNAT��DNAT��Ϊʲô����Ҫ��Ӧ������DNAT��SNAT���ں�����������������أ� ��ƪ������������

## CT��NATЭͬ�������̷���

�������³����������ں˴���Ĵ����߼���

* ����A��10.10.1.2/24�� ��Host1�ϣ�192.168.0.101/24��
* ����D��10.10.1.5/24�� ��Host2�ϣ�192.168.0.102/24��
* ����A����10.10.1.5:80��ʵ�ʷ���192.168.0.102:8080������A�����ı��ĻᱻHost1ִ��SNAT����
* Host2ʵ���յ��ı���Ϊ��sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080��

### Host2 NF_INET_PRE_ROUTING��CT����

```c
static unsigned int ipv4_conntrack_in(const struct nf_hook_ops *ops,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	return nf_conntrack_in(dev_net(state->in), PF_INET, ops->hooknum, skb);
}

unsigned int
nf_conntrack_in(struct net *net, u_int8_t pf, unsigned int hooknum,
		struct sk_buff *skb)
{
	struct nf_conn *ct, *tmpl = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int *timeouts;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;

	if (skb->nfct) {		//��ʱΪ�գ�������˷�֧
		/* Previously seen (loopback or untracked)?  Ignore. */
		tmpl = (struct nf_conn *)skb->nfct;
		if (!nf_ct_is_template(tmpl)) {
			NF_CT_STAT_INC_ATOMIC(net, ignore);
			return NF_ACCEPT;
		}
		skb->nfct = NULL;
	}

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find(pf);	//�ҵ�����Э�飬IPv4��Ϊnf_conntrack_l3proto_ipv4
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb),  //����Ĳ�Э������
				   &dataoff, &protonum);
	if (ret <= 0) {
		pr_debug("not prepared to track yet or error occurred\n");
		NF_CT_STAT_INC_ATOMIC(net, error);
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = -ret;
		goto out;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);		//�ҵ��Ĳ�Э��

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL) {
		ret = l4proto->error(net, tmpl, skb, dataoff, &ctinfo,
				     pf, hooknum);
		if (ret <= 0) {
			NF_CT_STAT_INC_ATOMIC(net, error);
			NF_CT_STAT_INC_ATOMIC(net, invalid);
			ret = -ret;
			goto out;
		}
		/* ICMP[v6] protocol trackers may assign one conntrack. */
		if (skb->nfct)
			goto out;
	}

	ct = resolve_normal_ct(net, tmpl, skb, dataoff, pf, protonum,   //��ȡ�򴴽�ct����
			       l3proto, l4proto, &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = NF_ACCEPT;
		goto out;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = NF_DROP;
		goto out;
	}

	NF_CT_ASSERT(skb->nfct);

	/* Decide what timeout policy we want to apply to this flow. */
	timeouts = nf_ct_timeout_lookup(net, ct, l4proto);

	ret = l4proto->packet(ct, skb, dataoff, ctinfo, pf, hooknum, timeouts);
	if (ret <= 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		pr_debug("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put(skb->nfct);
		skb->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		if (ret == -NF_DROP)
			NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = -ret;
		goto out;
	}

	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status))	
		nf_conntrack_event_cache(IPCT_REPLY, ct);
out:
	if (tmpl) {
		/* Special case: we have to repeat this hook, assign the
		 * template again to this packet. We assume that this packet
		 * has no conntrack assigned. This is used by nf_ct_tcp. */
		if (ret == NF_REPEAT)
			skb->nfct = (struct nf_conntrack *)tmpl;
		else
			nf_ct_put(tmpl);
	}

	return ret;
}

static inline struct nf_conn *
resolve_normal_ct(struct net *net, struct nf_conn *tmpl,
		  struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int16_t l3num,
		  u_int8_t protonum,
		  struct nf_conntrack_l3proto *l3proto,
		  struct nf_conntrack_l4proto *l4proto,
		  int *set_reply,
		  enum ip_conntrack_info *ctinfo)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	u16 zone = tmpl ? nf_ct_zone(tmpl) : NF_CT_DEFAULT_ZONE;
	u32 hash;

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, l3num, protonum, &tuple, l3proto,
			     l4proto)) {
		pr_debug("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	hash = hash_conntrack_raw(&tuple, zone);
	h = __nf_conntrack_find_get(net, zone, &tuple, hash);  //����tuple��hashֵ���ҵ��ں���tuple����
	if (!h) {
		h = init_conntrack(net, tmpl, &tuple, l3proto, l4proto,  //���δ�ҵ������½�nf_conn����
				   skb, dataoff, hash);
		if (!h)
			return NULL;
		if (IS_ERR(h))
			return (void *)h;
	}
	ct = nf_ct_tuplehash_to_ctrack(h);		//�ҵ�nf_conn����

	/* It exists; we have (non-exclusive) reference. */
	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
		*ctinfo = IP_CT_ESTABLISHED_REPLY;
		/* Please set reply bit if this packet OK */
		*set_reply = 1;
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: normal packet for %p\n", ct);
			*ctinfo = IP_CT_ESTABLISHED;
		} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: related packet for %p\n",
				 ct);
			*ctinfo = IP_CT_RELATED;
		} else {
			pr_debug("nf_conntrack_in: new packet for %p\n", ct);
			*ctinfo = IP_CT_NEW;
		}
		*set_reply = 0;
	}
	skb->nfct = &ct->ct_general;			//skb����nf_conn����
	skb->nfctinfo = *ctinfo;
	return ct;
}
```

�˽׶δ�����ɺ�����nf_conn������tuple��Ϣ���£�

```
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:192.168.0.102, sport:8080, dip:192.168.0.101, dport:1234}
   }
```

### Host2 NF_INET_PRE_ROUTING��NAT����

```c
static unsigned int iptable_nat_ipv4_in(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	return nf_nat_ipv4_in(ops, skb, state, iptable_nat_do_chain);
}

unsigned int
nf_nat_ipv4_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state,
					 struct nf_conn *ct))
{
	unsigned int ret;
	__be32 daddr = ip_hdr(skb)->daddr;

	ret = nf_nat_ipv4_fn(ops, skb, state, do_chain);
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    daddr != ip_hdr(skb)->daddr)	//���ı����ܣ�����Ŀ��IP��ַ�ı���
		skb_dst_drop(skb);		        //���skb��·����Ϣ����Ҫ�����µ�IP������·��

	return ret;
}

unsigned int
nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state,
					struct nf_conn *ct))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);

	/* We never see fragments: conntrack defrags on pre-routing
	 * and local-out, and nf_nat_out protects post-routing.
	 */
	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));

	ct = nf_ct_get(skb, &ctinfo);	//�ҵ����ĵ�CT����
	/* Can't track?  It's not due to stress, or conntrack would
	 * have dropped it.  Hence it's the user's responsibilty to
	 * packet filter it out, or implement conntrack/NAT for that
	 * protocol. 8) --RR
	 */
	if (!ct)			//�Ѿ���conntrackģ�飬���Ŀ϶���nf_conn����
		return NF_ACCEPT;

	/* Don't try to NAT if this packet is not conntracked */
	if (nf_ct_is_untracked(ct))
		return NF_ACCEPT;

	nat = nf_ct_nat_ext_add(ct); //���NAT��Ϣ��ֻ��δconfirmed��ct�����nat��չ��Ϣ����ʱct���ڷ�confirmed״̬
	if (nat == NULL)
		return NF_ACCEPT;	//���û��NAT��Ϣ����ʾ����δ��NAT��������Ҫ�޸�

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   ops->hooknum))
				return NF_DROP;
			else
				return NF_ACCEPT;
		}
		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
	case IP_CT_NEW:													    //���˷�֧
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {	 //��ʱδִ�й�NAT����������������
			unsigned int ret;

			ret = do_chain(ops, skb, state, ct);//iptable_nat_do_chain��ִ��nat���еĹ��򣬼���������DNAT����ִ��DNAT���������ջ����nf_nat_setup_info�޸�ct��reply tuple��Ϣ
			if (ret != NF_ACCEPT)
				return ret;

			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))  // ִ��DNAT���ˢ�´�״̬������������������ѭ��
				break;

			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);	
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			pr_debug("Already setup manip %s for ct %p\n",
				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
				 ct);
			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat,
					       state->out))
				goto oif_changed;
		}
		break;

	default:
		/* ESTABLISHED */
		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
			     ctinfo == IP_CT_ESTABLISHED_REPLY);
		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, state->out))
			goto oif_changed;
	}

	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);		//�޸�skb����

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}

unsigned int nf_nat_packet(struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo,
			   unsigned int hooknum,
			   struct sk_buff *skb)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned long statusbit;
	enum nf_nat_manip_type mtype = HOOK2MANIP(hooknum);		//��ǰΪNF_INET_PRE_ROUTING��mtypeΪDNAT

	if (mtype == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;
	else
		statusbit = IPS_DST_NAT;		//���˷�֧

	/* Invert if this is reply dir. */
	if (dir == IP_CT_DIR_REPLY)				//��ʱdirΪorigin�������˷�֧
		statusbit ^= IPS_NAT_MASK;

	/* Non-atomic: these bits don't change. */
	if (ct->status & statusbit) {		//��iptable_nat_do_chain�����֧�У����ct->status����IPS_DST_NAT��ǣ��˷�֧��������
		struct nf_conntrack_tuple target;

		/* We are aiming to look like inverse of other direction. */
		nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);	  //��reply���ģ�����һ����ת��tuple�����tuple��origin���ƣ����ǣ�

		l3proto = __nf_nat_l3proto_find(target.src.l3num);
		l4proto = __nf_nat_l4proto_find(target.src.l3num,
						target.dst.protonum);
		if (!l3proto->manip_pkt(skb, 0, l4proto, &target, mtype))		//ʵ�ʵ���nf_nat_ipv4_manip_pkt���޸ı���Ŀ��IP��ַ��Ŀ�Ķ˿�
			return NF_DROP;
	}
	return NF_ACCEPT;
}

static bool nf_nat_ipv4_manip_pkt(struct sk_buff *skb,
				  unsigned int iphdroff,
				  const struct nf_nat_l4proto *l4proto,
				  const struct nf_conntrack_tuple *target,
				  enum nf_nat_manip_type maniptype)
{
	struct iphdr *iph;
	unsigned int hdroff;

	if (!skb_make_writable(skb, iphdroff + sizeof(*iph)))
		return false;

	iph = (void *)skb->data + iphdroff;		//�õ�IPͷ
	hdroff = iphdroff + iph->ihl * 4;

	if (!l4proto->manip_pkt(skb, &nf_nat_l3proto_ipv4, iphdroff, hdroff,		//�޸�Ŀ�Ķ˿�
				target, maniptype))
		return false;
	iph = (void *)skb->data + iphdroff;

	if (maniptype == NF_NAT_MANIP_SRC) {	//��ǰΪNF_INET_PRE_ROUTING��maniptypeΪDNAT
		csum_replace4(&iph->check, iph->saddr, target->src.u3.ip);
		iph->saddr = target->src.u3.ip;	
	} else {
		csum_replace4(&iph->check, iph->daddr, target->dst.u3.ip);
		iph->daddr = target->dst.u3.ip;		//�޸ı���Ŀ��IP��ַ
	}
	return true;
}

//iptable_nat_do_chain���յ��ô˺����޸�tuple
unsigned int
nf_nat_setup_info(struct nf_conn *ct,
		  const struct nf_nat_range *range,
		  enum nf_nat_manip_type maniptype)
{
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_tuple curr_tuple, new_tuple;
	struct nf_conn_nat *nat;

	/* nat helper or nfctnetlink also setup binding */
	nat = nf_ct_nat_ext_add(ct);
	if (nat == NULL)
		return NF_ACCEPT;

	NF_CT_ASSERT(maniptype == NF_NAT_MANIP_SRC ||
		     maniptype == NF_NAT_MANIP_DST);
	BUG_ON(nf_nat_initialized(ct, maniptype));

	/* What we've got will look like inverse of reply. Normally
	 * this is what is in the conntrack, except for prior
	 * manipulations (future optimization: if num_manips == 0,
	 * orig_tp = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)
	 */
	nf_ct_invert_tuplepr(&curr_tuple,					//��reply����һ����ת��tuple����ʱcurr_tuple��origin tuple����ͬ��
			     &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	get_unique_tuple(&new_tuple, &curr_tuple, range, ct, maniptype);	//����target�����û�ȡһ������NATת��֮���IP��ַ�Ͷ˿���Ϣ

	if (!nf_ct_tuple_equal(&new_tuple, &curr_tuple)) {		//DNAT֮��new_tuple��dst�޸��ˣ�����������
		struct nf_conntrack_tuple reply;

		/* Alter conntrack table so will recognize replies. */
		nf_ct_invert_tuplepr(&reply, &new_tuple);			//��תnew_tuple���൱��reply��src�޸��ˣ� ��Ҳ��Ϊʲô������DNAT�� SNAT����Ҫ����
		nf_conntrack_alter_reply(ct, &reply);				//�޸�reply��tuple

		/* Non-atomic: we own this at the moment. */
		if (maniptype == NF_NAT_MANIP_SRC)
			ct->status |= IPS_SRC_NAT;				
		else
			ct->status |= IPS_DST_NAT;   //�������Ӹ��ٵ�DNAT��־

		if (nfct_help(ct))
			nfct_seqadj_ext_add(ct);
	}

	if (maniptype == NF_NAT_MANIP_SRC) {
		unsigned int srchash;

		srchash = hash_by_src(net, nf_ct_zone(ct),
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		spin_lock_bh(&nf_nat_lock);
		/* nf_conntrack_alter_reply might re-allocate extension aera */
		nat = nfct_nat(ct);	
		nat->ct = ct;
		hlist_add_head_rcu(&nat->bysource,
				   &net->ct.nat_bysource[srchash]);
		spin_unlock_bh(&nf_nat_lock);
	}

	/* It's done. */
	if (maniptype == NF_NAT_MANIP_DST)
		ct->status |= IPS_DST_NAT_DONE;		//����NAT_DONEλ��������conntrack�е�NAT��Ϣ�Ѿ��������
	else
		ct->status |= IPS_SRC_NAT_DONE;

	return NF_ACCEPT;
}

static void
get_unique_tuple(struct nf_conntrack_tuple *tuple,
		 const struct nf_conntrack_tuple *orig_tuple,
		 const struct nf_nat_range *range,
		 struct nf_conn *ct,
		 enum nf_nat_manip_type maniptype)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	struct net *net = nf_ct_net(ct);
	u16 zone = nf_ct_zone(ct);

	rcu_read_lock();
	l3proto = __nf_nat_l3proto_find(orig_tuple->src.l3num);
	l4proto = __nf_nat_l4proto_find(orig_tuple->src.l3num,
					orig_tuple->dst.protonum);

	/* 1) If this srcip/proto/src-proto-part is currently mapped,
	 * and that same mapping gives a unique tuple within the given
	 * range, use that.
	 *
	 * This is only required for source (ie. NAT/masq) mappings.
	 * So far, we don't do local source mappings, so multiple
	 * manips not an issue.
	 */
	if (maniptype == NF_NAT_MANIP_SRC &&
	    !(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
		/* try the original tuple first */
		if (in_range(l3proto, l4proto, orig_tuple, range)) {
			if (!nf_nat_used_tuple(orig_tuple, ct)) {
				*tuple = *orig_tuple;
				goto out;
			}
		} else if (find_appropriate_src(net, zone, l3proto, l4proto,
						orig_tuple, tuple, range)) {
			pr_debug("get_unique_tuple: Found current src map\n");
			if (!nf_nat_used_tuple(tuple, ct))
				goto out;
		}
	}

	/* 2) Select the least-used IP/proto combination in the given range */
	*tuple = *orig_tuple;		              //tuple��ֵreply�ķ�תtuple
	find_best_ips_proto(zone, tuple, range, ct, maniptype);    //����IP��Χ���޸�tuple

	/* 3) The per-protocol part of the manip is made to map into
	 * the range to make a unique tuple.
	 */

	/* Only bother mapping if it's not already in range and unique */
	if (!(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
		if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
			if (l4proto->in_range(tuple, maniptype,
					      &range->min_proto,
					      &range->max_proto) &&
			    (range->min_proto.all == range->max_proto.all ||
			     !nf_nat_used_tuple(tuple, ct)))
				goto out;
		} else if (!nf_nat_used_tuple(tuple, ct)) {
			goto out;
		}
	}

	/* Last change: get protocol to try to obtain unique tuple. */
	l4proto->unique_tuple(l3proto, tuple, range, maniptype, ct);		//�޸Ķ˿�
out:
	rcu_read_unlock();
}

static void
find_best_ips_proto(u16 zone, struct nf_conntrack_tuple *tuple,
		    const struct nf_nat_range *range,
		    const struct nf_conn *ct,
		    enum nf_nat_manip_type maniptype)
{
	union nf_inet_addr *var_ipp;
	unsigned int i, max;
	/* Host order */
	u32 minip, maxip, j, dist;
	bool full_range;

	/* No IP mapping?  Do nothing. */
	if (!(range->flags & NF_NAT_RANGE_MAP_IPS))
		return;

	if (maniptype == NF_NAT_MANIP_SRC)			//��ǰΪDNAT
		var_ipp = &tuple->src.u3;
	else
		var_ipp = &tuple->dst.u3;	//DNAT�׶Σ�reply�ķ�תtuple��dst��Ϊorgin��dst����DNAT�޸ĵ����ݣ�������е��ƣ��൱�ڸ���origin����dst�޸���

	/* Fast path: only one choice. */
	if (nf_inet_addr_cmp(&range->min_addr, &range->max_addr)) {
		*var_ipp = range->min_addr;
		return;
	}

	if (nf_ct_l3num(ct) == NFPROTO_IPV4)
		max = sizeof(var_ipp->ip) / sizeof(u32) - 1;
	else
		max = sizeof(var_ipp->ip6) / sizeof(u32) - 1;

	/* Hashing source and destination IPs gives a fairly even
	 * spread in practice (if there are a small number of IPs
	 * involved, there usually aren't that many connections
	 * anyway).  The consistency means that servers see the same
	 * client coming from the same IP (some Internet Banking sites
	 * like this), even across reboots.
	 */
	j = jhash2((u32 *)&tuple->src.u3, sizeof(tuple->src.u3) / sizeof(u32),
		   range->flags & NF_NAT_RANGE_PERSISTENT ?
			0 : (__force u32)tuple->dst.u3.all[max] ^ zone);

	full_range = false;
	for (i = 0; i <= max; i++) {
		/* If first bytes of the address are at the maximum, use the
		 * distance. Otherwise use the full range.
		 */
		if (!full_range) {
			minip = ntohl((__force __be32)range->min_addr.all[i]);
			maxip = ntohl((__force __be32)range->max_addr.all[i]);
			dist  = maxip - minip + 1;
		} else {
			minip = 0;
			dist  = ~0;
		}

		var_ipp->all[i] = (__force __u32)
			htonl(minip + reciprocal_scale(j, dist));
		if (var_ipp->all[i] != range->max_addr.all[i])
			full_range = true;

		if (!(range->flags & NF_NAT_RANGE_PERSISTENT))
			j ^= (__force u32)tuple->dst.u3.all[i];
	}
}
```

�˽׶δ�����ɺ�nf_conn�����reply tuple���޸��ˣ���ǰskbҲ���޸��ˣ�����Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

�ں˼���IP���հ������ֱ��ĵ�Ŀ��IP���Ǳ��ڵ㣬��ip_forward��֧�������뵽NF_INET_POST_ROUTING hook��

### Host2 NF_INET_POST_ROUTING��NAT����

```c
static unsigned int iptable_nat_ipv4_out(const struct nf_hook_ops *ops,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	return nf_nat_ipv4_out(ops, skb, state, iptable_nat_do_chain);
}

unsigned int
nf_nat_ipv4_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
		const struct nf_hook_state *state,
		unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					  struct sk_buff *skb,
					  const struct nf_hook_state *state,
					  struct nf_conn *ct))
{
#ifdef CONFIG_XFRM
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int err;
#endif
	unsigned int ret;

	/* root is playing with raw sockets. */
	if (skb->len < sizeof(struct iphdr) ||
	    ip_hdrlen(skb) < sizeof(struct iphdr))
		return NF_ACCEPT;

	ret = nf_nat_ipv4_fn(ops, skb, state, do_chain);
#ifdef CONFIG_XFRM
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    !(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);

		if ((ct->tuplehash[dir].tuple.src.u3.ip !=
		     ct->tuplehash[!dir].tuple.dst.u3.ip) ||
		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
		     ct->tuplehash[dir].tuple.src.u.all !=
		     ct->tuplehash[!dir].tuple.dst.u.all)) {
			err = nf_xfrm_me_harder(skb, AF_INET);
			if (err < 0)
				ret = NF_DROP_ERR(err);
		}
	}
#endif
	return ret;
}

unsigned int
nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state,
					struct nf_conn *ct))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);

	/* We never see fragments: conntrack defrags on pre-routing
	 * and local-out, and nf_nat_out protects post-routing.
	 */
	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));

	ct = nf_ct_get(skb, &ctinfo);		//�ҵ����ĵ�CT����
	/* Can't track?  It's not due to stress, or conntrack would
	 * have dropped it.  Hence it's the user's responsibilty to
	 * packet filter it out, or implement conntrack/NAT for that
	 * protocol. 8) --RR
	 */
	if (!ct)			//����conntrackģ�飬���Ŀ϶���nf_conn����
		return NF_ACCEPT;

	/* Don't try to NAT if this packet is not conntracked */
	if (nf_ct_is_untracked(ct))
		return NF_ACCEPT;

	nat = nf_ct_nat_ext_add(ct);	//�ҵ�NAT��Ϣ����ʱct�Ѿ�����nat��Ϣ��ǰһ�׶ε�DNAT��
	if (nat == NULL)
		return NF_ACCEPT;

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   ops->hooknum))
				return NF_DROP;
			else
				return NF_ACCEPT;
		}
		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {		//��ǰ��POSTROUTING��ִ�е���SNAT�����������㣨ǰһ�׶���DNAT��
			unsigned int ret;

			ret = do_chain(ops, skb, state, ct);		//iptable_nat_do_chain������nat���е�snat���򣬴�ʱδ����snat����
			if (ret != NF_ACCEPT)
				return ret;

			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))  //��Ϊδ����snat�����Դ�����������
				break;

			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);		//�޸�reply tuple
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			pr_debug("Already setup manip %s for ct %p\n",
				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
				 ct);
			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat,
					       state->out))
				goto oif_changed;
		}
		break;

	default:
		/* ESTABLISHED */
		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
			     ctinfo == IP_CT_ESTABLISHED_REPLY);
		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, state->out))
			goto oif_changed;
	}

	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);		//�޸�skb����

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}

static unsigned int
__nf_nat_alloc_null_binding(struct nf_conn *ct, enum nf_nat_manip_type manip)
{
	/* Force range to this IP; let proto decide mapping for
	 * per-proto parts (hence not IP_NAT_RANGE_PROTO_SPECIFIED).
	 * Use reply in case it's already been mangled (eg local packet).
	 */
	union nf_inet_addr ip =
		(manip == NF_NAT_MANIP_SRC ?
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3 :		//��ǰ���˷�֧��ip��ַΪreply��dst���൱��origin��src��û��SNAT��������������ֵ����ͬ�ģ�
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3);
	struct nf_nat_range range = {
		.flags		= NF_NAT_RANGE_MAP_IPS,
		.min_addr	= ip,
		.max_addr	= ip,
	};
	return nf_nat_setup_info(ct, &range, manip);			//׼���޸�tuple��ʵ����Ϊû���޸�ԴIP�����Դ�ʱ��û���޸�tuple
}

unsigned int
nf_nat_setup_info(struct nf_conn *ct,
		  const struct nf_nat_range *range,
		  enum nf_nat_manip_type maniptype)
{
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_tuple curr_tuple, new_tuple;
	struct nf_conn_nat *nat;

	/* nat helper or nfctnetlink also setup binding */
	nat = nf_ct_nat_ext_add(ct);
	if (nat == NULL)
		return NF_ACCEPT;

	NF_CT_ASSERT(maniptype == NF_NAT_MANIP_SRC ||
		     maniptype == NF_NAT_MANIP_DST);
	BUG_ON(nf_nat_initialized(ct, maniptype));

	/* What we've got will look like inverse of reply. Normally
	 * this is what is in the conntrack, except for prior
	 * manipulations (future optimization: if num_manips == 0,
	 * orig_tp = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)
	 */
	nf_ct_invert_tuplepr(&curr_tuple,					//��reply����һ����ת��tuple����ʱcurr_tuple��origin tuple��src����ͬ��dst��ͬ��DNAT����
			     &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	get_unique_tuple(&new_tuple, &curr_tuple, range, ct, maniptype);	//����target�����û�ȡһ������NATת��֮���IP��ַ�Ͷ˿���Ϣ��ʵ�ʲ�û���޸�

	if (!nf_ct_tuple_equal(&new_tuple, &curr_tuple)) {		//����û��SDNAT��new_tuple��curr_tuple��ͬ���˷�֧����������
		struct nf_conntrack_tuple reply;

		/* Alter conntrack table so will recognize replies. */
		nf_ct_invert_tuplepr(&reply, &new_tuple);			
		nf_conntrack_alter_reply(ct, &reply);

		/* Non-atomic: we own this at the moment. */
		if (maniptype == NF_NAT_MANIP_SRC)
			ct->status |= IPS_SRC_NAT;
		else
			ct->status |= IPS_DST_NAT;

		if (nfct_help(ct))
			nfct_seqadj_ext_add(ct);
	}

	if (maniptype == NF_NAT_MANIP_SRC) {
		unsigned int srchash;

		srchash = hash_by_src(net, nf_ct_zone(ct),
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		spin_lock_bh(&nf_nat_lock);
		/* nf_conntrack_alter_reply might re-allocate extension aera */
		nat = nfct_nat(ct);	
		nat->ct = ct;
		hlist_add_head_rcu(&nat->bysource,
				   &net->ct.nat_bysource[srchash]);
		spin_unlock_bh(&nf_nat_lock);
	}

	/* It's done. */
	if (maniptype == NF_NAT_MANIP_DST)
		ct->status |= IPS_DST_NAT_DONE;		//����NAT_DONEλ��������conntrack�е�NAT��Ϣ�Ѿ��������
	else
		ct->status |= IPS_SRC_NAT_DONE;

	return NF_ACCEPT;
}
```

�˽׶δ�����ɺ�nf_conn�����tuple��Ϣ�ޱ仯����Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

### Host2 NF_INET_POST_ROUTING��CT����

```c
static unsigned int ipv4_confirm(const struct nf_hook_ops *ops,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		goto out;

	/* adjust seqs for loopback traffic only in outgoing direction */
	if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) &&
	    !nf_is_loopback_packet(skb)) {
		if (!nf_ct_seq_adjust(skb, ct, ctinfo, ip_hdrlen(skb))) {
			NF_CT_STAT_INC_ATOMIC(nf_ct_net(ct), drop);
			return NF_DROP;
		}
	}
out:
	/* We've seen it coming out the other side: confirm it */
	return nf_conntrack_confirm(skb);  //ȷ��CT
}

/* Confirm a connection: returns NF_DROP if packet must be dropped. */
static inline int nf_conntrack_confirm(struct sk_buff *skb)
{
	struct nf_conn *ct = (struct nf_conn *)skb->nfct;
	int ret = NF_ACCEPT;

	if (ct && !nf_ct_is_untracked(ct)) {
		if (!nf_ct_is_confirmed(ct))            //���δȷ�ϣ������ȷ��
			ret = __nf_conntrack_confirm(skb);	//ȷ��CT
		if (likely(ret == NF_ACCEPT))
			nf_ct_deliver_cached_events(ct);
	}
	return ret;
}

```

�˽׶δ�����ɺ�nf_conn�����tuple��Ϣ�ޱ仯����Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

����ת�����������������ձ��ĺ󣬷�����Ӧ���ģ�sip:10.10.1.5, sport:80, dip:192.168.0.101, dport:1234��

Host2�ں��յ�����ʱ������ip���հ��󣬻��Ƚ���NF_INET_PRE_ROUTING��

### Host2 NF_INET_PRE_ROUTING��CT����

```c
static unsigned int ipv4_conntrack_in(const struct nf_hook_ops *ops,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	return nf_conntrack_in(dev_net(state->in), PF_INET, ops->hooknum, skb);
}

unsigned int
nf_conntrack_in(struct net *net, u_int8_t pf, unsigned int hooknum,
		struct sk_buff *skb)
{
	struct nf_conn *ct, *tmpl = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int *timeouts;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;

	if (skb->nfct) {		//��ʱskbΪ��
		/* Previously seen (loopback or untracked)?  Ignore. */
		tmpl = (struct nf_conn *)skb->nfct;
		if (!nf_ct_is_template(tmpl)) {
			NF_CT_STAT_INC_ATOMIC(net, ignore);
			return NF_ACCEPT;
		}
		skb->nfct = NULL;
	}

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find(pf);				//�ҵ�����Э��
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb),
				   &dataoff, &protonum);
	if (ret <= 0) {
		pr_debug("not prepared to track yet or error occurred\n");
		NF_CT_STAT_INC_ATOMIC(net, error);
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = -ret;
		goto out;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);		//�ҵ��Ĳ�Э��

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL) {
		ret = l4proto->error(net, tmpl, skb, dataoff, &ctinfo,
				     pf, hooknum);
		if (ret <= 0) {
			NF_CT_STAT_INC_ATOMIC(net, error);
			NF_CT_STAT_INC_ATOMIC(net, invalid);
			ret = -ret;
			goto out;
		}
		/* ICMP[v6] protocol trackers may assign one conntrack. */
		if (skb->nfct)
			goto out;
	}

	ct = resolve_normal_ct(net, tmpl, skb, dataoff, pf, protonum,    //��ʱ�ܹ��ҵ�ct����ct��replyƥ��
			       l3proto, l4proto, &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = NF_ACCEPT;
		goto out;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = NF_DROP;
		goto out;
	}

	NF_CT_ASSERT(skb->nfct);

	/* Decide what timeout policy we want to apply to this flow. */
	timeouts = nf_ct_timeout_lookup(net, ct, l4proto);

	ret = l4proto->packet(ct, skb, dataoff, ctinfo, pf, hooknum, timeouts);
	if (ret <= 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		pr_debug("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put(skb->nfct);
		skb->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		if (ret == -NF_DROP)
			NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = -ret;
		goto out;
	}

	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status))	
		nf_conntrack_event_cache(IPCT_REPLY, ct);
out:
	if (tmpl) {
		/* Special case: we have to repeat this hook, assign the
		 * template again to this packet. We assume that this packet
		 * has no conntrack assigned. This is used by nf_ct_tcp. */
		if (ret == NF_REPEAT)
			skb->nfct = (struct nf_conntrack *)tmpl;
		else
			nf_ct_put(tmpl);
	}

	return ret;
}
```

�˽׶δ�����ɺ�nf_conn�����tuple��Ϣ�ޱ仯����Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

### Host2 NF_INET_PRE_ROUTING��NAT����
```c
static unsigned int iptable_nat_ipv4_in(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	return nf_nat_ipv4_in(ops, skb, state, iptable_nat_do_chain);
}

unsigned int
nf_nat_ipv4_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state,
					 struct nf_conn *ct))
{
	unsigned int ret;
	__be32 daddr = ip_hdr(skb)->daddr;

	ret = nf_nat_ipv4_fn(ops, skb, state, do_chain);
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    daddr != ip_hdr(skb)->daddr)
		skb_dst_drop(skb);

	return ret;
}

unsigned int
nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state,
					struct nf_conn *ct))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);

	/* We never see fragments: conntrack defrags on pre-routing
	 * and local-out, and nf_nat_out protects post-routing.
	 */
	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));

	ct = nf_ct_get(skb, &ctinfo);		//�ҵ����ĵ�CT����
	/* Can't track?  It's not due to stress, or conntrack would
	 * have dropped it.  Hence it's the user's responsibilty to
	 * packet filter it out, or implement conntrack/NAT for that
	 * protocol. 8) --RR
	 */
	if (!ct)			//����conntrackģ�飬���Ŀ϶���nf_conn����
		return NF_ACCEPT;

	/* Don't try to NAT if this packet is not conntracked */
	if (nf_ct_is_untracked(ct))
		return NF_ACCEPT;

	nat = nf_ct_nat_ext_add(ct);	//ct�Ѱ���nat��Ϣ
	if (nat == NULL)
		return NF_ACCEPT;

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   ops->hooknum))
				return NF_DROP;
			else
				return NF_ACCEPT;
		}
		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {
			unsigned int ret;

			ret = do_chain(ops, skb, state, ct);
			if (ret != NF_ACCEPT)
				return ret;

			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum))) 
				break;

			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			pr_debug("Already setup manip %s for ct %p\n",
				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
				 ct);
			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat,
					       state->out))
				goto oif_changed;
		}
		break;

	default:
		/* ESTABLISHED */
		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||							//���˷�֧����ǰ��ƥ�䵽����ct��reply tuple
			     ctinfo == IP_CT_ESTABLISHED_REPLY);
		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, state->out))
			goto oif_changed;
	}

	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);		//�޸�skb����

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}

/* Do packet manipulations according to nf_nat_setup_info. */
unsigned int nf_nat_packet(struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo,
			   unsigned int hooknum,
			   struct sk_buff *skb)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned long statusbit;
	enum nf_nat_manip_type mtype = HOOK2MANIP(hooknum);		//NF_INET_PRE_ROUTING�㣬ִ��DNAT

	if (mtype == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;
	else
		statusbit = IPS_DST_NAT;			//���˷�֧

	/* Invert if this is reply dir. */
	if (dir == IP_CT_DIR_REPLY)					//��ǰdirΪreply��statusbit��SNAT���DNAT��ԭ����DNAT�ı����SNAT
		statusbit ^= IPS_NAT_MASK;				//statusbitΪIPS_SRC_NAT

	/* Non-atomic: these bits don't change. */
	if (ct->status & statusbit) {				//Ҫִ��SNAT����������CTδ����SNAT��ǣ����Դ˷�֧��������ֱ�ӷ���
		struct nf_conntrack_tuple target;

		/* We are aiming to look like inverse of other direction. */
		nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);

		l3proto = __nf_nat_l3proto_find(target.src.l3num);
		l4proto = __nf_nat_l4proto_find(target.src.l3num,
						target.dst.protonum);
		if (!l3proto->manip_pkt(skb, 0, l4proto, &target, mtype))
			return NF_DROP;
	}
	return NF_ACCEPT;
}

```

�˽׶δ�����ɺ�nf_conn�����tuple��Ϣ�ޱ仯��skb�ޱ仯����Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

�˹����У����Ĳ�δ���޸ģ� �ں˼���IP���հ������ֱ��ĵ�Ŀ��IP���Ǳ��ڵ㣬��ip_forward��֧�������뵽NF_INET_POST_ROUTING

### Host2 NF_INET_POST_ROUTING��NAT����

```c
static unsigned int iptable_nat_ipv4_out(const struct nf_hook_ops *ops,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	return nf_nat_ipv4_out(ops, skb, state, iptable_nat_do_chain);
}

unsigned int
nf_nat_ipv4_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
		const struct nf_hook_state *state,
		unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					  struct sk_buff *skb,
					  const struct nf_hook_state *state,
					  struct nf_conn *ct))
{
#ifdef CONFIG_XFRM
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int err;
#endif
	unsigned int ret;

	/* root is playing with raw sockets. */
	if (skb->len < sizeof(struct iphdr) ||
	    ip_hdrlen(skb) < sizeof(struct iphdr))
		return NF_ACCEPT;

	ret = nf_nat_ipv4_fn(ops, skb, state, do_chain);
#ifdef CONFIG_XFRM
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    !(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);

		if ((ct->tuplehash[dir].tuple.src.u3.ip !=
		     ct->tuplehash[!dir].tuple.dst.u3.ip) ||
		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
		     ct->tuplehash[dir].tuple.src.u.all !=
		     ct->tuplehash[!dir].tuple.dst.u.all)) {
			err = nf_xfrm_me_harder(skb, AF_INET);
			if (err < 0)
				ret = NF_DROP_ERR(err);
		}
	}
#endif
	return ret;
}

unsigned int
nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct nf_hook_state *state,
					struct nf_conn *ct))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);

	/* We never see fragments: conntrack defrags on pre-routing
	 * and local-out, and nf_nat_out protects post-routing.
	 */
	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));

	ct = nf_ct_get(skb, &ctinfo);		//�ҵ����ĵ�CT����
	/* Can't track?  It's not due to stress, or conntrack would
	 * have dropped it.  Hence it's the user's responsibilty to
	 * packet filter it out, or implement conntrack/NAT for that
	 * protocol. 8) --RR
	 */
	if (!ct)			//����conntrackģ�飬���Ŀ϶���nf_conn����
		return NF_ACCEPT;

	/* Don't try to NAT if this packet is not conntracked */
	if (nf_ct_is_untracked(ct))
		return NF_ACCEPT;

	nat = nf_ct_nat_ext_add(ct);	//�ҵ�NAT��Ϣ��CT�Ѱ���NAT��Ϣ
	if (nat == NULL)
		return NF_ACCEPT;

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   ops->hooknum))
				return NF_DROP;
			else
				return NF_ACCEPT;
		}
		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {
			unsigned int ret;

			ret = do_chain(ops, skb, state, ct);
			if (ret != NF_ACCEPT)
				return ret;

			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))
				break;

			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			pr_debug("Already setup manip %s for ct %p\n",
				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
				 ct);
			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat,
					       state->out))
				goto oif_changed;
		}
		break;

	default:
		/* ESTABLISHED */
		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||			//���˷�֧����ǰ��ƥ�䵽����ct��reply
			     ctinfo == IP_CT_ESTABLISHED_REPLY);
		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, state->out))
			goto oif_changed;
	}

	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);		//�޸�skb����

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}

unsigned int nf_nat_packet(struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo,
			   unsigned int hooknum,
			   struct sk_buff *skb)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned long statusbit;
	enum nf_nat_manip_type mtype = HOOK2MANIP(hooknum);		//��ǰ��NF_INET_POST_ROUTING�㣬ִ��SNAT

	if (mtype == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;		    //���˷�֧
	else
		statusbit = IPS_DST_NAT;

	/* Invert if this is reply dir. */
	if (dir == IP_CT_DIR_REPLY)                 //��ǰdirΪreply��statusbit��SNAT���DNAT��ԭ����DNAT�ı����SNAT
		statusbit ^= IPS_NAT_MASK;	           //statusbitΪIPS_DST_NAT

	/* Non-atomic: these bits don't change. */
	if (ct->status & statusbit) {					//ct�����ΪDNAT������������
		struct nf_conntrack_tuple target;

		/* We are aiming to look like inverse of other direction. */
		nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);	    //ʹ��origin tuple�ķ�תtuple

		l3proto = __nf_nat_l3proto_find(target.src.l3num);
		l4proto = __nf_nat_l4proto_find(target.src.l3num,
						target.dst.protonum);
		if (!l3proto->manip_pkt(skb, 0, l4proto, &target, mtype))		//�޸ı���ԴIP��ַ��Դ�˿�
			return NF_DROP;
	}
	return NF_ACCEPT;
}

static bool nf_nat_ipv4_manip_pkt(struct sk_buff *skb,
				  unsigned int iphdroff,
				  const struct nf_nat_l4proto *l4proto,
				  const struct nf_conntrack_tuple *target,
				  enum nf_nat_manip_type maniptype)
{
	struct iphdr *iph;
	unsigned int hdroff;

	if (!skb_make_writable(skb, iphdroff + sizeof(*iph)))
		return false;

	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;

	if (!l4proto->manip_pkt(skb, &nf_nat_l3proto_ipv4, iphdroff, hdroff,
				target, maniptype))
		return false;
	iph = (void *)skb->data + iphdroff;

	if (maniptype == NF_NAT_MANIP_SRC) {
		csum_replace4(&iph->check, iph->saddr, target->src.u3.ip);
		iph->saddr = target->src.u3.ip;			    //���˷�֧��ʹ��origin tuple�ķ�תtuple��ԴIP��ַ����192.168.0.102
	} else {
		csum_replace4(&iph->check, iph->daddr, target->dst.u3.ip);
		iph->daddr = target->dst.u3.ip;	
	}
	return true;
}

```

�˽׶δ�����ɺ�nf_conn�����tuple��Ϣ�ޱ仯��skbִ����SNAT�����������õ�DNAT��Ӧ������Ϣ���£�

```bash
CT { 
   orign {sip:192.168.0.101, sport:1234, dip:192.168.0.102, dport:8080} 
   reply {sip:10.10.1.5,     sport:80,   dip:192.168.0.101, dport:1234}
   }
```

���ˣ����սڵ��CT��NAT���������Ѿ���ɣ��������̱Ƚ��ƣ��ܽ����£�

* CT��tupleֻ���޸�һ�Σ��޸ķ�����origin�����NAT����ʱ
* ��PREROUTING��������DNAT������POSTROUTING��ִ��SNAT

