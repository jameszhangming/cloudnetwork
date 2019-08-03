# OVS数据面action处理

本文介绍内核态OVS数据面actin执行流程。


# ovs_execute_actions(入口)

```c
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct sw_flow_actions *acts,
			struct sw_flow_key *key)
{
	int level = this_cpu_read(exec_actions_level);
	int err;

	if (unlikely(level >= EXEC_ACTIONS_LEVEL_LIMIT)) {
		if (net_ratelimit())
			pr_warn("%s: packet loop detected, dropping.\n",
				ovs_dp_name(dp));

		kfree_skb(skb);
		return -ELOOP;
	}

	this_cpu_inc(exec_actions_level);
	err = do_execute_actions(dp, skb, key,
				 acts->actions, acts->actions_len);

	if (!level)
		process_deferred_actions(dp);

	this_cpu_dec(exec_actions_level);

	/* This return status currently does not reflect the errors
	 * encounted during deferred actions execution. Probably needs to
	 * be fixed in the future.
	 */
	return err;
}

static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that.
	 */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		if (unlikely(prev_port != -1)) {
			struct sk_buff *out_skb = skb_clone(skb, GFP_ATOMIC);

			if (out_skb)
				do_output(dp, out_skb, prev_port, key);

			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, key, a, attr, len);
			break;

		case OVS_ACTION_ATTR_HASH:
			execute_hash(skb, key, a);
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS:
			err = push_mpls(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_MPLS:
			err = pop_mpls(skb, key, nla_get_be16(a));
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb, key);
			break;

		case OVS_ACTION_ATTR_RECIRC:
			err = execute_recirc(dp, skb, key, a, rem);
			if (nla_is_last(a, rem)) {
				/* If this is the last action, the skb has
				 * been consumed or freed.
				 * Return immediately.
				 */
				return err;
			}
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
			err = execute_masked_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, key, a, attr, len);
			break;

		case OVS_ACTION_ATTR_CT:
			if (!is_flow_key_valid(key)) {
				err = ovs_flow_key_update(skb, key);
				if (err)
					return err;
			}

			err = ovs_ct_execute(ovs_dp_get_net(dp), skb, key,
					     nla_data(a));

			/* Hide stolen IP fragments from user space. */
			if (err)
				return err == -EINPROGRESS ? 0 : err;
			break;
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1)
		do_output(dp, skb, prev_port, key);
	else
		consume_skb(skb);

	return 0;
}
```


# do_output

```c
static void do_output(struct datapath *dp, struct sk_buff *skb, int out_port,
		      struct sw_flow_key *key)
{
	struct vport *vport = ovs_vport_rcu(dp, out_port);

	if (likely(vport)) {
		u16 mru = OVS_CB(skb)->mru;

		if (likely(!mru || (skb->len <= mru + ETH_HLEN))) {
			ovs_vport_send(vport, skb);
		} else if (mru <= vport->dev->mtu) {
			__be16 ethertype = key->eth.type;

			if (!is_flow_key_valid(key)) {
				if (eth_p_mpls(skb->protocol))
					ethertype = ovs_skb_get_inner_protocol(skb);
				else
					ethertype = vlan_get_protocol(skb);
			}

			ovs_fragment(vport, skb, mru, ethertype);
		} else {
			OVS_NLERR(true, "Cannot fragment IP frames");
			kfree_skb(skb);
		}
	} else {
		kfree_skb(skb);
	}
}
```


## ovs_vport_send

```c
void ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
	int mtu = vport->dev->mtu;

	if (unlikely(packet_length(skb) > mtu && !skb_is_gso(skb))) {
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     vport->dev->name,
				     packet_length(skb), mtu);
		vport->dev->stats.tx_errors++;
		goto drop;
	}

	skb->dev = vport->dev;
	vport->ops->send(skb);       //调用vport_class的send方法
	return;

drop:
	kfree_skb(skb);
}

```


# output_userspace

```c
static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    struct sw_flow_key *key, const struct nlattr *attr,
			    const struct nlattr *actions, int actions_len)
{
	struct ip_tunnel_info info;
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	memset(&upcall, 0, sizeof(upcall));
	upcall.cmd = OVS_PACKET_CMD_ACTION;    //upcall类型
	upcall.mru = OVS_CB(skb)->mru;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;

		case OVS_USERSPACE_ATTR_EGRESS_TUN_PORT: {
			/* Get out tunnel info. */
			struct vport *vport;

			vport = ovs_vport_rcu(dp, nla_get_u32(a));
			if (vport) {
				int err;

				upcall.egress_tun_info = &info;
				err = ovs_vport_get_egress_tun_info(vport, skb,
								    &upcall);
				if (err)
					upcall.egress_tun_info = NULL;
			}

			break;
		}

		case OVS_USERSPACE_ATTR_ACTIONS: {
			/* Include actions. */
			upcall.actions = actions;
			upcall.actions_len = actions_len;
			break;
		}

		} /* End of switch. */
	}

	return ovs_dp_upcall(dp, skb, key, &upcall);   //调用upcall，发送到用户态
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
		err = queue_userspace_packet(dp, skb, key, upcall_info);
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


# execute_hash

```c
static void execute_hash(struct sk_buff *skb, struct sw_flow_key *key,
			 const struct nlattr *attr)
{
	struct ovs_action_hash *hash_act = nla_data(attr);
	u32 hash = 0;

	/* OVS_HASH_ALG_L4 is the only possible hash algorithm.  */
	hash = skb_get_hash(skb);
	hash = jhash_1word(hash, hash_act->hash_basis);
	if (!hash)
		hash = 0x1;

	key->ovs_flow_hash = hash;
}
```


# push_vlan

```c
static int push_vlan(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_action_push_vlan *vlan)
{
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = vlan->vlan_tci;
	return skb_vlan_push(skb, vlan->vlan_tpid,
			     ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
}
```


# pop_vlan

```c
static int pop_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	int err;

	err = skb_vlan_pop(skb);
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = 0;
	return err;
}
```


# execute_recirc

```c
static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
			  struct sw_flow_key *key,
			  const struct nlattr *a, int rem)
{
	struct deferred_action *da;

	if (!is_flow_key_valid(key)) {
		int err;

		err = ovs_flow_key_update(skb, key);
		if (err)
			return err;
	}
	BUG_ON(!is_flow_key_valid(key));

	if (!nla_is_last(a, rem)) {
		/* Recirc action is the not the last action
		 * of the action list, need to clone the skb.
		 */
		skb = skb_clone(skb, GFP_ATOMIC);

		/* Skip the recirc action when out of memory, but
		 * continue on with the rest of the action list.
		 */
		if (!skb)
			return 0;
	}

	da = add_deferred_actions(skb, key, NULL);
	if (da) {
		da->pkt_key.recirc_id = nla_get_u32(a);
	} else {
		kfree_skb(skb);

		if (net_ratelimit())
			pr_warn("%s: deferred action limit reached, drop recirc action\n",
				ovs_dp_name(dp));
	}

	return 0;
}
```

# execute_set_action

```c
static int execute_set_action(struct sk_buff *skb,
			      struct sw_flow_key *flow_key,
			      const struct nlattr *a)
{
	/* Only tunnel set execution is supported without a mask. */
	if (nla_type(a) == OVS_KEY_ATTR_TUNNEL_INFO) {
		struct ovs_tunnel_info *tun = nla_data(a);

		ovs_skb_dst_drop(skb);
		ovs_dst_hold((struct dst_entry *)tun->tun_dst);
		ovs_skb_dst_set(skb, (struct dst_entry *)tun->tun_dst);
		return 0;
	}

	return -EINVAL;
}
```


# execute_masked_set_action

```c
static int execute_masked_set_action(struct sk_buff *skb,
				     struct sw_flow_key *flow_key,
				     const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY:
		OVS_SET_MASKED(skb->priority, nla_get_u32(a),
			       *get_mask(a, u32 *));
		flow_key->phy.priority = skb->priority;
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		OVS_SET_MASKED(skb->mark, nla_get_u32(a), *get_mask(a, u32 *));
		flow_key->phy.skb_mark = skb->mark;
		break;

	case OVS_KEY_ATTR_TUNNEL_INFO:
		/* Masked data not supported for tunnel. */
		err = -EINVAL;
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, flow_key, nla_data(a),
				   get_mask(a, struct ovs_key_ethernet *));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv4 *));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv6 *));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_tcp *));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_udp *));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_sctp *));
		break;

	case OVS_KEY_ATTR_MPLS:
		err = set_mpls(skb, flow_key, nla_data(a), get_mask(a,
								    __be32 *));
		break;

	case OVS_KEY_ATTR_CT_STATE:
	case OVS_KEY_ATTR_CT_ZONE:
	case OVS_KEY_ATTR_CT_MARK:
	case OVS_KEY_ATTR_CT_LABELS:
		err = -EINVAL;
		break;
	}

	return err;
}
```


# sample

```c
static int sample(struct datapath *dp, struct sk_buff *skb,
		  struct sw_flow_key *key, const struct nlattr *attr,
		  const struct nlattr *actions, int actions_len)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		u32 probability;

		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			probability = nla_get_u32(a);
			if (!probability || prandom_u32() > probability)
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	rem = nla_len(acts_list);
	a = nla_data(acts_list);

	/* Actions list is empty, do nothing */
	if (unlikely(!rem))
		return 0;

	/* The only known usage of sample action is having a single user-space
	 * action. Treat this usage as a special case.
	 * The output_userspace() should clone the skb to be sent to the
	 * user space. This skb will be consumed by its caller.
	 */
	if (likely(nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
		   nla_is_last(a, rem)))
		return output_userspace(dp, skb, key, a, actions, actions_len);

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		/* Skip the sample action when out of memory. */
		return 0;

	if (!add_deferred_actions(skb, key, a)) {
		if (net_ratelimit())
			pr_warn("%s: deferred actions limit reached, dropping sample action\n",
				ovs_dp_name(dp));

		kfree_skb(skb);
	}
	return 0;
}
```


# ovs_ct_execute

```c
int ovs_ct_execute(struct net *net, struct sk_buff *skb,
		   struct sw_flow_key *key,
		   const struct ovs_conntrack_info *info)
{
	int nh_ofs;
	int err;

	/* The conntrack module expects to be working at L3. */
	nh_ofs = skb_network_offset(skb);
	skb_pull(skb, nh_ofs);

	if (key->ip.frag != OVS_FRAG_TYPE_NONE) {
		err = handle_fragments(net, key, info->zone.id, skb);
		if (err)
			return err;
	}

	if (info->commit)
		err = ovs_ct_commit(net, key, info, skb);
	else
		err = ovs_ct_lookup(net, key, info, skb);
	if (err)
		goto err;

	if (info->mark.mask) {
		err = ovs_ct_set_mark(skb, key, info->mark.value,
				      info->mark.mask);
		if (err)
			goto err;
	}
	if (labels_nonzero(&info->labels.mask))
		err = ovs_ct_set_labels(skb, key, &info->labels.value,
					&info->labels.mask);
err:
	skb_push(skb, nh_ofs);
	if (err)
		kfree_skb(skb);
	return err;
}
```


## ovs_ct_commit

```c
static int ovs_ct_commit(struct net *net, struct sw_flow_key *key,
			 const struct ovs_conntrack_info *info,
			 struct sk_buff *skb)
{
	u8 state;
	int err;

	state = key->ct.state;
	if (key->ct.zone == info->zone.id &&
	    ((state & OVS_CS_F_TRACKED) && !(state & OVS_CS_F_NEW))) {
		/* Previous lookup has shown that this connection is already
		 * tracked and committed. Skip committing.
		 */
		return 0;
	}

	err = __ovs_ct_lookup(net, key, info, skb);
	if (err)
		return err;
	if (nf_conntrack_confirm(skb) != NF_ACCEPT)   //check conntrack
		return -EINVAL;

	return 0;
}
```


### __ovs_ct_lookup

```c
static int __ovs_ct_lookup(struct net *net, struct sw_flow_key *key,
			   const struct ovs_conntrack_info *info,
			   struct sk_buff *skb)
{
	/* If we are recirculating packets to match on conntrack fields and
	 * committing with a separate conntrack action,  then we don't need to
	 * actually run the packet through conntrack twice unless it's for a
	 * different zone.
	 */
	if (!skb_nfct_cached(net, skb, info)) {
		struct nf_conn *tmpl = info->ct;

		/* Associate skb with specified zone. */
		if (tmpl) {
			if (skb->nfct)
				nf_conntrack_put(skb->nfct);
			nf_conntrack_get(&tmpl->ct_general);
			skb->nfct = &tmpl->ct_general;
			skb->nfctinfo = IP_CT_NEW;
		}

		if (nf_conntrack_in(net, info->family, NF_INET_FORWARD,
				    skb) != NF_ACCEPT)
			return -ENOENT;

		if (ovs_ct_helper(skb, info->family) != NF_ACCEPT) {
			WARN_ONCE(1, "helper rejected packet");
			return -EINVAL;
		}
	}

	ovs_ct_update_key(skb, info, key, true);

	return 0;
}
```


## ovs_ct_lookup

```c
static int ovs_ct_lookup(struct net *net, struct sw_flow_key *key,
			 const struct ovs_conntrack_info *info,
			 struct sk_buff *skb)
{
	struct nf_conntrack_expect *exp;

	exp = ovs_ct_expect_find(net, &info->zone, info->family, skb);
	if (exp) {
		u8 state;

		state = OVS_CS_F_TRACKED | OVS_CS_F_NEW | OVS_CS_F_RELATED;
		__ovs_ct_update_key(key, state, &info->zone, exp->master);
	} else {
		int err;

		err = __ovs_ct_lookup(net, key, info, skb);
		if (err)
			return err;
	}

	return 0;
}
```
