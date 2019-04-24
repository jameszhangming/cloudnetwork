# Neighbor

�ھ���ϵͳ��IP�����·���Ŧ�����ṩ�˶��㱨�ĵķ�װ������ͬʱʵ����MAC��ַ��ȡ��ARP�������Ĺ��ܡ�


## ��Ҫ���ݽṹ


### Neighbour ״̬����

```c
#define NUD_INCOMPLETE	0x01
#define NUD_REACHABLE	0x02
#define NUD_STALE	0x04
#define NUD_DELAY	0x08
#define NUD_PROBE	0x10
#define NUD_FAILED	0x20

/* Dummy states */
#define NUD_NOARP	0x40
#define NUD_PERMANENT	0x80
#define NUD_NONE	0x00

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	    (NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)
```


### Neighbour ouput����

Neighbor���ڲ�ͬ״̬�ķ�������ʱ�в��

```c
static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
};

static const struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		neigh_direct_output,       //ֱ�Ӷ��㷢����dev_queue_xmit��
	.connected_output =	neigh_direct_output,   //ֱ�Ӷ��㷢����dev_queue_xmit��
};
```

#### neigh_direct_output

```c
int neigh_direct_output(struct neighbour *neigh, struct sk_buff *skb)
{
	return dev_queue_xmit(skb);
}
```

#### neigh_resolve_output

ʹ��neigh_resolve_output����˵��neighbour��δ����connected״̬������˵���ǻ����ܹ������㱨��ͷ
neigh_resolve_output�ᷢ��ARP���󣬲��ѱ��Ļ����ڶ����У����Ƶ��յ�ARP�������Է���
neigh_resolve_output��������֮��neighbour����NUD_INCOMPLETE״̬

```c
int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc = 0;

	if (!neigh_event_send(neigh, skb)) {   // Neighbour������ܷ�װ���㱨�ģ�����arp����
		int err;
		struct net_device *dev = neigh->dev;
		unsigned int seq;

		if (dev->header_ops->cache && !neigh->hh.hh_len)
			neigh_hh_init(neigh);		//��ʼ��neigh->hh����

		do {
			__skb_pull(skb, skb_network_offset(skb));	//skb�ƶ���IPͷ
			seq = read_seqbegin(&neigh->ha_lock);
			err = dev_hard_header(skb, dev, ntohs(skb->protocol),	//����skb����ͷ
					      neigh->ha, NULL, skb->len);
		} while (read_seqretry(&neigh->ha_lock, seq));

		if (err >= 0)
			rc = dev_queue_xmit(skb);   //���㷢�ͱ���
		else
			goto out_kfree_skb;
	}
out:
	return rc;
out_kfree_skb:
	rc = -EINVAL;
	kfree_skb(skb);
	goto out;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	unsigned long now = jiffies;
	
	if (neigh->used != now)
		neigh->used = now;	//����ʹ��ʱ��
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);   //���neigh��������������״̬
	return 0;
}

int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	int rc;
	bool immediate_probe = false;

	write_lock_bh(&neigh->lock);

	rc = 0;
	if (neigh->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		goto out_unlock_bh;
	if (neigh->dead)
		goto out_dead;

	if (!(neigh->nud_state & (NUD_STALE | NUD_INCOMPLETE))) {   //��ǰΪNONE״̬����������
		if (NEIGH_VAR(neigh->parms, MCAST_PROBES) +
		    NEIGH_VAR(neigh->parms, APP_PROBES)) {
			unsigned long next, now = jiffies;

			atomic_set(&neigh->probes,
				   NEIGH_VAR(neigh->parms, UCAST_PROBES));
			neigh->nud_state     = NUD_INCOMPLETE;             //����״̬ΪNUD_INCOMPLETE
			neigh->updated = now;
			next = now + max(NEIGH_VAR(neigh->parms, RETRANS_TIME),
					 HZ/2);
			neigh_add_timer(neigh, next);		//����timer
			immediate_probe = true;
		} else {
			neigh->nud_state = NUD_FAILED;
			neigh->updated = jiffies;
			write_unlock_bh(&neigh->lock);

			kfree_skb(skb);
			return 1;
		}
	} else if (neigh->nud_state & NUD_STALE) {
		neigh_dbg(2, "neigh %p is delayed\n", neigh);
		neigh->nud_state = NUD_DELAY;
		neigh->updated = jiffies;
		neigh_add_timer(neigh, jiffies +
				NEIGH_VAR(neigh->parms, DELAY_PROBE_TIME));
	}

	if (neigh->nud_state == NUD_INCOMPLETE) {
		if (skb) {
			while (neigh->arp_queue_len_bytes + skb->truesize >
			       NEIGH_VAR(neigh->parms, QUEUE_LEN_BYTES)) {
				struct sk_buff *buff;

				buff = __skb_dequeue(&neigh->arp_queue);	//��ȡarp���б���
				if (!buff)
					break;
				neigh->arp_queue_len_bytes -= buff->truesize;
				kfree_skb(buff);                //�ͷ�skb������arp���б��ĵ��ֽ�����
				NEIGH_CACHE_STAT_INC(neigh->tbl, unres_discards);
			}
			skb_dst_force(skb);
			__skb_queue_tail(&neigh->arp_queue, skb);		//skb��ӵ�arp����
			neigh->arp_queue_len_bytes += skb->truesize;
		}
		rc = 1;
	}
out_unlock_bh:
	if (immediate_probe)
		neigh_probe(neigh);		//����ARP����
	else
		write_unlock(&neigh->lock);
	local_bh_enable();
	return rc;

out_dead:
	if (neigh->nud_state & NUD_STALE)
		goto out_unlock_bh;
	write_unlock_bh(&neigh->lock);
	kfree_skb(skb);
	return 1;
}

static void neigh_probe(struct neighbour *neigh)
	__releases(neigh->lock)
{
	struct sk_buff *skb = skb_peek_tail(&neigh->arp_queue);		//ȡ���һ������
	/* keep skb alive even if arp_queue overflows */
	if (skb)
		skb = skb_copy(skb, GFP_ATOMIC);	//����skb
	write_unlock(&neigh->lock);
	neigh->ops->solicit(neigh, skb);		//����ARP����
	atomic_inc(&neigh->probes);
	kfree_skb(skb);
}
```

#### neigh_connected_output

```c
int neigh_connected_output(struct neighbour *neigh, struct sk_buff *skb)
{
	struct net_device *dev = neigh->dev;
	unsigned int seq;
	int err;

	do {
		__skb_pull(skb, skb_network_offset(skb));
		seq = read_seqbegin(&neigh->ha_lock);
		err = dev_hard_header(skb, dev, ntohs(skb->protocol),   //��װ����ͷ
				      neigh->ha, NULL, skb->len);
	} while (read_seqretry(&neigh->ha_lock, seq));

	if (err >= 0)
		err = dev_queue_xmit(skb);    //���㷢��
	else {
		err = -EINVAL;
		kfree_skb(skb);
	}
	return err;
}
```


### Neighbour ����

```c
struct neigh_table arp_tbl = {
	.family		= AF_INET,
	.key_len	= 4,
	.protocol	= cpu_to_be16(ETH_P_IP),
	.hash		= arp_hash,
	.key_eq		= arp_key_eq,
	.constructor	= arp_constructor,
	.proxy_redo	= parp_redo,
	.id		= "arp_cache",
	.parms		= {
		.tbl			= &arp_tbl,
		.reachable_time		= 30 * HZ,
		.data	= {
			[NEIGH_VAR_MCAST_PROBES] = 3,
			[NEIGH_VAR_UCAST_PROBES] = 3,
			[NEIGH_VAR_RETRANS_TIME] = 1 * HZ,
			[NEIGH_VAR_BASE_REACHABLE_TIME] = 30 * HZ,
			[NEIGH_VAR_DELAY_PROBE_TIME] = 5 * HZ,
			[NEIGH_VAR_GC_STALETIME] = 60 * HZ,
			[NEIGH_VAR_QUEUE_LEN_BYTES] = 64 * 1024,
			[NEIGH_VAR_PROXY_QLEN] = 64,
			[NEIGH_VAR_ANYCAST_DELAY] = 1 * HZ,
			[NEIGH_VAR_PROXY_DELAY]	= (8 * HZ) / 10,
			[NEIGH_VAR_LOCKTIME] = 1 * HZ,
		},
	},
	.gc_interval	= 30 * HZ,
	.gc_thresh1	= 128,
	.gc_thresh2	= 512,
	.gc_thresh3	= 1024,
};
```


### header_ops

```c
const struct header_ops eth_header_ops ____cacheline_aligned = {
	.create		= eth_header,
	.parse		= eth_header_parse,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
};

int eth_header(struct sk_buff *skb, struct net_device *dev,
	       unsigned short type,
	       const void *daddr, const void *saddr, unsigned int len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

	if (type != ETH_P_802_3 && type != ETH_P_802_2)
		eth->h_proto = htons(type);
	else
		eth->h_proto = htons(len);

	/*
	 *      Set the source hardware address.
	 */

	if (!saddr)
		saddr = dev->dev_addr;
	memcpy(eth->h_source, saddr, ETH_ALEN);

	if (daddr) {
		memcpy(eth->h_dest, daddr, ETH_ALEN);
		return ETH_HLEN;
	}

	/*
	 *      Anyway, the loopback-device should never use this function...
	 */

	if (dev->flags & (IFF_LOOPBACK | IFF_NOARP)) {
		eth_zero_addr(eth->h_dest);
		return ETH_HLEN;
	}

	return -ETH_HLEN;
}
```


## Neighbour ����ӿ�


### �����ھӱ���

```c
//�ӿ�1
static inline struct neighbour *__ipv4_neigh_lookup_noref(struct net_device *dev, u32 key)
{
	return ___neigh_lookup_noref(&arp_tbl, neigh_key_eq32, arp_hashfn, &key, dev);	//ipv4��arp_tbl�в���
}

static inline struct neighbour *___neigh_lookup_noref(
	struct neigh_table *tbl,
	bool (*key_eq)(const struct neighbour *n, const void *pkey),
	__u32 (*hash)(const void *pkey,
		      const struct net_device *dev,
		      __u32 *hash_rnd),
	const void *pkey,
	struct net_device *dev)
{
	struct neigh_hash_table *nht = rcu_dereference_bh(tbl->nht);	//hash���ھ�������ʱ����
	struct neighbour *n;
	u32 hash_val;

	hash_val = hash(pkey, dev, nht->hash_rnd) >> (32 - nht->hash_shift);	//����hashֵ
	for (n = rcu_dereference_bh(nht->hash_buckets[hash_val]);
	     n != NULL;
	     n = rcu_dereference_bh(n->next)) {
		if (n->dev == dev && key_eq(n, pkey))	//dev��ͬ����pkey��ͬ������pkey��IPV4��ַ
			return n;
	}

	return NULL;
}

//�ӿ�2����IPV4Э����ʹ�ã�����ARP
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);   //���ұ���

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);   //���δ�ҵ�����򴴽�����
	return IS_ERR(n) ? NULL : n;
}
```

### �����ھӱ���

```c
struct neighbour *__neigh_create(struct neigh_table *tbl, const void *pkey,
				 struct net_device *dev, bool want_ref)
{
	u32 hash_val;
	int key_len = tbl->key_len;
	int error;
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl, dev);    //����neighbour
	struct neigh_hash_table *nht;

	if (!n) {
		rc = ERR_PTR(-ENOBUFS);
		goto out;
	}

	memcpy(n->primary_key, pkey, key_len);  //����keyֵ��ΪIP���ȣ�4�ֽ�
	n->dev = dev;
	dev_hold(dev);

	/* Protocol specific setup. */
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {	//IPV4ʵ�ʵ���arp_constructor����
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	if (dev->netdev_ops->ndo_neigh_construct) {		//��ͨ�豸�����ô˽ӿڣ�ֻ��clip_netdev_ops�豸���������ø�ֵ
		error = dev->netdev_ops->ndo_neigh_construct(n);
		if (error < 0) {
			rc = ERR_PTR(error);
			goto out_neigh_release;
		}
	}

	/* Device specific setup. */
	if (n->parms->neigh_setup &&				//��ͨ�豸�����ô˽ӿڣ�ֻ��bond�豸���øýӿ�
	    (error = n->parms->neigh_setup(n)) < 0) {		
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}

	n->confirmed = jiffies - (NEIGH_VAR(n->parms, BASE_REACHABLE_TIME) << 1);  //����confirmedʱ��

	write_lock_bh(&tbl->lock);
	nht = rcu_dereference_protected(tbl->nht,
					lockdep_is_held(&tbl->lock));

	if (atomic_read(&tbl->entries) > (1 << nht->hash_shift))
		nht = neigh_hash_grow(tbl, nht->hash_shift + 1);

	hash_val = tbl->hash(pkey, dev, nht->hash_rnd) >> (32 - nht->hash_shift);	//����hashֵ�����㷽ʽ���ھӱ���

	if (n->parms->dead) {
		rc = ERR_PTR(-EINVAL);
		goto out_tbl_unlock;
	}

	for (n1 = rcu_dereference_protected(nht->hash_buckets[hash_val],	//�ҵ�����ͬhashֵ��neighbour����
					    lockdep_is_held(&tbl->lock));
	     n1 != NULL;
	     n1 = rcu_dereference_protected(n1->next,
			lockdep_is_held(&tbl->lock))) {
		if (dev == n1->dev && !memcmp(n1->primary_key, pkey, key_len)) {  //�ҵ���ͬ��neighbour
			if (want_ref)
				neigh_hold(n1);
			rc = n1;
			goto out_tbl_unlock;
		}
	}

	n->dead = 0;    //��0�󣬿��Է����ͽ���ARP�������״̬
	if (want_ref)
		neigh_hold(n);
	rcu_assign_pointer(n->next,
			   rcu_dereference_protected(nht->hash_buckets[hash_val],
						     lockdep_is_held(&tbl->lock)));	
	rcu_assign_pointer(nht->hash_buckets[hash_val], n);        //���뵽������
	write_unlock_bh(&tbl->lock);
	neigh_dbg(2, "neigh %p is created\n", n);
	rc = n;
out:
	return rc;
out_tbl_unlock:
	write_unlock_bh(&tbl->lock);
out_neigh_release:
	neigh_release(n);
	goto out;
}

static struct neighbour *neigh_alloc(struct neigh_table *tbl, struct net_device *dev)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	entries = atomic_inc_return(&tbl->entries) - 1;
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {
		if (!neigh_forced_gc(tbl) &&
		    entries >= tbl->gc_thresh3)
			goto out_entries;
	}

	n = kzalloc(tbl->entry_size + dev->neigh_priv_len, GFP_ATOMIC);
	if (!n)
		goto out_entries;

	__skb_queue_head_init(&n->arp_queue);
	rwlock_init(&n->lock);
	seqlock_init(&n->ha_lock);
	n->updated	  = n->used = now;
	n->nud_state	  = NUD_NONE;      //NONE״̬
	n->output	  = neigh_blackhole;   //ֱ�Ӷ���
	seqlock_init(&n->hh.hh_lock);
	n->parms	  = neigh_parms_clone(&tbl->parms);
	setup_timer(&n->timer, neigh_timer_handler, (unsigned long)n);   //���ö�ʱ��

	NEIGH_CACHE_STAT_INC(tbl, allocs);
	n->tbl		  = tbl;
	atomic_set(&n->refcnt, 1);
	n->dead		  = 1;
out:
	return n;

out_entries:
	atomic_dec(&tbl->entries);
	goto out;
}

static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr = *(__be32 *)neigh->primary_key;
	struct net_device *dev = neigh->dev;
	struct in_device *in_dev;
	struct neigh_parms *parms;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);			//�õ�in_dev
	if (!in_dev) {
		rcu_read_unlock();
		return -EINVAL;
	}

	neigh->type = inet_addr_type(dev_net(dev), addr);  //��ַ���ͣ��㲥���鲥�������ȵ�

	parms = in_dev->arp_parms;
	__neigh_parms_put(neigh->parms);			//�ͷ�parms
	neigh->parms = neigh_parms_clone(parms);	//ʹ��in_dev��parms
	rcu_read_unlock();

	if (!dev->header_ops) {			//�����豸û�иýӿ�
		neigh->nud_state = NUD_NOARP;
		neigh->ops = &arp_direct_ops;		    //ֱ�ӷ���
		neigh->output = neigh_direct_output;	//ֱ�Ӷ��㷢����dev_queue_xmit��
	} else {
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

		if (neigh->type == RTN_MULTICAST) {
			neigh->nud_state = NUD_NOARP;
			arp_mc_map(addr, neigh->ha, dev, 1);
		} else if (dev->flags & (IFF_NOARP | IFF_LOOPBACK)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);	//ʹ��dev��mac��ַ
		} else if (neigh->type == RTN_BROADCAST ||
			   (dev->flags & IFF_POINTOPOINT)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);	//ʹ��dev�Ĺ㲥��ַ
		}

		if (dev->header_ops->cache)		
			neigh->ops = &arp_hh_ops;   //eth�����豸eth_header_ops������cache�ӿ�
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state & NUD_VALID)    //NUD_VALID��һ��״̬������ʾ��ǰ״̬����ҪARP�����Ѿ����˶����ַ�������
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;
	}
	return 0;
}
```


### neighbour����

```c
static inline int dst_neigh_output(struct dst_entry *dst, struct neighbour *n,
				   struct sk_buff *skb)
{
	const struct hh_cache *hh;

	if (dst->pending_confirm) {
		unsigned long now = jiffies;

		dst->pending_confirm = 0;
		/* avoid dirtying neighbour */
		if (n->confirmed != now)
			n->confirmed = now;
	}

	hh = &n->hh;
	//���neighbour��������״̬������hh��ֵ������neigh_hh_init������ NUD_CONNECTED = (NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)
	if ((n->nud_state & NUD_CONNECTED) && hh->hh_len)	
		return neigh_hh_output(hh, skb);		//��װ����ͷ������·���������ѱ����ύ��������·��
	else
		return n->output(n, skb); 
}

static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq;
	int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		if (likely(hh_len <= HH_DATA_MOD)) {
			/* this is inlined by gcc */
			memcpy(skb->data - HH_DATA_MOD, hh->hh_data, HH_DATA_MOD);
		} else {
			int hh_alen = HH_DATA_ALIGN(hh_len);

			memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);	//��������ͷ������·��
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);		//skb���macͷ
	return dev_queue_xmit(skb);	//skb�Ѿ�ָ��macͷ
}
```
