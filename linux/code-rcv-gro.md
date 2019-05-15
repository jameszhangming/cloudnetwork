# GRO

GRO�ۺ��յ��ı��ģ�������ϵͳ���������� ������̫����MTUΪ1500����TCP���Ĵ�С�����ᳬ��MTU��С��������������ʱ��ְ��ɷ���MTUҪ��ı��ģ�����հ��˲��ۺ϶�TCP������������Ӱ���

��GRO�Ĺ����������м�����Ƶ㣺

* ʲô���Ŀ��Ծۺϣ����ۺϵı�׼
* ���ĳ�ʱ��û���ϱ�����Ҫ�л��ƴ�������Э��ջ�����ⱨ�ĵ�ʱ��


## �������ݽṹ

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


## napi gro���

```c
static inline int gro_cell_poll(struct napi_struct *napi, int budget)
{
	struct gro_cell *cell = container_of(napi, struct gro_cell, napi);
	struct sk_buff *skb;
	int work_done = 0;

	spin_lock(&cell->napi_skbs.lock);
	while (work_done < budget) {
		skb = __skb_dequeue(&cell->napi_skbs);
		if (!skb)
			break;
		spin_unlock(&cell->napi_skbs.lock);
		napi_gro_receive(napi, skb);         //��ʼִ��gro�հ��߼�
		work_done++;
		spin_lock(&cell->napi_skbs.lock);
	}

	if (work_done < budget)
		napi_complete(napi);
	spin_unlock(&cell->napi_skbs.lock);
	return work_done;
}
```


## ��ں���

```c
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	trace_napi_gro_receive_entry(skb);

	skb_gro_reset_offset(skb);	//��ʼ��NAPI_GRO_CB�ṹ��

	return napi_skb_finish(dev_gro_receive(napi, skb), skb);  //gro�հ����ύ��Э��ջ����
}

//����gro�հ��ķ��ؽ�������д���
static gro_result_t napi_skb_finish(gro_result_t ret, struct sk_buff *skb)
{
	switch (ret) {
	case GRO_NORMAL:
		if (netif_receive_skb_internal(skb))	//����ֵΪnormal����ֱ���ύ���ĸ�Э��ջ
			ret = GRO_DROP;
		break;

	case GRO_DROP:
		kfree_skb(skb);
		break;

	case GRO_MERGED_FREE:
		if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)  //�����Ѿ�merge����Ҫ�ͷ�skb
			kmem_cache_free(skbuff_head_cache, skb);
		else
			__kfree_skb(skb);
		break;

	case GRO_HELD:
	case GRO_MERGED:	//�����Ѿ������浽gro_list�У���Ҫ���ͷ�skb
		break;
	}

	return ret;
}
```


### napi���

```c
static inline void napi_complete(struct napi_struct *n)
{
	return napi_complete_done(n, 0);
}

void napi_complete_done(struct napi_struct *n, int work_done)
{
	unsigned long flags;

	/*
	 * don't let napi dequeue from the cpu poll list
	 * just in case its running on a different cpu
	 */
	if (unlikely(test_bit(NAPI_STATE_NPSVC, &n->state)))
		return;

	if (n->gro_list) {
		unsigned long timeout = 0;

		if (work_done)
			timeout = n->dev->gro_flush_timeout;

		if (timeout)
			hrtimer_start(&n->timer, ns_to_ktime(timeout),
				      HRTIMER_MODE_REL_PINNED);
		else
			napi_gro_flush(n, false);
	}
	if (likely(list_empty(&n->poll_list))) {
		WARN_ON_ONCE(!test_and_clear_bit(NAPI_STATE_SCHED, &n->state));
	} else {
		/* If n->poll_list is not empty, we need to mask irqs */
		local_irq_save(flags);
		__napi_complete(n);
		local_irq_restore(flags);
	}
}

void napi_gro_flush(struct napi_struct *napi, bool flush_old)
{
	struct sk_buff *skb, *prev = NULL;

	/* scan list and build reverse chain */
	for (skb = napi->gro_list; skb != NULL; skb = skb->next) {
		skb->prev = prev;
		prev = skb;
	}

	for (skb = prev; skb; skb = prev) {
		skb->next = NULL;

		if (flush_old && NAPI_GRO_CB(skb)->age == jiffies)
			return;

		prev = skb->prev;
		napi_gro_complete(skb);
		napi->gro_count--;
	}

	napi->gro_list = NULL;
}
```


## ��·��GRO�հ�

```c
static enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;		//packet_offload����ipЭ���
	int same_flow;
	enum gro_result ret;
	int grow;

	//����豸��֧��GRO����ֱ���ύ���ĸ�Э��ջ����
	if (!(skb->dev->features & NETIF_F_GRO))	
		goto normal;

    //���������GSO���ģ�����frag_list����csum_bad���ύ��Э��ջ����
	if (skb_is_gso(skb) || skb_has_frag_list(skb) || skb->csum_bad)	
		goto normal;

    //����gro_list�еı��ĺ͵�ǰ�����Ƿ�ͬ������ͬ������豸��vlan_tci��macͷ��ͬ
	gro_list_prepare(napi, skb);	

	rcu_read_lock();
	//����packet_offload�����ҵ��͵�ǰЭ����ͬ��packet_offload��IP����Ϊip_packet_offload
	list_for_each_entry_rcu(ptype, head, list) {	
		if (ptype->type != type || !ptype->callbacks.gro_receive)
			continue;

        //����network header����������napi_gro_receiveǰ��Ҫ�ѱ����Ƶ�network header
		skb_set_network_header(skb, skb_gro_offset(skb));	
		skb_reset_mac_len(skb);	//����mac����
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 0;
		NAPI_GRO_CB(skb)->free = 0;
		NAPI_GRO_CB(skb)->udp_mark = 0;
		NAPI_GRO_CB(skb)->gro_remcsum_start = 0;

		/* Setup for GRO checksum validation */
		switch (skb->ip_summed) {		//����ip_summed�ֶγ�ʼ������
		case CHECKSUM_COMPLETE:
			NAPI_GRO_CB(skb)->csum = skb->csum;
			NAPI_GRO_CB(skb)->csum_valid = 1;
			NAPI_GRO_CB(skb)->csum_cnt = 0;
			break;
		case CHECKSUM_UNNECESSARY:
			NAPI_GRO_CB(skb)->csum_cnt = skb->csum_level + 1;
			NAPI_GRO_CB(skb)->csum_valid = 0;
			break;
		default:
			NAPI_GRO_CB(skb)->csum_cnt = 0;
			NAPI_GRO_CB(skb)->csum_valid = 0;
		}

		pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);	//����������gro_receive����
		break;
	}
	rcu_read_unlock();

	if (&ptype->list == head)	//û��ƥ�䵽packet_offload������ֱ���ύ���ĸ�Э��ջ
		goto normal;

	same_flow = NAPI_GRO_CB(skb)->same_flow;	//�����gro_receive�����same_flow���ܱ�ˢ��
	ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;

	if (pp) {	//���pp��Ϊ�գ�˵���ñ�����Ҫ�ύ��Э��ջ
		struct sk_buff *nskb = *pp;

		*pp = nskb->next;
		nskb->next = NULL;
		napi_gro_complete(nskb);	//�ύ��Э��ջ
		napi->gro_count--;
	}

	if (same_flow)	//�������ͬ�������򷵻�GRO_MERGED_FREE �� GRO_MERGED�����Ĳ��ᱻ�ύ��Э��ջ
		goto ok;

	if (NAPI_GRO_CB(skb)->flush)	//δƥ�䵽������flush����1����ֱ���ύ���ĸ�Э��ջ
		goto normal;

	if (unlikely(napi->gro_count >= MAX_GRO_SKBS)) {	//gro_list�еı��ĳ������趨ֵ
		struct sk_buff *nskb = napi->gro_list;

		/* locate the end of the list to select the 'oldest' flow */
		while (nskb->next) {
			pp = &nskb->next;
			nskb = *pp;
		}
		*pp = NULL;
		nskb->next = NULL;
		napi_gro_complete(nskb);	//ȡ������ı��ģ��ύ��Э��ջ����
	} else {
		napi->gro_count++;
	}
	//δƥ�䵽������flushδ����1����Ѹñ��Ĳ��뵽gro_list�У����Ժ�ƥ�䴦��
	NAPI_GRO_CB(skb)->count = 1;		
	NAPI_GRO_CB(skb)->age = jiffies;
	NAPI_GRO_CB(skb)->last = skb;
	skb_shinfo(skb)->gso_size = skb_gro_len(skb);
	skb->next = napi->gro_list;
	napi->gro_list = skb;
	ret = GRO_HELD;

pull:
	grow = skb_gro_offset(skb) - skb_headlen(skb);	
	if (grow > 0)	//��ǰ����ƫ���������������������Ҫ��չ��������������������������֤����
		gro_pull_from_frag0(skb, grow);		//��չ����������
ok:
	return ret;

normal:
	ret = GRO_NORMAL;
	goto pull;
}
```


### ��·��GRO complete

```c
static int napi_gro_complete(struct sk_buff *skb)
{
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {		//count����1��˵��ֻ�е�ǰһ�����ģ�ֱ���ύ��Э��ջ
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = ptype->callbacks.gro_complete(skb, 0);  //����������gro_complete����
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);
		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return netif_receive_skb_internal(skb);	 //�ύ������Э��ջ
}
```


## IP��GRO�հ�

```c
static struct sk_buff **inet_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	const struct net_offload *ops;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	const struct iphdr *iph;
	unsigned int hlen;
	unsigned int off;
	unsigned int id;
	int flush = 1;
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header_fast(skb, off); //�õ�IPͷ���ں�֧������skb�������������ͷ���frag
	if (skb_gro_header_hard(skb, hlen)) {
		iph = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!iph))
			goto out;
	}

	proto = iph->protocol;		//�õ������Э��

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);	//�õ�������Ӧ��offload
	if (!ops || !ops->callbacks.gro_receive)	//���δ�ҵ���Ӧ��offload�����Ľ����ύ��Э��ջ
		goto out_unlock;

    //IP���ĵ�Э��汾����Ϊ4���ұ���ͷ����Ϊ20��5*4���������Ľ����ύ��Э��ջ
	if (*(u8 *)iph != 0x45)		
		goto out_unlock;

    //IPͷcsumУ�飬���ͨ��������flush��1�����Ľ����ύ��Э��ջ
	if (unlikely(ip_fast_csum((u8 *)iph, 5)))	
		goto out_unlock;
    //�õ�16λ��IDֵ��3λflag��13λ��Ƭƫ��
	id = ntohl(*(__be32 *)&iph->id);	
	//IP�������ݳ��Ȳ�����gro_len���߱���Я��DF��ǣ�flush��1
	flush = (u16)((ntohl(*(__be32 *)iph) ^ skb_gro_len(skb)) | (id & ~IP_DF)); 
	id >>= 16;

	for (p = *head; p; p = p->next) {	//����gro_list�еı���
		struct iphdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)	//same_flowΪ��˵��MAC����ƥ��δͨ��������Ҫ��һ������
			continue;

	    //�õ����ĵ�IPͷ����ʱ�����������ķ�ʽ���ӵ�ǰ���ĵ�IPͷ��ȡ��ʽ���˴�Ҳ����ı�
		iph2 = (struct iphdr *)(p->data + off);	 
		/* The above works because, with the exception of the top
		 * (inner most) layer, we only aggregate pkts with the same
		 * hdr length so all the hdrs we'll need to verify will start
		 * at the same offset.
		 */
		if ((iph->protocol ^ iph2->protocol) |		//IP���ж�ͬһ������Ҫ��4��Э��Ҫ��ͬ
		    ((__force u32)iph->saddr ^ (__force u32)iph2->saddr) |	//Դ��ַҪ��ͬ
		    ((__force u32)iph->daddr ^ (__force u32)iph2->daddr)) {	//Ŀ���ַҪ��ͬ
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			(iph->ttl ^ iph2->ttl) |	//ͬһ����������ttl��tos����һ�����İ���DF��ǣ�����Ҫflush��ǰ�ñ���
			(iph->tos ^ iph2->tos) |
			((iph->frag_off ^ iph2->frag_off) & htons(IP_DF));

		/* Save the IP ID check to be included later when we get to
		 * the transport layer so only the inner most IP ID is checked.
		 * This is because some GSO/TSO implementations do not
		 * correctly increment the IP ID for the outer hdrs.
		 */
		NAPI_GRO_CB(p)->flush_id =
			    ((u16)(ntohs(iph2->id) + NAPI_GRO_CB(p)->count) ^ id);
		NAPI_GRO_CB(p)->flush |= flush;		//ˢ�±��ĵ�flush
	}

	NAPI_GRO_CB(skb)->flush |= flush;	//ˢ�µ�ǰ���ĵ�flush
	skb_set_network_header(skb, off);	//����network header�������ҵ�IPͷ
	/* The above will be needed by the transport layer if there is one
	 * immediately following this IP hdr.
	 */

	/* Note : No need to call skb_gro_postpull_rcsum() here,
	 * as we already checked checksum over ipv4 header was 0
	 */
	skb_gro_pull(skb, sizeof(*iph));	//�����ƶ���4��ͷ
	skb_set_transport_header(skb, skb_gro_offset(skb));	//���ô����headerֵ

	pp = ops->callbacks.gro_receive(head, skb);	//����4���offload

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;	//ˢ�µ�ǰ���ĵ�flush�������Ĳ�offload�󣬿��ܻ�ˢ��

	return pp;
}
```

### IP��GRO complete

```c
static int inet_gro_complete(struct sk_buff *skb, int nhoff)
{
	__be16 newlen = htons(skb->len - nhoff);
	struct iphdr *iph = (struct iphdr *)(skb->data + nhoff);	//�ҵ�IPͷ
	const struct net_offload *ops;
	int proto = iph->protocol;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_network_header(skb, nhoff);   //��������Ƿ�װ���ģ���ôiphָ��ľ����ڲ㱨��

	csum_replace2(&iph->check, iph->tot_len, newlen);	//���ڳ��ȱ仯��ˢ��csumֵ
	iph->tot_len = newlen;		//ָ��IPͷ�еĳ����ֶ�

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);		//�ҵ�������offload
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out_unlock;

	/* Only need to add sizeof(*iph) to get to the next hdr below
	 * because any hdr with option will have been flushed in
	 * inet_gro_receive().
	 */
	err = ops->callbacks.gro_complete(skb, nhoff + sizeof(*iph));	//���ô�����gro_complete����

out_unlock:
	rcu_read_unlock();

	return err;
}
```

## TCP��GRO�հ�

```c
static struct sk_buff **tcp4_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (!NAPI_GRO_CB(skb)->flush &&
	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
				      inet_gro_compute_pseudo)) {	//���flushΪ0����Ҫ���csum
		NAPI_GRO_CB(skb)->flush = 1;	//������ʧ����flush��1�����Ľ����ύ��Э��ջ
		return NULL;
	}

	return tcp_gro_receive(head, skb);	//TCP gro receive������IPЭ���޹�
}

struct sk_buff **tcp_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct tcphdr *th;
	struct tcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	__be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int i;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*th);
	th = skb_gro_header_fast(skb, off);	//�õ�TCPͷ
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	thlen = th->doff * 4;	//�õ�TCPͷ�ĳ���
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {	//��ⱨ��
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	skb_gro_pull(skb, thlen);	//�����ƶ���payload������

	len = skb_gro_len(skb);		//�õ����ĵ�����������
	flags = tcp_flag_word(th);

	for (; (p = *head); head = &p->next) {		//����gro_list�еı���
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = tcp_hdr(p);	//�õ�����tcpͷ

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {	//Դ��Ŀ�Ķ˿ڲ�һ�µĲ���ͬһ����
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;	//�ҵ�ͬһ�����ı��ģ�������ѭ������pָ��ͬһ������skb
	}

	goto out_check_final;

found:
	/* Include the IP ID check below from the inner most IP hdr */
	flush = NAPI_GRO_CB(p)->flush | NAPI_GRO_CB(p)->flush_id;	//�õ�flushֵ������MAC/IP������
	//�����ǰ����Я��CWR��ǣ���flush��1
	flush |= (__force int)(flags & TCP_FLAG_CWR);	
	//�����ǰ���ĺ�ͬ��������(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH)���֮��ı�ǲ���ͬ������flushΪ1
	flush |= (__force int)((flags ^ tcp_flag_word(th2)) &	
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
    //�����ǰ���ĺ�ͬ�����ĵ�ack_seq��ͬ������flushΪ1
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);	
	//�����ǰ���ĺ�ͬ�����ĵ�TCPͷoption��Ϣ��ͬ������flushΪ1
	for (i = sizeof(*th); i < thlen; i += 4)	
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	mss = tcp_skb_mss(p);	//�õ�mssֵ

	flush |= (len - 1) >= mss;	//�����ǰ�������������ȳ���mss������flushΪ1
	//�����ǰ���ĺ�ͬ�����Ĳ�����������flushΪ1
	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);	

	if (flush || skb_gro_receive(head, skb)) {	//���flushΪ0����ѵ�ǰ���ĺϲ���ͬ������
		mss = 1;
		goto out_check_final;
	}

	p = *head;		//ͬ������	
	th2 = tcp_hdr(p);
	//�����ǰ���İ���(TCP_FLAG_FIN | TCP_FLAG_PSH)��ǣ���ͬ������Ҳ��Ӹñ��
	tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);	

out_check_final:
	flush = len < mss;		//���ĳ���С��mss��һ����һ����������ģ���Ҫ�����ύ����
	flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |	//�������Я����5����ǣ���flushΪ1
					TCP_FLAG_RST | TCP_FLAG_SYN |
					TCP_FLAG_FIN));
    //p��Ϊ�գ����ҵ�ͬ�����ģ����ֳ�����1��ͬ�����ĳ���65536��2��flushΪ1
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))	
		pp = head;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0); //���õ�ǰ���ĵ�flush�������Ƿ��ύ��ǰ���ĵ�Э��ջ

	return pp;
}

int skb_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct skb_shared_info *pinfo, *skbinfo = skb_shinfo(skb);
	unsigned int offset = skb_gro_offset(skb);
	unsigned int headlen = skb_headlen(skb);
	unsigned int len = skb_gro_len(skb);
	struct sk_buff *lp, *p = *head;		//pָ��gro_list���뵱ǰ����ͬ����skb
	unsigned int delta_truesize;

	if (unlikely(p->len + len >= 65536))	//����������������ش����ύͬ������
		return -E2BIG;

	lp = NAPI_GRO_CB(p)->last;	//��ʼʱ��lastָ��p����
	pinfo = skb_shinfo(lp);

	if (headlen <= offset) {	//�������������С��offset����frag�л��б�ͷ����
		skb_frag_t *frag;
		skb_frag_t *frag2;
		int i = skbinfo->nr_frags;
		int nr_frags = pinfo->nr_frags + i;	//�ϲ����frag��

		if (nr_frags > MAX_SKB_FRAGS)	//����ϲ����frag�������frag��������Ҫmerge
			goto merge;

		offset -= headlen;
		pinfo->nr_frags = nr_frags;
		skbinfo->nr_frags = 0;

		frag = pinfo->frags + nr_frags;
		frag2 = skbinfo->frags + i;
		do {
			*--frag = *--frag2;
		} while (--i);

		frag->page_offset += offset;		//������һ��frag����Ҫ������ͷ����
		skb_frag_size_sub(frag, offset);

		/* all fragments truesize : remove (head size + sk_buff) */
		delta_truesize = skb->truesize -
				 SKB_TRUESIZE(skb_end_offset(skb));

		skb->truesize -= skb->data_len;
		skb->len -= skb->data_len;
		skb->data_len = 0;

		NAPI_GRO_CB(skb)->free = NAPI_GRO_FREE;		//��ǰ���ı��ϲ������ͷ�
		goto done;
	} else if (skb->head_frag) {		//ixgbe����������skb���ñ��Ϊtrue
		int nr_frags = pinfo->nr_frags;
		skb_frag_t *frag = pinfo->frags + nr_frags;
		struct page *page = virt_to_head_page(skb->head);	//�õ���������page
		unsigned int first_size = headlen - offset;
		unsigned int first_offset;

		if (nr_frags + 1 + skbinfo->nr_frags > MAX_SKB_FRAGS)	//�ϲ����frag���������frag��������Ҫmerge
			goto merge;

		first_offset = skb->data -
			       (unsigned char *)page_address(page) +
			       offset;

		pinfo->nr_frags = nr_frags + 1 + skbinfo->nr_frags;

		frag->page.p	  = page;		//��frag���ı����������е�����
		frag->page_offset = first_offset;
		skb_frag_size_set(frag, first_size);

		memcpy(frag + 1, skbinfo->frags, sizeof(*frag) * skbinfo->nr_frags);	//����frag
		/* We dont need to clear skbinfo->nr_frags here */

		delta_truesize = skb->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));
		NAPI_GRO_CB(skb)->free = NAPI_GRO_FREE_STOLEN_HEAD;	//��ǰ���ı��ϲ������ͷ�
		goto done;
	}

merge:
	delta_truesize = skb->truesize;
	if (offset > headlen) {		//���offset���ڱ��ĵ����������ȣ���ζ��frag���в��������Ǳ���ͷ
		unsigned int eat = offset - headlen;

		skbinfo->frags[0].page_offset += eat;		//����frag0�е����ݣ���������ͷ
		skb_frag_size_sub(&skbinfo->frags[0], eat);
		skb->data_len -= eat;
		skb->len -= eat;
		offset = headlen;
	}

	__skb_pull(skb, offset);	//��ǰ�����ƶ���������

	if (NAPI_GRO_CB(p)->last == p)	//��ʼ״̬ʱ��skb��һ�ηŵ�gro_list�У�����û��merge��
		skb_shinfo(p)->frag_list = skb;		//���ı��浽frag_list��
	else
		NAPI_GRO_CB(p)->last->next = skb;	//���ı��浽frag_list�е����һ�����ĵ�
	NAPI_GRO_CB(p)->last = skb;	//merge���Ժ󣬱��Ķ�����frag_list������
	__skb_header_release(skb);	//�ͷ�skb��������
	lp = p;

done:
	NAPI_GRO_CB(p)->count++;	//count��һ���������Ϊsegs
	p->data_len += len;		//ͬ�����ĵĳ��ȼ��ϵ�ǰ���ĵ�����������
	p->truesize += delta_truesize;	//ͬ�����ĵ�truesize���ϵ�ǰ���ĵ�truesize
	p->len += len;		//ͬ�����ĵĳ������ӵ�ǰ���ĵĳ���
	if (lp != p) {		//��lp��p����ͬʱ��lp������س�����ϢҲ��Ҫ����
		lp->data_len += len;
		lp->truesize += delta_truesize;
		lp->len += len;
	}
	NAPI_GRO_CB(skb)->same_flow = 1;	//same_flow��1��˵�������Ѿ����ϲ���gro_list��
	return 0;
}
```


## TCP��GRO complete

```c
static int tcp4_gro_complete(struct sk_buff *skb, int thoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v4_check(skb->len - thoff, iph->saddr,	 //ˢ��checkֵ
				  iph->daddr, 0);
	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4;	//��GSO_TCPV4���

	return tcp_gro_complete(skb);
}

int tcp_gro_complete(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	skb->csum_start = (unsigned char *)th - skb->head;	//����ip_summed�����ֵ
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count; //����segs

	//�����ǰ����Я��cwr��ǣ���Я��SKB_GSO_TCP_ECN���
	if (th->cwr)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;	

	return 0;
}
```

