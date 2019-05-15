# GRO

GRO聚合收到的报文，以提升系统的吞吐量。 由于以太网的MTU为1500，而TCP报文大小基本会超过MTU大小，物理网卡发包时会分包成符合MTU要求的报文，如果收包端不聚合对TCP的吞吐量性能影响大。

从GRO的功能来看，有几个设计点：

* 什么报文可以聚合，即聚合的标准
* 报文长时间没有上报，需要有机制触发上送协议栈，避免报文的时延


## 基础数据结构

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


## napi gro入口

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
		napi_gro_receive(napi, skb);         //开始执行gro收包逻辑
		work_done++;
		spin_lock(&cell->napi_skbs.lock);
	}

	if (work_done < budget)
		napi_complete(napi);
	spin_unlock(&cell->napi_skbs.lock);
	return work_done;
}
```


## 入口函数

```c
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	trace_napi_gro_receive_entry(skb);

	skb_gro_reset_offset(skb);	//初始化NAPI_GRO_CB结构体

	return napi_skb_finish(dev_gro_receive(napi, skb), skb);  //gro收包并提交给协议栈处理
}

//根据gro收包的返回结果，进行处理
static gro_result_t napi_skb_finish(gro_result_t ret, struct sk_buff *skb)
{
	switch (ret) {
	case GRO_NORMAL:
		if (netif_receive_skb_internal(skb))	//返回值为normal，则直接提交报文给协议栈
			ret = GRO_DROP;
		break;

	case GRO_DROP:
		kfree_skb(skb);
		break;

	case GRO_MERGED_FREE:
		if (NAPI_GRO_CB(skb)->free == NAPI_GRO_FREE_STOLEN_HEAD)  //报文已经merge，需要释放skb
			kmem_cache_free(skbuff_head_cache, skb);
		else
			__kfree_skb(skb);
		break;

	case GRO_HELD:
	case GRO_MERGED:	//报文已经被保存到gro_list中，不要求释放skb
		break;
	}

	return ret;
}
```


### napi完成

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


## 链路层GRO收包

```c
static enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;		//packet_offload链表，ip协议等
	int same_flow;
	enum gro_result ret;
	int grow;

	//如果设备不支持GRO，则直接提交报文给协议栈处理
	if (!(skb->dev->features & NETIF_F_GRO))	
		goto normal;

    //如果报文是GSO报文，包含frag_list，或csum_bad则提交给协议栈处理
	if (skb_is_gso(skb) || skb_has_frag_list(skb) || skb->csum_bad)	
		goto normal;

    //遍历gro_list中的报文和当前报文是否同流，相同的入口设备、vlan_tci、mac头相同
	gro_list_prepare(napi, skb);	

	rcu_read_lock();
	//遍历packet_offload链表，找到和当前协议相同的packet_offload，IP报文为ip_packet_offload
	list_for_each_entry_rcu(ptype, head, list) {	
		if (ptype->type != type || !ptype->callbacks.gro_receive)
			continue;

        //设置network header，驱动调用napi_gro_receive前需要把报文移到network header
		skb_set_network_header(skb, skb_gro_offset(skb));	
		skb_reset_mac_len(skb);	//设置mac长度
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 0;
		NAPI_GRO_CB(skb)->free = 0;
		NAPI_GRO_CB(skb)->udp_mark = 0;
		NAPI_GRO_CB(skb)->gro_remcsum_start = 0;

		/* Setup for GRO checksum validation */
		switch (skb->ip_summed) {		//根据ip_summed字段初始化参数
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

		pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);	//调用网络层的gro_receive函数
		break;
	}
	rcu_read_unlock();

	if (&ptype->list == head)	//没有匹配到packet_offload对象，则直接提交报文给协议栈
		goto normal;

	same_flow = NAPI_GRO_CB(skb)->same_flow;	//网络层gro_receive处理后，same_flow可能被刷新
	ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;

	if (pp) {	//如果pp不为空，说明该报文需要提交给协议栈
		struct sk_buff *nskb = *pp;

		*pp = nskb->next;
		nskb->next = NULL;
		napi_gro_complete(nskb);	//提交给协议栈
		napi->gro_count--;
	}

	if (same_flow)	//如果是相同的流，则返回GRO_MERGED_FREE 或 GRO_MERGED，报文不会被提交给协议栈
		goto ok;

	if (NAPI_GRO_CB(skb)->flush)	//未匹配到流，且flush被置1，则直接提交报文给协议栈
		goto normal;

	if (unlikely(napi->gro_count >= MAX_GRO_SKBS)) {	//gro_list中的报文超过了设定值
		struct sk_buff *nskb = napi->gro_list;

		/* locate the end of the list to select the 'oldest' flow */
		while (nskb->next) {
			pp = &nskb->next;
			nskb = *pp;
		}
		*pp = NULL;
		nskb->next = NULL;
		napi_gro_complete(nskb);	//取出最早的报文，提交给协议栈处理
	} else {
		napi->gro_count++;
	}
	//未匹配到流，且flush未被置1，则把该报文插入到gro_list中，待以后匹配处理
	NAPI_GRO_CB(skb)->count = 1;		
	NAPI_GRO_CB(skb)->age = jiffies;
	NAPI_GRO_CB(skb)->last = skb;
	skb_shinfo(skb)->gso_size = skb_gro_len(skb);
	skb->next = napi->gro_list;
	napi->gro_list = skb;
	ret = GRO_HELD;

pull:
	grow = skb_gro_offset(skb) - skb_headlen(skb);	
	if (grow > 0)	//当前数据偏移如果超过线性区，则需要扩展线性区，线性区长度由驱动保证够用
		gro_pull_from_frag0(skb, grow);		//扩展报文线性区
ok:
	return ret;

normal:
	ret = GRO_NORMAL;
	goto pull;
}
```


### 链路层GRO complete

```c
static int napi_gro_complete(struct sk_buff *skb)
{
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &offload_base;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {		//count等于1，说明只有当前一个报文，直接提交给协议栈
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = ptype->callbacks.gro_complete(skb, 0);  //调用网络层的gro_complete函数
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);
		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return netif_receive_skb_internal(skb);	 //提交给网络协议栈
}
```


## IP层GRO收包

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
	iph = skb_gro_header_fast(skb, off); //得到IP头，内核支持两种skb，放在线性区和放在frag
	if (skb_gro_header_hard(skb, hlen)) {
		iph = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!iph))
			goto out;
	}

	proto = iph->protocol;		//得到传输层协议

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);	//得到传输层对应的offload
	if (!ops || !ops->callbacks.gro_receive)	//如果未找到对应的offload，则报文将被提交给协议栈
		goto out_unlock;

    //IP报文的协议版本必须为4，且报文头长度为20（5*4），否则报文将被提交给协议栈
	if (*(u8 *)iph != 0x45)		
		goto out_unlock;

    //IP头csum校验，如果通不过，则flush置1，报文将被提交给协议栈
	if (unlikely(ip_fast_csum((u8 *)iph, 5)))	
		goto out_unlock;
    //得到16位的ID值，3位flag和13位分片偏移
	id = ntohl(*(__be32 *)&iph->id);	
	//IP报文数据长度不等于gro_len或者报文携带DF标记，flush置1
	flush = (u16)((ntohl(*(__be32 *)iph) ^ skb_gro_len(skb)) | (id & ~IP_DF)); 
	id >>= 16;

	for (p = *head; p; p = p->next) {	//遍历gro_list中的报文
		struct iphdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)	//same_flow为零说明MAC的流匹配未通过，不需要下一步处理
			continue;

	    //得到报文的IP头，此时采用线性区的方式，从当前报文的IP头获取方式，此处也将会改变
		iph2 = (struct iphdr *)(p->data + off);	 
		/* The above works because, with the exception of the top
		 * (inner most) layer, we only aggregate pkts with the same
		 * hdr length so all the hdrs we'll need to verify will start
		 * at the same offset.
		 */
		if ((iph->protocol ^ iph2->protocol) |		//IP层判断同一个流，要求：4层协议要相同
		    ((__force u32)iph->saddr ^ (__force u32)iph2->saddr) |	//源地址要相同
		    ((__force u32)iph->daddr ^ (__force u32)iph2->daddr)) {	//目标地址要相同
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			(iph->ttl ^ iph2->ttl) |	//同一个流，但是ttl、tos、有一个报文包含DF标记，则需要flush当前该报文
			(iph->tos ^ iph2->tos) |
			((iph->frag_off ^ iph2->frag_off) & htons(IP_DF));

		/* Save the IP ID check to be included later when we get to
		 * the transport layer so only the inner most IP ID is checked.
		 * This is because some GSO/TSO implementations do not
		 * correctly increment the IP ID for the outer hdrs.
		 */
		NAPI_GRO_CB(p)->flush_id =
			    ((u16)(ntohs(iph2->id) + NAPI_GRO_CB(p)->count) ^ id);
		NAPI_GRO_CB(p)->flush |= flush;		//刷新报文的flush
	}

	NAPI_GRO_CB(skb)->flush |= flush;	//刷新当前报文的flush
	skb_set_network_header(skb, off);	//设置network header，可以找到IP头
	/* The above will be needed by the transport layer if there is one
	 * immediately following this IP hdr.
	 */

	/* Note : No need to call skb_gro_postpull_rcsum() here,
	 * as we already checked checksum over ipv4 header was 0
	 */
	skb_gro_pull(skb, sizeof(*iph));	//报文移动到4层头
	skb_set_transport_header(skb, skb_gro_offset(skb));	//设置传输层header值

	pp = ops->callbacks.gro_receive(head, skb);	//调用4层的offload

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;	//刷新当前报文的flush，调用四层offload后，可能会刷新

	return pp;
}
```

### IP层GRO complete

```c
static int inet_gro_complete(struct sk_buff *skb, int nhoff)
{
	__be16 newlen = htons(skb->len - nhoff);
	struct iphdr *iph = (struct iphdr *)(skb->data + nhoff);	//找到IP头
	const struct net_offload *ops;
	int proto = iph->protocol;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_network_header(skb, nhoff);   //如果报文是封装报文，那么iph指向的就是内层报文

	csum_replace2(&iph->check, iph->tot_len, newlen);	//由于长度变化，刷新csum值
	iph->tot_len = newlen;		//指定IP头中的长度字段

	rcu_read_lock();
	ops = rcu_dereference(inet_offloads[proto]);		//找到传输层的offload
	if (WARN_ON(!ops || !ops->callbacks.gro_complete))
		goto out_unlock;

	/* Only need to add sizeof(*iph) to get to the next hdr below
	 * because any hdr with option will have been flushed in
	 * inet_gro_receive().
	 */
	err = ops->callbacks.gro_complete(skb, nhoff + sizeof(*iph));	//调用传输层的gro_complete函数

out_unlock:
	rcu_read_unlock();

	return err;
}
```

## TCP层GRO收包

```c
static struct sk_buff **tcp4_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	/* Don't bother verifying checksum if we're going to flush anyway. */
	if (!NAPI_GRO_CB(skb)->flush &&
	    skb_gro_checksum_validate(skb, IPPROTO_TCP,
				      inet_gro_compute_pseudo)) {	//如果flush为0，需要检测csum
		NAPI_GRO_CB(skb)->flush = 1;	//如果检测失败则flush置1，报文将被提交到协议栈
		return NULL;
	}

	return tcp_gro_receive(head, skb);	//TCP gro receive处理，与IP协议无关
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
	th = skb_gro_header_fast(skb, off);	//得到TCP头
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	thlen = th->doff * 4;	//得到TCP头的长度
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {	//检测报文
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	skb_gro_pull(skb, thlen);	//报文移动到payload数据区

	len = skb_gro_len(skb);		//得到报文的数据区长度
	flags = tcp_flag_word(th);

	for (; (p = *head); head = &p->next) {		//遍历gro_list中的报文
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = tcp_hdr(p);	//得到报文tcp头

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {	//源和目的端口不一致的不是同一个流
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;	//找到同一个流的报文，则跳出循环，即p指向同一个流的skb
	}

	goto out_check_final;

found:
	/* Include the IP ID check below from the inner most IP hdr */
	flush = NAPI_GRO_CB(p)->flush | NAPI_GRO_CB(p)->flush_id;	//得到flush值，经过MAC/IP层设置
	//如果当前报文携带CWR标记，则flush置1
	flush |= (__force int)(flags & TCP_FLAG_CWR);	
	//如果当前报文和同流报文在(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH)标记之外的标记不相同，则置flush为1
	flush |= (__force int)((flags ^ tcp_flag_word(th2)) &	
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
    //如果当前报文和同流报文的ack_seq不同，则置flush为1
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);	
	//如果当前报文和同流报文的TCP头option信息不同，则置flush为1
	for (i = sizeof(*th); i < thlen; i += 4)	
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	mss = tcp_skb_mss(p);	//得到mss值

	flush |= (len - 1) >= mss;	//如果当前报文数据区长度超过mss，则置flush为1
	//如果当前报文和同流报文不连续，则置flush为1
	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);	

	if (flush || skb_gro_receive(head, skb)) {	//如果flush为0，则把当前报文合并到同流报文
		mss = 1;
		goto out_check_final;
	}

	p = *head;		//同流报文	
	th2 = tcp_hdr(p);
	//如果当前报文包含(TCP_FLAG_FIN | TCP_FLAG_PSH)标记，则同流报文也添加该标记
	tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);	

out_check_final:
	flush = len < mss;		//报文长度小于mss，一般是一个流的最后报文，需要尽快提交报文
	flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |	//如果报文携带这5个标记，则flush为1
					TCP_FLAG_RST | TCP_FLAG_SYN |
					TCP_FLAG_FIN));
    //p不为空，即找到同流报文，两种场景，1）同流报文超过65536；2）flush为1
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))	
		pp = head;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0); //设置当前报文的flush，决定是否提交当前报文到协议栈

	return pp;
}

int skb_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct skb_shared_info *pinfo, *skbinfo = skb_shinfo(skb);
	unsigned int offset = skb_gro_offset(skb);
	unsigned int headlen = skb_headlen(skb);
	unsigned int len = skb_gro_len(skb);
	struct sk_buff *lp, *p = *head;		//p指向gro_list中与当前报文同流的skb
	unsigned int delta_truesize;

	if (unlikely(p->len + len >= 65536))	//超过最大报文数，返回错误将提交同流报文
		return -E2BIG;

	lp = NAPI_GRO_CB(p)->last;	//初始时，last指向p自身
	pinfo = skb_shinfo(lp);

	if (headlen <= offset) {	//如果线性区长度小于offset，即frag中还有报头数据
		skb_frag_t *frag;
		skb_frag_t *frag2;
		int i = skbinfo->nr_frags;
		int nr_frags = pinfo->nr_frags + i;	//合并后的frag数

		if (nr_frags > MAX_SKB_FRAGS)	//如果合并后的frag超过最大frag数，则需要merge
			goto merge;

		offset -= headlen;
		pinfo->nr_frags = nr_frags;
		skbinfo->nr_frags = 0;

		frag = pinfo->frags + nr_frags;
		frag2 = skbinfo->frags + i;
		do {
			*--frag = *--frag2;
		} while (--i);

		frag->page_offset += offset;		//修正第一个frag，需要减掉报头数据
		skb_frag_size_sub(frag, offset);

		/* all fragments truesize : remove (head size + sk_buff) */
		delta_truesize = skb->truesize -
				 SKB_TRUESIZE(skb_end_offset(skb));

		skb->truesize -= skb->data_len;
		skb->len -= skb->data_len;
		skb->data_len = 0;

		NAPI_GRO_CB(skb)->free = NAPI_GRO_FREE;		//当前报文被合并，待释放
		goto done;
	} else if (skb->head_frag) {		//ixgbe驱动创建的skb，该标记为true
		int nr_frags = pinfo->nr_frags;
		skb_frag_t *frag = pinfo->frags + nr_frags;
		struct page *page = virt_to_head_page(skb->head);	//得到线性区的page
		unsigned int first_size = headlen - offset;
		unsigned int first_offset;

		if (nr_frags + 1 + skbinfo->nr_frags > MAX_SKB_FRAGS)	//合并后的frag数超过最大frag数，则需要merge
			goto merge;

		first_offset = skb->data -
			       (unsigned char *)page_address(page) +
			       offset;

		pinfo->nr_frags = nr_frags + 1 + skbinfo->nr_frags;

		frag->page.p	  = page;		//该frag报文报文线性区中的数据
		frag->page_offset = first_offset;
		skb_frag_size_set(frag, first_size);

		memcpy(frag + 1, skbinfo->frags, sizeof(*frag) * skbinfo->nr_frags);	//拷贝frag
		/* We dont need to clear skbinfo->nr_frags here */

		delta_truesize = skb->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));
		NAPI_GRO_CB(skb)->free = NAPI_GRO_FREE_STOLEN_HEAD;	//当前报文被合并，待释放
		goto done;
	}

merge:
	delta_truesize = skb->truesize;
	if (offset > headlen) {		//如果offset大于报文的线性区长度，意味着frag中有部分数据是报文头
		unsigned int eat = offset - headlen;

		skbinfo->frags[0].page_offset += eat;		//调整frag0中的数据，减掉报文头
		skb_frag_size_sub(&skbinfo->frags[0], eat);
		skb->data_len -= eat;
		skb->len -= eat;
		offset = headlen;
	}

	__skb_pull(skb, offset);	//当前报文移动到数据区

	if (NAPI_GRO_CB(p)->last == p)	//初始状态时（skb第一次放到gro_list中），且没有merge过
		skb_shinfo(p)->frag_list = skb;		//报文保存到frag_list中
	else
		NAPI_GRO_CB(p)->last->next = skb;	//报文保存到frag_list中的最后一个报文的
	NAPI_GRO_CB(p)->last = skb;	//merge过以后，报文都放在frag_list链表中
	__skb_header_release(skb);	//释放skb的线性区
	lp = p;

done:
	NAPI_GRO_CB(p)->count++;	//count加一，最后设置为segs
	p->data_len += len;		//同流报文的长度加上当前报文的数据区长度
	p->truesize += delta_truesize;	//同流报文的truesize加上当前报文的truesize
	p->len += len;		//同流报文的长度增加当前报文的长度
	if (lp != p) {		//当lp与p不相同时，lp报文相关长度信息也需要调整
		lp->data_len += len;
		lp->truesize += delta_truesize;
		lp->len += len;
	}
	NAPI_GRO_CB(skb)->same_flow = 1;	//same_flow置1，说明报文已经被合并到gro_list中
	return 0;
}
```


## TCP层GRO complete

```c
static int tcp4_gro_complete(struct sk_buff *skb, int thoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v4_check(skb->len - thoff, iph->saddr,	 //刷新check值
				  iph->daddr, 0);
	skb_shinfo(skb)->gso_type |= SKB_GSO_TCPV4;	//置GSO_TCPV4标记

	return tcp_gro_complete(skb);
}

int tcp_gro_complete(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	skb->csum_start = (unsigned char *)th - skb->head;	//设置ip_summed及相关值
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count; //设置segs

	//如果当前报文携带cwr标记，则携带SKB_GSO_TCP_ECN标记
	if (th->cwr)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;	

	return 0;
}
```

