# XFRM output

本文介绍XFRM output的处理流程。


## 系统入口

发包函数为xfrm4_state_afinfo的output函数。

```c
int xfrm4_output(struct sock *sk, struct sk_buff *skb)
{
	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, sk, skb,
			    NULL, skb_dst(skb)->dev, __xfrm4_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

static int __xfrm4_output(struct sock *sk, struct sk_buff *skb)
{
	struct xfrm_state *x = skb_dst(skb)->xfrm;

#ifdef CONFIG_NETFILTER
	if (!x) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output_sk(sk, skb);
	}
#endif
	
	//即调用xfrm4_state_afinfo的output_finish函数
	return x->outer_mode->afinfo->output_finish(sk, skb);
}
```

### xfrm4_output_finish

```c
int xfrm4_output_finish(struct sock *sk, struct sk_buff *skb)
{
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

#ifdef CONFIG_NETFILTER
	IPCB(skb)->flags |= IPSKB_XFRM_TRANSFORMED;
#endif

	return xfrm_output(sk, skb);
}

int xfrm_output(struct sock *sk, struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	int err;

	if (skb_is_gso(skb))
		return xfrm_output_gso(sk, skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = skb_checksum_help(skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return err;
		}
	}

	return xfrm_output2(sk, skb);
}

static int xfrm_output2(struct sock *sk, struct sk_buff *skb)
{
	return xfrm_output_resume(skb, 1);
}

int xfrm_output_resume(struct sk_buff *skb, int err)
{
	//第一次调用时，异步加密的话xfrm_output_one返回-EINPROGRESS
	while (likely((err = xfrm_output_one(skb, err)) == 0)) {   
		nf_reset(skb);
		
		//实际调用__ip_local_out，dst已经是原来的dst_entry了
		err = skb_dst(skb)->ops->local_out(skb);		
		if (unlikely(err != 1))
			goto out;

		if (!skb_dst(skb)->xfrm)
			return dst_output(skb);	 //满足条件，此时是使用原dst_entry进行报文发送的

		err = nf_hook(skb_dst(skb)->ops->family,
			      NF_INET_POST_ROUTING, skb->sk, skb,
			      NULL, skb_dst(skb)->dev, xfrm_output2);
		if (unlikely(err != 1))
			goto out;
	}

	if (err == -EINPROGRESS)
		err = 0;

out:
	return err;
}
```


## xfrm_output_one

```c
static int xfrm_output_one(struct sk_buff *skb, int err)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	if (err <= 0)	//加密后，err为0，跳过加密步骤
		goto resume;

	do {
		err = xfrm_skb_check_space(skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			goto error_nolock;
		}
		//报文准备ESP/AH头空间，并且拷贝好IP头， 此时报文为  |IP头|ESP/AH（未设置）|数据
		err = x->outer_mode->output(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
			goto error_nolock;
		}

		spin_lock_bh(&x->lock);

		if (unlikely(x->km.state != XFRM_STATE_VALID)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEINVALID);
			err = -EINVAL;
			goto error;
		}

		err = xfrm_state_check_expire(x);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEEXPIRED);
			goto error;
		}

		err = x->repl->overflow(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATESEQERROR);
			goto error;
		}

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);

		skb_dst_force(skb);

		//设置ESP/AH头，异步加密，加密数据不包含ESP头
		err = x->type->output(x, skb);	
		//正常调用结果，满足此条件，直接退出
		if (err == -EINPROGRESS)		
			goto out;

resume:
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			goto error_nolock;
		}
		
		//获取dst的child对象， 对于一条匹配的流，那么child为原dst_entry
		dst = skb_dst_pop(skb);	
		if (!dst) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		//设置dst为原来dst的child对象，该对象是没有xfrm的，可以跳出循环
		skb_dst_set(skb, dst);		
		x = dst->xfrm;   //此时x为空
	} while (x && !(x->outer_mode->flags & XFRM_MODE_FLAG_TUNNEL));

	return 0;

error:
	spin_unlock_bh(&x->lock);
error_nolock:
	kfree_skb(skb);
out:
	return err;
}
```

## Transport Mode

```c
static int xfrm4_transport_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int ihl = iph->ihl * 4;
	//该值为 sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead);
	skb_set_network_header(skb, -x->props.header_len);		
	skb->mac_header = skb->network_header +
			  offsetof(struct iphdr, protocol);
	skb->transport_header = skb->network_header + ihl;
	__skb_pull(skb, ihl);	//去掉内层IP报文头
    //network_header指向的为IP头，IP头之后留下了header_len的空洞，把内层报文的IP头去掉了	
	memmove(skb_network_header(skb), iph, ihl);		
	return 0;
}
```

## Tunnel Mode

```c
int xfrm4_prepare_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;

	err = xfrm_inner_extract_output(x, skb);
	if (err)
		return err;

	IPCB(skb)->flags |= IPSKB_XFRM_TUNNEL_SIZE;
	skb->protocol = htons(ETH_P_IP);

	return x->outer_mode->output2(x, skb); //实际调用xfrm4_mode_tunnel_output
}

int xfrm_inner_extract_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_mode *inner_mode;
	if (x->sel.family == AF_UNSPEC)
		inner_mode = xfrm_ip2inner_mode(x,
				xfrm_af2proto(skb_dst(skb)->ops->family));
	else
		inner_mode = x->inner_mode;

	if (inner_mode == NULL)
		return -EAFNOSUPPORT;
	return inner_mode->afinfo->extract_output(x, skb);	//保存报文IP头的信息
}

static int xfrm4_mode_tunnel_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct iphdr *top_iph;
	int flags;

	skb_set_network_header(skb, -x->props.header_len);	//留出IP头、ESP头、64位、加密数据，IP头移到新的位置
	skb->mac_header = skb->network_header +		//MAC头指向IP报头中的协议
			  offsetof(struct iphdr, protocol);
	skb->transport_header = skb->network_header + sizeof(*top_iph);	//传输层指向IP头之后的位置
	top_iph = ip_hdr(skb);	//外层IP头

	top_iph->ihl = 5;	//外层IP头长度为20
	top_iph->version = 4;

	top_iph->protocol = xfrm_af2proto(skb_dst(skb)->ops->family);

	/* DS disclosing depends on XFRM_SA_XFLAG_DONT_ENCAP_DSCP */
	if (x->props.extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)
		top_iph->tos = 0;
	else
		top_iph->tos = XFRM_MODE_SKB_CB(skb)->tos;
	top_iph->tos = INET_ECN_encapsulate(top_iph->tos,
					    XFRM_MODE_SKB_CB(skb)->tos);

	flags = x->props.flags;
	if (flags & XFRM_STATE_NOECN)
		IP_ECN_clear(top_iph);

	top_iph->frag_off = (flags & XFRM_STATE_NOPMTUDISC) ?
		0 : (XFRM_MODE_SKB_CB(skb)->frag_off & htons(IP_DF));

	top_iph->ttl = ip4_dst_hoplimit(dst->child);

	top_iph->saddr = x->props.saddr.a4;		//外层IP头源IP地址为xfrm_state中指定的IP地址
	top_iph->daddr = x->id.daddr.a4;		//外层IP头目标地址为xfrm_state中指定的IP地址
	ip_select_ident(dev_net(dst->dev), skb, NULL);

	return 0;
}
```

## ESP Type

```c
static int esp_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	struct aead_givcrypt_request *req;
	struct scatterlist *sg;
	struct scatterlist *asg;
	struct sk_buff *trailer;
	void *tmp;
	u8 *iv;
	u8 *tail;
	int blksize;
	int clen;
	int alen;
	int plen;
	int tfclen;
	int nfrags;
	int assoclen;
	int sglists;
	int seqhilen;
	__be32 *seqhi;

	/* skb is pure payload to encrypt */

	aead = x->data;
	alen = crypto_aead_authsize(aead);

	tfclen = 0;
	if (x->tfcpad) {
		struct xfrm_dst *dst = (struct xfrm_dst *)skb_dst(skb);
		u32 padto;

		padto = min(x->tfcpad, esp4_get_mtu(x, dst->child_mtu_cached));
		if (skb->len < padto)
			tfclen = padto - skb->len;
	}
	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(skb->len + 2 + tfclen, blksize);
	plen = clen - skb->len - tfclen;

	err = skb_cow_data(skb, tfclen + plen + alen, &trailer);	//skb增加结尾空间
	if (err < 0)
		goto error;
	nfrags = err;

	assoclen = sizeof(*esph);
	sglists = 1;
	seqhilen = 0;

	if (x->props.flags & XFRM_STATE_ESN) {
		sglists += 2;
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}

	tmp = esp_alloc_tmp(aead, nfrags + sglists, seqhilen);
	if (!tmp) {
		err = -ENOMEM;
		goto error;
	}

	seqhi = esp_tmp_seqhi(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_givreq(aead, iv);
	asg = esp_givreq_sg(aead, req);
	sg = asg + sglists;

	/* Fill padding... */
	tail = skb_tail_pointer(trailer);
	if (tfclen) {
		memset(tail, 0, tfclen);
		tail += tfclen;
	}
	do {
		int i;
		for (i = 0; i < plen - 2; i++)
			tail[i] = i + 1;
	} while (0);
	tail[plen - 2] = plen - 2;
	tail[plen - 1] = *skb_mac_header(skb);			//该值当前指向原数据的IP协议
	pskb_put(skb, trailer, clen - skb->len + alen);

	skb_push(skb, -skb_network_offset(skb));		//skb指向IP头
	esph = ip_esp_hdr(skb);					//当前TRANSPORT_HEADER指向ESP头
	*skb_mac_header(skb) = IPPROTO_ESP;			//IP协议改成ESP协议

	/* this is non-NULL only with UDP Encapsulation */
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;
		struct udphdr *uh;
		__be32 *udpdata32;
		__be16 sport, dport;
		int encap_type;

		spin_lock_bh(&x->lock);
		sport = encap->encap_sport;
		dport = encap->encap_dport;
		encap_type = encap->encap_type;
		spin_unlock_bh(&x->lock);

		uh = (struct udphdr *)esph;		//esph头实际为UDP头
		uh->source = sport;
		uh->dest = dport;
		uh->len = htons(skb->len - skb_transport_offset(skb));	//设置UDP的报文长度， 真实传递时，内层的IP已经被剥除了。
		uh->check = 0;

		switch (encap_type) {
		default:
		case UDP_ENCAP_ESPINUDP:
			esph = (struct ip_esp_hdr *)(uh + 1);	//ESP头为UDP头之后
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			udpdata32 = (__be32 *)(uh + 1);
			udpdata32[0] = udpdata32[1] = 0;
			esph = (struct ip_esp_hdr *)(udpdata32 + 2);
			break;
		}

		*skb_mac_header(skb) = IPPROTO_UDP;	 //IP协议为UDP协议
	}

	esph->spi = x->id.spi;
	esph->seq_no = htonl(XFRM_SKB_CB(skb)->seq.output.low);		//设置esp头

	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg,
		     esph->enc_data + crypto_aead_ivsize(aead) - skb->data,		//加密的数据不包括ESP头
		     clen + alen);

	if ((x->props.flags & XFRM_STATE_ESN)) {
		sg_init_table(asg, 3);
		sg_set_buf(asg, &esph->spi, sizeof(__be32));
		*seqhi = htonl(XFRM_SKB_CB(skb)->seq.output.hi);
		sg_set_buf(asg + 1, seqhi, seqhilen);
		sg_set_buf(asg + 2, &esph->seq_no, sizeof(__be32));
	} else
		sg_init_one(asg, esph, sizeof(*esph));

	aead_givcrypt_set_callback(req, 0, esp_output_done, skb);   //设置回调函数
	aead_givcrypt_set_crypt(req, sg, sg, clen, iv);
	aead_givcrypt_set_assoc(req, asg, assoclen);
	aead_givcrypt_set_giv(req, esph->enc_data,
			      XFRM_SKB_CB(skb)->seq.output.low +
			      ((u64)XFRM_SKB_CB(skb)->seq.output.hi << 32));

	ESP_SKB_CB(skb)->tmp = tmp;
	err = crypto_aead_givencrypt(req);   //执行加密操作
	if (err == -EINPROGRESS)
		goto error;

	if (err == -EBUSY)
		err = NET_XMIT_DROP;

	kfree(tmp);

error:
	return err;
}
```

### ESP 回调函数

```c
static void esp_output_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	kfree(ESP_SKB_CB(skb)->tmp);
	xfrm_output_resume(skb, err);
}
```

## AH Type

```c
static int ah_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	int nfrags;
	int ihl;
	u8 *icv;
	struct sk_buff *trailer;
	struct crypto_ahash *ahash;
	struct ahash_request *req;
	struct scatterlist *sg;
	struct iphdr *iph, *top_iph;
	struct ip_auth_hdr *ah;
	struct ah_data *ahp;
	int seqhi_len = 0;
	__be32 *seqhi;
	int sglists = 0;
	struct scatterlist *seqhisg;

	ahp = x->data;
	ahash = ahp->ahash;

	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto out;
	nfrags = err;

	skb_push(skb, -skb_network_offset(skb));
	ah = ip_auth_hdr(skb);
	ihl = ip_hdrlen(skb);

	if (x->props.flags & XFRM_STATE_ESN) {
		sglists = 1;
		seqhi_len = sizeof(*seqhi);
	}
	err = -ENOMEM;
	iph = ah_alloc_tmp(ahash, nfrags + sglists, ihl + seqhi_len);
	if (!iph)
		goto out;
	seqhi = (__be32 *)((char *)iph + ihl);
	icv = ah_tmp_icv(ahash, seqhi, seqhi_len);
	req = ah_tmp_req(ahash, icv);
	sg = ah_req_sg(ahash, req);
	seqhisg = sg + nfrags;

	memset(ah->auth_data, 0, ahp->icv_trunc_len);

	top_iph = ip_hdr(skb);

	iph->tos = top_iph->tos;
	iph->ttl = top_iph->ttl;
	iph->frag_off = top_iph->frag_off;

	if (top_iph->ihl != 5) {
		iph->daddr = top_iph->daddr;
		memcpy(iph+1, top_iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
		err = ip_clear_mutable_options(top_iph, &top_iph->daddr);
		if (err)
			goto out_free;
	}

	ah->nexthdr = *skb_mac_header(skb);
	*skb_mac_header(skb) = IPPROTO_AH;

	top_iph->tos = 0;
	top_iph->tot_len = htons(skb->len);
	top_iph->frag_off = 0;
	top_iph->ttl = 0;
	top_iph->check = 0;

	if (x->props.flags & XFRM_STATE_ALIGN4)
		ah->hdrlen  = (XFRM_ALIGN4(sizeof(*ah) + ahp->icv_trunc_len) >> 2) - 2;
	else
		ah->hdrlen  = (XFRM_ALIGN8(sizeof(*ah) + ahp->icv_trunc_len) >> 2) - 2;

	ah->reserved = 0;
	ah->spi = x->id.spi;
	ah->seq_no = htonl(XFRM_SKB_CB(skb)->seq.output.low);

	sg_init_table(sg, nfrags + sglists);
	skb_to_sgvec_nomark(skb, sg, 0, skb->len);

	if (x->props.flags & XFRM_STATE_ESN) {
		/* Attach seqhi sg right after packet payload */
		*seqhi = htonl(XFRM_SKB_CB(skb)->seq.output.hi);
		sg_set_buf(seqhisg, seqhi, seqhi_len);
	}
	ahash_request_set_crypt(req, sg, icv, skb->len + seqhi_len);
	ahash_request_set_callback(req, 0, ah_output_done, skb);   //设置回调函数

	AH_SKB_CB(skb)->tmp = iph;

	err = crypto_ahash_digest(req);   //执行摘要
	if (err) {
		if (err == -EINPROGRESS)
			goto out;

		if (err == -EBUSY)
			err = NET_XMIT_DROP;
		goto out_free;
	}

	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);

	top_iph->tos = iph->tos;
	top_iph->ttl = iph->ttl;
	top_iph->frag_off = iph->frag_off;
	if (top_iph->ihl != 5) {
		top_iph->daddr = iph->daddr;
		memcpy(top_iph+1, iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
	}

out_free:
	kfree(iph);
out:
	return err;
}
```

### AH 回调函数

```c
static void ah_output_done(struct crypto_async_request *base, int err)
{
	u8 *icv;
	struct iphdr *iph;
	struct sk_buff *skb = base->data;
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	struct ah_data *ahp = x->data;
	struct iphdr *top_iph = ip_hdr(skb);
	struct ip_auth_hdr *ah = ip_auth_hdr(skb);
	int ihl = ip_hdrlen(skb);

	iph = AH_SKB_CB(skb)->tmp;
	icv = ah_tmp_icv(ahp->ahash, iph, ihl);
	memcpy(ah->auth_data, icv, ahp->icv_trunc_len);

	top_iph->tos = iph->tos;
	top_iph->ttl = iph->ttl;
	top_iph->frag_off = iph->frag_off;
	if (top_iph->ihl != 5) {
		top_iph->daddr = iph->daddr;
		memcpy(top_iph+1, iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
	}

	kfree(AH_SKB_CB(skb)->tmp);
	xfrm_output_resume(skb, err);
}
```




