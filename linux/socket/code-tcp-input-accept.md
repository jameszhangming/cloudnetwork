# TCP Accept流程

本文将介绍TCP Server 处于listen状态时，接收到client的syn报文后的处理过程。


## TCP Socket收包处理

匹配到TCP Socket，进行TCP Socket处理，TCP Socket在不同状态下有不同的处理行为。

```c
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *rsk;

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */   //establish状态处理
		struct dst_entry *dst = sk->sk_rx_dst;

		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		if (dst) {
			if (inet_sk(sk)->rx_dst_ifindex != skb->skb_iif ||
			    !dst->ops->check(dst, 0)) {
				dst_release(dst);
				sk->sk_rx_dst = NULL;
			}
		}
		tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len);   //establish收包处理
		return 0;
	}

	if (skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v4_hnd_req(sk, skb);   //创建新socket，第一次收到syn报文时 nsk==sk，第二次会创建新socket
		if (!nsk)
			goto discard;

		if (nsk != sk) {    
			sock_rps_save_rxhash(nsk, skb);
			sk_mark_napi_id(sk, skb);
			if (tcp_child_process(sk, nsk, skb)) {
				rsk = nsk;
				goto reset;
			}
			return 0;     //创建新socket后，直接返回
		}
	} else
		sock_rps_save_rxhash(sk, skb);

	if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {  //根据socket进行收包处理，添加conn request
		rsk = sk;
		goto reset;
	}
	return 0;

reset:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	/* Be careful here. If this function gets more complicated and
	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
	goto discard;
}
```


## tcp_v4_hnd_req

```c
static struct sock *tcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	struct request_sock *req;
	struct sock *nsk;

	req = inet_csk_search_req(sk, th->source, iph->saddr, iph->daddr);    //查询到连接请求
	if (req) {
		nsk = tcp_check_req(sk, skb, req, false);   //创建新socket
		if (!nsk || nsk == sk)
			reqsk_put(req);
		return nsk;
	}

	nsk = inet_lookup_established(sock_net(sk), &tcp_hashinfo, iph->saddr,  //查找已建立的socket
			th->source, iph->daddr, th->dest, inet_iif(skb));

	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	if (!th->syn)
		sk = cookie_v4_check(sk, skb);
#endif
	return sk;
}

struct request_sock *inet_csk_search_req(struct sock *sk,
					 const __be16 rport,
					 const __be32 raddr,
					 const __be32 laddr)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;    //请求队列
	struct request_sock *req;
	u32 hash = inet_synq_hash(raddr, rport, lopt->hash_rnd,
				  lopt->nr_table_entries);

	spin_lock(&icsk->icsk_accept_queue.syn_wait_lock);
	for (req = lopt->syn_table[hash]; req != NULL; req = req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->ir_rmt_port == rport &&
		    ireq->ir_rmt_addr == raddr &&
		    ireq->ir_loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			atomic_inc(&req->rsk_refcnt);
			WARN_ON(req->sk);
			break;
		}
	}
	spin_unlock(&icsk->icsk_accept_queue.syn_wait_lock);

	return req;
}

static inline struct sock *
	inet_lookup_established(struct net *net, struct inet_hashinfo *hashinfo,
				const __be32 saddr, const __be16 sport,
				const __be32 daddr, const __be16 dport,
				const int dif)
{
	return __inet_lookup_established(net, hashinfo, saddr, sport, daddr,
					 ntohs(dport), dif);
}

struct sock *__inet_lookup_established(struct net *net,
				  struct inet_hashinfo *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 hnum,
				  const int dif)
{
	INET_ADDR_COOKIE(acookie, saddr, daddr);
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	const struct hlist_nulls_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
	unsigned int slot = hash & hashinfo->ehash_mask;
	struct inet_ehash_bucket *head = &hashinfo->ehash[slot];

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(sk, node, &head->chain) {
		if (sk->sk_hash != hash)
			continue;
		if (likely(INET_MATCH(sk, net, acookie,
				      saddr, daddr, ports, dif))) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt)))
				goto out;
			if (unlikely(!INET_MATCH(sk, net, acookie,
						 saddr, daddr, ports, dif))) {
				sock_gen_put(sk);
				goto begin;
			}
			goto found;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;
out:
	sk = NULL;
found:
	rcu_read_unlock();
	return sk;
}
```


### tcp_check_req

```c
struct sock *tcp_check_req(struct sock *sk, struct sk_buff *skb,
			   struct request_sock *req,
			   bool fastopen)
{
	struct tcp_options_received tmp_opt;
	struct sock *child;
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST|TCP_FLAG_SYN|TCP_FLAG_ACK);
	bool paws_reject = false;

	BUG_ON(fastopen == (sk->sk_state == TCP_LISTEN));

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(struct tcphdr)>>2)) {
		tcp_parse_options(skb, &tmp_opt, 0, NULL);

		if (tmp_opt.saw_tstamp) {
			tmp_opt.ts_recent = req->ts_recent;
			/* We do not store true stamp, but it is not required,
			 * it can be estimated (approximately)
			 * from another data.
			 */
			tmp_opt.ts_recent_stamp = get_seconds() - ((TCP_TIMEOUT_INIT/HZ)<<req->num_timeout);
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	/* Check for pure retransmitted SYN. */
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
	    flg == TCP_FLAG_SYN &&
	    !paws_reject) {
		/*
		 * RFC793 draws (Incorrectly! It was fixed in RFC1122)
		 * this case on figure 6 and figure 8, but formal
		 * protocol description says NOTHING.
		 * To be more exact, it says that we should send ACK,
		 * because this segment (at least, if it has no data)
		 * is out of window.
		 *
		 *  CONCLUSION: RFC793 (even with RFC1122) DOES NOT
		 *  describe SYN-RECV state. All the description
		 *  is wrong, we cannot believe to it and should
		 *  rely only on common sense and implementation
		 *  experience.
		 *
		 * Enforce "SYN-ACK" according to figure 8, figure 6
		 * of RFC793, fixed by RFC1122.
		 *
		 * Note that even if there is new data in the SYN packet
		 * they will be thrown away too.
		 *
		 * Reset timer after retransmitting SYNACK, similar to
		 * the idea of fast retransmit in recovery.
		 */
		if (!tcp_oow_rate_limited(sock_net(sk), skb,
					  LINUX_MIB_TCPACKSKIPPEDSYNRECV,
					  &tcp_rsk(req)->last_oow_ack_time) &&

		    !inet_rtx_syn_ack(sk, req)) {
			unsigned long expires = jiffies;

			expires += min(TCP_TIMEOUT_INIT << req->num_timeout,
				       TCP_RTO_MAX);
			if (!fastopen)
				mod_timer_pending(&req->rsk_timer, expires);
			else
				req->rsk_timer.expires = expires;
		}
		return NULL;
	}

	/* Further reproduces section "SEGMENT ARRIVES"
	   for state SYN-RECEIVED of RFC793.
	   It is broken, however, it does not work only
	   when SYNs are crossed.

	   You would think that SYN crossing is impossible here, since
	   we should have a SYN_SENT socket (from connect()) on our end,
	   but this is not true if the crossed SYNs were sent to both
	   ends by a malicious third party.  We must defend against this,
	   and to do that we first verify the ACK (as per RFC793, page
	   36) and reset if it is invalid.  Is this a true full defense?
	   To convince ourselves, let us consider a way in which the ACK
	   test can still pass in this 'malicious crossed SYNs' case.
	   Malicious sender sends identical SYNs (and thus identical sequence
	   numbers) to both A and B:

		A: gets SYN, seq=7
		B: gets SYN, seq=7

	   By our good fortune, both A and B select the same initial
	   send sequence number of seven :-)

		A: sends SYN|ACK, seq=7, ack_seq=8
		B: sends SYN|ACK, seq=7, ack_seq=8

	   So we are now A eating this SYN|ACK, ACK test passes.  So
	   does sequence test, SYN is truncated, and thus we consider
	   it a bare ACK.

	   If icsk->icsk_accept_queue.rskq_defer_accept, we silently drop this
	   bare ACK.  Otherwise, we create an established connection.  Both
	   ends (listening sockets) accept the new incoming connection and try
	   to talk to each other. 8-)

	   Note: This case is both harmless, and rare.  Possibility is about the
	   same as us discovering intelligent life on another plant tomorrow.

	   But generally, we should (RFC lies!) to accept ACK
	   from SYNACK both here and in tcp_rcv_state_process().
	   tcp_rcv_state_process() does not, hence, we do not too.

	   Note that the case is absolutely generic:
	   we cannot optimize anything here without
	   violating protocol. All the checks must be made
	   before attempt to create socket.
	 */

	/* RFC793 page 36: "If the connection is in any non-synchronized state ...
	 *                  and the incoming segment acknowledges something not yet
	 *                  sent (the segment carries an unacceptable ACK) ...
	 *                  a reset is sent."
	 *
	 * Invalid ACK: reset will be sent by listening socket.
	 * Note that the ACK validity check for a Fast Open socket is done
	 * elsewhere and is checked directly against the child socket rather
	 * than req because user data may have been sent out.
	 */
	if ((flg & TCP_FLAG_ACK) && !fastopen &&
	    (TCP_SKB_CB(skb)->ack_seq !=
	     tcp_rsk(req)->snt_isn + 1))
		return sk;

	/* Also, it would be not so bad idea to check rcv_tsecr, which
	 * is essentially ACK extension and too early or too late values
	 * should cause reset in unsynchronized states.
	 */

	/* RFC793: "first check sequence number". */

	if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
					  tcp_rsk(req)->rcv_nxt, tcp_rsk(req)->rcv_nxt + req->rcv_wnd)) {
		/* Out of window: send ACK and drop. */
		if (!(flg & TCP_FLAG_RST))
			req->rsk_ops->send_ack(sk, skb, req);
		if (paws_reject)
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
		return NULL;
	}

	/* In sequence, PAWS is OK. */

	if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_nxt))
		req->ts_recent = tmp_opt.rcv_tsval;

	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
		/* Truncate SYN, it is out of window starting
		   at tcp_rsk(req)->rcv_isn + 1. */
		flg &= ~TCP_FLAG_SYN;
	}

	/* RFC793: "second check the RST bit" and
	 *	   "fourth, check the SYN bit"
	 */
	if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
		goto embryonic_reset;
	}

	/* ACK sequence verified above, just make sure ACK is
	 * set.  If ACK not set, just silently drop the packet.
	 *
	 * XXX (TFO) - if we ever allow "data after SYN", the
	 * following check needs to be removed.
	 */
	if (!(flg & TCP_FLAG_ACK))
		return NULL;

	/* For Fast Open no more processing is needed (sk is the
	 * child socket).
	 */
	if (fastopen)
		return sk;

	/* While TCP_DEFER_ACCEPT is active, drop bare ACK. */
	if (req->num_timeout < inet_csk(sk)->icsk_accept_queue.rskq_defer_accept &&
	    TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {
		inet_rsk(req)->acked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPDEFERACCEPTDROP);
		return NULL;
	}

	/* OK, ACK is valid, create big socket and
	 * feed this segment to it. It will repeat all
	 * the tests. THIS SEGMENT MUST MOVE SOCKET TO
	 * ESTABLISHED STATE. If it will be dropped after
	 * socket is created, wait for troubles.
	 */
	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL);   //调用ipv4_specific的接口
	if (!child)
		goto listen_overflow;

	inet_csk_reqsk_queue_drop(sk, req);
	inet_csk_reqsk_queue_add(sk, req, child);
	/* Warning: caller must not call reqsk_put(req);
	 * child stole last reference on it.
	 */
	return child;

listen_overflow:
	if (!sysctl_tcp_abort_on_overflow) {
		inet_rsk(req)->acked = 1;
		return NULL;
	}

embryonic_reset:
	if (!(flg & TCP_FLAG_RST)) {
		/* Received a bad SYN pkt - for TFO We try not to reset
		 * the local connection unless it's really necessary to
		 * avoid becoming vulnerable to outside attack aiming at
		 * resetting legit local connections.
		 */
		req->rsk_ops->send_reset(sk, skb);
	} else if (fastopen) { /* received a valid RST pkt */
		reqsk_fastopen_remove(sk, req, true);
		tcp_reset(sk);
	}
	if (!fastopen) {
		inet_csk_reqsk_queue_drop(sk, req);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_EMBRYONICRSTS);
	}
	return NULL;
}

struct sock *tcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif
	struct ip_options_rcu *inet_opt;

	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	newsk = tcp_create_openreq_child(sk, req, skb);   //创建新socket
	if (!newsk)
		goto exit_nonewsk;

	newsk->sk_gso_type = SKB_GSO_TCPV4;
	inet_sk_rx_dst_set(newsk, skb);

	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	sk_daddr_set(newsk, ireq->ir_rmt_addr);
	sk_rcv_saddr_set(newsk, ireq->ir_loc_addr);
	newinet->inet_saddr	      = ireq->ir_loc_addr;   //修改源IP
	inet_opt	      = ireq->opt;
	rcu_assign_pointer(newinet->inet_opt, inet_opt);
	ireq->opt	      = NULL;
	newinet->mc_index     = inet_iif(skb);
	newinet->mc_ttl	      = ip_hdr(skb)->ttl;
	newinet->rcv_tos      = ip_hdr(skb)->tos;
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	inet_set_txhash(newsk);
	if (inet_opt)
		inet_csk(newsk)->icsk_ext_hdr_len = inet_opt->opt.optlen;
	newinet->inet_id = newtp->write_seq ^ jiffies;

	if (!dst) {
		dst = inet_csk_route_child_sock(sk, newsk, req);
		if (!dst)
			goto put_and_exit;
	} else {
		/* syncookie case : see end of cookie_v4_check() */
	}
	sk_setup_caps(newsk, dst);

	tcp_ca_openreq_child(newsk, dst);

	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric_advmss(dst);
	if (tcp_sk(sk)->rx_opt.user_mss &&
	    tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = tcp_sk(sk)->rx_opt.user_mss;

	tcp_initialize_rcv_mss(newsk);

#ifdef CONFIG_TCP_MD5SIG
	/* Copy over the MD5 key from the original socket */
	key = tcp_md5_do_lookup(sk, (union tcp_md5_addr *)&newinet->inet_daddr,
				AF_INET);
	if (key) {
		/*
		 * We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		tcp_md5_do_add(newsk, (union tcp_md5_addr *)&newinet->inet_daddr,
			       AF_INET, key->key, key->keylen, GFP_ATOMIC);
		sk_nocaps_add(newsk, NETIF_F_GSO_MASK);
	}
#endif

	if (__inet_inherit_port(sk, newsk) < 0)
		goto put_and_exit;
	__inet_hash_nolisten(newsk, NULL);

	return newsk;

exit_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit_nonewsk:
	dst_release(dst);
exit:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return NULL;
put_and_exit:
	inet_csk_prepare_forced_close(newsk);
	tcp_done(newsk);
	goto exit;
}

struct sock *tcp_create_openreq_child(struct sock *sk, struct request_sock *req, struct sk_buff *skb)
{
	struct sock *newsk = inet_csk_clone_lock(sk, req, GFP_ATOMIC);

	if (newsk) {
		const struct inet_request_sock *ireq = inet_rsk(req);
		struct tcp_request_sock *treq = tcp_rsk(req);
		struct inet_connection_sock *newicsk = inet_csk(newsk);
		struct tcp_sock *newtp = tcp_sk(newsk);

		/* Now setup tcp_sock */
		newtp->pred_flags = 0;

		newtp->rcv_wup = newtp->copied_seq =
		newtp->rcv_nxt = treq->rcv_isn + 1;

		newtp->snd_sml = newtp->snd_una =
		newtp->snd_nxt = newtp->snd_up = treq->snt_isn + 1;

		tcp_prequeue_init(newtp);
		INIT_LIST_HEAD(&newtp->tsq_node);

		tcp_init_wl(newtp, treq->rcv_isn);

		newtp->srtt_us = 0;
		newtp->mdev_us = jiffies_to_usecs(TCP_TIMEOUT_INIT);
		newicsk->icsk_rto = TCP_TIMEOUT_INIT;

		newtp->packets_out = 0;
		newtp->retrans_out = 0;
		newtp->sacked_out = 0;
		newtp->fackets_out = 0;
		newtp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
		tcp_enable_early_retrans(newtp);
		newtp->tlp_high_seq = 0;
		newtp->lsndtime = treq->snt_synack;
		newtp->last_oow_ack_time = 0;
		newtp->total_retrans = req->num_retrans;

		/* So many TCP implementations out there (incorrectly) count the
		 * initial SYN frame in their delayed-ACK and congestion control
		 * algorithms that we must have the following bandaid to talk
		 * efficiently to them.  -DaveM
		 */
		newtp->snd_cwnd = TCP_INIT_CWND;
		newtp->snd_cwnd_cnt = 0;

		tcp_init_xmit_timers(newsk);
		__skb_queue_head_init(&newtp->out_of_order_queue);
		newtp->write_seq = newtp->pushed_seq = treq->snt_isn + 1;

		newtp->rx_opt.saw_tstamp = 0;

		newtp->rx_opt.dsack = 0;
		newtp->rx_opt.num_sacks = 0;

		newtp->urg_data = 0;

		if (sock_flag(newsk, SOCK_KEEPOPEN))
			inet_csk_reset_keepalive_timer(newsk,
						       keepalive_time_when(newtp));

		newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;
		if ((newtp->rx_opt.sack_ok = ireq->sack_ok) != 0) {
			if (sysctl_tcp_fack)
				tcp_enable_fack(newtp);
		}
		newtp->window_clamp = req->window_clamp;
		newtp->rcv_ssthresh = req->rcv_wnd;
		newtp->rcv_wnd = req->rcv_wnd;
		newtp->rx_opt.wscale_ok = ireq->wscale_ok;
		if (newtp->rx_opt.wscale_ok) {
			newtp->rx_opt.snd_wscale = ireq->snd_wscale;
			newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
		} else {
			newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
			newtp->window_clamp = min(newtp->window_clamp, 65535U);
		}
		newtp->snd_wnd = (ntohs(tcp_hdr(skb)->window) <<
				  newtp->rx_opt.snd_wscale);
		newtp->max_window = newtp->snd_wnd;

		if (newtp->rx_opt.tstamp_ok) {
			newtp->rx_opt.ts_recent = req->ts_recent;
			newtp->rx_opt.ts_recent_stamp = get_seconds();
			newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		} else {
			newtp->rx_opt.ts_recent_stamp = 0;
			newtp->tcp_header_len = sizeof(struct tcphdr);
		}
		newtp->tsoffset = 0;
#ifdef CONFIG_TCP_MD5SIG
		newtp->md5sig_info = NULL;	/*XXX*/
		if (newtp->af_specific->md5_lookup(sk, newsk))
			newtp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif
		if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
			newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
		newtp->rx_opt.mss_clamp = req->mss;
		tcp_ecn_openreq_child(newtp, req);
		newtp->fastopen_rsk = NULL;
		newtp->syn_data_acked = 0;

		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_PASSIVEOPENS);
	}
	return newsk;
}

struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);

	if (newsk) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;          //设置socket状态为syn recv
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->ir_rmt_port;  //设置目的端口
		inet_sk(newsk)->inet_num = inet_rsk(req)->ir_num;
		inet_sk(newsk)->inet_sport = htons(inet_rsk(req)->ir_num);  //设置源端口
		newsk->sk_write_space = sk_stream_write_space;

		newsk->sk_mark = inet_rsk(req)->ir_mark;
		atomic64_set(&newsk->sk_cookie,
			     atomic64_read(&inet_rsk(req)->ir_cookie));

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}


struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority)
{
	struct sock *newsk;
	bool is_charged = true;

	newsk = sk_prot_alloc(sk->sk_prot, priority, sk->sk_family);
	if (newsk != NULL) {
		struct sk_filter *filter;

		sock_copy(newsk, sk);

		/* SANITY */
		get_net(sock_net(newsk));
		sk_node_init(&newsk->sk_node);
		sock_lock_init(newsk);
		bh_lock_sock(newsk);
		newsk->sk_backlog.head	= newsk->sk_backlog.tail = NULL;
		newsk->sk_backlog.len = 0;

		atomic_set(&newsk->sk_rmem_alloc, 0);
		/*
		 * sk_wmem_alloc set to one (see sk_free() and sock_wfree())
		 */
		atomic_set(&newsk->sk_wmem_alloc, 1);
		atomic_set(&newsk->sk_omem_alloc, 0);
		skb_queue_head_init(&newsk->sk_receive_queue);
		skb_queue_head_init(&newsk->sk_write_queue);

		spin_lock_init(&newsk->sk_dst_lock);
		rwlock_init(&newsk->sk_callback_lock);
		lockdep_set_class_and_name(&newsk->sk_callback_lock,
				af_callback_keys + newsk->sk_family,
				af_family_clock_key_strings[newsk->sk_family]);

		newsk->sk_dst_cache	= NULL;
		newsk->sk_wmem_queued	= 0;
		newsk->sk_forward_alloc = 0;
		newsk->sk_send_head	= NULL;
		newsk->sk_userlocks	= sk->sk_userlocks & ~SOCK_BINDPORT_LOCK;

		sock_reset_flag(newsk, SOCK_DONE);
		skb_queue_head_init(&newsk->sk_error_queue);

		filter = rcu_dereference_protected(newsk->sk_filter, 1);
		if (filter != NULL)
			/* though it's an empty new sock, the charging may fail
			 * if sysctl_optmem_max was changed between creation of
			 * original socket and cloning
			 */
			is_charged = sk_filter_charge(newsk, filter);

		if (unlikely(!is_charged || xfrm_sk_clone_policy(newsk))) {
			/* It is still raw copy of parent, so invalidate
			 * destructor and make plain sk_free() */
			newsk->sk_destruct = NULL;
			bh_unlock_sock(newsk);
			sk_free(newsk);
			newsk = NULL;
			goto out;
		}

		newsk->sk_err	   = 0;
		newsk->sk_priority = 0;
		newsk->sk_incoming_cpu = raw_smp_processor_id();
		atomic64_set(&newsk->sk_cookie, 0);
		/*
		 * Before updating sk_refcnt, we must commit prior changes to memory
		 * (Documentation/RCU/rculist_nulls.txt for details)
		 */
		smp_wmb();
		atomic_set(&newsk->sk_refcnt, 2);

		/*
		 * Increment the counter in the same struct proto as the master
		 * sock (sk_refcnt_debug_inc uses newsk->sk_prot->socks, that
		 * is the same as sk->sk_prot->socks, as this field was copied
		 * with memcpy).
		 *
		 * This _changes_ the previous behaviour, where
		 * tcp_create_openreq_child always was incrementing the
		 * equivalent to tcp_prot->socks (inet_sock_nr), so this have
		 * to be taken into account in all callers. -acme
		 */
		sk_refcnt_debug_inc(newsk);
		sk_set_socket(newsk, NULL);
		newsk->sk_wq = NULL;

		sk_update_clone(sk, newsk);

		if (newsk->sk_prot->sockets_allocated)
			sk_sockets_allocated_inc(newsk);

		if (newsk->sk_flags & SK_FLAGS_TIMESTAMP)
			net_enable_timestamp();
	}
out:
	return newsk;
}
```


## tcp_v4_conn_request

tcp_rcv_state_process函数处理中，当socket状态处于listen状态时，会调用ipv4_specific的conn_request函数

```c
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	/* Never answer to SYNs send to broadcast or multicast */
	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	return tcp_conn_request(&tcp_request_sock_ops,
				&tcp_request_sock_ipv4_ops, sk, skb);

drop:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0;
}


int tcp_conn_request(struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
{
	struct tcp_options_received tmp_opt;
	struct request_sock *req;
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = NULL;
	__u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
	bool want_cookie = false, fastopen;
	struct flowi fl;
	struct tcp_fastopen_cookie foc = { .len = -1 };
	int err;


	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	if ((sysctl_tcp_syncookies == 2 ||
	     inet_csk_reqsk_queue_is_full(sk)) && !isn) {
		want_cookie = tcp_syn_flood_action(sk, skb, rsk_ops->slab_name);
		if (!want_cookie)
			goto drop;
	}


	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
		goto drop;
	}

	req = inet_reqsk_alloc(rsk_ops, sk);   //申请conn request
	if (!req)
		goto drop;

	tcp_rsk(req)->af_specific = af_ops;

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = af_ops->mss_clamp;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, 0, want_cookie ? NULL : &foc);

	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb, sk);

	/* Note: tcp_v6_init_req() might override ir_iif for link locals */
	inet_rsk(req)->ir_iif = sk->sk_bound_dev_if;

	af_ops->init_req(req, sk, skb);   //初始化request

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	if (!want_cookie && !isn) {
		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tcp_death_row.sysctl_tw_recycle) {
			bool strict;

			dst = af_ops->route_req(sk, &fl, req, &strict);

			if (dst && strict &&
			    !tcp_peer_is_proven(req, dst, true,
						tmp_opt.saw_tstamp)) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 !tcp_peer_is_proven(req, dst, false,
					     tmp_opt.saw_tstamp)) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			pr_drop_req(req, ntohs(tcp_hdr(skb)->source),
				    rsk_ops->family);
			goto drop_and_release;
		}

		isn = af_ops->init_seq(skb);
	}
	if (!dst) {
		dst = af_ops->route_req(sk, &fl, req, NULL);
		if (!dst)
			goto drop_and_free;
	}

	tcp_ecn_create_request(req, skb, sk, dst);

	if (want_cookie) {
		isn = cookie_init_sequence(af_ops, sk, skb, &req->mss);
		req->cookie_ts = tmp_opt.tstamp_ok;
		if (!tmp_opt.tstamp_ok)
			inet_rsk(req)->ecn_ok = 0;
	}

	tcp_rsk(req)->snt_isn = isn;
	tcp_openreq_init_rwin(req, sk, dst);
	fastopen = !want_cookie &&
		   tcp_try_fastopen(sk, skb, req, &foc, dst);
	err = af_ops->send_synack(sk, dst, &fl, req,          //发送syn+ack
				  skb_get_queue_mapping(skb), &foc);
	if (!fastopen) {
		if (err || want_cookie)
			goto drop_and_free;

		tcp_rsk(req)->tfo_listener = false;
		af_ops->queue_hash_add(sk, req, TCP_TIMEOUT_INIT);    //添加request到hash表，调用tcp_request_sock_ops的函数
	}

	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
drop:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0;
}

void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	const u32 h = inet_synq_hash(inet_rsk(req)->ir_rmt_addr,
				     inet_rsk(req)->ir_rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}

void reqsk_queue_hash_req(struct request_sock_queue *queue,
			  u32 hash, struct request_sock *req,
			  unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->num_retrans = 0;
	req->num_timeout = 0;
	req->sk = NULL;

	setup_timer(&req->rsk_timer, reqsk_timer_handler, (unsigned long)req);
	mod_timer_pinned(&req->rsk_timer, jiffies + timeout);
	req->rsk_hash = hash;

	/* before letting lookups find us, make sure all req fields
	 * are committed to memory and refcnt initialized.
	 */
	smp_wmb();
	atomic_set(&req->rsk_refcnt, 2);

	spin_lock(&queue->syn_wait_lock);
	req->dl_next = lopt->syn_table[hash];
	lopt->syn_table[hash] = req;
	spin_unlock(&queue->syn_wait_lock);
}
```

