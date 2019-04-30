# UDP协议

本文将介绍UDP的收发包处理流程。


## 基本数据结构

```c
// UDP协议收包
static const struct net_protocol udp_protocol = {
	.early_demux =	udp_v4_early_demux,
	.handler =	udp_rcv,
	.err_handler =	udp_err,
	.no_policy =	1,
	.netns_ok =	1,
};

// UDP SOCKET
struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = __udp_queue_rcv_skb,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v4_rehash,
	.get_port	   = udp_v4_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
	.obj_size	   = sizeof(struct udp_sock),
	.slab_flags	   = SLAB_DESTROY_BY_RCU,
	.h.udp_table	   = &udp_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	.clear_sk	   = sk_prot_clear_portaddr_nulls,
};

// UDP SOCKET ops
const struct proto_ops inet_dgram_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,      //UDP SOCKET也没有accept
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,    //UDP SOCKET不需要listen
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};
```


## UDP协议收包处理

```c
int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

int __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);	//得到路由表项信息
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);

	/*
	 *  Validate the packet.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))		//检测报文长度
		goto drop;		/* No space for header. */

	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	if (ulen > skb->len)  //skb报文长度必须UDP头设定的长度，skb可能存在pad
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))	//裁剪skb报文
			goto short_packet;
		uh = udp_hdr(skb);
	}

	if (udp4_csum_init(skb, uh, proto))	//csum值校验，如果非零则表示csum错误
		goto csum_error;

	sk = skb_steal_sock(skb);	//IP层调用UDP的early_demux函数设置的sk
	if (sk) {
		struct dst_entry *dst = skb_dst(skb);
		int ret;

		if (unlikely(sk->sk_rx_dst != dst))
			udp_sk_rx_dst_set(sk, dst);

		//sock处理skb报文，如果定义了encap_rcv，则会调用此函数处理报文，例如vxlan端口场景
		ret = udp_queue_rcv_skb(sk, skb);	
		sock_put(sk);
		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}

	if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return __udp4_lib_mcast_deliver(net, skb, uh,		//组播报文上送
						saddr, daddr, udptable, proto);

	sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);	//全量检索sock
	if (sk) {
		int ret;

		//如果skb->ip_summed == CHECKSUM_NONE，重置csum
		if (inet_get_convert_csum(sk) && uh->check && !IS_UDPLITE(sk))
			skb_checksum_try_convert(skb, IPPROTO_UDP, uh->check,	
						 inet_compute_pseudo);

		ret = udp_queue_rcv_skb(sk, skb);	//sock处理skb报文
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}
	
	// 未检索到socket
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))	//ipset安全检测
		goto drop;
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_lib_checksum_complete(skb))	//没有socket，如果checksum出错则直接丢弃
		goto csum_error;

	UDP_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);	//发送icmp，通知发送方目的不可达

	/*
	 * Hmm.  We got an UDP packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb);
	return 0;

short_packet:
	net_dbg_ratelimited("UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
			    proto == IPPROTO_UDPLITE ? "Lite" : "",
			    &saddr, ntohs(uh->source),
			    ulen, skb->len,
			    &daddr, ntohs(uh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	net_dbg_ratelimited("UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
			    proto == IPPROTO_UDPLITE ? "Lite" : "",
			    &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
			    ulen);
	UDP_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);	//UDP csum错误统计
drop:
	UDP_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);	//UDP in error错误统计
	kfree_skb(skb);
	return 0;
}

int udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))	  //xfrm检测
		goto drop;
	nf_reset(skb);

	if (static_key_false(&udp_encap_needed) && up->encap_type) {
		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
		 * This is an encapsulation socket so pass the skb to
		 * the socket's udp_encap_rcv() hook. Otherwise, just
		 * fall through and pass this up the UDP socket.
		 * up->encap_rcv() returns the following value:
		 * =0 if skb was successfully passed to the encap
		 *    handler or was discarded by it.
		 * >0 if skb should be passed on to UDP.
		 * <0 if skb should be resubmitted as proto -N
		 */

		/* if we're overly short, let UDP handle it */
		encap_rcv = ACCESS_ONCE(up->encap_rcv);
		if (skb->len > sizeof(struct udphdr) && encap_rcv) {
			int ret;

			/* Verify checksum before giving to encap */
			if (udp_lib_checksum_complete(skb))
				goto csum_error;

			ret = encap_rcv(sk, skb);	 //报文处理，例如vxlan报文就是通过此方式实现
			if (ret <= 0) {
				UDP_INC_STATS_BH(sock_net(sk),
						 UDP_MIB_INDATAGRAMS,
						 is_udplite);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
	if ((is_udplite & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			net_dbg_ratelimited("UDPLite: partial coverage %d while full coverage %d requested\n",
					    UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			net_dbg_ratelimited("UDPLite: coverage %d too small, need min %d\n",
					    UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (rcu_access_pointer(sk->sk_filter) &&
	    udp_lib_checksum_complete(skb))		//报文checksum检测
		goto csum_error;

	if (sk_rcvqueues_full(sk, sk->sk_rcvbuf)) {
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
				 is_udplite);
		goto drop;
	}

	rc = 0;

	ipv4_pktinfo_prepare(sk, skb);
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		rc = __udp_queue_rcv_skb(sk, skb);	   //报文保存到sk的接收队列，并通知用户进程
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		bh_unlock_sock(sk);
		goto drop;
	}
	bh_unlock_sock(sk);

	return rc;

csum_error:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
drop:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}

static int __udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
		sk_incoming_cpu_update(sk);
	}

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 is_udplite);
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
		kfree_skb(skb);
		trace_udp_fail_queue_rcv_skb(rc, sk);
		return -1;
	}

	return 0;

}

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int err;
	unsigned long flags;
	struct sk_buff_head *list = &sk->sk_receive_queue;	//sock接收队列

	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf) {
		atomic_inc(&sk->sk_drops);
		trace_sock_rcvqueue_full(sk, skb);
		return -ENOMEM;
	}

	err = sk_filter(sk, skb);
	if (err)
		return err;

	if (!sk_rmem_schedule(sk, skb, skb->truesize)) {
		atomic_inc(&sk->sk_drops);
		return -ENOBUFS;
	}

	skb->dev = NULL;
	skb_set_owner_r(skb, sk);

	/* we escape from rcu protected region, make sure we dont leak
	 * a norefcounted dst
	 */
	skb_dst_force(skb);

	spin_lock_irqsave(&list->lock, flags);
	sock_skb_set_dropcount(sk, skb);
	__skb_queue_tail(list, skb);					//发送到接收队列
	spin_unlock_irqrestore(&list->lock, flags);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk);			//唤醒wait队列
	return 0;
}
```

###  查询UDP socket 

```c
static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
						 __be16 sport, __be16 dport,
						 struct udp_table *udptable)
{
	const struct iphdr *iph = ip_hdr(skb);

	return __udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, sport,  //设备的网络空间
				 iph->daddr, dport, inet_iif(skb),
				 udptable);
}

struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
		__be16 sport, __be32 daddr, __be16 dport,
		int dif, struct udp_table *udptable)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2, slot = udp_hashfn(net, hnum, udptable->mask);  //根据端口号计算hash
	struct udp_hslot *hslot2, *hslot = &udptable->hash[slot];
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

	rcu_read_lock();
	if (hslot->count > 10) {   //数量过多，使用hash2计算方法，以提速
		hash2 = udp4_portaddr_hash(net, daddr, hnum);   //根据目的IP和端口号计算hash
		slot2 = hash2 & udptable->mask;
		hslot2 = &udptable->hash2[slot2];
		if (hslot->count < hslot2->count)
			goto begin;

		result = udp4_lib_lookup2(net, saddr, sport,   //根据源ip、源端口、目的IP、目的端口查找
					  daddr, hnum, dif,
					  hslot2, slot2);
		if (!result) {
			hash2 = udp4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
			slot2 = hash2 & udptable->mask;
			hslot2 = &udptable->hash2[slot2];
			if (hslot->count < hslot2->count)
				goto begin;

			result = udp4_lib_lookup2(net, saddr, sport, //根据源ip、源端口、目的端口查找
						  htonl(INADDR_ANY), hnum, dif,
						  hslot2, slot2);
		}
		rcu_read_unlock();
		return result;
	}
begin:
	result = NULL;
	badness = 0;
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		score = compute_score(sk, net, saddr, hnum, sport,
				      daddr, dport, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (reciprocal_scale(hash, matches) == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;

	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score(result, net, saddr, hnum, sport,
				  daddr, dport, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}

static struct sock *udp4_lib_lookup2(struct net *net,
		__be32 saddr, __be16 sport,
		__be32 daddr, unsigned int hnum, int dif,
		struct udp_hslot *hslot2, unsigned int slot2)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

begin:
	result = NULL;
	badness = 0;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		score = compute_score2(sk, net, saddr, sport,
				      daddr, hnum, dif);
		if (score > badness) {   //根据分数来选择最优的socket，
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (reciprocal_scale(hash, matches) == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot2)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score2(result, net, saddr, sport,
				  daddr, hnum, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	return result;
}

static inline int compute_score(struct sock *sk, struct net *net,
				__be32 saddr, unsigned short hnum, __be16 sport,
				__be32 daddr, __be16 dport, int dif)
{
	int score;
	struct inet_sock *inet;

	if (!net_eq(sock_net(sk), net) ||
	    udp_sk(sk)->udp_port_hash != hnum ||    //协议需要相同
	    ipv6_only_sock(sk))
		return -1;

	score = (sk->sk_family == PF_INET) ? 2 : 1;   //协议号相同可以得分
	inet = inet_sk(sk);

	if (inet->inet_rcv_saddr) {
		if (inet->inet_rcv_saddr != daddr)   //指定本地IP地址
			return -1;
		score += 4;
	}

	if (inet->inet_daddr) {
		if (inet->inet_daddr != saddr)    //指定对端IP地址
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)    //指定对端port
			return -1;
		score += 4;
	}

	if (sk->sk_bound_dev_if) {
		if (sk->sk_bound_dev_if != dif)
			return -1;
		score += 4;
	}

	return score;
}

static inline int compute_score2(struct sock *sk, struct net *net,
				 __be32 saddr, __be16 sport,
				 __be32 daddr, unsigned int hnum, int dif)
{
	int score;
	struct inet_sock *inet;

	if (!net_eq(sock_net(sk), net) ||
	    ipv6_only_sock(sk))
		return -1;

	inet = inet_sk(sk);

	if (inet->inet_rcv_saddr != daddr ||   //指定本端IP，指定本端端口
	    inet->inet_num != hnum)
		return -1;

	score = (sk->sk_family == PF_INET) ? 2 : 1;

	if (inet->inet_daddr) {
		if (inet->inet_daddr != saddr)   //指定对端IP
			return -1;
		score += 4;
	}

	if (inet->inet_dport) {
		if (inet->inet_dport != sport)   //指定对端port
			return -1;
		score += 4;
	}

	if (sk->sk_bound_dev_if) {
		if (sk->sk_bound_dev_if != dif)
			return -1;
		score += 4;
	}

	return score;
}
```


##  用户态使用UDP Socket

服务器端示意代码如下：

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define SERVER_PORT 8888
#define BUFF_LEN 1024

void handle_udp_msg(int fd)
{
    char buf[BUFF_LEN];  //接收缓冲区，1024字节
    socklen_t len;
    int count;
    struct sockaddr_in clent_addr;  //clent_addr用于记录发送方的地址信息
    while(1)
    {
        memset(buf, 0, BUFF_LEN);
        len = sizeof(clent_addr);
        count = recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  //recvfrom是拥塞函数，没有数据就一直拥塞
        if(count == -1)
        {
            printf("recieve data fail!\n");
            return;
        }
        printf("client:%s\n",buf);  //打印client发过来的信息
        memset(buf, 0, BUFF_LEN);
        sprintf(buf, "I have recieved %d bytes data!\n", count);  //回复client
        printf("server:%s\n",buf);  //打印自己发送的信息给
        sendto(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, len);  //发送信息给client，注意使用了clent_addr结构体指针

    }
}

int main(int argc, char* argv[])
{
    int server_fd, ret;
    struct sockaddr_in ser_addr; 

    server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
    if(server_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(SERVER_PORT);  //端口号，需要网络序转换

	//绑定本地端口
    ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return -1;
    }

    handle_udp_msg(server_fd);   //处理接收到的数据

    close(server_fd);
    return 0;
}
```

客户端示意代码如下：

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define SERVER_PORT 8888
#define BUFF_LEN 512
#define SERVER_IP "172.0.5.182"

void udp_msg_sender(int fd, struct sockaddr* dst)
{

    socklen_t len;
    struct sockaddr_in src;
    while(1)
    {
        char buf[BUFF_LEN] = "TEST UDP MSG!\n";
        len = sizeof(*dst);
        printf("client:%s\n",buf);  //打印自己发送的信息
        sendto(fd, buf, BUFF_LEN, 0, dst, len);
        memset(buf, 0, BUFF_LEN);
        recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&src, &len);  //接收来自server的信息
        printf("server:%s\n",buf);
        sleep(1);  //一秒发送一次消息
    }
}

int main(int argc, char* argv[])
{
    int client_fd;
    struct sockaddr_in ser_addr;

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //注意网络序转换
    ser_addr.sin_port = htons(SERVER_PORT);  //注意网络序转换

    udp_msg_sender(client_fd, (struct sockaddr*)&ser_addr);

    close(client_fd);

    return 0;
}
```


##  UDP Socket bind

用户态程序调用bind系统调用，最终会调用到inet_sockraw_ops的bind函数。

```c

int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {    //UDP socket未定义此函数
		err = sk->sk_prot->bind(sk, uaddr, addr_len);
		goto out;
	}
	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	if (addr->sin_family != AF_INET) {
		/* Compatibility games : accept AF_UNSPEC (mapped to AF_INET)
		 * only if s_addr is INADDR_ANY.
		 */
		err = -EAFNOSUPPORT;
		if (addr->sin_family != AF_UNSPEC ||
		    addr->sin_addr.s_addr != htonl(INADDR_ANY))
			goto out;
	}

	chk_addr_ret = inet_addr_type(net, addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (!net->ipv4.sysctl_ip_nonlocal_bind &&
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	if (snum && snum < PROT_SOCK &&
	    !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))   //不允许绑定服务端口
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;   //设置本端IP地址
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num);   //如果addr->sin_port未被使用，则使用该端口设置为 本端口
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;
out_release_sock:
	release_sock(sk);
out:
	return err;
}

int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		udp4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		udp4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal, hash2_nulladdr);
}


int udp_lib_get_port(struct sock *sk, unsigned short snum,
		     int (*saddr_comp)(const struct sock *sk1,
				       const struct sock *sk2),
		     unsigned int hash2_nulladdr)
{
	struct udp_hslot *hslot, *hslot2;
	struct udp_table *udptable = sk->sk_prot->h.udp_table;
	int    error = 1;
	struct net *net = sock_net(sk);

	if (!snum) {
		int low, high, remaining;
		unsigned int rand;
		unsigned short first, last;
		DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);

		inet_get_local_port_range(net, &low, &high);
		remaining = (high - low) + 1;

		rand = prandom_u32();
		first = reciprocal_scale(rand, remaining) + low;
		/*
		 * force rand to be an odd multiple of UDP_HTABLE_SIZE
		 */
		rand = (rand | 1) * (udptable->mask + 1);
		last = first + udptable->mask + 1;
		do {
			hslot = udp_hashslot(udptable, net, first);
			bitmap_zero(bitmap, PORTS_PER_CHAIN);
			spin_lock_bh(&hslot->lock);
			udp_lib_lport_inuse(net, snum, hslot, bitmap, sk,
					    saddr_comp, udptable->log);

			snum = first;
			/*
			 * Iterate on all possible values of snum for this hash.
			 * Using steps of an odd multiple of UDP_HTABLE_SIZE
			 * give us randomization and full range coverage.
			 */
			do {
				if (low <= snum && snum <= high &&
				    !test_bit(snum >> udptable->log, bitmap) &&
				    !inet_is_local_reserved_port(net, snum))
					goto found;
				snum += rand;
			} while (snum != first);
			spin_unlock_bh(&hslot->lock);
		} while (++first != last);
		goto fail;
	} else {
		hslot = udp_hashslot(udptable, net, snum);
		spin_lock_bh(&hslot->lock);
		if (hslot->count > 10) {
			int exist;
			unsigned int slot2 = udp_sk(sk)->udp_portaddr_hash ^ snum;

			slot2          &= udptable->mask;
			hash2_nulladdr &= udptable->mask;

			hslot2 = udp_hashslot2(udptable, slot2);
			if (hslot->count < hslot2->count)
				goto scan_primary_hash;

			exist = udp_lib_lport_inuse2(net, snum, hslot2,
						     sk, saddr_comp);
			if (!exist && (hash2_nulladdr != slot2)) {
				hslot2 = udp_hashslot2(udptable, hash2_nulladdr);
				exist = udp_lib_lport_inuse2(net, snum, hslot2,
							     sk, saddr_comp);
			}
			if (exist)
				goto fail_unlock;
			else
				goto found;
		}
scan_primary_hash:
		if (udp_lib_lport_inuse(net, snum, hslot, NULL, sk,
					saddr_comp, 0))
			goto fail_unlock;
	}
found:
	inet_sk(sk)->inet_num = snum;      //如果snum未被使用，则使用该端口号
	udp_sk(sk)->udp_port_hash = snum;
	udp_sk(sk)->udp_portaddr_hash ^= snum;
	if (sk_unhashed(sk)) {             //未添加到udp_table中，未bind时，udp协议栈收包时找不到此socket
		sk_nulls_add_node_rcu(sk, &hslot->head);
		hslot->count++;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash); 
		spin_lock(&hslot2->lock);
		hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
					 &hslot2->head);
		hslot2->count++;
		spin_unlock(&hslot2->lock);
	}
	error = 0;
fail_unlock:
	spin_unlock_bh(&hslot->lock);
fail:
	return error;
}
```


##  UDP Socket connect

用户态程序调用connect系统调用，最终会调用到inet_sockraw_ops的connect函数。

```c
int inet_dgram_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	if (!inet_sk(sk)->inet_num && inet_autobind(sk))
		return -EAGAIN;
	return sk->sk_prot->connect(sk, uaddr, addr_len);   //调用proto的connect
}


int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int res;

	lock_sock(sk);
	res = __ip4_datagram_connect(sk, uaddr, addr_len);
	release_sock(sk);
	return res;
}

int __ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *) uaddr;   //目的IP和目的PORT
	struct flowi4 *fl4;
	struct rtable *rt;
	__be32 saddr;
	int oif;
	int err;


	if (addr_len < sizeof(*usin))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	sk_dst_reset(sk);

	oif = sk->sk_bound_dev_if;
	saddr = inet->inet_saddr;
	if (ipv4_is_multicast(usin->sin_addr.s_addr)) {
		if (!oif)
			oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	}
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, usin->sin_addr.s_addr, saddr,
			      RT_CONN_FLAGS(sk), oif,
			      sk->sk_protocol,
			      inet->inet_sport, usin->sin_port, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		goto out;
	}

	if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST)) {
		ip_rt_put(rt);
		err = -EACCES;
		goto out;
	}
	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;	//设置本端的IP
	if (!inet->inet_rcv_saddr) {
		inet->inet_rcv_saddr = fl4->saddr;
		if (sk->sk_prot->rehash)		//重新计算hash，将改变udp socket在udptable中的位置
			sk->sk_prot->rehash(sk);
	}
	inet->inet_daddr = fl4->daddr;      //设置对端的IP
	inet->inet_dport = usin->sin_port;  //设置对端的端口
	sk->sk_state = TCP_ESTABLISHED;
	inet_set_txhash(sk);
	inet->inet_id = jiffies;

	sk_dst_set(sk, &rt->dst);
	err = 0;
out:
	return err;
}
```


##  UDP Socket 发送报文

```c
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(sk, msg, size);
}

int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;

	getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}
	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;

	sock_tx_timestamp(sk, &ipc.tx_flags);

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sock_net(sk), msg, &ipc,
				   sk->sk_family == AF_INET6);
		if (err)
			return err;
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (!rt) {
		struct net *net = sock_net(sk);

		fl4 = &fl4_stack;
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   inet_sk_flowi_flags(sk),
				   faddr, saddr, dport, inet->inet_sport);

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			err = udp_send_skb(skb, fl4);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited("cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, fl4, getfrag, msg, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}
```

### ip_make_skb

```c
struct sk_buff *ip_make_skb(struct sock *sk,
			    struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    unsigned int flags)
{
	struct inet_cork cork;
	struct sk_buff_head queue;
	int err;

	if (flags & MSG_PROBE)
		return NULL;

	__skb_queue_head_init(&queue);

	cork.flags = 0;
	cork.addr = 0;
	cork.opt = NULL;
	err = ip_setup_cork(sk, &cork, ipc, rtp);
	if (err)
		return ERR_PTR(err);

	err = __ip_append_data(sk, fl4, &queue, &cork,
			       &current->task_frag, getfrag,
			       from, length, transhdrlen, flags);
	if (err) {
		__ip_flush_pending_frames(sk, &queue, &cork);
		return ERR_PTR(err);
	}

	return __ip_make_skb(sk, fl4, &queue, &cork);
}

struct sk_buff *__ip_make_skb(struct sock *sk,
			      struct flowi4 *fl4,
			      struct sk_buff_head *queue,
			      struct inet_cork *cork)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)cork->dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;

	skb = __skb_dequeue(queue);
	if (!skb)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));
	while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	skb->ignore_df = ip_sk_ignore_df(sk);

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If ignore_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    inet->pmtudisc == IP_PMTUDISC_PROBE ||
	    (skb->len <= dst_mtu(&rt->dst) &&
	     ip_dont_fragment(sk, &rt->dst)))
		df = htons(IP_DF);

	if (cork->flags & IPCORK_OPT)
		opt = cork->opt;

	if (cork->ttl != 0)
		ttl = cork->ttl;
	else if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->dst);

	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = (cork->tos != -1) ? cork->tos : inet->tos;
	iph->frag_off = df;
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	ip_copy_addrs(iph, fl4);
	ip_select_ident(net, skb, sk);

	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, cork->addr, rt, 0);
	}

	skb->priority = (cork->tos != -1) ? cork->priority: sk->sk_priority;
	skb->mark = sk->sk_mark;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	cork->dst = NULL;
	skb_dst_set(skb, &rt->dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	ip_cork_release(cork);
out:
	return skb;
}
```


### udp_send_skb

```c
static int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	if (is_udplite)  				 /*     UDP-Lite      */
		csum = udplite_csum(skb);

	else if (sk->sk_no_check_tx) {   /* UDP csum disabled */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS_USER(sock_net(sk),
				   UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}

int ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;

	err = ip_local_out(skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	return err;
}
```

