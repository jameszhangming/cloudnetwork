# Netlink

Netlink是Linux系统用于用户态和内核态进行通信的机制，本文将介绍Netlink Socket的工作原理

## Netlink procotol

```c
#define NETLINK_ROUTE		0	/* Routing/device hook				*/
#define NETLINK_UNUSED		1	/* Unused number				*/
#define NETLINK_USERSOCK	2	/* Reserved for user mode socket protocols 	*/
#define NETLINK_FIREWALL	3	/* Unused number, formerly ip_queue		*/
#define NETLINK_SOCK_DIAG	4	/* socket monitoring				*/
#define NETLINK_NFLOG		5	/* netfilter/iptables ULOG */
#define NETLINK_XFRM		6	/* ipsec */
#define NETLINK_SELINUX		7	/* SELinux event notifications */
#define NETLINK_ISCSI		8	/* Open-iSCSI */
#define NETLINK_AUDIT		9	/* auditing */
#define NETLINK_FIB_LOOKUP	10	
#define NETLINK_CONNECTOR	11
#define NETLINK_NETFILTER	12	/* netfilter subsystem */
#define NETLINK_IP6_FW		13
#define NETLINK_DNRTMSG		14	/* DECnet routing messages */
#define NETLINK_KOBJECT_UEVENT	15	/* Kernel messages to userspace */
#define NETLINK_GENERIC		16
/* leave room for NETLINK_DM (DM Events) */
#define NETLINK_SCSITRANSPORT	18	/* SCSI Transports */
#define NETLINK_ECRYPTFS	19
#define NETLINK_RDMA		20
#define NETLINK_CRYPTO		21	/* Crypto layer */
```

## 创建Netlink Socket

```c
static const struct net_proto_family netlink_family_ops = {
	.family = PF_NETLINK,
	.create = netlink_create,
	.owner	= THIS_MODULE,	/* for consistency 8) */
};

static int netlink_create(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	struct module *module = NULL;
	struct mutex *cb_mutex;
	struct netlink_sock *nlk;
	int (*bind)(struct net *net, int group);
	void (*unbind)(struct net *net, int group);
	int err = 0;

	sock->state = SS_UNCONNECTED;

	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)   //socket类型只支持这两种
		return -ESOCKTNOSUPPORT;

	if (protocol < 0 || protocol >= MAX_LINKS)
		return -EPROTONOSUPPORT;

	netlink_lock_table();
#ifdef CONFIG_MODULES
	if (!nl_table[protocol].registered) {	//判断该协议是否已经支持
		netlink_unlock_table();
		request_module("net-pf-%d-proto-%d", PF_NETLINK, protocol);
		netlink_lock_table();
	}
#endif
	if (nl_table[protocol].registered &&
	    try_module_get(nl_table[protocol].module))
		module = nl_table[protocol].module;
	else
		err = -EPROTONOSUPPORT;
	cb_mutex = nl_table[protocol].cb_mutex;
	bind = nl_table[protocol].bind;
	unbind = nl_table[protocol].unbind;
	netlink_unlock_table();

	if (err < 0)
		goto out;

	err = __netlink_create(net, sock, cb_mutex, protocol);   //创建sock
	if (err < 0)
		goto out_module;

	local_bh_disable();
	sock_prot_inuse_add(net, &netlink_proto, 1);
	local_bh_enable();

	nlk = nlk_sk(sock->sk);
	nlk->module = module;
	nlk->netlink_bind = bind;
	nlk->netlink_unbind = unbind;
out:
	return err;

out_module:
	module_put(module);
	goto out;
}

static int __netlink_create(struct net *net, struct socket *sock,
			    struct mutex *cb_mutex, int protocol)
{
	struct sock *sk;
	struct netlink_sock *nlk;

	sock->ops = &netlink_ops;    //设置socket的ops

	sk = sk_alloc(net, PF_NETLINK, GFP_KERNEL, &netlink_proto);   //netlink proto
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);     //初始sk对象

	nlk = nlk_sk(sk);
	if (cb_mutex) {
		nlk->cb_mutex = cb_mutex;
	} else {
		nlk->cb_mutex = &nlk->cb_def_mutex;
		mutex_init(nlk->cb_mutex);
	}
	init_waitqueue_head(&nlk->wait);      //初始化wait队列
#ifdef CONFIG_NETLINK_MMAP
	mutex_init(&nlk->pg_vec_lock);
#endif

	sk->sk_destruct = netlink_sock_destruct;
	sk->sk_protocol = protocol;
	return 0;
}
```

## 用户态Netlink Socket消息接收和发送

```c
static const struct proto_ops netlink_ops = {
	.family =	PF_NETLINK,
	.owner =	THIS_MODULE,
	.release =	netlink_release,
	.bind =		netlink_bind,
	.connect =	netlink_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	netlink_getname,
	.poll =		netlink_poll,
	.ioctl =	sock_no_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	netlink_setsockopt,
	.getsockopt =	netlink_getsockopt,
	.sendmsg =	netlink_sendmsg,
	.recvmsg =	netlink_recvmsg,
	.mmap =		netlink_mmap,
	.sendpage =	sock_no_sendpage,
};
```

### 用户态Netlink Socket发送消息

```c
static int netlink_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_nl *, addr, msg->msg_name);
	u32 dst_portid;
	u32 dst_group;
	struct sk_buff *skb;
	int err;
	struct scm_cookie scm;
	u32 netlink_skb_flags = 0;

	if (msg->msg_flags&MSG_OOB)
		return -EOPNOTSUPP;

	err = scm_send(sock, msg, &scm, true);
	if (err < 0)
		return err;

	if (msg->msg_namelen) {
		err = -EINVAL;
		if (addr->nl_family != AF_NETLINK)
			goto out;
		dst_portid = addr->nl_pid;         //目标socket id
		dst_group = ffs(addr->nl_groups);
		err =  -EPERM;
		if ((dst_group || dst_portid) &&
		    !netlink_allowed(sock, NL_CFG_F_NONROOT_SEND))
			goto out;
		netlink_skb_flags |= NETLINK_SKB_DST;
	} else {
		dst_portid = nlk->dst_portid;	    //目的socket id，在connect中设置
		dst_group = nlk->dst_group;
	}

	if (!nlk->bound) {
		err = netlink_autobind(sock);
		if (err)
			goto out;
	} else {
		/* Ensure nlk is hashed and visible. */
		smp_rmb();
	}

	/* It's a really convoluted way for userland to ask for mmaped
	 * sendmsg(), but that's what we've got...
	 */
	if (netlink_tx_is_mmaped(sk) &&
	    msg->msg_iter.type == ITER_IOVEC &&
	    msg->msg_iter.nr_segs == 1 &&
	    msg->msg_iter.iov->iov_base == NULL) {
		err = netlink_mmap_sendmsg(sk, msg, dst_portid, dst_group,
					   &scm);
		goto out;
	}

	err = -EMSGSIZE;
	if (len > sk->sk_sndbuf - 32)
		goto out;
	err = -ENOBUFS;
	skb = netlink_alloc_large_skb(len, dst_group);
	if (skb == NULL)
		goto out;

	NETLINK_CB(skb).portid	= nlk->portid;
	NETLINK_CB(skb).dst_group = dst_group;
	NETLINK_CB(skb).creds	= scm.creds;
	NETLINK_CB(skb).flags	= netlink_skb_flags;

	err = -EFAULT;
	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		kfree_skb(skb);
		goto out;
	}

	err = security_netlink_send(sk, skb);
	if (err) {
		kfree_skb(skb);
		goto out;
	}

	if (dst_group) {
		atomic_inc(&skb->users);
		netlink_broadcast(sk, skb, dst_portid, dst_group, GFP_KERNEL);
	}
	err = netlink_unicast(sk, skb, dst_portid, msg->msg_flags&MSG_DONTWAIT);   //向目的socket发送消息

out:
	scm_destroy(&scm);
	return err;
}

int netlink_unicast(struct sock *ssk, struct sk_buff *skb,
		    u32 portid, int nonblock)
{
	struct sock *sk;
	int err;
	long timeo;

	skb = netlink_trim(skb, gfp_any());

	timeo = sock_sndtimeo(ssk, nonblock);
retry:
	sk = netlink_getsockbyportid(ssk, portid);		//根据portid找到netlink_sock对象
	if (IS_ERR(sk)) {
		kfree_skb(skb);
		return PTR_ERR(sk);
	}
	if (netlink_is_kernel(sk))
		return netlink_unicast_kernel(sk, skb, ssk);	//如果是kernel socket 走此分支， 例如generic netlink

	if (sk_filter(sk, skb)) {
		err = skb->len;
		kfree_skb(skb);
		sock_put(sk);
		return err;
	}

	err = netlink_attachskb(sk, skb, &timeo, ssk);
	if (err == 1)
		goto retry;
	if (err)
		return err;

	return netlink_sendskb(sk, skb);		// 用户态netlink socket
}

static struct sock *netlink_getsockbyportid(struct sock *ssk, u32 portid)
{
	struct sock *sock;
	struct netlink_sock *nlk;

	sock = netlink_lookup(sock_net(ssk), ssk->sk_protocol, portid);		//根据协议和端口查找
	if (!sock)
		return ERR_PTR(-ECONNREFUSED);

	/* Don't bother queuing skb if kernel socket has no input function */
	nlk = nlk_sk(sock);
	if (sock->sk_state == NETLINK_CONNECTED &&
	    nlk->dst_portid != nlk_sk(ssk)->portid) {
		sock_put(sock);
		return ERR_PTR(-ECONNREFUSED);
	}
	return sock;
}

static int netlink_unicast_kernel(struct sock *sk, struct sk_buff *skb,
				  struct sock *ssk)
{
	int ret;
	struct netlink_sock *nlk = nlk_sk(sk);

	ret = -ECONNREFUSED;
	if (nlk->netlink_rcv != NULL) {
		ret = skb->len;
		netlink_skb_set_owner_r(skb, sk);
		NETLINK_CB(skb).sk = ssk;
		netlink_deliver_tap_kernel(sk, ssk, skb);
		nlk->netlink_rcv(skb);				            //generic netlink 为 genl_rcv函数
		consume_skb(skb);
	} else {
		kfree_skb(skb);
	}
	sock_put(sk);
	return ret;
}

int netlink_sendskb(struct sock *sk, struct sk_buff *skb)
{
	int len = __netlink_sendskb(sk, skb);

	sock_put(sk);
	return len;
}

static int __netlink_sendskb(struct sock *sk, struct sk_buff *skb)
{
	int len = skb->len;

	netlink_deliver_tap(skb);

#ifdef CONFIG_NETLINK_MMAP
	if (netlink_skb_is_mmaped(skb))
		netlink_queue_mmaped_skb(sk, skb);
	else if (netlink_rx_is_mmaped(sk))
		netlink_ring_set_copied(sk, skb);
	else
#endif /* CONFIG_NETLINK_MMAP */
		skb_queue_tail(&sk->sk_receive_queue, skb);      //用户态的netlink socket 则发送到sock的接收队列中
	sk->sk_data_ready(sk);	//唤醒收包进程
	return len;
}
```

### 用户态Netlink Socket接收消息

```c
static int netlink_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
			   int flags)
{
	struct scm_cookie scm;
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	int noblock = flags&MSG_DONTWAIT;
	size_t copied;
	struct sk_buff *skb, *data_skb;
	int err, ret;

	if (flags&MSG_OOB)
		return -EOPNOTSUPP;

	copied = 0;

	skb = skb_recv_datagram(sk, flags, noblock, &err);    //收包
	if (skb == NULL)
		goto out;

	data_skb = skb;

#ifdef CONFIG_COMPAT_NETLINK_MESSAGES
	if (unlikely(skb_shinfo(skb)->frag_list)) {
		/*
		 * If this skb has a frag_list, then here that means that we
		 * will have to use the frag_list skb's data for compat tasks
		 * and the regular skb's data for normal (non-compat) tasks.
		 *
		 * If we need to send the compat skb, assign it to the
		 * 'data_skb' variable so that it will be used below for data
		 * copying. We keep 'skb' for everything else, including
		 * freeing both later.
		 */
		if (flags & MSG_CMSG_COMPAT)
			data_skb = skb_shinfo(skb)->frag_list;
	}
#endif

	/* Record the max length of recvmsg() calls for future allocations */
	nlk->max_recvmsg_len = max(nlk->max_recvmsg_len, len);
	nlk->max_recvmsg_len = min_t(size_t, nlk->max_recvmsg_len,
				     16384);

	copied = data_skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	skb_reset_transport_header(data_skb);
	err = skb_copy_datagram_msg(data_skb, 0, msg, copied);

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_nl *, addr, msg->msg_name);
		addr->nl_family = AF_NETLINK;
		addr->nl_pad    = 0;
		addr->nl_pid	= NETLINK_CB(skb).portid;
		addr->nl_groups	= netlink_group_mask(NETLINK_CB(skb).dst_group);
		msg->msg_namelen = sizeof(*addr);
	}

	if (nlk->flags & NETLINK_RECV_PKTINFO)
		netlink_cmsg_recv_pktinfo(msg, skb);

	memset(&scm, 0, sizeof(scm));
	scm.creds = *NETLINK_CREDS(skb);
	if (flags & MSG_TRUNC)
		copied = data_skb->len;

	skb_free_datagram(sk, skb);

	if (nlk->cb_running &&
	    atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf / 2) {
		ret = netlink_dump(sk);
		if (ret) {
			sk->sk_err = -ret;
			sk->sk_error_report(sk);
		}
	}

	scm_recv(sock, msg, &scm, flags);
out:
	netlink_rcv_wake(sk);
	return err ? : copied;
}

struct sk_buff *skb_recv_datagram(struct sock *sk, unsigned int flags,
				  int noblock, int *err)
{
	int peeked, off = 0;

	return __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				   &peeked, &off, err);
}

struct sk_buff *__skb_recv_datagram(struct sock *sk, unsigned int flags,
				    int *peeked, int *off, int *err)
{
	struct sk_buff_head *queue = &sk->sk_receive_queue;      //从sk收包队列收包
	struct sk_buff *skb, *last;
	unsigned long cpu_flags;
	long timeo;
	/*
	 * Caller is allowed not to check sk->sk_err before skb_recv_datagram()
	 */
	int error = sock_error(sk);

	if (error)
		goto no_packet;

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	do {
		/* Again only user level code calls this function, so nothing
		 * interrupt level will suddenly eat the receive_queue.
		 *
		 * Look at current nfs client by the way...
		 * However, this function was correct in any case. 8)
		 */
		int _off = *off;

		last = (struct sk_buff *)queue;
		spin_lock_irqsave(&queue->lock, cpu_flags);
		skb_queue_walk(queue, skb) {
			last = skb;
			*peeked = skb->peeked;
			if (flags & MSG_PEEK) {
				if (_off >= skb->len && (skb->len || _off ||
							 skb->peeked)) {
					_off -= skb->len;
					continue;
				}

				skb = skb_set_peeked(skb);
				error = PTR_ERR(skb);
				if (IS_ERR(skb))
					goto unlock_err;

				atomic_inc(&skb->users);
			} else
				__skb_unlink(skb, queue);

			spin_unlock_irqrestore(&queue->lock, cpu_flags);
			*off = _off;
			return skb;
		}
		spin_unlock_irqrestore(&queue->lock, cpu_flags);

		if (sk_can_busy_loop(sk) &&
		    sk_busy_loop(sk, flags & MSG_DONTWAIT))
			continue;

		/* User doesn't want to wait */
		error = -EAGAIN;
		if (!timeo)
			goto no_packet;

	} while (!wait_for_more_packets(sk, err, &timeo, last));	//没有报文则休眠，当前进程添加到wait队列中

	return NULL;

unlock_err:
	spin_unlock_irqrestore(&queue->lock, cpu_flags);
no_packet:
	*err = error;
	return NULL;
}
```

## 用户态Netlink Socket connect操作

Netlink Socket connect操作可以把用户Socket和内核态Socket绑定，实现用户态和内核态通信， 例如generic netlink

```c
static int netlink_connect(struct socket *sock, struct sockaddr *addr,
			   int alen, int flags)
{
	int err = 0;
	struct sock *sk = sock->sk;
	struct netlink_sock *nlk = nlk_sk(sk);
	struct sockaddr_nl *nladdr = (struct sockaddr_nl *)addr;

	if (alen < sizeof(addr->sa_family))
		return -EINVAL;

	if (addr->sa_family == AF_UNSPEC) {
		sk->sk_state	= NETLINK_UNCONNECTED;
		nlk->dst_portid	= 0;
		nlk->dst_group  = 0;
		return 0;
	}
	if (addr->sa_family != AF_NETLINK)
		return -EINVAL;

	if ((nladdr->nl_groups || nladdr->nl_pid) &&
	    !netlink_allowed(sock, NL_CFG_F_NONROOT_SEND))
		return -EPERM;

	/* No need for barriers here as we return to user-space without
	 * using any of the bound attributes.
	 */
	if (!nlk->bound)
		err = netlink_autobind(sock);

	if (err == 0) {
		sk->sk_state	= NETLINK_CONNECTED;
		nlk->dst_portid = nladdr->nl_pid;             //设置了dst_portid，在sendmsg中使用
		nlk->dst_group  = ffs(nladdr->nl_groups);
	}

	return err;
}
```

