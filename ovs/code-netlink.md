# Netlink

OVS使用Netlink用于内核态和用户态通信。


## 主要流程

![netlink-progress](images/netlink-progress.png "netlink-progress")


# 用户态发送netlink消息


## nl_transact

发送netlink请求，并等待响应

```c
int
nl_transact(int protocol, const struct ofpbuf *request,
            struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    int error;

    error = nl_pool_alloc(protocol, &sock);    //从netlink sock池中申请sock，如果不存在则申请
    if (error) {
        *replyp = NULL;
        return error;
    }

    error = nl_sock_transact(sock, request, replyp);   //发送netlink消息并等待响应

    nl_pool_release(sock);
    return error;
}

static int
nl_pool_alloc(int protocol, struct nl_sock **sockp)
{
    struct nl_sock *sock = NULL;
    struct nl_pool *pool;

    ovs_assert(protocol >= 0 && protocol < ARRAY_SIZE(pools));

    ovs_mutex_lock(&pool_mutex);
    pool = &pools[protocol];
    if (pool->n > 0) {                   //如果pool中有sock，则直接从pool中分配
        sock = pool->socks[--pool->n];
    }
    ovs_mutex_unlock(&pool_mutex);

    if (sock) {
        *sockp = sock;
        return 0;
    } else {
        return nl_sock_create(protocol, sockp);    //pool池中没有sock，则直接创建
    }
}
```


## nl_sock_create

```c
int
nl_sock_create(int protocol, struct nl_sock **sockp)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct nl_sock *sock;
#ifndef _WIN32
    struct sockaddr_nl local, remote;
#endif
    socklen_t local_size;
    int rcvbuf;
    int retval = 0;

    if (ovsthread_once_start(&once)) {
        int save_errno = errno;
        errno = 0;

        max_iovs = sysconf(_SC_UIO_MAXIOV);
        if (max_iovs < _XOPEN_IOV_MAX) {
            if (max_iovs == -1 && errno) {
                VLOG_WARN("sysconf(_SC_UIO_MAXIOV): %s", ovs_strerror(errno));
            }
            max_iovs = _XOPEN_IOV_MAX;
        } else if (max_iovs > MAX_IOVS) {
            max_iovs = MAX_IOVS;
        }

        errno = save_errno;
        ovsthread_once_done(&once);
    }

    *sockp = NULL;
    sock = xmalloc(sizeof *sock);  //申请nl_sock对象空间

#ifdef _WIN32
    sock->handle = CreateFile(OVS_DEVICE_NAME_USER,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, NULL);

    if (sock->handle == INVALID_HANDLE_VALUE) {
        VLOG_ERR("fcntl: %s", ovs_lasterror_to_string());
        goto error;
    }

    memset(&sock->overlapped, 0, sizeof sock->overlapped);
    sock->overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (sock->overlapped.hEvent == NULL) {
        VLOG_ERR("fcntl: %s", ovs_lasterror_to_string());
        goto error;
    }
    /* Initialize the type/ioctl to Generic */
    sock->read_ioctl = OVS_IOCTL_READ;
#else
    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);    //创建netlink sock
    if (sock->fd < 0) {
        VLOG_ERR("fcntl: %s", ovs_strerror(errno));
        goto error;
    }
#endif

    sock->protocol = protocol;
    sock->next_seq = 1;

    rcvbuf = 1024 * 1024;
#ifdef _WIN32
    sock->rcvbuf = rcvbuf;
    retval = get_sock_pid_from_kernel(sock);
    if (retval != 0) {
        goto error;
    }
#else
    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof rcvbuf)) {
        /* Only root can use SO_RCVBUFFORCE.  Everyone else gets EPERM.
         * Warn only if the failure is therefore unexpected. */
        if (errno != EPERM) {
            VLOG_WARN_RL(&rl, "setting %d-byte socket receive buffer failed "
                         "(%s)", rcvbuf, ovs_strerror(errno));
        }
    }

    retval = get_socket_rcvbuf(sock->fd);
    if (retval < 0) {
        retval = -retval;
        goto error;
    }
    sock->rcvbuf = retval;
    retval = 0;

    /* Connect to kernel (pid 0) as remote address. */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;   //内核netlink sock
	//与kernel genlink绑定，内核中注册了gen_family的方法可以被调用
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
        VLOG_ERR("connect(0): %s", ovs_strerror(errno));
        goto error;
    }

    /* Obtain pid assigned by kernel. */
    local_size = sizeof local;
    if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
        VLOG_ERR("getsockname: %s", ovs_strerror(errno));
        goto error;
    }
    if (local_size < sizeof local || local.nl_family != AF_NETLINK) {
        VLOG_ERR("getsockname returned bad Netlink name");
        retval = EINVAL;
        goto error;
    }
	//得到portid，这个需要发送内内核，内核依赖这个信息来响应
	//connect执行后portid值会被设置
    sock->pid = local.nl_pid;  
#endif

    *sockp = sock;
    return 0;

error:
    if (retval == 0) {
        retval = errno;
        if (retval == 0) {
            retval = EINVAL;
        }
    }
#ifdef _WIN32
    if (sock->overlapped.hEvent) {
        CloseHandle(sock->overlapped.hEvent);
    }
    if (sock->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(sock->handle);
    }
#else
    if (sock->fd >= 0) {
        close(sock->fd);
    }
#endif
    free(sock);
    return retval;
}
```


## nl_sock_transact

```c
static int
nl_sock_transact(struct nl_sock *sock, const struct ofpbuf *request,
                 struct ofpbuf **replyp)
{
    struct nl_transaction *transactionp;
    struct nl_transaction transaction;

    transaction.request = CONST_CAST(struct ofpbuf *, request);
    transaction.reply = replyp ? ofpbuf_new(1024) : NULL;
    transactionp = &transaction;

    nl_sock_transact_multiple(sock, &transactionp, 1);

    if (replyp) {
        if (transaction.error) {
            ofpbuf_delete(transaction.reply);
            *replyp = NULL;
        } else {
            *replyp = transaction.reply;
        }
    }

    return transaction.error;
}

static void
nl_sock_transact_multiple(struct nl_sock *sock,
                          struct nl_transaction **transactions, size_t n)
{
    int max_batch_count;
    int error;

    if (!n) {
        return;
    }

    /* In theory, every request could have a 64 kB reply.  But the default and
     * maximum socket rcvbuf size with typical Dom0 memory sizes both tend to
     * be a bit below 128 kB, so that would only allow a single message in a
     * "batch".  So we assume that replies average (at most) 4 kB, which allows
     * a good deal of batching.
     *
     * In practice, most of the requests that we batch either have no reply at
     * all or a brief reply. */
    max_batch_count = MAX(sock->rcvbuf / 4096, 1);
    max_batch_count = MIN(max_batch_count, max_iovs);

    while (n > 0) {
        size_t count, bytes;
        size_t done;

        /* Batch up to 'max_batch_count' transactions.  But cap it at about a
         * page of requests total because big skbuffs are expensive to
         * allocate in the kernel.  */
#if defined(PAGESIZE)
        enum { MAX_BATCH_BYTES = MAX(1, PAGESIZE - 512) };
#else
        enum { MAX_BATCH_BYTES = 4096 - 512 };
#endif
        bytes = transactions[0]->request->size;
        for (count = 1; count < n && count < max_batch_count; count++) {
            if (bytes + transactions[count]->request->size > MAX_BATCH_BYTES) {
                break;
            }
            bytes += transactions[count]->request->size;
        }

        error = nl_sock_transact_multiple__(sock, transactions, count, &done);
        transactions += done;
        n -= done;

        if (error == ENOBUFS) {
            VLOG_DBG_RL(&rl, "receive buffer overflow, resending request");
        } else if (error) {
            VLOG_ERR_RL(&rl, "transaction error (%s)", ovs_strerror(error));
            nl_sock_record_errors__(transactions, n, error);
            if (error != EAGAIN) {
                /* A fatal error has occurred.  Abort the rest of
                 * transactions. */
                break;
            }
        }
    }
}

static int
nl_sock_transact_multiple__(struct nl_sock *sock,
                            struct nl_transaction **transactions, size_t n,
                            size_t *done)
{
    uint64_t tmp_reply_stub[1024 / 8];
    struct nl_transaction tmp_txn;
    struct ofpbuf tmp_reply;

    uint32_t base_seq;
    struct iovec iovs[MAX_IOVS];
    struct msghdr msg;
    int error;
    int i;

    base_seq = nl_sock_allocate_seq(sock, n);
    *done = 0;
    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(txn->request);   //封装netlink消息头

        nlmsg->nlmsg_len = txn->request->size;
        nlmsg->nlmsg_seq = base_seq + i;
        nlmsg->nlmsg_pid = sock->pid;

        iovs[i].iov_base = txn->request->data;
        iovs[i].iov_len = txn->request->size;
    }

#ifndef _WIN32
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iovs;
    msg.msg_iovlen = n;
    do {
        error = sendmsg(sock->fd, &msg, 0) < 0 ? errno : 0;    //发送netlink消息
    } while (error == EINTR);

    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        log_nlmsg(__func__, error, txn->request->data,
                  txn->request->size, sock->protocol);
    }
    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }

    if (error) {
        return error;
    }

    ofpbuf_use_stub(&tmp_reply, tmp_reply_stub, sizeof tmp_reply_stub);
    tmp_txn.request = NULL;
    tmp_txn.reply = &tmp_reply;
    tmp_txn.error = 0;
    while (n > 0) {
        struct nl_transaction *buf_txn, *txn;
        uint32_t seq;

        /* Find a transaction whose buffer we can use for receiving a reply.
         * If no such transaction is left, use tmp_txn. */
        buf_txn = &tmp_txn;
        for (i = 0; i < n; i++) {
            if (transactions[i]->reply) {
                buf_txn = transactions[i];
                break;
            }
        }

        /* Receive a reply. */
        error = nl_sock_recv__(sock, buf_txn->reply, false);      //接收响应消息
        if (error) {
            if (error == EAGAIN) {
                nl_sock_record_errors__(transactions, n, 0);
                *done += n;
                error = 0;
            }
            break;
        }

        /* Match the reply up with a transaction. */
        seq = nl_msg_nlmsghdr(buf_txn->reply)->nlmsg_seq;
        if (seq < base_seq || seq >= base_seq + n) {
            VLOG_DBG_RL(&rl, "ignoring unexpected seq %#"PRIx32, seq);
            continue;
        }
        i = seq - base_seq;
        txn = transactions[i];

        /* Fill in the results for 'txn'. */
        if (nl_msg_nlmsgerr(buf_txn->reply, &txn->error)) {
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
            if (txn->error) {
                VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                            error, ovs_strerror(txn->error));
            }
        } else {
            txn->error = 0;
            if (txn->reply && txn != buf_txn) {
                /* Swap buffers. */
                struct ofpbuf *reply = buf_txn->reply;
                buf_txn->reply = txn->reply;
                txn->reply = reply;
            }
        }

        /* Fill in the results for transactions before 'txn'.  (We have to do
         * this after the results for 'txn' itself because of the buffer swap
         * above.) */
        nl_sock_record_errors__(transactions, i, 0);

        /* Advance. */
        *done += i + 1;
        transactions += i + 1;
        n -= i + 1;
        base_seq += i + 1;
    }
    ofpbuf_uninit(&tmp_reply);
#else
    error = 0;
    uint8_t reply_buf[65536];
    for (i = 0; i < n; i++) {
        DWORD reply_len;
        bool ret;
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *request_nlmsg, *reply_nlmsg;

        ret = DeviceIoControl(sock->handle, OVS_IOCTL_TRANSACT,
                              txn->request->data,
                              txn->request->size,
                              reply_buf, sizeof reply_buf,
                              &reply_len, NULL);

        if (ret && reply_len == 0) {
            /*
             * The current transaction did not produce any data to read and that
             * is not an error as such. Continue with the remainder of the
             * transactions.
             */
            txn->error = 0;
            if (txn->reply) {
                ofpbuf_clear(txn->reply);
            }
        } else if (!ret) {
            /* XXX: Map to a more appropriate error. */
            error = EINVAL;
            VLOG_DBG_RL(&rl, "fatal driver failure: %s",
                ovs_lasterror_to_string());
            break;
        }

        if (reply_len != 0) {
            if (reply_len < sizeof *reply_nlmsg) {
                nl_sock_record_errors__(transactions, n, 0);
                VLOG_DBG_RL(&rl, "insufficient length of reply %#"PRIu32
                    " for seq: %#"PRIx32, reply_len, request_nlmsg->nlmsg_seq);
                break;
            }

            /* Validate the sequence number in the reply. */
            request_nlmsg = nl_msg_nlmsghdr(txn->request);
            reply_nlmsg = (struct nlmsghdr *)reply_buf;

            if (request_nlmsg->nlmsg_seq != reply_nlmsg->nlmsg_seq) {
                ovs_assert(request_nlmsg->nlmsg_seq == reply_nlmsg->nlmsg_seq);
                VLOG_DBG_RL(&rl, "mismatched seq request %#"PRIx32
                    ", reply %#"PRIx32, request_nlmsg->nlmsg_seq,
                    reply_nlmsg->nlmsg_seq);
                break;
            }

            /* Handle errors embedded within the netlink message. */
            ofpbuf_use_stub(&tmp_reply, reply_buf, sizeof reply_buf);
            tmp_reply.size = sizeof reply_buf;
            if (nl_msg_nlmsgerr(&tmp_reply, &txn->error)) {
                if (txn->reply) {
                    ofpbuf_clear(txn->reply);
                }
                if (txn->error) {
                    VLOG_DBG_RL(&rl, "received NAK error=%d (%s)",
                                error, ovs_strerror(txn->error));
                }
            } else {
                txn->error = 0;
                if (txn->reply) {
                    /* Copy the reply to the buffer specified by the caller. */
                    if (reply_len > txn->reply->allocated) {
                        ofpbuf_reinit(txn->reply, reply_len);
                    }
                    memcpy(txn->reply->data, reply_buf, reply_len);
                    txn->reply->size = reply_len;
                }
            }
            ofpbuf_uninit(&tmp_reply);
        }

        /* Count the number of successful transactions. */
        (*done)++;

    }

    if (!error) {
        COVERAGE_ADD(netlink_sent, n);
    }
#endif

    return error;
}
```



# 内核态处理方法注册

genl_family定义：
```
static struct genl_family dp_flow_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = OVS_FLOW_VERSION,
	.maxattr = OVS_FLOW_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_flow_genl_ops,
	.n_ops = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps = &ovs_dp_flow_multicast_group,
	.n_mcgrps = 1,
};
```

netlink消息处理函数：
```
static struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};
```

注册genl_family：
```
static int dp_register_genl(void)
{
	int err;
	int i;

	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {

		err = genl_register_family(dp_genl_families[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	dp_unregister_genl(i);
	return err;
}
```


# 数据结构


## 主要数据结构

![netlink-object](images/netlink-object.png "netlink-object")


## ofpbuf数据结构

OVS使用ofpbuf用于netlink通信时自定义数据。

ofpbuf数据结构定义：
```
struct ofpbuf {
    void *base; /* First byte of allocated space. */
    void *data; /* First byte actually in use. */
    uint32_t size; /* Number of bytes in use. */
    uint32_t allocated; /* Number of bytes allocated. */

    void *header; /* OpenFlow header. */
    void *msg;  /* message's body */
    /* Private list element for use by owner. */
    struct ovs_list list_node; 
    /* Source of memory allocated as 'base'. */
    enum ofpbuf_source source;
};
```

![ofpbuf](images/ofpbuf.png "ofpbuf")

清除数据：
```
static inline void ofpbuf_clear(struct ofpbuf *b)
{
    b->data = b->base;
    b->size = 0;
}
```

头部预留空间:
```
Void ofpbuf_reserve(struct ofpbuf *b, size_t size)
{
    ovs_assert(!b->size);
    ofpbuf_prealloc_tailroom(b, size);
    b->data = (char*)b->data + size;
}
```

新分配空间，返回值为新空间的首地址，长度为size：
```
void * ofpbuf_put_uninit(struct ofpbuf *b, size_t size)
{
    void *p;
    ofpbuf_prealloc_tailroom(b, size);
    p = ofpbuf_tail(b);
    b->size += size;
    return p;
}
```


## nlattr数据结构

nlattr数据结构定义：
```
struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};
```

负载数据长度:
```
static inline int nla_len(const struct nlattr *nla)
{
      return nla->nla_len - NLA_HDRLEN;
}
```

获取指针数据，例如字符串:
```
static inline void *nla_data(const struct nlattr *nla)
{
       return (char *) nla + NLA_HDRLEN;
}
```

获取无符号32位int值:
```
static inline u32 nla_get_u32(const struct nlattr *nla)
{
    return *(u32 *) nla_data(nla);
}
```

获取无符号16位值:
```
static inline u16 nla_get_u16(const struct nlattr *nla)
{
     return *(u16 *) nla_data(nla);
}
```


## Netlink消息头示例

Netlink通信时，有标准消息格式定义，除nlmsghdr和genlmsghdr两个标准消息头外，还支持用户自定义的数据。

![netlink-data](images/netlink-data.png "netlink-data")


genl_ops函数可以直接得到nlattr属性值
```
static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
     struct nlattr **a = info->attrs;
     ……
     if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
           !a[OVS_VPORT_ATTR_UPCALL_PID])
     ……
           parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
           parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
           parms.options = a[OVS_VPORT_ATTR_OPTIONS];
           ……
}
```


