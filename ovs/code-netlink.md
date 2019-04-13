# Netlink

OVSʹ��Netlink�����ں�̬���û�̬ͨ�š�

## ��Ҫ���ݽṹ

![netlink-object](images/netlink-object.png "netlink-object")


## Ofpbuf���ݽṹ

OVSʹ��ofpbuf����netlinkͨ�š�

ofpbuf���ݽṹ���壺
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

������ݣ�
```
static inline void ofpbuf_clear(struct ofpbuf *b)
{
    b->data = b->base;
    b->size = 0;
}
```

ͷ��Ԥ���ռ�:
```
Void ofpbuf_reserve(struct ofpbuf *b, size_t size)
{
    ovs_assert(!b->size);
    ofpbuf_prealloc_tailroom(b, size);
    b->data = (char*)b->data + size;
}
```

�·���ռ䣬����ֵΪ�¿ռ���׵�ַ������Ϊsize
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

nlattr���ݽṹ���壺
```
struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};
```

�������ݳ���:
```
static inline int nla_len(const struct nlattr *nla)
{
      return nla->nla_len - NLA_HDRLEN;
}
```

��ȡָ�����ݣ������ַ���:
```
static inline void *nla_data(const struct nlattr *nla)
{
       return (char *) nla + NLA_HDRLEN;
}
```

��ȡ�޷���32λintֵ:
```
static inline u32 nla_get_u32(const struct nlattr *nla)
{
    return *(u32 *) nla_data(nla);
}
```

��ȡ�޷���16λֵ:
```
static inline u16 nla_get_u16(const struct nlattr *nla)
{
     return *(u16 *) nla_data(nla);
}
```


## ��Ҫ����

![netlink-progress](images/netlink-progress.png "netlink-progress")


## �û�̬����Netlink Socket
```
int nl_sock_create(int protocol, struct nl_sock **sockp)
{

    *sockp = NULL;
	//����nl_sock����ռ�
    sock = xmalloc(sizeof *sock);      
	
	//����socket������protocolΪNETLINK_GENERIC
    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);	    
    if (sock->fd < 0) {
        VLOG_ERR("fcntl: %s", ovs_strerror(errno));
        goto error;
    }

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof rcvbuf)) {
    }
    ����
    /* Connect to kernel (pid 0) as remote address. */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;
	//��kernel genlink�󶨣��ں���ע����gen_family�ķ������Ա�����
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {	
        goto error;
    }

    /* Obtain pid assigned by kernel. */
    local_size = sizeof local;
    if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
        goto error;
    }
	//�õ�portid�������Ҫ�������ںˣ��ں����������Ϣ����Ӧ
    sock->pid = local.nl_pid;		
    ����
    free(sock);
    return retval;
}

```


## �û�̬ʹ��Netlink Socket
```
static int nl_sock_transact_multiple__(struct nl_sock *sock,
                            struct nl_transaction **transactions, size_t n,
                            size_t *done)
{
    ����
    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];
        struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(txn->request);

        nlmsg->nlmsg_len = txn->request->size;
        nlmsg->nlmsg_seq = base_seq + i;
		//����socketʱ�õ���pid
        nlmsg->nlmsg_pid = sock->pid;              

        iovs[i].iov_base = txn->request->data;
        iovs[i].iov_len = txn->request->size;
    }

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iovs;
    msg.msg_iovlen = n;
    do {
	    //����linux��sendmsg����������genlink��Ϣ
        error = sendmsg(sock->fd, &msg, 0) < 0 ? errno : 0;   
    } while (error == EINTR);

     ����
    /* Receive a reply. */
	//����genlink ��Ϣ���������reply��ͨ������recvmsgʵ��
    error = nl_sock_recv__(sock, buf_txn->reply, false);	
    ����
}

```

## �ں�̬ע�ᴦ����

genl_family���壺
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

netlink��Ϣ��������
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

ע��genl_family��
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


## Netlink��Ϣͷ����

![netlink-data](images/netlink-data.png "netlink-data")


genl_ops�������Եõ�nlattr����ֵ
```
static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
     struct nlattr **a = info->attrs;
     ����
     if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
           !a[OVS_VPORT_ATTR_UPCALL_PID])
     ����
           parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
           parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
           parms.options = a[OVS_VPORT_ATTR_OPTIONS];
           ����
}
```


