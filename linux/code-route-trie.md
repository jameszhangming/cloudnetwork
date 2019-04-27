# trie�㷨

Trie���ֳ��ֵ��������ʲ��������������һ�����νṹ����һ�ֹ�ϣ���ı��֡�����Ӧ��������ͳ�ƣ�����ͱ���������ַ����������������ַ����������Ծ�������������ϵͳ�����ı���Ƶͳ�ơ������ŵ��ǣ������ַ����Ĺ���ǰ׺�����ٲ�ѯʱ�䣬����޶ȵؼ�����ν���ַ����Ƚϣ���ѯЧ�ʱȹ�ϣ���ߡ�

Linux Routeʹ��trie����·�ɵĹ����������trie�ֽ������Ż����Է�ֹ���������


## Linux Route trie�㷨ԭ��


### �������ݽṹ

![route-class](images/route-class.png "route-class")

### trie���ݽṹ

key_vectorΪtrie���Ľڵ㶨��

```c
struct key_vector {
	t_key key;
	unsigned char pos;		/* 2log(KEYLENGTH) bits needed */
	unsigned char bits;		/* 2log(KEYLENGTH) bits needed */
	unsigned char slen;
	union {
		/* This list pointer if valid if (pos | bits) == 0 (LEAF) */
		struct hlist_head leaf;
		/* This array is valid if (pos | bits) > 0 (TNODE) */
		struct key_vector __rcu *tnode[0];
	};
};

struct tnode {
	struct rcu_head rcu;
	t_key empty_children;		/* KEYLENGTH bits needed */
	t_key full_children;		/* KEYLENGTH bits needed */
	struct key_vector __rcu *parent;
	struct key_vector kv[1];
#define tn_bits kv[0].bits
};
```

key_vector�еĲ���˵��ԭ�����£���������ģ�

* key�ֶ�ֻ����key_vectorΪleaf�ڵ�ʱ��ȫ�������壬����IPƥ��
* pos��bits��Ϊ0ʱ����ʾkey_vectorΪleaf�ڵ�
* key�ֶε�pos��(pos + bits - 1)������Ϊchild��index
* key�ֶε�31��(pos + 1)λ֮�����ƥ�������
* posԽС��ƥ���λ��Խ��
* slen�������볤�ȣ�slen����posʱ��˵������ƥ��
* parent��slen��С��child��slen

```c
/* To understand this stuff, an understanding of keys and all their bits is
 * necessary. Every node in the trie has a key associated with it, but not
 * all of the bits in that key are significant.
 *
 * Consider a node 'n' and its parent 'tp'.
 *
 * If n is a leaf, every bit in its key is significant. Its presence is
 * necessitated by path compression, since during a tree traversal (when
 * searching for a leaf - unless we are doing an insertion) we will completely
 * ignore all skipped bits we encounter. Thus we need to verify, at the end of
 * a potentially successful search, that we have indeed been walking the
 * correct key path.
 *
 * Note that we can never "miss" the correct key in the tree if present by
 * following the wrong path. Path compression ensures that segments of the key
 * that are the same for all keys with a given prefix are skipped, but the
 * skipped part *is* identical for each node in the subtrie below the skipped
 * bit! trie_insert() in this implementation takes care of that.
 *
 * if n is an internal node - a 'tnode' here, the various parts of its key
 * have many different meanings.
 *
 * Example:
 * _________________________________________________________________
 * | i | i | i | i | i | i | i | N | N | N | S | S | S | S | S | C |
 * -----------------------------------------------------------------
 *  31  30  29  28  27  26  25  24  23  22  21  20  19  18  17  16
 *
 * _________________________________________________________________
 * | C | C | C | u | u | u | u | u | u | u | u | u | u | u | u | u |
 * -----------------------------------------------------------------
 *  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
 *
 * tp->pos = 22
 * tp->bits = 3
 * n->pos = 13
 * n->bits = 4
 *
 * First, let's just ignore the bits that come before the parent tp, that is
 * the bits from (tp->pos + tp->bits) to 31. They are *known* but at this
 * point we do not use them for anything.
 *
 * The bits from (tp->pos) to (tp->pos + tp->bits - 1) - "N", above - are the
 * index into the parent's child array. That is, they will be used to find
 * 'n' among tp's children.
 *
 * The bits from (n->pos + n->bits) to (tn->pos - 1) - "S" - are skipped bits
 * for the node n.
 *
 * All the bits we have seen so far are significant to the node n. The rest
 * of the bits are really not needed or indeed known in n->key.
 *
 * The bits from (n->pos) to (n->pos + n->bits - 1) - "C" - are the index into
 * n's child array, and will of course be different for each child.
 *
 * The rest of the bits, from 0 to (n->pos + n->bits), are completely unknown
 * at this point.
 */
```


### trie�ؼ�����


#### ����Ҷ�ӽڵ�

```c
static struct key_vector *leaf_new(t_key key, struct fib_alias *fa)
{
	struct tnode *kv = kmem_cache_alloc(trie_leaf_kmem, GFP_KERNEL);
	struct key_vector *l = kv->kv;

	if (!kv)
		return NULL;

	/* initialize key vector */
	l->key = key;
	l->pos = 0;
	l->bits = 0;
	l->slen = fa->fa_slen;

	/* link leaf to fib alias */
	INIT_HLIST_HEAD(&l->leaf);
	hlist_add_head(&fa->fa_list, &l->leaf);

	return l;
}
```

#### ����inner�ڵ�

```c
static struct key_vector *tnode_new(t_key key, int pos, int bits)
{
	struct tnode *tnode = tnode_alloc(bits);
	unsigned int shift = pos + bits;
	struct key_vector *tn = tnode->kv;

	/* verify bits and pos their msb bits clear and values are valid */
	BUG_ON(!bits || (shift > KEYLENGTH));

	pr_debug("AT %p s=%zu %zu\n", tnode, TNODE_SIZE(0),
		 sizeof(struct key_vector *) << bits);

	if (!tnode)
		return NULL;

	if (bits == KEYLENGTH)
		tnode->full_children = 1;
	else
		tnode->empty_children = 1ul << bits;
	
	//cidex��unkown��λȫ�����㣬����ƥ�������ȫ�����㣨bits����1ʱ��
	//��bits����1ʱ��������bitλ������bitҲ��Ϊchild��indexֵ��linux��bitsĬ��ȡ1
	tn->key = (shift < KEYLENGTH) ? (key >> shift) << shift : 0;
	tn->pos = pos;
	tn->bits = bits;
	tn->slen = pos;

	return tn;
}
```

#### ��ȡchild��index

����inner�ڵ��key��0�� (pos + bits - 1) ����0�ˣ�����((key) ^ (kv)->key)��ֵ���ƥ��Ļ�ֻ��0�� (pos + bits - 1)��ֵ

```c
#define get_cindex(key, kv) (((key) ^ (kv)->key) >> (kv)->pos)
```

#### pos���㷽��

��ǰ�ڵ��posͨ��parent��key�͵�ǰ��key��������㣬����һ�������λ�á�
__fls����������ߵķ���λ����32bits�����֣������������ĵ�һ������λ����һ��Ϊ31�����һ��Ϊ0��

```c
__fls(key ^ n->key)
```


#### �����ڵ�

```c
static struct key_vector *fib_find_node(struct trie *t,
					struct key_vector **tp, u32 key)
{
	struct key_vector *pn, *n = t->kv;   //���ڵ�
	unsigned long index = 0;             //���ڵ�ֻ��һ��child

	do {
		pn = n;                        //pnΪparent�ڵ㣬����Ϊn
		n = get_child_rcu(n, index);   //����index���ҵ�n��child�ڵ㣨��index����

		if (!n)      //������Ӳ��������˳�ѭ����Ҷ�ӽڵ㣬���߸��ڵ�δ��ʼ��ʱ��
			break;

		index = get_cindex(key, n);    //����key�������key�Ľڵ�����n�ڵ���ĸ�����

		/* This bit of code is a bit tricky but it combines multiple
		 * checks into a single check.  The prefix consists of the
		 * prefix plus zeros for the bits in the cindex. The index
		 * is the difference between the key and this value.  From
		 * this we can actually derive several pieces of data.
		 *   if (index >= (1ul << bits))
		 *     we have a mismatch in skip bits and failed
		 *   else
		 *     we know the value is cindex
		 *
		 * This check is safe even if bits == KEYLENGTH due to the
		 * fact that we can only allocate a node with 32 bits if a
		 * long is greater than 32 bits.
		 */
		if (index >= (1ul << n->bits)) {    //��ʱ˵��key��child��ƥ�䣬
			n = NULL;
			break;
		}

		/* keep searching until we find a perfect match leaf or NULL */
	} while (IS_TNODE(n));

	*tp = pn;     //�õ�������parent�ڵ�

	return n;
}
```


## ���·�ɣ�·�ɱ��½���

ͨ��·�ɲ���������trie����ʵ�ֻ��ƺ�ԭ��

```c
static int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct fib_config cfg;
	struct fib_table *tb;
	int err;

	err = rtm_to_fib_config(net, skb, nlh, &cfg);
	if (err < 0)
		goto errout;

	tb = fib_new_table(net, cfg.fc_table);  //����·�ɱ���������ڵĻ�
	if (!tb) {
		err = -ENOBUFS;
		goto errout;
	}

	err = fib_table_insert(tb, &cfg);   //���·��
errout:
	return err;
}

struct fib_table *fib_new_table(struct net *net, u32 id)
{
	struct fib_table *tb, *alias = NULL;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	tb = fib_get_table(net, id);    //��ѯ·�ɱ�
	if (tb)
		return tb;

	if (id == RT_TABLE_LOCAL)
		alias = fib_new_table(net, RT_TABLE_MAIN);     

	tb = fib_trie_table(id, alias);   //����·�ɱ�
	if (!tb)
		return NULL;

	switch (id) {
	case RT_TABLE_LOCAL:
		rcu_assign_pointer(net->ipv4.fib_local, tb);
		break;
	case RT_TABLE_MAIN:
		rcu_assign_pointer(net->ipv4.fib_main, tb);
		break;
	case RT_TABLE_DEFAULT:
		rcu_assign_pointer(net->ipv4.fib_default, tb);
		break;
	default:
		break;
	}

	h = id & (FIB_TABLE_HASHSZ - 1);
	hlist_add_head_rcu(&tb->tb_hlist, &net->ipv4.fib_table_hash[h]);   //���뵽������
	return tb;
}

struct fib_table *fib_trie_table(u32 id, struct fib_table *alias)
{
	struct fib_table *tb;
	struct trie *t;
	size_t sz = sizeof(*tb);

	if (!alias)
		sz += sizeof(struct trie);		//·�ɱ����֮��Ϊtrie����

	tb = kzalloc(sz, GFP_KERNEL);		//����·�ɱ�+trie����ռ�
	if (!tb)
		return NULL;

	tb->tb_id = id;
	tb->tb_default = -1;
	tb->tb_num_default = 0;
	tb->tb_data = (alias ? alias->__data : tb->__data);   //��ʼ��ָ��

	if (alias)
		return tb;

	t = (struct trie *) tb->tb_data;       //��ʼ��trie���ĸ��ڵ�
	t->kv[0].pos = KEYLENGTH;              //32
	t->kv[0].slen = KEYLENGTH;             //32
#ifdef CONFIG_IP_FIB_TRIE_STATS
	t->stats = alloc_percpu(struct trie_use_stats);
	if (!t->stats) {
		kfree(tb);
		tb = NULL;
	}
#endif

	return tb;
}
```	


```c
int fib_table_insert(struct fib_table *tb, struct fib_config *cfg)
{
	struct trie *t = (struct trie *)tb->tb_data;
	struct fib_alias *fa, *new_fa;
	struct key_vector *l, *tp;
	struct fib_info *fi;
	u8 plen = cfg->fc_dst_len;		//Ŀ��IP���糤��
	u8 slen = KEYLENGTH - plen;     //Ŀ��IP��������
	u8 tos = cfg->fc_tos;
	u32 key;
	int err;

	if (plen > KEYLENGTH)   //���IP���糤��
		return -EINVAL;

	key = ntohl(cfg->fc_dst);    //�õ�Ŀ��IP��ַ�������ַ��������ַ��

	pr_debug("Insert table=%u %08x/%d\n", tb->tb_id, key, plen);

	if ((plen < KEYLENGTH) && (key << plen))  //IP���ȷ�32������£���֧������IP��ַ��ֻ��ʹ�������ַ��������λ��0��
		return -EINVAL;

	fi = fib_create_info(cfg);    //����·����
	if (IS_ERR(fi)) {
		err = PTR_ERR(fi);
		goto err;
	}

	l = fib_find_node(t, &tp, key);    //���������Ľڵ㣬��ǰ����null
	fa = l ? fib_find_alias(&l->leaf, slen, tos, fi->fib_priority,
				tb->tb_id) : NULL;

	/* Now fa, if non-NULL, points to the first fib alias
	 * with the same keys [prefix,tos,priority], if such key already
	 * exists or to the node before which we will insert new one.
	 *
	 * If fa is NULL, we will need to allocate a new one and
	 * insert to the tail of the section matching the suffix length
	 * of the new alias.
	 */

	if (fa && fa->fa_tos == tos &&
	    fa->fa_info->fib_priority == fi->fib_priority) {
		struct fib_alias *fa_first, *fa_match;

		err = -EEXIST;
		if (cfg->fc_nlflags & NLM_F_EXCL)
			goto out;

		/* We have 2 goals:
		 * 1. Find exact match for type, scope, fib_info to avoid
		 * duplicate routes
		 * 2. Find next 'fa' (or head), NLM_F_APPEND inserts before it
		 */
		fa_match = NULL;
		fa_first = fa;
		hlist_for_each_entry_from(fa, fa_list) {
			if ((fa->fa_slen != slen) ||
			    (fa->tb_id != tb->tb_id) ||
			    (fa->fa_tos != tos))
				break;
			if (fa->fa_info->fib_priority != fi->fib_priority)
				break;
			if (fa->fa_type == cfg->fc_type &&
			    fa->fa_info == fi) {
				fa_match = fa;
				break;
			}
		}

		if (cfg->fc_nlflags & NLM_F_REPLACE) {
			struct fib_info *fi_drop;
			u8 state;

			fa = fa_first;
			if (fa_match) {
				if (fa == fa_match)
					err = 0;
				goto out;
			}
			err = -ENOBUFS;
			new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);
			if (!new_fa)
				goto out;

			fi_drop = fa->fa_info;
			new_fa->fa_tos = fa->fa_tos;
			new_fa->fa_info = fi;
			new_fa->fa_type = cfg->fc_type;
			state = fa->fa_state;
			new_fa->fa_state = state & ~FA_S_ACCESSED;
			new_fa->fa_slen = fa->fa_slen;
			new_fa->tb_id = tb->tb_id;

			err = netdev_switch_fib_ipv4_add(key, plen, fi,
							 new_fa->fa_tos,
							 cfg->fc_type,
							 cfg->fc_nlflags,
							 tb->tb_id);
			if (err) {
				netdev_switch_fib_ipv4_abort(fi);
				kmem_cache_free(fn_alias_kmem, new_fa);
				goto out;
			}

			hlist_replace_rcu(&fa->fa_list, &new_fa->fa_list);

			alias_free_mem_rcu(fa);

			fib_release_info(fi_drop);
			if (state & FA_S_ACCESSED)
				rt_cache_flush(cfg->fc_nlinfo.nl_net);
			rtmsg_fib(RTM_NEWROUTE, htonl(key), new_fa, plen,
				tb->tb_id, &cfg->fc_nlinfo, NLM_F_REPLACE);

			goto succeeded;
		}
		/* Error if we find a perfect match which
		 * uses the same scope, type, and nexthop
		 * information.
		 */
		if (fa_match)
			goto out;

		if (!(cfg->fc_nlflags & NLM_F_APPEND))
			fa = fa_first;
	}
	err = -ENOENT;
	if (!(cfg->fc_nlflags & NLM_F_CREATE))
		goto out;

	err = -ENOBUFS;
	new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);   //����fib_alias����
	if (!new_fa)
		goto out;

	new_fa->fa_info = fi;
	new_fa->fa_tos = tos;
	new_fa->fa_type = cfg->fc_type;
	new_fa->fa_state = 0;
	new_fa->fa_slen = slen;
	new_fa->tb_id = tb->tb_id;

	/* (Optionally) offload fib entry to switch hardware. */
	err = netdev_switch_fib_ipv4_add(key, plen, fi, tos,    //���·�ɵ�switch
					 cfg->fc_type,
					 cfg->fc_nlflags,
					 tb->tb_id);
	if (err) {
		netdev_switch_fib_ipv4_abort(fi);
		goto out_free_new_fa;
	}

	/* Insert new entry to the list. */
	err = fib_insert_alias(t, tp, l, new_fa, fa, key);   //�����½�·�ɱ���
	if (err)
		goto out_sw_fib_del;

	if (!plen)
		tb->tb_num_default++;

	rt_cache_flush(cfg->fc_nlinfo.nl_net);
	rtmsg_fib(RTM_NEWROUTE, htonl(key), new_fa, plen, new_fa->tb_id,   //��Ϣ֪ͨ
		  &cfg->fc_nlinfo, 0);
succeeded:
	return 0;

out_sw_fib_del:
	netdev_switch_fib_ipv4_del(key, plen, fi, tos, cfg->fc_type, tb->tb_id);
out_free_new_fa:
	kmem_cache_free(fn_alias_kmem, new_fa);
out:
	fib_release_info(fi);
err:
	return err;
}

static int fib_insert_alias(struct trie *t, struct key_vector *tp,
			    struct key_vector *l, struct fib_alias *new,
			    struct fib_alias *fa, t_key key)
{
	if (!l)   //lΪ�ձ�ʾûƥ��Ľڵ㣬�����Ϊ����ζ��ƥ�䵽��Ҷ�ӽڵ�
		return fib_insert_node(t, tp, new, key);    //�ߴ˷�֧

	if (fa) {
		hlist_add_before_rcu(&new->fa_list, &fa->fa_list);   //�嵽leaf�ڵ���
	} else {
		struct fib_alias *last;

		hlist_for_each_entry(last, &l->leaf, fa_list) {
			if (new->fa_slen < last->fa_slen)
				break;
			if ((new->fa_slen == last->fa_slen) &&
			    (new->tb_id > last->tb_id))
				break;
			fa = last;
		}

		if (fa)
			hlist_add_behind_rcu(&new->fa_list, &fa->fa_list);
		else
			hlist_add_head_rcu(&new->fa_list, &l->leaf);
	}

	/* if we added to the tail node then we need to update slen */
	if (l->slen < new->fa_slen) {
		l->slen = new->fa_slen;
		leaf_push_suffix(tp, l);
	}

	return 0;
}

static int fib_insert_node(struct trie *t, struct key_vector *tp,
			   struct fib_alias *new, t_key key)
{
	struct key_vector *n, *l;

	l = leaf_new(key, new);    //�½�һ��leaf���͵�key_vector
	if (!l)
		goto noleaf;

	/* retrieve child from parent node */
	//�����parent�е�child�ڵ㣬���nΪ�������ֱ�Ӳ嵽���λ��
	//�����Ϊ����Ҫ����
	n = get_child(tp, get_index(key, tp));  

	/* Case 2: n is a LEAF or a TNODE and the key doesn't match.
	 *
	 *  Add a new tnode here
	 *  first tnode need some special handling
	 *  leaves us in position for handling as case 3
	 */
	if (n) {
		struct key_vector *tn;

		tn = tnode_new(key, __fls(key ^ n->key), 1);   //����inner�ڵ�
		if (!tn)
			goto notnode;

		/* initialize routes out of node */
		NODE_INIT_PARENT(tn, tp);                    //inner�ڵ��parentΪtp
		put_child(tn, get_index(key, tn) ^ 1, n);    //��n�ڵ�ŵ�tn��childλ��

		/* start adding routes into the node */
		put_child_root(tp, key, tn);    //tn�ŵ�tp�ϣ���ʱtpΪ��kv��tnֱ�ӷŵ�0��λ��child��
		node_set_parent(n, tn);         //����n��parentΪtn

		/* parent now has a NULL spot where the leaf can go */
		tp = tn;                       //��ǰ��parentΪtn�� ��Ϊl��parent
	}

	/* Case 3: n is NULL, and will just insert a new leaf */
	NODE_INIT_PARENT(l, tp);
	put_child_root(tp, key, l);  //l����Ϊtp�ĺ��ӣ���l���õ�tp�ĺ���childλ��
	trie_rebalance(t, tp);    //������

	return 0;
notnode:
	node_free(l);
noleaf:
	return -ENOMEM;
}
```	

## ·�ɱ����

·����ӱȽϼ򵥣���trie����������ң����ջ��ҵ�parent�Ĳ���㣬�ò����ֻ�����ֽ����

1. �������leaf�ڵ㣬����node�ڵ㣬��ԭleaf����leaf���뵽��node��
2. �������leaf�ڵ㣬ֱ�Ӳ��뵽parent�յ�λ���ϣ�

·�ɲ��ҹ��̺Ͳ������ƣ����������

1. �ҵ�Ҷ�ӽڵ㣻
2. δƥ�䵽Ҷ�ӽڵ㣻
   ʹ�ñ��������м�¼��pn�ڵ㣨�ýڵ������ƥ���Ҷ�ӽڵ㣩

�ܹ�ƥ�䵽��Ҷ�ӽڵ�ֻ�У�

1. ֱ��ƥ�䵽��Ҷ�ӽڵ㣻
2. pn�ڵ�ĵܵܽڵ㣨�����ܵܽڵ���������
3. pn���ȵĵܵܽڵ㣨�����ܵܽڵ���������


   
```c
int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
		     struct fib_result *res, int fib_flags)
{
	struct trie *t = (struct trie *) tb->tb_data;
#ifdef CONFIG_IP_FIB_TRIE_STATS
	struct trie_use_stats __percpu *stats = t->stats;
#endif
	const t_key key = ntohl(flp->daddr);    //Ŀ��IP��ַת��Ϊkey
	struct key_vector *n, *pn;
	struct fib_alias *fa;
	unsigned long index;
	t_key cindex;

	pn = t->kv;    //���ڵ�
	cindex = 0;

	n = get_child_rcu(pn, cindex);   //��һ�����ڵ�
	if (!n)
		return -EAGAIN;

#ifdef CONFIG_IP_FIB_TRIE_STATS
	this_cpu_inc(stats->gets);
#endif

	/* Step 1: Travel to the longest prefix match in the trie */
	for (;;) {
		index = get_cindex(key, n);

		/* This bit of code is a bit tricky but it combines multiple
		 * checks into a single check.  The prefix consists of the
		 * prefix plus zeros for the "bits" in the prefix. The index
		 * is the difference between the key and this value.  From
		 * this we can actually derive several pieces of data.
		 *   if (index >= (1ul << bits))
		 *     we have a mismatch in skip bits and failed
		 *   else
		 *     we know the value is cindex
		 *
		 * This check is safe even if bits == KEYLENGTH due to the
		 * fact that we can only allocate a node with 32 bits if a
		 * long is greater than 32 bits.
		 */
		if (index >= (1ul << n->bits))    //δƥ�䵽������index==0�ҵ�Ҷ�ӽڵ�
			break;

		/* we have found a leaf. Prefixes have already been compared */
		if (IS_LEAF(n))   //�ҵ�Ҷ�ӽڵ�
			goto found;

		/* only record pn and cindex if we are going to be chopping
		 * bits later.  Otherwise we are just wasting cycles.
		 */
		if (n->slen > n->pos) {     //����ƥ��
			pn = n;
			cindex = index;
		}

		n = get_child_rcu(n, index);
		if (unlikely(!n))                //δ�ҵ�����Ҫ����Ѱ��
			goto backtrace;
	}

	/* Step 2: Sort out leaves and begin backtracing for longest prefix */
	for (;;) {
		/* record the pointer where our next node pointer is stored */
		//��磨�ұߣ��͵ܵܵ������Һ��Ӷ��ǲ���ƥ���
		//����ĳЩ�ܵ��ǿ���ƥ��ģ�bits>1,bits����1ʱ�����϶��ܹ��͵ܵ�ƥ�䣩
		struct key_vector __rcu **cptr = n->tnode; 

		/* This test verifies that none of the bits that differ
		 * between the key and the prefix exist in the region of
		 * the lsb and higher in the prefix.
		 */
		if (unlikely(prefix_mismatch(key, n)) || (n->slen == n->pos))
			goto backtrace;

		/* exit out and process leaf */
		if (unlikely(IS_LEAF(n)))	
			break;

		/* Don't bother recording parent info.  Since we are in
		 * prefix match mode we will have to come back to wherever
		 * we started this traversal anyway
		 */

		while ((n = rcu_dereference(*cptr)) == NULL) {
backtrace:
#ifdef CONFIG_IP_FIB_TRIE_STATS
			if (!n)
				this_cpu_inc(stats->null_node_hit);
#endif
			/* If we are at cindex 0 there are no more bits for
			 * us to strip at this level so we must ascend back
			 * up one level to see if there are any more bits to
			 * be stripped there.
			 */
			while (!cindex) {        
				t_key pkey = pn->key;

				/* If we don't have a parent then there is
				 * nothing for us to do as we do not have any
				 * further nodes to parse.
				 */
				if (IS_TRIE(pn))
					return -EAGAIN;
#ifdef CONFIG_IP_FIB_TRIE_STATS
				this_cpu_inc(stats->backtrack);
#endif
				/* Get Child's index */
				pn = node_parent_rcu(pn);   		//������һ����� 
				cindex = get_index(pkey, pn);       //�����ڸ��ڵ��index
			}

			/* strip the least significant bit from the cindex */
			cindex &= cindex - 1;		//����߲��ң��ҵܵ�

			/* grab pointer for next child node */
			cptr = &pn->tnode[cindex];  //����һ���ڵ�
		}
	}

found:
	/* this line carries forward the xor from earlier in the function */
	index = key ^ n->key;

	/* Step 3: Process the leaf, if that fails fall back to backtracing */
	hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {      //����·�ɱ������ƥ��
		struct fib_info *fi = fa->fa_info;
		int nhsel, err;

		if ((index >= (1ul << fa->fa_slen)) &&
		    ((BITS_PER_LONG > KEYLENGTH) || (fa->fa_slen != KEYLENGTH)))
			continue;
		if (fa->fa_tos && fa->fa_tos != flp->flowi4_tos)
			continue;
		if (fi->fib_dead)
			continue;
		if (fa->fa_info->fib_scope < flp->flowi4_scope)
			continue;
		fib_alias_accessed(fa);
		err = fib_props[fa->fa_type].error;
		if (unlikely(err < 0)) {
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			return err;
		}
		if (fi->fib_flags & RTNH_F_DEAD)
			continue;
		for (nhsel = 0; nhsel < fi->fib_nhs; nhsel++) {
			const struct fib_nh *nh = &fi->fib_nh[nhsel];

			if (nh->nh_flags & RTNH_F_DEAD)
				continue;
			if (flp->flowi4_oif && flp->flowi4_oif != nh->nh_oif)
				continue;

			if (!(fib_flags & FIB_LOOKUP_NOREF))
				atomic_inc(&fi->fib_clntref);

			res->prefixlen = KEYLENGTH - fa->fa_slen;
			res->nh_sel = nhsel;
			res->type = fa->fa_type;
			res->scope = fi->fib_scope;
			res->fi = fi;
			res->table = tb;
			res->fa_head = &n->leaf;
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			return err;
		}
	}
#ifdef CONFIG_IP_FIB_TRIE_STATS
	this_cpu_inc(stats->semantic_match_miss);
#endif
	goto backtrace;
}
```

## ·����ӹ����ܽ�

![route-add1](images/route-add1.png "route-add1")

![route-add2](images/route-add2.png "route-add2")

����ͼ���Կ�������ʼʱtrieΪһ�Ŷ�������������������Ӷ�����ѹƽ����ʱ��Linux�����ѹƽ��

ѹƽ�󣬼����ٶ����ӣ�����ͼ��δѹƽǰÿ�ν���ǰ��һ�㣬����ƽ����ͼ����һ�μ�������ǰ�����㣬Խƽ�����ٶ�Խ�죬���Ǵ洢�ռ�Խ��2��bits���ݣ�

![route-inflate](images/route-inflate.png "route-inflate")

