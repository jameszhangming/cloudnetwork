# ARP Netfilter

ARP报文的防火墙，例如允许某些ARP报文通过，不允许某些ARP报文通过，提供更加灵活的ARP处理。


## 数据结构

```c
#define FILTER_VALID_HOOKS ((1 << NF_ARP_IN) | (1 << NF_ARP_OUT) | \
			   (1 << NF_ARP_FORWARD))

static const struct xt_table packet_filter = {
	.name		= "filter",
	.valid_hooks	= FILTER_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_ARP,
	.priority	= NF_IP_PRI_FILTER,
};

static struct nf_hook_ops *arpfilter_ops __read_mostly;

//net namespace操作
static struct pernet_operations arptable_filter_net_ops = {
	.init = arptable_filter_net_init,
	.exit = arptable_filter_net_exit,
};
```


## 模块初始化

```c
static int __init arptable_filter_init(void)
{
	int ret;

	ret = register_pernet_subsys(&arptable_filter_net_ops);   //注册net namespace操作
	if (ret < 0)
		return ret;

	arpfilter_ops = xt_hook_link(&packet_filter, arptable_filter_hook);   //注册hook点
	if (IS_ERR(arpfilter_ops)) {
		ret = PTR_ERR(arpfilter_ops);
		goto cleanup_table;
	}
	return ret;

cleanup_table:
	unregister_pernet_subsys(&arptable_filter_net_ops);
	return ret;
}
```


### arp filter 网络命名空间操作

```c
static int __net_init arptable_filter_net_init(struct net *net)
{
	struct arpt_replace *repl;
	
	repl = arpt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	net->ipv4.arptable_filter =
		arpt_register_table(net, &packet_filter, repl);
	kfree(repl);
	return PTR_ERR_OR_ZERO(net->ipv4.arptable_filter);
}

void *arpt_alloc_initial_table(const struct xt_table *info)
{
	return xt_alloc_initial_table(arpt, ARPT);
}

#define xt_alloc_initial_table(type, typ2) ({ \
	unsigned int hook_mask = info->valid_hooks; \
	unsigned int nhooks = hweight32(hook_mask); \
	unsigned int bytes = 0, hooknum = 0, i = 0; \
	struct { \
		struct type##_replace repl; \
		struct type##_standard entries[]; \
	} *tbl; \
	struct type##_error *term; \
	size_t term_offset = (offsetof(typeof(*tbl), entries[nhooks]) + \
		__alignof__(*term) - 1) & ~(__alignof__(*term) - 1); \
	tbl = kzalloc(term_offset + sizeof(*term), GFP_KERNEL); \
	if (tbl == NULL) \
		return NULL; \
	term = (struct type##_error *)&(((char *)tbl)[term_offset]); \
	strncpy(tbl->repl.name, info->name, sizeof(tbl->repl.name)); \
	*term = (struct type##_error)typ2##_ERROR_INIT;  \
	tbl->repl.valid_hooks = hook_mask; \
	tbl->repl.num_entries = nhooks + 1; \
	tbl->repl.size = nhooks * sizeof(struct type##_standard) + \
			 sizeof(struct type##_error); \
	for (; hook_mask != 0; hook_mask >>= 1, ++hooknum) { \
		if (!(hook_mask & 1)) \
			continue; \
		tbl->repl.hook_entry[hooknum] = bytes; \
		tbl->repl.underflow[hooknum]  = bytes; \
		tbl->entries[i++] = (struct type##_standard) \
			typ2##_STANDARD_INIT(NF_ACCEPT); \
		bytes += sizeof(struct type##_standard); \
	} \
	tbl; \
})

struct xt_table *arpt_register_table(struct net *net,
				     const struct xt_table *table,
				     const struct arpt_replace *repl)
{
	int ret;
	struct xt_table_info *newinfo;
	struct xt_table_info bootstrap = {0};
	void *loc_cpu_entry;
	struct xt_table *new_table;

	newinfo = xt_alloc_table_info(repl->size);
	if (!newinfo) {
		ret = -ENOMEM;
		goto out;
	}

	/* choose the copy on our node/cpu */
	loc_cpu_entry = newinfo->entries[raw_smp_processor_id()];
	memcpy(loc_cpu_entry, repl->entries, repl->size);

	ret = translate_table(newinfo, loc_cpu_entry, repl);
	duprintf("arpt_register_table: translate table gives %d\n", ret);
	if (ret != 0)
		goto out_free;

	new_table = xt_register_table(net, table, &bootstrap, newinfo);   //注册到net namespace中
	if (IS_ERR(new_table)) {
		ret = PTR_ERR(new_table);
		goto out_free;
	}
	return new_table;

out_free:
	xt_free_table_info(newinfo);
out:
	return ERR_PTR(ret);
}
```


### Hook注册

```c
static int __init arptable_filter_init(void)
{
	int ret;

	ret = register_pernet_subsys(&arptable_filter_net_ops);  //注册pernet_ops
	if (ret < 0)
		return ret;

	arpfilter_ops = xt_hook_link(&packet_filter, arptable_filter_hook);  //注册hooks
	if (IS_ERR(arpfilter_ops)) {
		ret = PTR_ERR(arpfilter_ops);
		goto cleanup_table;
	}
	return ret;

cleanup_table:
	unregister_pernet_subsys(&arptable_filter_net_ops);
	return ret;
}

struct nf_hook_ops *xt_hook_link(const struct xt_table *table, nf_hookfn *fn)
{
	unsigned int hook_mask = table->valid_hooks;
	uint8_t i, num_hooks = hweight32(hook_mask);
	uint8_t hooknum;
	struct nf_hook_ops *ops;
	int ret;

	ops = kmalloc(sizeof(*ops) * num_hooks, GFP_KERNEL);
	if (ops == NULL)
		return ERR_PTR(-ENOMEM);

	for (i = 0, hooknum = 0; i < num_hooks && hook_mask != 0;
	     hook_mask >>= 1, ++hooknum) {
		if (!(hook_mask & 1))
			continue;
		ops[i].hook     = fn;
		ops[i].owner    = table->me;
		ops[i].pf       = table->af;
		ops[i].hooknum  = hooknum;
		ops[i].priority = table->priority;
		++i;
	}

	ret = nf_register_hooks(ops, num_hooks);    //注册到内核
	if (ret < 0) {
		kfree(ops);
		return ERR_PTR(ret);
	}

	return ops;
}
```


## hook回调函数

```c
static unsigned int
arptable_filter_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
		     const struct nf_hook_state *state)
{
	const struct net *net = dev_net(state->in ? state->in : state->out);

	return arpt_do_table(skb, ops->hooknum, state,
			     net->ipv4.arptable_filter);
}

unsigned int arpt_do_table(struct sk_buff *skb,
			   unsigned int hook,
			   const struct nf_hook_state *state,
			   struct xt_table *table)
{
	static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
	unsigned int verdict = NF_DROP;
	const struct arphdr *arp;
	struct arpt_entry *e, *back;
	const char *indev, *outdev;
	void *table_base;
	const struct xt_table_info *private;
	struct xt_action_param acpar;
	unsigned int addend;

	if (!pskb_may_pull(skb, arp_hdr_len(skb->dev)))
		return NF_DROP;

	indev = state->in ? state->in->name : nulldevname;
	outdev = state->out ? state->out->name : nulldevname;

	local_bh_disable();
	addend = xt_write_recseq_begin();
	private = table->private;
	/*
	 * Ensure we load private-> members after we've fetched the base
	 * pointer.
	 */
	smp_read_barrier_depends();
	table_base = private->entries[smp_processor_id()];

	e = get_entry(table_base, private->hook_entry[hook]);
	back = get_entry(table_base, private->underflow[hook]);

	acpar.in      = state->in;
	acpar.out     = state->out;
	acpar.hooknum = hook;
	acpar.family  = NFPROTO_ARP;
	acpar.hotdrop = false;

	arp = arp_hdr(skb);
	do {
		const struct xt_entry_target *t;

		if (!arp_packet_match(arp, skb->dev, indev, outdev, &e->arp)) {
			e = arpt_next_entry(e);
			continue;
		}

		ADD_COUNTER(e->counters, arp_hdr_len(skb->dev), 1);

		t = arpt_get_target_c(e);

		/* Standard target? */
		if (!t->u.kernel.target->target) {
			int v;

			v = ((struct xt_standard_target *)t)->verdict;
			if (v < 0) {
				/* Pop from stack? */
				if (v != XT_RETURN) {
					verdict = (unsigned int)(-v) - 1;
					break;
				}
				e = back;
				back = get_entry(table_base, back->comefrom);
				continue;
			}
			if (table_base + v
			    != arpt_next_entry(e)) {
				/* Save old back ptr in next entry */
				struct arpt_entry *next = arpt_next_entry(e);
				next->comefrom = (void *)back - table_base;

				/* set back pointer to next entry */
				back = next;
			}

			e = get_entry(table_base, v);
			continue;
		}

		/* Targets which reenter must return
		 * abs. verdicts
		 */
		acpar.target   = t->u.kernel.target;
		acpar.targinfo = t->data;
		verdict = t->u.kernel.target->target(skb, &acpar);

		/* Target might have changed stuff. */
		arp = arp_hdr(skb);

		if (verdict == XT_CONTINUE)
			e = arpt_next_entry(e);
		else
			/* Verdict */
			break;
	} while (!acpar.hotdrop);
	xt_write_recseq_end(addend);
	local_bh_enable();

	if (acpar.hotdrop)
		return NF_DROP;
	else
		return verdict;
}
```


