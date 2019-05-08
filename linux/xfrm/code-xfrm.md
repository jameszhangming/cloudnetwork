# XFRM

Linux XFRM是IPSEC的实现，用来在数据包经过路由路径的过程中对其进行修改，包含 3 种数据结构：策略(xfrm policy)，模板(template)和状态(xfrm state)。


## 安全协议

* AH(AuthenticationHeader)协议
  * 用来向IP通信提供数据完整性和身份验证,同时可以提供抗重播服务。
* ESP(EncapsulatedSecurityPayload)协议
  * 提供IP层加密保证和验证数据源以对付网络上的监听。因为AH虽然可以保护通信免受篡改, 但并不对数据进行变形转换, 数据对于黑客而言仍然是清晰的。

  
### 数据结构

```c
static struct xfrm4_protocol esp4_protocol = {
	.handler	=	xfrm4_rcv,
	.input_handler	=	xfrm_input,
	.cb_handler	=	esp4_rcv_cb,
	.err_handler	=	esp4_err,
	.priority	=	0,
};

static const struct net_protocol esp4_protocol = {
	.handler	=	xfrm4_esp_rcv,
	.err_handler	=	xfrm4_esp_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

static const struct xfrm_type esp_type =
{
	.description	= "ESP4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.flags		= XFRM_TYPE_REPLAY_PROT,
	.init_state	= esp_init_state,
	.destructor	= esp_destroy,
	.get_mtu	= esp4_get_mtu,
	.input		= esp_input,
	.output		= esp_output
};
```
  

## 传输模式

* 传输模式
  * 在传输模式下，AH或ESP被插入到IP头之后但在所有传输层协议之前，或所有其他IPSec协议之前。
* 隧道模式
  * 在隧道模式下，AH或ESP插在原始IP头之前，另外生成一个新IP头放到AH或ESP之前。


### 数据结构

```c
static struct xfrm_mode xfrm4_transport_mode = {
	.input = xfrm4_transport_input,
	.output = xfrm4_transport_output,
	.owner = THIS_MODULE,
	.encap = XFRM_MODE_TRANSPORT,
};

static struct xfrm_mode xfrm4_tunnel_mode = {
	.input2 = xfrm4_mode_tunnel_input,
	.input = xfrm_prepare_input,
	.output2 = xfrm4_mode_tunnel_output,
	.output = xfrm4_prepare_output,
	.owner = THIS_MODULE,
	.encap = XFRM_MODE_TUNNEL,
	.flags = XFRM_MODE_FLAG_TUNNEL,
};
```


## 安全联盟

安全联盟SA,记录每条 IP安全通路的策略和策略参数。安全联盟是 IPSec 的基础, 是通信双方建立的一种协定,决定了用来保护数据包的协议、转码方式、密钥以及密钥有效期等。
AH和 ESP都要用到安全联盟,IKE的一个主要功能就是建立和维护安全联盟。

### 数据结构

```c
static struct xfrm_state_afinfo xfrm4_state_afinfo = {
	.family			= AF_INET,
	.proto			= IPPROTO_IPIP,
	.eth_proto		= htons(ETH_P_IP),
	.owner			= THIS_MODULE,
	.init_flags		= xfrm4_init_flags,
	.init_tempsel		= __xfrm4_init_tempsel,
	.init_temprop		= xfrm4_init_temprop,
	.output			= xfrm4_output,
	.output_finish		= xfrm4_output_finish,
	.extract_input		= xfrm4_extract_input,
	.extract_output		= xfrm4_extract_output,
	.transport_finish	= xfrm4_transport_finish,
	.local_error		= xfrm4_local_error,
};
```


## xfrm 模块初始化

在ip_rt_init函数中被调用

```c
void __init xfrm_init(void)
{
	register_pernet_subsys(&xfrm_net_ops);  //注册net namespace操作
	xfrm_input_init();  //xfrm input初始化
}
```

### xfrm net namespace操作

```c
static int __net_init xfrm_net_init(struct net *net)
{
	int rv;

	rv = xfrm_statistics_init(net);   // 统计信息初始化
	if (rv < 0)
		goto out_statistics;
	rv = xfrm_state_init(net);   // state初始化
	if (rv < 0)
		goto out_state;
	rv = xfrm_policy_init(net);  // policy 初始化
	if (rv < 0)
		goto out_policy;
	xfrm_dst_ops_init(net);      // dst ops初始化
	rv = xfrm_sysctl_init(net);
	if (rv < 0)
		goto out_sysctl;
	rv = flow_cache_init(net);   // cache初始化
	if (rv < 0)
		goto out;

	/* Initialize the per-net locks here */
	spin_lock_init(&net->xfrm.xfrm_state_lock);
	rwlock_init(&net->xfrm.xfrm_policy_lock);
	mutex_init(&net->xfrm.xfrm_cfg_mutex);

	return 0;

out:
	xfrm_sysctl_fini(net);
out_sysctl:
	xfrm_policy_fini(net);
out_policy:
	xfrm_state_fini(net);
out_state:
	xfrm_statistics_fini(net);
out_statistics:
	return rv;
}

int __net_init xfrm_state_init(struct net *net)
{
	unsigned int sz;

	INIT_LIST_HEAD(&net->xfrm.state_all);

	sz = sizeof(struct hlist_head) * 8;

	net->xfrm.state_bydst = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bydst)
		goto out_bydst;
	net->xfrm.state_bysrc = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_bysrc)
		goto out_bysrc;
	net->xfrm.state_byspi = xfrm_hash_alloc(sz);
	if (!net->xfrm.state_byspi)
		goto out_byspi;
	net->xfrm.state_hmask = ((sz / sizeof(struct hlist_head)) - 1);

	net->xfrm.state_num = 0;
	INIT_WORK(&net->xfrm.state_hash_work, xfrm_hash_resize);
	INIT_HLIST_HEAD(&net->xfrm.state_gc_list);
	INIT_WORK(&net->xfrm.state_gc_work, xfrm_state_gc_task);
	spin_lock_init(&net->xfrm.xfrm_state_lock);
	return 0;

out_byspi:
	xfrm_hash_free(net->xfrm.state_bysrc, sz);
out_bysrc:
	xfrm_hash_free(net->xfrm.state_bydst, sz);
out_bydst:
	return -ENOMEM;
}

static int __net_init xfrm_policy_init(struct net *net)
{
	unsigned int hmask, sz;
	int dir;

	if (net_eq(net, &init_net))
		xfrm_dst_cache = kmem_cache_create("xfrm_dst_cache",  //申请xfrm_dst时用到
					   sizeof(struct xfrm_dst),
					   0, SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					   NULL);

	hmask = 8 - 1;
	sz = (hmask+1) * sizeof(struct hlist_head);

	net->xfrm.policy_byidx = xfrm_hash_alloc(sz);
	if (!net->xfrm.policy_byidx)
		goto out_byidx;
	net->xfrm.policy_idx_hmask = hmask;

	for (dir = 0; dir < XFRM_POLICY_MAX; dir++) {
		struct xfrm_policy_hash *htab;

		net->xfrm.policy_count[dir] = 0;
		net->xfrm.policy_count[XFRM_POLICY_MAX + dir] = 0;
		INIT_HLIST_HEAD(&net->xfrm.policy_inexact[dir]);

		htab = &net->xfrm.policy_bydst[dir];
		htab->table = xfrm_hash_alloc(sz);
		if (!htab->table)
			goto out_bydst;
		htab->hmask = hmask;
		htab->dbits4 = 32;
		htab->sbits4 = 32;
		htab->dbits6 = 128;
		htab->sbits6 = 128;
	}
	net->xfrm.policy_hthresh.lbits4 = 32;
	net->xfrm.policy_hthresh.rbits4 = 32;
	net->xfrm.policy_hthresh.lbits6 = 128;
	net->xfrm.policy_hthresh.rbits6 = 128;

	seqlock_init(&net->xfrm.policy_hthresh.lock);

	INIT_LIST_HEAD(&net->xfrm.policy_all);
	INIT_WORK(&net->xfrm.policy_hash_work, xfrm_hash_resize);
	INIT_WORK(&net->xfrm.policy_hthresh.work, xfrm_hash_rebuild);
	if (net_eq(net, &init_net))
		register_netdevice_notifier(&xfrm_dev_notifier);
	return 0;

out_bydst:
	for (dir--; dir >= 0; dir--) {
		struct xfrm_policy_hash *htab;

		htab = &net->xfrm.policy_bydst[dir];
		xfrm_hash_free(htab->table, sz);
	}
	xfrm_hash_free(net->xfrm.policy_byidx, sz);
out_byidx:
	return -ENOMEM;
}


int flow_cache_init(struct net *net)
{
	int i;
	struct flow_cache *fc = &net->xfrm.flow_cache_global;

	if (!flow_cachep)
		flow_cachep = kmem_cache_create("flow_cache",   // flow_cache_entry
						sizeof(struct flow_cache_entry),
						0, SLAB_PANIC, NULL);
	spin_lock_init(&net->xfrm.flow_cache_gc_lock);
	INIT_LIST_HEAD(&net->xfrm.flow_cache_gc_list);
	INIT_WORK(&net->xfrm.flow_cache_gc_work, flow_cache_gc_task);
	INIT_WORK(&net->xfrm.flow_cache_flush_work, flow_cache_flush_task);
	mutex_init(&net->xfrm.flow_flush_sem);

	fc->hash_shift = 10;
	fc->low_watermark = 2 * flow_cache_hash_size(fc);
	fc->high_watermark = 4 * flow_cache_hash_size(fc);

	fc->percpu = alloc_percpu(struct flow_cache_percpu);  //初始化per cpu cache
	if (!fc->percpu)
		return -ENOMEM;

	cpu_notifier_register_begin();

	for_each_online_cpu(i) {
		if (flow_cache_cpu_prepare(fc, i))
			goto err;
	}
	fc->hotcpu_notifier = (struct notifier_block){
		.notifier_call = flow_cache_cpu,
	};
	__register_hotcpu_notifier(&fc->hotcpu_notifier);   //注册CPU热插消息

	cpu_notifier_register_done();

	setup_timer(&fc->rnd_timer, flow_cache_new_hashrnd,
		    (unsigned long) fc);
	fc->rnd_timer.expires = jiffies + FLOW_HASH_RND_PERIOD;
	add_timer(&fc->rnd_timer);

	return 0;

err:
	for_each_possible_cpu(i) {
		struct flow_cache_percpu *fcp = per_cpu_ptr(fc->percpu, i);
		kfree(fcp->hash_table);
		fcp->hash_table = NULL;
	}

	cpu_notifier_register_done();

	free_percpu(fc->percpu);
	fc->percpu = NULL;

	return -ENOMEM;
}
```


## xfrm4 模块初始化

在ip_rt_init函数中被调用

```c
void __init xfrm4_init(void)
{
	dst_entries_init(&xfrm4_dst_ops);

	xfrm4_state_init();
	xfrm4_policy_init();
	xfrm4_protocol_init();
#ifdef CONFIG_SYSCTL
	register_pernet_subsys(&xfrm4_net_ops);
#endif
}
```


###  xfrm4_state_init

```c
void __init xfrm4_state_init(void)
{
	xfrm_state_register_afinfo(&xfrm4_state_afinfo);
}

int xfrm_state_register_afinfo(struct xfrm_state_afinfo *afinfo)
{
	int err = 0;
	if (unlikely(afinfo == NULL))
		return -EINVAL;
	if (unlikely(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	spin_lock_bh(&xfrm_state_afinfo_lock);
	if (unlikely(xfrm_state_afinfo[afinfo->family] != NULL))
		err = -ENOBUFS;
	else
		rcu_assign_pointer(xfrm_state_afinfo[afinfo->family], afinfo);
	spin_unlock_bh(&xfrm_state_afinfo_lock);
	return err;
}
```


### xfrm4_policy_init

```c
static void __init xfrm4_policy_init(void)
{
	xfrm_policy_register_afinfo(&xfrm4_policy_afinfo);   //注册
}

int xfrm_policy_register_afinfo(struct xfrm_policy_afinfo *afinfo)
{
	struct net *net;
	int err = 0;
	if (unlikely(afinfo == NULL))
		return -EINVAL;
	if (unlikely(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	spin_lock(&xfrm_policy_afinfo_lock);
	if (unlikely(xfrm_policy_afinfo[afinfo->family] != NULL))
		err = -ENOBUFS;
	else {
		struct dst_ops *dst_ops = afinfo->dst_ops;
		if (likely(dst_ops->kmem_cachep == NULL))
			dst_ops->kmem_cachep = xfrm_dst_cache;   //注册kmem_cachep，申请xfrm_dst时用到
		if (likely(dst_ops->check == NULL))
			dst_ops->check = xfrm_dst_check;
		if (likely(dst_ops->default_advmss == NULL))
			dst_ops->default_advmss = xfrm_default_advmss;
		if (likely(dst_ops->mtu == NULL))
			dst_ops->mtu = xfrm_mtu;
		if (likely(dst_ops->negative_advice == NULL))
			dst_ops->negative_advice = xfrm_negative_advice;
		if (likely(dst_ops->link_failure == NULL))
			dst_ops->link_failure = xfrm_link_failure;
		if (likely(dst_ops->neigh_lookup == NULL))
			dst_ops->neigh_lookup = xfrm_neigh_lookup;
		if (likely(afinfo->garbage_collect == NULL))
			afinfo->garbage_collect = xfrm_garbage_collect_deferred;
		rcu_assign_pointer(xfrm_policy_afinfo[afinfo->family], afinfo);
	}
	spin_unlock(&xfrm_policy_afinfo_lock);

	rtnl_lock();
	for_each_net(net) {
		struct dst_ops *xfrm_dst_ops;

		switch (afinfo->family) {
		case AF_INET:
			xfrm_dst_ops = &net->xfrm.xfrm4_dst_ops;
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6:
			xfrm_dst_ops = &net->xfrm.xfrm6_dst_ops;
			break;
#endif
		default:
			BUG();
		}
		*xfrm_dst_ops = *afinfo->dst_ops;
	}
	rtnl_unlock();

	return err;
}
```


### xfrm4_protocol_init

```c
void __init xfrm4_protocol_init(void)
{
	xfrm_input_register_afinfo(&xfrm4_input_afinfo);
}

int xfrm_input_register_afinfo(struct xfrm_input_afinfo *afinfo)
{
	int err = 0;

	if (unlikely(afinfo == NULL))
		return -EINVAL;
	if (unlikely(afinfo->family >= NPROTO))
		return -EAFNOSUPPORT;
	spin_lock_bh(&xfrm_input_afinfo_lock);
	if (unlikely(xfrm_input_afinfo[afinfo->family] != NULL))
		err = -ENOBUFS;
	else
		rcu_assign_pointer(xfrm_input_afinfo[afinfo->family], afinfo);
	spin_unlock_bh(&xfrm_input_afinfo_lock);
	return err;
}
```

