# Traffic Control

Traffic Control（TC）流量控制，是网络QoS的Linux实现，Linux内核通过Qdisc，class和filter三者来实现，本文将介绍系统默认Qidsc的初始化过程，以及Qidsc、Class和filter配置流程。


## 设备默认Qdisc初始化

默认网卡的Qdisc分两种情况：

* 单队列：基于优先级的先进先出策略
* 多队列：直接发送到设备驱动

register_netdevice注册设备时，调用如下函数，初始化qdisc：
```c
void dev_init_scheduler(struct net_device *dev)
{
	dev->qdisc = &noop_qdisc;
	netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);   //默认qdisc
	if (dev_ingress_queue(dev))
		dev_init_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);

	setup_timer(&dev->watchdog_timer, dev_watchdog, (unsigned long)dev);
}

static void dev_init_scheduler_queue(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_qdisc)
{
	struct Qdisc *qdisc = _qdisc;

	rcu_assign_pointer(dev_queue->qdisc, qdisc);   //队列设置qdisc
	dev_queue->qdisc_sleeping = qdisc;
}

```

__dev_open打开网卡设备时，调用如下函数，完成根Qdisc初始化：
```c
void dev_activate(struct net_device *dev)
{
	int need_watchdog;

	/* No queueing discipline is attached to device;
	 * create default one for devices, which need queueing
	 * and noqueue_qdisc for virtual interfaces
	 */

	if (dev->qdisc == &noop_qdisc)
		attach_default_qdiscs(dev);   //挂载默认qdisc，条件满足，网卡open之后重新进此函数将不满足

	if (!netif_carrier_ok(dev))
		/* Delay activation until next carrier-on event */
		return;

	need_watchdog = 0;
	netdev_for_each_tx_queue(dev, transition_one_qdisc, &need_watchdog);
	if (dev_ingress_queue(dev))
		transition_one_qdisc(dev, dev_ingress_queue(dev), NULL);

	if (need_watchdog) {
		dev->trans_start = jiffies;
		dev_watchdog_up(dev);
	}
}


static void transition_one_qdisc(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 void *_need_watchdog)
{
	struct Qdisc *new_qdisc = dev_queue->qdisc_sleeping;   //新qdisc先放在qdisc_sleeping，然后再设置到qdisc
	int *need_watchdog_p = _need_watchdog;

	if (!(new_qdisc->flags & TCQ_F_BUILTIN))
		clear_bit(__QDISC_STATE_DEACTIVATED, &new_qdisc->state);

	rcu_assign_pointer(dev_queue->qdisc, new_qdisc);       //新disc复制
	if (need_watchdog_p && new_qdisc != &noqueue_qdisc) {
		dev_queue->trans_start = 0;
		*need_watchdog_p = 1;
	}
}

static void attach_default_qdiscs(struct net_device *dev)
{
	struct netdev_queue *txq;
	struct Qdisc *qdisc;

	txq = netdev_get_tx_queue(dev, 0);  //获取发送队列

	if (!netif_is_multiqueue(dev) || dev->tx_queue_len == 0) {   //单队列，或者发送队列长度为0
		netdev_for_each_tx_queue(dev, attach_one_default_qdisc, NULL);
		dev->qdisc = txq->qdisc_sleeping;    //都设置为新创建根qdisc
		atomic_inc(&dev->qdisc->refcnt);
	} else {
		qdisc = qdisc_create_dflt(txq, &mq_qdisc_ops, TC_H_ROOT);  //创建根qdisc，这个qdisc没有enqueue函数
		if (qdisc) {
			dev->qdisc = qdisc;         //qdisc赋值给dev
			qdisc->ops->attach(qdisc);  
		}
	}
}

static void attach_one_default_qdisc(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_unused)
{
	struct Qdisc *qdisc = &noqueue_qdisc;   //没有enqueue函数

	if (dev->tx_queue_len) {
		qdisc = qdisc_create_dflt(dev_queue,
					  default_qdisc_ops, TC_H_ROOT);   //创建根qdisc，单队列场景
		if (!qdisc) {
			netdev_info(dev, "activation failed\n");
			return;
		}
		if (!netif_is_multiqueue(dev))
			qdisc->flags |= TCQ_F_ONETXQUEUE;
	}
	dev_queue->qdisc_sleeping = qdisc;      //没有enqueue函数
}

struct Qdisc *qdisc_create_dflt(struct netdev_queue *dev_queue,
				const struct Qdisc_ops *ops,
				unsigned int parentid)
{
	struct Qdisc *sch;

	if (!try_module_get(ops->owner))
		goto errout;

	sch = qdisc_alloc(dev_queue, ops);		//创建qdisc
	if (IS_ERR(sch))
		goto errout;
	sch->parent = parentid;    //设置parent

	if (!ops->init || ops->init(sch, NULL) == 0)   //qdisc初始化
		return sch;

	qdisc_destroy(sch);
errout:
	return NULL;
}

struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
			  const struct Qdisc_ops *ops)
{
	void *p;
	struct Qdisc *sch;
	unsigned int size = QDISC_ALIGN(sizeof(*sch)) + ops->priv_size;  //根据不同的ops创建不同的qdisc对象
	int err = -ENOBUFS;
	struct net_device *dev = dev_queue->dev;

	p = kzalloc_node(size, GFP_KERNEL,
			 netdev_queue_numa_node_read(dev_queue));

	if (!p)
		goto errout;
	sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
	/* if we got non aligned memory, ask more and do alignment ourself */
	if (sch != p) {
		kfree(p);
		p = kzalloc_node(size + QDISC_ALIGNTO - 1, GFP_KERNEL,
				 netdev_queue_numa_node_read(dev_queue));
		if (!p)
			goto errout;
		sch = (struct Qdisc *) QDISC_ALIGN((unsigned long) p);
		sch->padded = (char *) sch - (char *) p;
	}
	INIT_LIST_HEAD(&sch->list);
	skb_queue_head_init(&sch->q);

	spin_lock_init(&sch->busylock);
	lockdep_set_class(&sch->busylock,
			  dev->qdisc_tx_busylock ?: &qdisc_tx_busylock);

	sch->ops = ops;
	sch->enqueue = ops->enqueue;
	sch->dequeue = ops->dequeue;
	sch->dev_queue = dev_queue;   //赋值dev_queue
	dev_hold(dev);
	atomic_set(&sch->refcnt, 1);

	return sch;
errout:
	return ERR_PTR(err);
}
```


### 默认单队列的Qdisc
```c
const struct Qdisc_ops *default_qdisc_ops = &pfifo_fast_ops;  //单队列的默认Qdisc是基于优先级的算法，高优先级发完再发低优先级的

struct Qdisc_ops pfifo_fast_ops __read_mostly = {
	.id		=	"pfifo_fast",
	.priv_size	=	sizeof(struct pfifo_fast_priv),
	.enqueue	=	pfifo_fast_enqueue,
	.dequeue	=	pfifo_fast_dequeue,
	.peek		=	pfifo_fast_peek,
	.init		=	pfifo_fast_init,
	.reset		=	pfifo_fast_reset,
	.dump		=	pfifo_fast_dump,
	.owner		=	THIS_MODULE,
};

static int pfifo_fast_enqueue(struct sk_buff *skb, struct Qdisc *qdisc)
{
	if (skb_queue_len(&qdisc->q) < qdisc_dev(qdisc)->tx_queue_len) {  
		int band = prio2band[skb->priority & TC_PRIO_MAX];  //优先级转band，共有3中bond
		struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
		struct sk_buff_head *list = band2list(priv, band);   //共三个链表

		priv->bitmap |= (1 << band);   //bitmap记录哪些band有数据
		qdisc->q.qlen++;  //报文数加一
		return __qdisc_enqueue_tail(skb, qdisc, list);   //添加到队列中
	}

	return qdisc_drop(skb, qdisc);  //丢弃报文
}

static struct sk_buff *pfifo_fast_dequeue(struct Qdisc *qdisc)
{
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	int band = bitmap2band[priv->bitmap];     //根据bitmap，获得band，通过数组用空间换时间，队列数少可行

	if (likely(band >= 0)) {
		struct sk_buff_head *list = band2list(priv, band);
		struct sk_buff *skb = __qdisc_dequeue_head(qdisc, list);  //从队列中获取skb

		qdisc->q.qlen--;
		if (skb_queue_empty(list))
			priv->bitmap &= ~(1 << band);    //如果该链表为空，则标记该位为空

		return skb;
	}

	return NULL;
}

```

### 默认多队列的Qdisc

默认多队列的情况下，是不开启Qdisc的，直接发送报文

```c
struct Qdisc_ops mq_qdisc_ops __read_mostly = {
	.cl_ops		= &mq_class_ops,
	.id		= "mq",
	.priv_size	= sizeof(struct mq_sched),
	.init		= mq_init,
	.destroy	= mq_destroy,
	.attach		= mq_attach,
	.dump		= mq_dump,
	.owner		= THIS_MODULE,
};
```


## TC操作入口函数定义

### Qdisc和Class操作入口

```c
	rtnl_register(PF_UNSPEC, RTM_NEWQDISC, tc_modify_qdisc, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELQDISC, tc_get_qdisc, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETQDISC, tc_get_qdisc, tc_dump_qdisc, NULL);
	rtnl_register(PF_UNSPEC, RTM_NEWTCLASS, tc_ctl_tclass, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELTCLASS, tc_ctl_tclass, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETTCLASS, tc_ctl_tclass, tc_dump_tclass, NULL);
```

### Filter操作入口

```c
	rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_ctl_tfilter, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELTFILTER, tc_ctl_tfilter, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETTFILTER, tc_ctl_tfilter, tc_dump_tfilter, NULL);
```

### Action操作入口

```c
	rtnl_register(PF_UNSPEC, RTM_NEWACTION, tc_ctl_action, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELACTION, tc_ctl_action, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETACTION, tc_ctl_action, tc_dump_action, NULL);
```


## 创建Qdisc流程

```c
static int tc_modify_qdisc(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm;
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	u32 clid;
	struct Qdisc *q, *p;
	int err;

	if (!netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

replay:
	/* Reinit, just in case something touches this. */
	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);		//解析参数
	if (err < 0)
		return err;

	tcm = nlmsg_data(n);
	clid = tcm->tcm_parent;		//得到父class id，根qdisc没有此参数
	q = p = NULL;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);    //得到网卡设备
	if (!dev)
		return -ENODEV;


	if (clid) {
		if (clid != TC_H_ROOT) {
			if (clid != TC_H_INGRESS) {
				p = qdisc_lookup(dev, TC_H_MAJ(clid));
				if (!p)
					return -ENOENT;
				q = qdisc_leaf(p, clid);
			} else if (dev_ingress_queue_create(dev)) {
				q = dev_ingress_queue(dev)->qdisc_sleeping;
			}
		} else {
			q = dev->qdisc;
		}

		/* It may be default qdisc, ignore it */
		if (q && q->handle == 0)
			q = NULL;

		if (!q || !tcm->tcm_handle || q->handle != tcm->tcm_handle) {
			if (tcm->tcm_handle) {
				if (q && !(n->nlmsg_flags & NLM_F_REPLACE))
					return -EEXIST;
				if (TC_H_MIN(tcm->tcm_handle))
					return -EINVAL;
				q = qdisc_lookup(dev, tcm->tcm_handle);
				if (!q)
					goto create_n_graft;
				if (n->nlmsg_flags & NLM_F_EXCL)
					return -EEXIST;
				if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
					return -EINVAL;
				if (q == p ||
				    (p && check_loop(q, p, 0)))
					return -ELOOP;
				atomic_inc(&q->refcnt);
				goto graft;
			} else {
				if (!q)
					goto create_n_graft;		//根qdisc走此分支，创建qdisc

				/* This magic test requires explanation.
				 *
				 *   We know, that some child q is already
				 *   attached to this parent and have choice:
				 *   either to change it or to create/graft new one.
				 *
				 *   1. We are allowed to create/graft only
				 *   if CREATE and REPLACE flags are set.
				 *
				 *   2. If EXCL is set, requestor wanted to say,
				 *   that qdisc tcm_handle is not expected
				 *   to exist, so that we choose create/graft too.
				 *
				 *   3. The last case is when no flags are set.
				 *   Alas, it is sort of hole in API, we
				 *   cannot decide what to do unambiguously.
				 *   For now we select create/graft, if
				 *   user gave KIND, which does not match existing.
				 */
				if ((n->nlmsg_flags & NLM_F_CREATE) &&
				    (n->nlmsg_flags & NLM_F_REPLACE) &&
				    ((n->nlmsg_flags & NLM_F_EXCL) ||
				     (tca[TCA_KIND] &&
				      nla_strcmp(tca[TCA_KIND], q->ops->id))))
					goto create_n_graft;
			}
		}
	} else {
		if (!tcm->tcm_handle)
			return -EINVAL;
		q = qdisc_lookup(dev, tcm->tcm_handle);
	}

	/* Change qdisc parameters */
	if (q == NULL)
		return -ENOENT;
	if (n->nlmsg_flags & NLM_F_EXCL)
		return -EEXIST;
	if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
		return -EINVAL;
	err = qdisc_change(q, tca);
	if (err == 0)
		qdisc_notify(net, skb, n, clid, NULL, q);
	return err;

create_n_graft:
	if (!(n->nlmsg_flags & NLM_F_CREATE))
		return -ENOENT;
	if (clid == TC_H_INGRESS) {
		if (dev_ingress_queue(dev))
			q = qdisc_create(dev, dev_ingress_queue(dev), p,
					 tcm->tcm_parent, tcm->tcm_parent,
					 tca, &err);
		else
			err = -ENOENT;
	} else {
		struct netdev_queue *dev_queue;

		if (p && p->ops->cl_ops && p->ops->cl_ops->select_queue)
			dev_queue = p->ops->cl_ops->select_queue(p, tcm);
		else if (p)
			dev_queue = p->dev_queue;
		else
			dev_queue = netdev_get_tx_queue(dev, 0);		//得到0号队列，根qdisc场景

		q = qdisc_create(dev, dev_queue, p,				//qdisc创建
				 tcm->tcm_parent, tcm->tcm_handle,
				 tca, &err);
	}
	if (q == NULL) {
		if (err == -EAGAIN)
			goto replay;
		return err;
	}

graft:
	err = qdisc_graft(dev, p, skb, n, clid, q, NULL);		//为网卡设备的其他发送队列分配qdisc，使用相同的qdisc
	if (err) {
		if (q)
			qdisc_destroy(q);
		return err;
	}

	return 0;
}


static struct Qdisc *
qdisc_create(struct net_device *dev, struct netdev_queue *dev_queue,
	     struct Qdisc *p, u32 parent, u32 handle,
	     struct nlattr **tca, int *errp)
{
	int err;
	struct nlattr *kind = tca[TCA_KIND];
	struct Qdisc *sch;
	struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;

	ops = qdisc_lookup_ops(kind);		//根据算法类型，得到qdisc_ops
#ifdef CONFIG_MODULES
	if (ops == NULL && kind != NULL) {
		char name[IFNAMSIZ];
		if (nla_strlcpy(name, kind, IFNAMSIZ) < IFNAMSIZ) {
			/* We dropped the RTNL semaphore in order to
			 * perform the module load.  So, even if we
			 * succeeded in loading the module we have to
			 * tell the caller to replay the request.  We
			 * indicate this using -EAGAIN.
			 * We replay the request because the device may
			 * go away in the mean time.
			 */
			rtnl_unlock();
			request_module("sch_%s", name);
			rtnl_lock();
			ops = qdisc_lookup_ops(kind);
			if (ops != NULL) {
				/* We will try again qdisc_lookup_ops,
				 * so don't keep a reference.
				 */
				module_put(ops->owner);
				err = -EAGAIN;
				goto err_out;
			}
		}
	}
#endif

	err = -ENOENT;
	if (ops == NULL)
		goto err_out;

	sch = qdisc_alloc(dev_queue, ops);		//创建qdisc，并初始化qdisc信息
	if (IS_ERR(sch)) {
		err = PTR_ERR(sch);
		goto err_out2;
	}

	sch->parent = parent;			//设置qdisc的parent，根qdisc没有parent， 子qdisc parent为class

	if (handle == TC_H_INGRESS) {
		sch->flags |= TCQ_F_INGRESS;
		handle = TC_H_MAKE(TC_H_INGRESS, 0);
		lockdep_set_class(qdisc_lock(sch), &qdisc_rx_lock);
	} else {
		if (handle == 0) {
			handle = qdisc_alloc_handle(dev);		//handle是32位数值
			err = -ENOMEM;
			if (handle == 0)
				goto err_out3;
		}
		lockdep_set_class(qdisc_lock(sch), &qdisc_tx_lock);
		if (!netif_is_multiqueue(dev))
			sch->flags |= TCQ_F_ONETXQUEUE;
	}

	sch->handle = handle;   //设置handle

	if (!ops->init || (err = ops->init(sch, tca[TCA_OPTIONS])) == 0) {		//调用qdisc驱动初始化，根据各自参数初始化
		if (qdisc_is_percpu_stats(sch)) {
			sch->cpu_bstats =
				netdev_alloc_pcpu_stats(struct gnet_stats_basic_cpu);
			if (!sch->cpu_bstats)
				goto err_out4;

			sch->cpu_qstats = alloc_percpu(struct gnet_stats_queue);
			if (!sch->cpu_qstats)
				goto err_out4;
		}

		if (tca[TCA_STAB]) {
			stab = qdisc_get_stab(tca[TCA_STAB]);
			if (IS_ERR(stab)) {
				err = PTR_ERR(stab);
				goto err_out4;
			}
			rcu_assign_pointer(sch->stab, stab);
		}
		if (tca[TCA_RATE]) {
			spinlock_t *root_lock;

			err = -EOPNOTSUPP;
			if (sch->flags & TCQ_F_MQROOT)
				goto err_out4;

			if ((sch->parent != TC_H_ROOT) &&
			    !(sch->flags & TCQ_F_INGRESS) &&
			    (!p || !(p->flags & TCQ_F_MQROOT)))
				root_lock = qdisc_root_sleeping_lock(sch);
			else
				root_lock = qdisc_lock(sch);

			err = gen_new_estimator(&sch->bstats,
						sch->cpu_bstats,
						&sch->rate_est,
						root_lock,
						tca[TCA_RATE]);
			if (err)
				goto err_out4;
		}

		qdisc_list_add(sch);   //添加到父qdisc的链表中

		return sch;
	}
err_out3:
	dev_put(dev);
	kfree((char *) sch - sch->padded);
err_out2:
	module_put(ops->owner);
err_out:
	*errp = err;
	return NULL;

err_out4:
	free_percpu(sch->cpu_bstats);
	free_percpu(sch->cpu_qstats);
	/*
	 * Any broken qdiscs that would require a ops->reset() here?
	 * The qdisc was never in action so it shouldn't be necessary.
	 */
	qdisc_put_stab(rtnl_dereference(sch->stab));
	if (ops->destroy)
		ops->destroy(sch);
	goto err_out3;
}


static int qdisc_graft(struct net_device *dev, struct Qdisc *parent,
		       struct sk_buff *skb, struct nlmsghdr *n, u32 classid,
		       struct Qdisc *new, struct Qdisc *old)
{
	struct Qdisc *q = old;
	struct net *net = dev_net(dev);
	int err = 0;

	if (parent == NULL) {
		unsigned int i, num_q, ingress;

		ingress = 0;
		num_q = dev->num_tx_queues;
		if ((q && q->flags & TCQ_F_INGRESS) ||
		    (new && new->flags & TCQ_F_INGRESS)) {
			num_q = 1;
			ingress = 1;
			if (!dev_ingress_queue(dev))
				return -ENOENT;
		}

		if (dev->flags & IFF_UP)
			dev_deactivate(dev);

		if (new && new->ops->attach)
			goto skip;

		for (i = 0; i < num_q; i++) {
			struct netdev_queue *dev_queue = dev_ingress_queue(dev);

			if (!ingress)
				dev_queue = netdev_get_tx_queue(dev, i);	//获取发送队列

			old = dev_graft_qdisc(dev_queue, new);	//为发送队列分配qdisc，返回源使用的qdisc，所有发送队列都是指向同一个qdisc
			if (new && i > 0)
				atomic_inc(&new->refcnt);

			if (!ingress)
				qdisc_destroy(old);	//释放原qdisc
		}

skip:
		if (!ingress) {
			notify_and_destroy(net, skb, n, classid,
					   dev->qdisc, new);
			if (new && !new->ops->attach)
				atomic_inc(&new->refcnt);
			dev->qdisc = new ? : &noop_qdisc;

			if (new && new->ops->attach)
				new->ops->attach(new);			//调用qdisc驱动的attach操作
		} else {
			notify_and_destroy(net, skb, n, classid, old, new);
		}

		if (dev->flags & IFF_UP)
			dev_activate(dev);			//更新网卡队列的qdisc
	} else {
		const struct Qdisc_class_ops *cops = parent->ops->cl_ops;

		err = -EOPNOTSUPP;
		if (cops && cops->graft) {
			unsigned long cl = cops->get(parent, classid);
			if (cl) {
				err = cops->graft(parent, cl, new, &old);   //调用class ops的graft操作
				cops->put(parent, cl);
			} else
				err = -ENOENT;
		}
		if (!err)
			notify_and_destroy(net, skb, n, classid, old, new);
	}
	return err;
}

struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
			      struct Qdisc *qdisc)
{
	struct Qdisc *oqdisc = dev_queue->qdisc_sleeping;    //原qdisc
	spinlock_t *root_lock;

	root_lock = qdisc_lock(oqdisc);
	spin_lock_bh(root_lock);

	/* Prune old scheduler */
	if (oqdisc && atomic_read(&oqdisc->refcnt) <= 1)
		qdisc_reset(oqdisc);

	/* ... and graft new one */
	if (qdisc == NULL)
		qdisc = &noop_qdisc;
	dev_queue->qdisc_sleeping = qdisc;
	rcu_assign_pointer(dev_queue->qdisc, &noop_qdisc);   //先把qdisc替换为默认qdisc，该qdisc直接丢包

	spin_unlock_bh(root_lock);

	return oqdisc;
}

void qdisc_list_add(struct Qdisc *q)
{
	if ((q->parent != TC_H_ROOT) && !(q->flags & TCQ_F_INGRESS)) {
		struct Qdisc *root = qdisc_dev(q)->qdisc;		//设备的qdisc为root qdisc（mq_qdisc_ops）

		WARN_ON_ONCE(root == &noop_qdisc);
		list_add_tail(&q->list, &root->list);
	}
}
```


## 创建Class流程

```c
static int tc_ctl_tclass(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm = nlmsg_data(n);
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	struct Qdisc *q = NULL;
	const struct Qdisc_class_ops *cops;
	unsigned long cl = 0;
	unsigned long new_cl;
	u32 portid;
	u32 clid;
	u32 qid;
	int err;

	if ((n->nlmsg_type != RTM_GETTCLASS) &&
	    !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);  //解析参数
	if (err < 0)
		return err;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);   //得到设备
	if (!dev)
		return -ENODEV;

	/*
	   parent == TC_H_UNSPEC - unspecified parent.
	   parent == TC_H_ROOT   - class is root, which has no parent.
	   parent == X:0	 - parent is root class.
	   parent == X:Y	 - parent is a node in hierarchy.
	   parent == 0:Y	 - parent is X:Y, where X:0 is qdisc.

	   handle == 0:0	 - generate handle from kernel pool.
	   handle == 0:Y	 - class is X:Y, where X:0 is qdisc.
	   handle == X:Y	 - clear.
	   handle == X:0	 - root class.
	 */

	/* Step 1. Determine qdisc handle X:0 */

	portid = tcm->tcm_parent;
	clid = tcm->tcm_handle;
	qid = TC_H_MAJ(clid);		//根据class id获得parent qdisc id

	if (portid != TC_H_ROOT) {
		u32 qid1 = TC_H_MAJ(portid);  //parent的qdisc id

		if (qid && qid1) {   //如果同时存在，必须相同
			/* If both majors are known, they must be identical. */
			if (qid != qid1)
				return -EINVAL;
		} else if (qid1) {
			qid = qid1;
		} else if (qid == 0)
			qid = dev->qdisc->handle;

		/* Now qid is genuine qdisc handle consistent
		 * both with parent and child.
		 *
		 * TC_H_MAJ(portid) still may be unspecified, complete it now.
		 */
		if (portid)
			portid = TC_H_MAKE(qid, portid);
	} else {
		if (qid == 0)
			qid = dev->qdisc->handle;
	}

	/* OK. Locate qdisc */
	q = qdisc_lookup(dev, qid);    //根据handle的major查找qdisc
	if (!q)
		return -ENOENT;

	/* An check that it supports classes */
	cops = q->ops->cl_ops;			//得到qdisc的class驱动
	if (cops == NULL)
		return -EINVAL;

	/* Now try to get class */
	if (clid == 0) {
		if (portid == TC_H_ROOT)
			clid = qid;
	} else
		clid = TC_H_MAKE(qid, clid);   //生成classid

	if (clid)
		cl = cops->get(q, clid);		//根据clid查找class

	if (cl == 0) {
		err = -ENOENT;
		if (n->nlmsg_type != RTM_NEWTCLASS ||
		    !(n->nlmsg_flags & NLM_F_CREATE))
			goto out;
	} else {
		switch (n->nlmsg_type) {
		case RTM_NEWTCLASS:
			err = -EEXIST;
			if (n->nlmsg_flags & NLM_F_EXCL)
				goto out;
			break;
		case RTM_DELTCLASS:
			err = -EOPNOTSUPP;
			if (cops->delete)
				err = cops->delete(q, cl);
			if (err == 0)
				tclass_notify(net, skb, n, q, cl, RTM_DELTCLASS);
			goto out;
		case RTM_GETTCLASS:
			err = tclass_notify(net, skb, n, q, cl, RTM_NEWTCLASS);
			goto out;
		default:
			err = -EINVAL;
			goto out;
		}
	}

	new_cl = cl;
	err = -EOPNOTSUPP;
	if (cops->change)
		err = cops->change(q, clid, portid, tca, &new_cl);   //创建class实例与实际Qdisc类型相关，待到相关章节介绍
	if (err == 0)
		tclass_notify(net, skb, n, q, new_cl, RTM_NEWTCLASS);

out:
	if (cl)
		cops->put(q, cl);

	return err;
}
```


## 创建Filter流程

```c
static int tc_ctl_tfilter(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct tcmsg *t;
	u32 protocol;
	u32 prio;
	u32 nprio;
	u32 parent;
	struct net_device *dev;
	struct Qdisc  *q;
	struct tcf_proto __rcu **back;
	struct tcf_proto __rcu **chain;
	struct tcf_proto *tp;
	const struct tcf_proto_ops *tp_ops;
	const struct Qdisc_class_ops *cops;
	unsigned long cl;
	unsigned long fh;
	int err;
	int tp_created = 0;

	if ((n->nlmsg_type != RTM_GETTFILTER) &&
	    !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

replay:
	err = nlmsg_parse(n, sizeof(*t), tca, TCA_MAX, NULL);   //参数解析
	if (err < 0)
		return err;

	t = nlmsg_data(n);
	protocol = TC_H_MIN(t->tcm_info);  
	prio = TC_H_MAJ(t->tcm_info); 
	nprio = prio;
	parent = t->tcm_parent;
	cl = 0;

	if (prio == 0) {
		/* If no priority is given, user wants we allocated it. */
		if (n->nlmsg_type != RTM_NEWTFILTER ||
		    !(n->nlmsg_flags & NLM_F_CREATE))
			return -ENOENT;
		prio = TC_H_MAKE(0x80000000U, 0U);
	}

	/* Find head of filter chain. */

	/* Find link */
	dev = __dev_get_by_index(net, t->tcm_ifindex);   //得到设备信息
	if (dev == NULL)
		return -ENODEV;

	/* Find qdisc */
	if (!parent) {
		q = dev->qdisc;
		parent = q->handle;
	} else {
		q = qdisc_lookup(dev, TC_H_MAJ(t->tcm_parent));   //得到父qdisc
		if (q == NULL)
			return -EINVAL;
	}

	/* Is it classful? */
	cops = q->ops->cl_ops;   //qdisc是否支持class
	if (!cops)
		return -EINVAL;

	if (cops->tcf_chain == NULL)
		return -EOPNOTSUPP;

	/* Do we search for filter, attached to class? */
	if (TC_H_MIN(parent)) {          //class的minor不为零，说明parent是class
		cl = cops->get(q, parent);   //得到class
		if (cl == 0)
			return -ENOENT;
	}

	/* And the last stroke */
	chain = cops->tcf_chain(q, cl);     //得到class的tcf链表
	err = -EINVAL;
	if (chain == NULL)
		goto errout;

	/* Check the chain for existence of proto-tcf with this priority */
	for (back = chain;
	     (tp = rtnl_dereference(*back)) != NULL;
	     back = &tp->next) {
		if (tp->prio >= prio) {
			if (tp->prio == prio) {
				if (!nprio ||
				    (tp->protocol != protocol && protocol))
					goto errout;
			} else
				tp = NULL;
			break;
		}
	}

	if (tp == NULL) {
		/* Proto-tcf does not exist, create new one */

		if (tca[TCA_KIND] == NULL || !protocol)
			goto errout;

		err = -ENOENT;
		if (n->nlmsg_type != RTM_NEWTFILTER ||
		    !(n->nlmsg_flags & NLM_F_CREATE))
			goto errout;


		/* Create new proto tcf */

		err = -ENOBUFS;
		tp = kzalloc(sizeof(*tp), GFP_KERNEL);        //申请filter
		if (tp == NULL)
			goto errout;
		err = -ENOENT;
		tp_ops = tcf_proto_lookup_ops(tca[TCA_KIND]);   //得到filter ops
		if (tp_ops == NULL) {
#ifdef CONFIG_MODULES
			struct nlattr *kind = tca[TCA_KIND];
			char name[IFNAMSIZ];

			if (kind != NULL &&
			    nla_strlcpy(name, kind, IFNAMSIZ) < IFNAMSIZ) {
				rtnl_unlock();
				request_module("cls_%s", name);
				rtnl_lock();
				tp_ops = tcf_proto_lookup_ops(kind);
				/* We dropped the RTNL semaphore in order to
				 * perform the module load.  So, even if we
				 * succeeded in loading the module we have to
				 * replay the request.  We indicate this using
				 * -EAGAIN.
				 */
				if (tp_ops != NULL) {
					module_put(tp_ops->owner);
					err = -EAGAIN;
				}
			}
#endif
			kfree(tp);
			goto errout;
		}
		tp->ops = tp_ops;         //设置filter ops
		tp->protocol = protocol;
		tp->prio = nprio ? :
			       TC_H_MAJ(tcf_auto_prio(rtnl_dereference(*back)));
		tp->q = q;
		tp->classify = tp_ops->classify;
		tp->classid = parent;

		err = tp_ops->init(tp);    //初始化filter
		if (err != 0) {
			module_put(tp_ops->owner);
			kfree(tp);
			goto errout;
		}

		tp_created = 1;

	} else if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], tp->ops->kind))
		goto errout;

	fh = tp->ops->get(tp, t->tcm_handle);   

	if (fh == 0) {
		if (n->nlmsg_type == RTM_DELTFILTER && t->tcm_handle == 0) {
			struct tcf_proto *next = rtnl_dereference(tp->next);

			RCU_INIT_POINTER(*back, next);

			tfilter_notify(net, skb, n, tp, fh, RTM_DELTFILTER);
			tcf_destroy(tp, true);
			err = 0;
			goto errout;
		}

		err = -ENOENT;
		if (n->nlmsg_type != RTM_NEWTFILTER ||
		    !(n->nlmsg_flags & NLM_F_CREATE))
			goto errout;
	} else {
		switch (n->nlmsg_type) {
		case RTM_NEWTFILTER:
			err = -EEXIST;
			if (n->nlmsg_flags & NLM_F_EXCL) {
				if (tp_created)
					tcf_destroy(tp, true);
				goto errout;
			}
			break;
		case RTM_DELTFILTER:
			err = tp->ops->delete(tp, fh);
			if (err == 0) {
				struct tcf_proto *next = rtnl_dereference(tp->next);

				tfilter_notify(net, skb, n, tp, fh, RTM_DELTFILTER);
				if (tcf_destroy(tp, false))
					RCU_INIT_POINTER(*back, next);
			}
			goto errout;
		case RTM_GETTFILTER:
			err = tfilter_notify(net, skb, n, tp, fh, RTM_NEWTFILTER);
			goto errout;
		default:
			err = -EINVAL;
			goto errout;
		}
	}

	err = tp->ops->change(net, skb, tp, cl, t->tcm_handle, tca, &fh,
			      n->nlmsg_flags & NLM_F_CREATE ? TCA_ACT_NOREPLACE : TCA_ACT_REPLACE);
	if (err == 0) {
		if (tp_created) {
			RCU_INIT_POINTER(tp->next, rtnl_dereference(*back));
			rcu_assign_pointer(*back, tp);
		}
		tfilter_notify(net, skb, n, tp, fh, RTM_NEWTFILTER);
	} else {
		if (tp_created)
			tcf_destroy(tp, true);
	}

errout:
	if (cl)
		cops->put(q, cl);
	if (err == -EAGAIN)
		/* Replay the request. */
		goto replay;
	return err;
}
```


## 创建Action流程

```c
static int tc_ctl_action(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_ACT_MAX + 1];
	u32 portid = skb ? NETLINK_CB(skb).portid : 0;
	int ret = 0, ovr = 0;

	if ((n->nlmsg_type != RTM_GETACTION) && !netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(n, sizeof(struct tcamsg), tca, TCA_ACT_MAX, NULL);
	if (ret < 0)
		return ret;

	if (tca[TCA_ACT_TAB] == NULL) {
		pr_notice("tc_ctl_action: received NO action attribs\n");
		return -EINVAL;
	}

	/* n->nlmsg_flags & NLM_F_CREATE */
	switch (n->nlmsg_type) {
	case RTM_NEWACTION:
		/* we are going to assume all other flags
		 * imply create only if it doesn't exist
		 * Note that CREATE | EXCL implies that
		 * but since we want avoid ambiguity (eg when flags
		 * is zero) then just set this
		 */
		if (n->nlmsg_flags & NLM_F_REPLACE)
			ovr = 1;
replay:
		ret = tcf_action_add(net, tca[TCA_ACT_TAB], n, portid, ovr);
		if (ret == -EAGAIN)
			goto replay;
		break;
	case RTM_DELACTION:
		ret = tca_action_gd(net, tca[TCA_ACT_TAB], n,
				    portid, RTM_DELACTION);
		break;
	case RTM_GETACTION:
		ret = tca_action_gd(net, tca[TCA_ACT_TAB], n,
				    portid, RTM_GETACTION);
		break;
	default:
		BUG();
	}

	return ret;
}

static int
tcf_action_add(struct net *net, struct nlattr *nla, struct nlmsghdr *n,
	       u32 portid, int ovr)
{
	int ret = 0;
	LIST_HEAD(actions);

	ret = tcf_action_init(net, nla, NULL, NULL, ovr, 0, &actions);
	if (ret)
		goto done;

	/* dump then free all the actions after update; inserted policy
	 * stays intact
	 */
	ret = tcf_add_notify(net, n, &actions, portid);
	cleanup_a(&actions);
done:
	return ret;
}

int tcf_action_init(struct net *net, struct nlattr *nla,
				  struct nlattr *est, char *name, int ovr,
				  int bind, struct list_head *actions)
{
	struct nlattr *tb[TCA_ACT_MAX_PRIO + 1];
	struct tc_action *act;
	int err;
	int i;

	err = nla_parse_nested(tb, TCA_ACT_MAX_PRIO, nla, NULL);
	if (err < 0)
		return err;

	for (i = 1; i <= TCA_ACT_MAX_PRIO && tb[i]; i++) {
		act = tcf_action_init_1(net, tb[i], est, name, ovr, bind);
		if (IS_ERR(act)) {
			err = PTR_ERR(act);
			goto err;
		}
		act->order = i;
		list_add_tail(&act->list, actions);
	}
	return 0;

err:
	tcf_action_destroy(actions, bind);
	return err;
}
```


## 总结

### handle和classid总结

* parent、handle和classid格式
  * major:minor
  * major:[0]
* qdisc handle的minor必须为零
* class classid的major必须等于所属qdisc的major
* class parent的major必须等于所属qdisc的major

