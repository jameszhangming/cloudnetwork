# Traffic Control

Traffic Control（TC）流量控制，是网络QoS的Linux实现，Linux内核通过Qdisc，class和filter三者来实现，本文将介绍系统默认Qidsc的初始化过程，以及Qidsc、Class和filter配置流程。

本篇分析物理网卡初始化Qdisc的过程，以及默认qidsc的功能实现，用户设置qdisc的流程涉及到不同qdisc的差异，将单独分析。

网卡Qdisc的初始化分两个阶段：

1. 网卡设备注册时
   * dev->qdisc = &noop_qdisc
   * dev_queue[all]->qdisc = &noop_qdisc
   * dev_queue[all]->qdisc_sleeping = &noop_qdisc
   * ingress_queue->qdisc = &noop_qdisc
   * ingress_queue->qdisc_sleeping = &noop_qdisc
2. 网卡设备打开时
   1. 单队列
      * dev->qdisc = 新建的根qdisc（default_qdisc_ops）
	  * dev_queue[0]->qdisc = 新建的根qdisc（default_qdisc_ops）
      * dev_queue[0]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops）
   2. 多队列且发送队列长度为0
      * dev->qdisc = &noqueue_qdisc
	  * dev_queue[all]->qdisc = &noqueue_qdisc
      * dev_queue[all]->qdisc_sleeping = &noqueue_qdisc
   3. 多队列且发送队列长度不为0
      * dev->qdisc = 新建的根qdisc（mq_qdisc_ops）
	  * dev_queue[all]->qdisc = 新建的根qdisc（default_qdisc_ops，每个队列都不同）
	  * dev_queue[all]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops，每个队列都不同）

	  
## 网卡设备注册

register_netdevice注册设备时，调用如下函数，初始化qdisc：

```c
void dev_init_scheduler(struct net_device *dev)
{
	dev->qdisc = &noop_qdisc;  //此类qdisc是用来标识当前设备没有配置qdisc
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

## 打开网卡设备

__dev_open打开网卡设备时，调用如下函数，完成根Qdisc初始化：

```c
void dev_activate(struct net_device *dev)
{
	int need_watchdog;

	/* No queueing discipline is attached to device;
	 * create default one for devices, which need queueing
	 * and noqueue_qdisc for virtual interfaces
	 */

	if (dev->qdisc == &noop_qdisc)   //条件成立
		attach_default_qdiscs(dev);  

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

/*
执行此函数后，设备的qdisc信息如下
   1. 单队列
      * dev->qdisc = 新建的根qdisc（default_qdisc_ops）
      * dev_queue[0]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops）
   2. 多队列且发送队列长度为0
      * dev->qdisc = &noqueue_qdisc
      * dev_queue[all]->qdisc_sleeping = &noqueue_qdisc
   3. 多队列且发送队列长度不为0
      * dev->qdisc = 新建的根qdisc（mq_qdisc_ops）
	  * dev_queue[all]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops，每个队列都不同）
*/
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
					  default_qdisc_ops, TC_H_ROOT);   //单队列场景，创建根qdisc，单队列场景
		if (!qdisc) {
			netdev_info(dev, "activation failed\n");
			return;
		}
		if (!netif_is_multiqueue(dev))
			qdisc->flags |= TCQ_F_ONETXQUEUE;  //qdisc打上单队列标记
	}
	dev_queue->qdisc_sleeping = qdisc;      //没有enqueue函数
}

/*
执行此函数后，设备的qdisc信息如下
   1. 单队列
      * dev->qdisc = 新建的根qdisc（default_qdisc_ops）
	  * dev_queue[0]->qdisc = 新建的根qdisc（default_qdisc_ops）
      * dev_queue[0]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops）
   2. 多队列且发送队列长度为0
      * dev->qdisc = &noqueue_qdisc
	  * dev_queue[all]->qdisc = &noqueue_qdisc
      * dev_queue[all]->qdisc_sleeping = &noqueue_qdisc
   3. 多队列且发送队列长度不为0
      * dev->qdisc = 新建的根qdisc（mq_qdisc_ops）
	  * dev_queue[all]->qdisc = 新建的根qdisc（default_qdisc_ops，每个队列都不同）
	  * dev_queue[all]->qdisc_sleeping = 新建的根qdisc（default_qdisc_ops，每个队列都不同）
*/
static void transition_one_qdisc(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 void *_need_watchdog)
{
	struct Qdisc *new_qdisc = dev_queue->qdisc_sleeping;   //初始化阶段，qdisc_sleeping和qdisc相同都是noop_qdisc
	int *need_watchdog_p = _need_watchdog;

	if (!(new_qdisc->flags & TCQ_F_BUILTIN))
		clear_bit(__QDISC_STATE_DEACTIVATED, &new_qdisc->state);

	rcu_assign_pointer(dev_queue->qdisc, new_qdisc);       //更新qdisc
	if (need_watchdog_p && new_qdisc != &noqueue_qdisc) {
		dev_queue->trans_start = 0;
		*need_watchdog_p = 1;
	}
}
```


## 创建Qdisc

```c
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

## default_qdisc_ops

基于优先级的qdisc，高优先级的报文发送完成后发送低优先级的报文

```c
const struct Qdisc_ops *default_qdisc_ops = &pfifo_fast_ops; 

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


## noqueue_qdisc

没有定义enqueue函数，报文直接发送给协议栈

```c
static struct Qdisc noqueue_qdisc = {
	.enqueue	=	NULL,
	.dequeue	=	noop_dequeue,
	.flags		=	TCQ_F_BUILTIN,
	.ops		=	&noqueue_qdisc_ops,
	.list		=	LIST_HEAD_INIT(noqueue_qdisc.list),
	.q.lock		=	__SPIN_LOCK_UNLOCKED(noqueue_qdisc.q.lock),
	.dev_queue	=	&noqueue_netdev_queue,
	.busylock	=	__SPIN_LOCK_UNLOCKED(noqueue_qdisc.busylock),
};
```


## mq_qdisc_ops

mq_qdisc_ops没有定义enqueue和dequeue函数，那么默认多队列的网卡是直接驱动发包

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

static int mq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct netdev_queue *dev_queue;
	struct Qdisc *qdisc;
	unsigned int ntx;

	if (sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	if (!netif_is_multiqueue(dev))
		return -EOPNOTSUPP;

	/* pre-allocate qdiscs, attachment can't fail */
	priv->qdiscs = kcalloc(dev->num_tx_queues, sizeof(priv->qdiscs[0]),
			       GFP_KERNEL);
	if (priv->qdiscs == NULL)
		return -ENOMEM;

	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		dev_queue = netdev_get_tx_queue(dev, ntx);
		qdisc = qdisc_create_dflt(dev_queue, default_qdisc_ops,    //创建qdisc
					  TC_H_MAKE(TC_H_MAJ(sch->handle),
						    TC_H_MIN(ntx + 1)));
		if (qdisc == NULL)
			goto err;
		priv->qdiscs[ntx] = qdisc;
		qdisc->flags |= TCQ_F_ONETXQUEUE;
	}

	sch->flags |= TCQ_F_MQROOT;
	return 0;

err:
	mq_destroy(sch);
	return -ENOMEM;
}

static void mq_attach(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct Qdisc *qdisc, *old;
	unsigned int ntx;

	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = priv->qdiscs[ntx];
		old = dev_graft_qdisc(qdisc->dev_queue, qdisc);    //设置为新qdisc，下次调用dev_activate时切换到新qdisc
		if (old)
			qdisc_destroy(old);
#ifdef CONFIG_NET_SCHED
		if (ntx < dev->real_num_tx_queues)
			qdisc_list_add(qdisc);
#endif

	}
	kfree(priv->qdiscs);
	priv->qdiscs = NULL;
}

struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
			      struct Qdisc *qdisc)
{
	struct Qdisc *oqdisc = dev_queue->qdisc_sleeping;
	spinlock_t *root_lock;

	root_lock = qdisc_lock(oqdisc);
	spin_lock_bh(root_lock);

	/* Prune old scheduler */
	if (oqdisc && atomic_read(&oqdisc->refcnt) <= 1)
		qdisc_reset(oqdisc);

	/* ... and graft new one */
	if (qdisc == NULL)
		qdisc = &noop_qdisc;
	dev_queue->qdisc_sleeping = qdisc;    //设置为新的qdisc
	rcu_assign_pointer(dev_queue->qdisc, &noop_qdisc);   //老的qdisc设置为noop_qdisc即空的qdisc

	spin_unlock_bh(root_lock);

	return oqdisc;
}
```


