# Traffic Control

本文将介绍Qdisc的整体实现框架，具体enqueue和dequeue的算法待到具体的算法实现来讲解，本文主要讲解Qdisc如何集成到内核协议栈。


## TC入口

TC的系统入口在dev_queue_xmit二层发包函数中，入口函数为__dev_queue_xmit。

```c
static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	struct Qdisc *q;
	int rc = -ENOMEM;

	skb_reset_mac_header(skb);	//设置mac header偏移

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
		__skb_tstamp_tx(skb, NULL, skb->sk, SCM_TSTAMP_SCHED);

	/* Disable soft irqs for various locks below. Also
	 * stops preemption for RCU.
	 */
	rcu_read_lock_bh();

	skb_update_prio(skb);	//设置skb->priority值

	/* If device/qdisc don't need skb->dst, release it right now while
	 * its hot in this cpu cache.
	 */
	if (dev->priv_flags & IFF_XMIT_DST_RELEASE)	//需要释放dst对象
		skb_dst_drop(skb);
	else
		skb_dst_force(skb);

	txq = netdev_pick_tx(dev, skb, accel_priv);	//获取发送队列，根据报文计算出队列
	q = rcu_dereference_bh(txq->qdisc);		//得到qdisc对象

#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_EGRESS);
#endif
	trace_net_dev_queue(skb);
	if (q->enqueue) {           //qdisc有enqueue函数
		rc = __dev_xmit_skb(skb, q, dev, txq);		//默认情况下，单队列进此分支，多队列直接发包
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that netif_tx_lock protection is necessary
	   here.  (f.e. loopback and IP tunnels are clean ignoring statistics
	   counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id(); /* ok because BHs are off */

		if (txq->xmit_lock_owner != cpu) {

			if (__this_cpu_read(xmit_recursion) > RECURSION_LIMIT)
				goto recursion_alert;

			skb = validate_xmit_skb(skb, dev);   //校验skb报文，gso检验
			if (!skb)
				goto drop;

			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_xmit_stopped(txq)) {   //发送队列运行中
				__this_cpu_inc(xmit_recursion);
				skb = dev_hard_start_xmit(skb, dev, txq, &rc);		//调用驱动发送报文
				__this_cpu_dec(xmit_recursion);
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			net_crit_ratelimited("Virtual device %s asks to queue packet!\n",
					     dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately
			 */
recursion_alert:
			net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
					     dev->name);
		}
	}

	rc = -ENETDOWN;
drop:
	rcu_read_unlock_bh();

	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}

/*
__dev_xmit_skb函数是TC实现的核心函数，它是Qdisc框架好内核之间的纽带，该函数的主要流程如下：
1. 判断qdisc是否处于running状态（即是否有其他进程先进，并且还未退出）
   1.1 如果是则要去抢busylock锁，避免两个进程同时进入
2.抢root_lock，防止对qdisc对象的并发修改
   2.1root_lock锁有两种情况下会释放:
     2.1.1 进入sch_direct_xmit函数进行发包，发包完成后还会再抢root_lock锁
	 2.1.2 退出__dev_xmit_skb函数
3. 根据qdisc状态进行处理
   3.1 当前disc包含TCQ_F_CAN_BYPASS标记，且缓冲队列为空，且qdisc处于非running状态
       直接调用sch_direct_xmit发包，发包完成后，check缓冲区是否有包？
	   3.1.1 有包，则调用__qdisc_run继续发包（此时只会出现在并发场景，其他进程发包）
	   3.1.2 无包，则调用qdisc_run_end退出running
   3.2 其他情况
       qdisc进队列，判断当前qdisc是否处于running状态
	   3.2.1 处于runnning状态，直接返回
	   3.2.2 非running状态，调用__qdisc_run继续发包
4.释放root_lock锁，退出

关于busylock锁：避免第一个进程进来，后续又有两个进程发包；
申请和释放锁的逻辑如下：
1. 当进入__dev_xmit_skb函数，qdisc处于running状态时，申请该锁；说明当前为第二个进入此函数的进程；
2. 释放锁有两种场景：
   2.1 当前进程进入函数时qdisc处于running状态，然后第一个进程qdisc被关闭，当前进程启动qdisc后，会释放该锁；
   2.2 当前进程进入函数时qdisc处于running状态，上述3.1.1分支，会释放该锁；

当qdisc的配额不足以发包时，并且后续又没有报文发送，剩余报文如何发出？
  * __qdisc_run函数中发现还有报文未发送，会调用__netif_schedule触发发包软中断
  * qdisc的dequeue失败时，会触发watchdog或work，这两个函数均会__netif_schedule触发发包软中断
*/
static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
				 struct net_device *dev,
				 struct netdev_queue *txq)
{
	spinlock_t *root_lock = qdisc_lock(q);			//qdisc的锁，多个qdisc可以并发运行
	bool contended;
	int rc;

	qdisc_pkt_len_init(skb);
	qdisc_calculate_pkt_len(skb, q);   //计算报文长度
	/*
	 * Heuristic to force contended enqueues to serialize on a
	 * separate lock before trying to get qdisc main lock.
	 * This permits __QDISC___STATE_RUNNING owner to get the lock more
	 * often and dequeue packets faster.
	 */
	contended = qdisc_is_running(q);	//判断qdisc是否运行，通过qdisc->__state是否携带running标记来判断
	if (unlikely(contended))
		spin_lock(&q->busylock);

	spin_lock(root_lock);    //操作都在root锁里，中间报文直接发送给驱动会释放该锁（发送过程和qdisc没关系）
	if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED, &q->state))) {  //deactive状态，丢弃报文
		kfree_skb(skb);
		rc = NET_XMIT_DROP;
	} else if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&	// 非deative状态，包含bybass标记（和算法有关，htb不设该标记），且没有缓存报文
		   qdisc_run_begin(q)) {                                    // 运行qdisc（添加running标记），如果当前已经处理running状态，不进此分支
		/*
		 * This is a work-conserving queue; there are no old skbs
		 * waiting to be sent out; and the qdisc is not running -
		 * xmit the skb directly.
		 */

		qdisc_bstats_update(q, skb);   //更新统计信息

		if (sch_direct_xmit(skb, q, dev, txq, root_lock, true)) {   //qdisc直接发送报文，当前skb是qdisc的第一个报文
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);		  //sch_direct_xmit返回为正值，说明qdisc中有报文待发送，尝试发送缓冲区报文
		} else
			qdisc_run_end(q);	  //正常发送完成，qdisc停止运行（删除running标记）

		rc = NET_XMIT_SUCCESS;
	} else {                                        //qdisc处于running状态，或当前有缓冲报文
		rc = q->enqueue(skb, q) & NET_XMIT_MASK;	//报文直接进qdisc队列
		if (qdisc_run_begin(q)) {			        //尝试启动qdisc，如果qisc成功启动，说明之前qdisc处于非running状态
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			__qdisc_run(q);		//如果当前正处于running状态，说明其他CPU先进入发包，只要添加到队列中，其他CPU会尝试放松缓冲区
		}
	}
	spin_unlock(root_lock);
	if (unlikely(contended))
		spin_unlock(&q->busylock);
	return rc;
}

/*
直接调用驱动发包，返回值比较关键
1. 非零值， 说明qdisc还有报文缓存
2. 0，说明qdisc没有报文，或者队列冻结或停止
*/
int sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
		    struct net_device *dev, struct netdev_queue *txq,
		    spinlock_t *root_lock, bool validate)
{
	int ret = NETDEV_TX_BUSY;

	/* And release qdisc */
	spin_unlock(root_lock);

	/* Note that we validate skb (GSO, checksum, ...) outside of locks */
	if (validate)
		skb = validate_xmit_skb_list(skb, dev);		//报文校验，gso分段、csum计算

	if (skb) {
		HARD_TX_LOCK(dev, txq, smp_processor_id());
		if (!netif_xmit_frozen_or_stopped(txq))                 //发送队列未冻结或停止
			skb = dev_hard_start_xmit(skb, dev, txq, &ret);		//调用驱动发送报文

		HARD_TX_UNLOCK(dev, txq);
	}
	spin_lock(root_lock);

	if (dev_xmit_complete(ret)) {
		/* Driver sent out skb successfully or skb was consumed */
		ret = qdisc_qlen(q);			//成功发送报文，如果缓存区中还有报文，则尝试继续发送报文
	} else if (ret == NETDEV_TX_LOCKED) {
		/* Driver try lock failed */
		ret = handle_dev_cpu_collision(skb, txq, q);
	} else {
		/* Driver returned NETDEV_TX_BUSY - requeue skb */
		if (unlikely(ret != NETDEV_TX_BUSY))
			net_warn_ratelimited("BUG %s code %d qlen %d\n",
					     dev->name, ret, q->q.qlen);

		ret = dev_requeue_skb(skb, q);		//发送失败，例如NETDEV_TX_BUSY，skb保存到qdisc中，并触发发包软中断
	}

	if (ret && netif_xmit_frozen_or_stopped(txq))
		ret = 0;

	return ret;
}

/*
执行qdisc发包，尝试发送一定配额的报文（如果有报文），直到：
1. qdisc报文发送完成（没有报文，或者流量限制）
2. 用完发送配额（避免长时间发包），如果配额用户场景，还会触发发包软中断
*/
void __qdisc_run(struct Qdisc *q)
{
	int quota = weight_p;
	int packets;

	while (qdisc_restart(q, &packets)) {      //尝试发送报文，直到报文被发送完成（或受流控限制导致取不出skb）
		/*
		 * Ordered by possible occurrence: Postpone processing if
		 * 1. we've exceeded packet quota
		 * 2. another process needs the CPU;
		 */
		quota -= packets;
		if (quota <= 0 || need_resched()) {
			__netif_schedule(q);				//还有报文可以发送，触发发包软中断
			break;
		}
	}

	qdisc_run_end(q);
}

/*
从qdisc中收包，并发送给网卡驱动
*/
static inline int qdisc_restart(struct Qdisc *q, int *packets)
{
	struct netdev_queue *txq;
	struct net_device *dev;
	spinlock_t *root_lock;
	struct sk_buff *skb;
	bool validate;

	/* Dequeue packet */
	skb = dequeue_skb(q, &validate, packets);   //从qdisc中收取报文，取不出报文，则会退出__qdisc_run
	if (unlikely(!skb))
		return 0;

	root_lock = qdisc_lock(q);
	dev = qdisc_dev(q);
	txq = skb_get_tx_queue(dev, skb);

	return sch_direct_xmit(skb, q, dev, txq, root_lock, validate);   //直接发送报文，发送给驱动
}

/*
从qdisc中收包，可以一次取多个报文
*/
static struct sk_buff *dequeue_skb(struct Qdisc *q, bool *validate,
				   int *packets)
{
	struct sk_buff *skb = q->gso_skb;				//队列被冻结时发的包
	const struct netdev_queue *txq = q->dev_queue;

	*packets = 1;
	*validate = true;
	if (unlikely(skb)) {   
		/* check the reason of requeuing without tx lock first */
		txq = skb_get_tx_queue(txq->dev, skb);
		if (!netif_xmit_frozen_or_stopped(txq)) {    //如果qdisc未冻结或停止，当前返回gso_skb报文
			q->gso_skb = NULL;
			q->q.qlen--;
		} else
			skb = NULL;
		/* skb in gso_skb were already validated */
		*validate = false;
	} else {
		if (!(q->flags & TCQ_F_ONETXQUEUE) ||
		    !netif_xmit_frozen_or_stopped(txq)) {
			skb = q->dequeue(q);						//从qdisc收包
			if (skb && qdisc_may_bulk(q))      
				try_bulk_dequeue_skb(q, skb, txq, packets);  //收取多个报文
		}
	}
	return skb; 
}

```


