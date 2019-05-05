# poll

ʹ��POLL���ƿ��Դ�������ӡ�

poll����ʹ��pollfd���͵Ľṹ�����һ���ļ������ufds��Ҫ��ص��ļ�������ϣ�nfds�Ǽ�ص��ļ����������timeout�ǵȴ��ĺ����������ʱ��������I/O�Ƿ�׼���ã�poll���᷵�ء�timeoutΪ������ʾ���ߵȴ���timeoutΪ0��ʾ���ú��������ء�

ִ�н����

* 0��ʾ��ʱǰû���κ��¼�������
* -1��ʾʧ�ܣ��ɹ��򷵻ؽṹ����revents��Ϊ0���ļ�������������
 
pollfd�ṹ��ص��¼��������£�
```c
#define POLLIN 0x0001     //�����ݿɶ�
#define POLLPRI 0x0002    //�н������ݿɶ�
#define POLLOUT 0x0004    //д���ݲ��ᵼ������
#define POLLERR 0x0008    //ָ�����ļ���������������
#define POLLHUP 0x0010    //ָ�����ļ������������¼�
#define POLLNVAL 0x0020   //ָ�����ļ��������Ƿ�
  
#define POLLRDNORM 0x0040   //����ͨ���ݿɶ�
#define POLLRDBAND 0x0080   //���������ݿɶ�
#define POLLWRNORM 0x0100   //д��ͨ���ݲ��ᵼ������
#define POLLWRBAND 0x0200   //д�������ݲ��ᵼ������
#define POLLMSG 0x0400      //SIGPOLL ��Ϣ����
#define POLLREMOVE 0x1000  
#define POLLRDHUP 0x2000  
```

POLLIN|POLLPRI������select�Ķ��¼���POLLOUT|POLLWRBAND������select��д�¼���


## ϵͳ�ӿ�

```c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds,
		int, timeout_msecs)
{
	struct timespec end_time, *to = NULL;
	int ret;

	if (timeout_msecs >= 0) {
		to = &end_time;
		poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC,
			NSEC_PER_MSEC * (timeout_msecs % MSEC_PER_SEC));
	}

	ret = do_sys_poll(ufds, nfds, to);

	if (ret == -EINTR) {
		struct restart_block *restart_block;

		restart_block = &current->restart_block;
		restart_block->fn = do_restart_poll;
		restart_block->poll.ufds = ufds;
		restart_block->poll.nfds = nfds;

		if (timeout_msecs >= 0) {
			restart_block->poll.tv_sec = end_time.tv_sec;
			restart_block->poll.tv_nsec = end_time.tv_nsec;
			restart_block->poll.has_timeout = 1;
		} else
			restart_block->poll.has_timeout = 0;

		ret = -ERESTART_RESTARTBLOCK;
	}
	return ret;
}

int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec *end_time)
{
	struct poll_wqueues table;
 	int err = -EFAULT, fdcount, len, size;
	/* Allocate small arguments on the stack to save memory and be
	   faster - use long to make sure the buffer is aligned properly
	   on 64 bit archs to avoid unaligned access */
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
 	unsigned long todo = nfds;

	if (nfds > rlimit(RLIMIT_NOFILE))
		return -EINVAL;

	len = min_t(unsigned int, nfds, N_STACK_PPS);
	for (;;) {
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;

		if (copy_from_user(walk->entries, ufds + nfds-todo,
					sizeof(struct pollfd) * walk->len))
			goto out_fds;

		todo -= walk->len;
		if (!todo)
			break;

		len = min(todo, POLLFD_PER_PAGE);
		size = sizeof(struct poll_list) + sizeof(struct pollfd) * len;
		walk = walk->next = kmalloc(size, GFP_KERNEL);
		if (!walk) {
			err = -ENOMEM;
			goto out_fds;
		}
	}

	poll_initwait(&table);   //��ʼ��poll_wqueues������poll_table��_qprocΪ__pollwait
	fdcount = do_poll(nfds, head, &table, end_time);
	poll_freewait(&table);

	for (walk = head; walk; walk = walk->next) {
		struct pollfd *fds = walk->entries;
		int j;

		for (j = 0; j < walk->len; j++, ufds++)
			if (__put_user(fds[j].revents, &ufds->revents))
				goto out_fds;
  	}

	err = fdcount;
out_fds:
	walk = head->next;
	while (walk) {
		struct poll_list *pos = walk;
		walk = walk->next;
		kfree(pos);
	}

	return err;
}
```


### do_poll

```c
static int do_poll(unsigned int nfds,  struct poll_list *list,
		   struct poll_wqueues *wait, struct timespec *end_time)
{
	poll_table* pt = &wait->pt;
	ktime_t expire, *to = NULL;
	int timed_out = 0, count = 0;
	unsigned long slack = 0;
	unsigned int busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
	unsigned long busy_end = 0;

	/* Optimise the no-wait case */
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		pt->_qproc = NULL;
		timed_out = 1;
	}

	if (end_time && !timed_out)
		slack = select_estimate_accuracy(end_time);

	for (;;) {
		struct poll_list *walk;
		bool can_busy_loop = false;

		for (walk = list; walk != NULL; walk = walk->next) {
			struct pollfd * pfd, * pfd_end;

			pfd = walk->entries;
			pfd_end = pfd + walk->len;
			for (; pfd != pfd_end; pfd++) {
				/*
				 * Fish for events. If we found one, record it
				 * and kill poll_table->_qproc, so we don't
				 * needlessly register any other waiters after
				 * this. They'll get immediately deregistered
				 * when we break out and return.
				 */
				if (do_pollfd(pfd, pt, &can_busy_loop,
					      busy_flag)) {
					count++;
					pt->_qproc = NULL;
					/* found something, stop busy polling */
					busy_flag = 0;
					can_busy_loop = false;
				}
			}
		}
		/*
		 * All waiters have already been registered, so don't provide
		 * a poll_table->_qproc to them on the next loop iteration.
		 */
		pt->_qproc = NULL;
		if (!count) {
			count = wait->error;
			if (signal_pending(current))
				count = -EINTR;
		}
		if (count || timed_out)    //��ʱ����fd����ready״̬
			break;

		/* only if found POLL_BUSY_LOOP sockets && not out of time */
		if (can_busy_loop && !need_resched()) {
			if (!busy_end) {
				busy_end = busy_loop_end_time();
				continue;
			}
			if (!busy_loop_timeout(busy_end))
				continue;
		}
		busy_flag = 0;

		/*
		 * If this is the first loop and we have a timeout
		 * given, then we convert to ktime_t and set the to
		 * pointer to the expiry value.
		 */
		if (end_time && !to) {
			expire = timespec_to_ktime(*end_time);
			to = &expire;
		}

		if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))  //��������
			timed_out = 1;
	}
	return count;
}

static inline unsigned int do_pollfd(struct pollfd *pollfd, poll_table *pwait,
				     bool *can_busy_poll,
				     unsigned int busy_flag)
{
	unsigned int mask;
	int fd;

	mask = 0;
	fd = pollfd->fd;
	if (fd >= 0) {
		struct fd f = fdget(fd);
		mask = POLLNVAL;
		if (f.file) {
			mask = DEFAULT_POLLMASK;
			if (f.file->f_op->poll) {
				pwait->_key = pollfd->events|POLLERR|POLLHUP;
				pwait->_key |= busy_flag;
				mask = f.file->f_op->poll(f.file, pwait);    //����fops��poll���������ջ����pwait��_qproc
				if (mask & busy_flag)
					*can_busy_poll = true;
			}
			/* Mask out unneeded events. */
			mask &= pollfd->events | POLLERR | POLLHUP;
			fdput(f);
		}
	}
	pollfd->revents = mask;

	return mask;
}

//socket->f_op->poll���ջ����poll_table��_qproc��ʵ��Ϊ__pollwait����
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
				poll_table *p)
{
	struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
	struct poll_table_entry *entry = poll_get_entry(pwq);
	if (!entry)
		return;
	entry->filp = get_file(filp);
	entry->wait_address = wait_address;
	entry->key = p->_key;
	init_waitqueue_func_entry(&entry->wait, pollwake); //��ʼ���ȴ���
	entry->wait.private = pwq;
	add_wait_queue(wait_address, &entry->wait);  //�ڵȴ������У������
}
```





