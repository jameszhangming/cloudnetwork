# Misc设备

在Linux系统中，存在一类字符设备，他们共享一个主设备号（10），但此设备号不同，我们称这类设备为混杂设备（miscdeivce），查看/proc/device中可以看到一个名为misc的主设备号为10.所有的混杂设备形成一个链表，对设备访问时内核根据次设备号找到对应的miscdevice设备。相对于普通字符设备驱动，它不需要自己去生成设备文件。


## 数据结构

```c
static const struct file_operations misc_fops = {
	.owner		= THIS_MODULE,
	.open		= misc_open,
	.llseek		= noop_llseek,
};

static const struct file_operations misc_proc_fops = {
	.owner	 = THIS_MODULE,
	.open    = misc_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};
```


## 模块初始化

```c
static int __init misc_init(void)
{
	int err;

#ifdef CONFIG_PROC_FS
	proc_create("misc", 0, NULL, &misc_proc_fops);
#endif
	misc_class = class_create(THIS_MODULE, "misc");
	err = PTR_ERR(misc_class);
	if (IS_ERR(misc_class))
		goto fail_remove;

	err = -EIO;
	//注册字符设备，把后续miscdevice需要注册的设备提前注册了
	//后续字符设备打开时，会先调用misc_fops的open函数
	if (register_chrdev(MISC_MAJOR,"misc",&misc_fops))    
		goto fail_printk;
	misc_class->devnode = misc_devnode;
	return 0;

fail_printk:
	printk("unable to get major %d for misc devices\n", MISC_MAJOR);
	class_destroy(misc_class);
fail_remove:
	remove_proc_entry("misc", NULL);
	return err;
}
```


## miscdevice 注册

```c
int misc_register(struct miscdevice * misc)
{
	dev_t dev;
	int err = 0;

	INIT_LIST_HEAD(&misc->list);

	mutex_lock(&misc_mtx);

	if (misc->minor == MISC_DYNAMIC_MINOR) {
		int i = find_first_zero_bit(misc_minors, DYNAMIC_MINORS);
		if (i >= DYNAMIC_MINORS) {
			err = -EBUSY;
			goto out;
		}
		misc->minor = DYNAMIC_MINORS - i - 1;
		set_bit(i, misc_minors);
	} else {
		struct miscdevice *c;

		list_for_each_entry(c, &misc_list, list) {
			if (c->minor == misc->minor) {
				err = -EBUSY;
				goto out;
			}
		}
	}

	dev = MKDEV(MISC_MAJOR, misc->minor);   //创建dev_t对象

	misc->this_device =
		device_create_with_groups(misc_class, misc->parent, dev,    //创建device设备
					  misc, misc->groups, "%s", misc->name);
	if (IS_ERR(misc->this_device)) {
		int i = DYNAMIC_MINORS - misc->minor - 1;
		if (i < DYNAMIC_MINORS && i >= 0)
			clear_bit(i, misc_minors);
		err = PTR_ERR(misc->this_device);
		goto out;
	}

	/*
	 * Add it to the front, so that later devices can "override"
	 * earlier defaults
	 */
	list_add(&misc->list, &misc_list);    //保存到全局链表中
 out:
	mutex_unlock(&misc_mtx);
	return err;
}
```


## miscdevice 打开

```c
static int misc_open(struct inode * inode, struct file * file)
{
	int minor = iminor(inode);
	struct miscdevice *c;
	int err = -ENODEV;
	const struct file_operations *new_fops = NULL;

	mutex_lock(&misc_mtx);
	
	list_for_each_entry(c, &misc_list, list) {
		if (c->minor == minor) {
			new_fops = fops_get(c->fops);		
			break;
		}
	}
		
	if (!new_fops) {
		mutex_unlock(&misc_mtx);
		request_module("char-major-%d-%d", MISC_MAJOR, minor);
		mutex_lock(&misc_mtx);

		list_for_each_entry(c, &misc_list, list) {
			if (c->minor == minor) {
				new_fops = fops_get(c->fops);
				break;
			}
		}
		if (!new_fops)
			goto fail;
	}

	/*
	 * Place the miscdevice in the file's
	 * private_data so it can be used by the
	 * file operations, including f_op->open below
	 */
	file->private_data = c;

	err = 0;
	replace_fops(file, new_fops);   //替换fops
	if (file->f_op->open)
		err = file->f_op->open(inode,file);   //调用新的fops，就是misc_register注册的设备
fail:
	mutex_unlock(&misc_mtx);
	return err;
}
```



