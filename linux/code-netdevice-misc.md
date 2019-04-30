# Misc�豸

��Linuxϵͳ�У�����һ���ַ��豸�����ǹ���һ�����豸�ţ�10���������豸�Ų�ͬ�����ǳ������豸Ϊ�����豸��miscdeivce�����鿴/proc/device�п��Կ���һ����Ϊmisc�����豸��Ϊ10.���еĻ����豸�γ�һ���������豸����ʱ�ں˸��ݴ��豸���ҵ���Ӧ��miscdevice�豸���������ͨ�ַ��豸������������Ҫ�Լ�ȥ�����豸�ļ���


## ���ݽṹ

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


## ģ���ʼ��

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
	//ע���ַ��豸���Ѻ���miscdevice��Ҫע����豸��ǰע����
	//�����ַ��豸��ʱ�����ȵ���misc_fops��open����
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


## miscdevice ע��

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

	dev = MKDEV(MISC_MAJOR, misc->minor);   //����dev_t����

	misc->this_device =
		device_create_with_groups(misc_class, misc->parent, dev,    //����device�豸
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
	list_add(&misc->list, &misc_list);    //���浽ȫ��������
 out:
	mutex_unlock(&misc_mtx);
	return err;
}
```


## miscdevice ��

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
	replace_fops(file, new_fops);   //�滻fops
	if (file->f_op->open)
		err = file->f_op->open(inode,file);   //�����µ�fops������misc_registerע����豸
fail:
	mutex_unlock(&misc_mtx);
	return err;
}
```



