# Neighbour


## Neighbour操作接口

```c
	rtnl_register(PF_UNSPEC, RTM_NEWNEIGH, neigh_add, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELNEIGH, neigh_delete, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETNEIGH, NULL, neigh_dump_info, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETNEIGHTBL, NULL, neightbl_dump_info, NULL);
	rtnl_register(PF_UNSPEC, RTM_SETNEIGHTBL, neightbl_set, NULL, NULL);
```

### 创建Neighbour项

```c
static int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int flags = NEIGH_UPDATE_F_ADMIN | NEIGH_UPDATE_F_OVERRIDE;
	struct net *net = sock_net(skb->sk);
	struct ndmsg *ndm;
	struct nlattr *tb[NDA_MAX+1];
	struct neigh_table *tbl;
	struct net_device *dev = NULL;
	struct neighbour *neigh;
	void *dst, *lladdr;
	int err;

	ASSERT_RTNL();
	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, NULL);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (tb[NDA_DST] == NULL)
		goto out;

	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex) {
		dev = __dev_get_by_index(net, ndm->ndm_ifindex);
		if (dev == NULL) {
			err = -ENODEV;
			goto out;
		}

		if (tb[NDA_LLADDR] && nla_len(tb[NDA_LLADDR]) < dev->addr_len)
			goto out;
	}

	tbl = neigh_find_table(ndm->ndm_family);
	if (tbl == NULL)
		return -EAFNOSUPPORT;

	if (nla_len(tb[NDA_DST]) < tbl->key_len)
		goto out;
	dst = nla_data(tb[NDA_DST]);
	lladdr = tb[NDA_LLADDR] ? nla_data(tb[NDA_LLADDR]) : NULL;

	if (ndm->ndm_flags & NTF_PROXY) {
		struct pneigh_entry *pn;

		err = -ENOBUFS;
		pn = pneigh_lookup(tbl, net, dst, dev, 1);
		if (pn) {
			pn->flags = ndm->ndm_flags;
			err = 0;
		}
		goto out;
	}

	if (dev == NULL)
		goto out;

	neigh = neigh_lookup(tbl, dst, dev);    //查找neighbour表项
	if (neigh == NULL) {
		if (!(nlh->nlmsg_flags & NLM_F_CREATE)) {
			err = -ENOENT;
			goto out;
		}

		neigh = __neigh_lookup_errno(tbl, dst, dev);   //查找neighbour表项，没有则创建
		if (IS_ERR(neigh)) {
			err = PTR_ERR(neigh);
			goto out;
		}
	} else {
		if (nlh->nlmsg_flags & NLM_F_EXCL) {
			err = -EEXIST;
			neigh_release(neigh);
			goto out;
		}

		if (!(nlh->nlmsg_flags & NLM_F_REPLACE))
			flags &= ~NEIGH_UPDATE_F_OVERRIDE;
	}

	if (ndm->ndm_flags & NTF_USE) {
		neigh_event_send(neigh, NULL);    //触发ARP请求
		err = 0;
	} else
		err = neigh_update(neigh, lladdr, ndm->ndm_state, flags);   //更新neigh状态
	neigh_release(neigh);

out:
	return err;
}
```

