# ovs-ofctl示例

本文介绍ovs-ofctl常用的示例


## Learn流表

### mac学习流表

```bash
ovs-ofctl add-flow "table=10,priority=1 actions=learn(
	table=20,hard_timeout=300,priority=1,
	NXM_OF_VLAN_TCI[0..11],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],
	load:0->NXM_OF_VLAN_TCI[],load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],output:NXM_OF_IN_PORT[]),output:1"
	
# 学习结果
# table=20, priority=2,dl_vlan=1,dl_dst=fa:16:3e:7e:ab:cc actions=strip_vlan,set_tunnel:0x3e9,output:5 
```

learn字段含义
table=20								：指定了学习到的流表规则添加到哪个表中。
hard_timeout							：指定了学习到的流表规则的过期时间。
NXM_OF_VLAN_TCI[0..11] 					：记录 vlan tag，所以学习结果中有 dl_vlan=1
NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[] 		：将 mac source address 记录，所以结果中有 dl_dst=fa:16:3e:7e:ab:cc
load:0->NXM_OF_VLAN_TCI[]				：在发送出去的时候，vlan tag设为0，所以结果中有 actions=strip_vlan
load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[] 	：发出去的时候，设置 tunnul id，所以结果中有set_tunnel:0x3e9
output:NXM_OF_IN_PORT[]					：指定发送给哪个port，由于是从 port2 进来的，因而结果中有output:2。
```


## ARP代答

```bash
ovs-ofctl add-flow " table=10,priority=1,arp,dl_vlan=1,nw_dst=$dip,actions=
('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'	    # 将ARP Request数据包的源MAC地址作为ARP Reply数据包的目的MAC地址
  'mod_dl_src:%(mac),'				            # 将ARP Request请求的目的IP的MAC地址作为ARP Reply数据包的源MAC地址
  'load:0x2->NXM_OF_ARP_OP[],'			        # 构造的ARP包的类型设置为ARP Reply
  'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'	# 将Request中的源MAC地址作为Reply中的目的MAC地址
  'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'	# 将Request中的源IP地址作为Reply中的目的IP地址
  'load:%(mac)->NXM_NX_ARP_SHA[],'		        # 将Request请求的目的IP的MAC地址作为Reply中的源MAC地址
  'load:%(ip)->NXM_OF_ARP_SPA[],'		        # 将Request请求的目的IP地址作为Reply中的源IP地址
  'in_port')"					                # 从入端口发出，返回给虚拟机
```


## 
