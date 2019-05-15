# ovs-ofctl

使用ovs-ofctl命令使用OPENFLOW标准来配置OVS转发面。


## ovs-ofctl命令

```bash
ovs-ofctl [OPTIONS] COMMAND [ARG...]

show SWITCH                 							show OpenFlow information
dump-desc SWITCH            							print switch description
dump-tables SWITCH          							print table stats
mod-port SWITCH IFACE ACT   							modify port behavior
get-frags SWITCH            							print fragment handling behavior
set-frags SWITCH FRAG_MODE  							set fragment handling behavior
dump-ports SWITCH [PORT]    							print port statistics
dump-ports-desc SWITCH      							print port descriptions
dump-flows SWITCH           							print all flow entries
dump-flows SWITCH FLOW      							print matching FLOWs
dump-aggregate SWITCH       							print aggregate flow statistics
dump-aggregate SWITCH FLOW  							print aggregate stats for FLOWs
queue-stats SWITCH [PORT [QUEUE]]  						dump queue stats
add-flow SWITCH FLOW        							add flow described by FLOW
add-flows SWITCH FILE       							add flows from FILE
mod-flows SWITCH FLOW       							modify actions of matching FLOWs
del-flows SWITCH [FLOW]     							delete matching FLOWs
replace-flows SWITCH FILE   							replace flows with those in FILE
diff-flows SOURCE1 SOURCE2  							compare flows from two sources
packet-out SWITCH IN_PORT ACTIONS PACKET...   			execute ACTIONS on PACKET
monitor SWITCH [MISSLEN] [invalid_ttl] [watch:[...]]   	print packets received from SWITCH
snoop SWITCH                							snoop on SWITCH and its controller
```

## ovs-ofctl add-flow命令

ovs-ofctl add-flow $bridge "[table=#],[priority=#],[idle_timeout=#],CRETIRIA=$$, actions=ACTION"

### CRETIRIA(匹配)

#### 基本条件字段

in_port		输入端口号,openflow端口ID
dl_src		链路层，源mac地址，01:00:00:00:00:00/01:00:00:00:00:00（多播和广播），00:00:00:00:00:00/01:00:00:00:00:00（单播）
dl_dst		链路层，目的mac地址
dl_type		链路层，帧类型，例如：0x0800（ip），0x0806（arp）
dl_vlan		链路层，vlan值（2字节）
dl_vlan_pcp	链路层，vlan优先级
nw_src		网络层，源ip地址，ip[/netmask]
nw_dst		网络层，目的ip地址，ip[/netmask] 
nw_proto	网络层，协议类型，此时dl_type为0x0800，取值例如：1（icmp），6（tcp），7（udp）
nw_tos		网络层，ToS/DSCP 
nw_ecn		网络层，ecn标记
nw_ttl		网络层，ttl值
tp_src		传输层，源端口
tp_dst		传输层，目的端口

#### 扩展字段

icmp_type	应用层，icmp类型，请求or响应
icmp_code	应用层
ip_frag		ip_frag报文类型，取值为：no（非frag报文），yes（frag报文），first（第一个frag报文），later（后续的frag报文），not_later（非frag报文或第一个frag报文）
arp_sha		ARP源硬件地址
arp_tha		ARP目标硬件地址
tun_id		隧道ID，格式为：tunnel-id[/mask]

#### NXM变量

NXM_OF_IN_PORT		报文入端口
NXM_OF_ETH_DST		传输层，报文目的MAC地址	
NXM_OF_ETH_SRC		传输层，报文源MAC地址
NXM_OF_ETH_TYPE		传输层，帧协议类型	//不能作为dst	
NXM_OF_VLAN_TCI		传输层，报文VLAN值	//不能作为dst
NXM_OF_IP_PROTO 	网络层，IP协议类型	//不能作为dst
NXM_OF_IP_SRC		网络层，源IP地址
NXM_OF_IP_DST 		网络层，目的IP地址
NXM_OF_IP_TOS		网络层，ToS/DSCP 	
NXM_OF_TCP_SRC		传输层，TCP源端口
NXM_OF_TCP_DST 		传输层，TCP目的端口
NXM_OF_UDP_SRC		传输层，UDP源端口
NXM_OF_UDP_DST		传输层，UDP目的端口
NXM_OF_SCTP_SRC		传输层，SCTP源端口
NXM_OF_SCTP_DST		传输层，SCTP目的端口
NXM_OF_ICMP_TYPE	应用层，ICMP类型，请求or响应
NXM_OF_ICMP_CODE	应用层，ICMP CODE
NXM_OF_ARP_OP		应用层，ARP操作类型
NXM_OF_ARP_SPA		应用层，ARP源硬件地址
NXM_OF_ARP_TPA		应用层，ARP目的硬件地址

NXM_NX_TUN_ID		报文tunnel封装ID			
NXM_NX_ARP_SHA		
NXM_NX_ARP_THA
NXM_NX_ICMPV6_TYPE
NXM_NX_ICMPV6_CODE				
NXM_NX_ND_SLL					//不能作为dst
NXM_NX_ND_TLL					//不能作为dst
NXM_NX_PKT_MARK
NXM_NX_TUN_IPV4_SRC				//不能作为dst
NXM_NX_TUN_IPV4_DST				//不能作为dst

NXM_NX_REG0
......
NXM_NX_REG6

### ACTION(操作)

#### 发送报文

output:port				发送报文，到openflow端口
output:src[start..end]	发送报文，到src值指定的端口，src值包括：
enqueue:port:queue		发送报文，到port对应的队列
normal					发送报文，按照传统交换机的处理方式（基于mac查找，如果没找到从其他端口flood报文）
flood					发送报文，从其他所有端口（排除flood disable端口）发送
all						发送报文，从其他所有端口发送
controller(key=value.)	发送报文，给controller，max_len=nbytes，reason=（action,no_match,invalid_ttl），id=controller-id（默认是0，特殊的controller会有一个16位的id）
in_port					发送报文，到报文入端口
drop					丢弃报文

#### 修改报文

mod_dl_src:mac			链路层，修改源MAC地址
mod_dl_dst:mac			链路层，修改目的MAC地址
mod_vlan_vid:vlan_vid	链路层，修改VLAN值
mod_vlan_pcp:vlan_pcp	链路层，修改VLAN优先级
strip_vlan				链路层，剥除VLAN
push_vlan:ethertype		链路层，添加新VLAN
push_mpls:ethertype		链路层，
pop_mpls:ethertype		链路层，
mod_nw_src:ip			网络层，修改源IP地址
mod_nw_dst:ip			网络层，修改目的IP地址
mod_nw_tos:tos			网络层，修改ToS/DSCP
mod_tp_src:port			传输层，修改源端口
mod_tp_dst:port			传输层，修改目的端口
set_tunnel:id 			隧道，设置隧道ID

#### 其他操作

resubmit([port],[table])	
set_queue:queue
pop_queue
dec_ttl[(id1,id2)]
set_mpls_ttl:ttl
dec_mpls_ttl

#### 内存操作

move:src[start..end]?>dst[start..end]	src中的拷贝到dst中，其中src和dst取值范围为NXM变量
load:value?>dst[start..end]				值设置到dst中，其中dst取值范围为NXM变量
push:src[start..end]					把src值压入堆栈
pop:dst[start..end]						弹出堆栈，设置到dst
set_field:value?>dst					设置参数，dst为CRETIRIA中定义的值


## ovs-ofctl示例

```bash
# 显示bridge的信息
ovs-ofctl show br0

# 显示bridge的流表
ovs-ofctl dump-flows br0

# 添加流表
ovs-ofctl add-flow br0 "in_port=2,actions=output:8"

# 删除所有flow
ovs-ofctl del-flows br0
```


