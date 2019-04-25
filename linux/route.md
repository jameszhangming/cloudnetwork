# route

路由子系统实现IP报文如何发送，确定下一跳去哪里。

## 路由概念

* 路由：跨越从源主机到目标主机的一个互联网络来转发数据包的过程
* 路由器：能够将数据包转发到正确的目的地，并在转发过程中选择最佳路径的设备
* 路由表：在路由器中维护的路由条目，路由器根据路由表做路径选择
* 直连路由：当在路由器上配置了接口的IP地址，并且接口状态为up的时候，路由表中就出现直连路由项
* 静态路由：是由管理员手工配置的，是单向的
* 默认路由：当路由器在路由表中找不到目标网络的路由条目时，路由器把请求转发到默认路由接口 


## 策略路由

于策略的路由比传统路由在功能上更强大，使用更灵活，它使网络管理员不仅能够根据目的地址而且能够根据报文大小、应用或IP源地址等属性来选择转发路径。


## ip route命令

```bash
ip route { list | flush } SELECTOR
ip route save SELECTOR
ip route restore
ip route showdump
ip route get ADDRESS [ from ADDRESS iif STRING ] [ oif STRING ] [ tos TOS ] [ mark NUMBER ]
ip route { add | del | change | append | replace } ROUTE

SELECTOR := [ root PREFIX ] [ match PREFIX ] [ exact PREFIX ]
            [ table TABLE_ID ] [ proto RTPROTO ]
            [ type TYPE ] [ scope SCOPE ]
ROUTE := NODE_SPEC [ INFO_SPEC ]
NODE_SPEC := [ TYPE ] PREFIX [ tos TOS ]
             [ table TABLE_ID ] [ proto RTPROTO ]
             [ scope SCOPE ] [ metric METRIC ]
INFO_SPEC := NH OPTIONS FLAGS [ nexthop NH ]...
NH := [ via ADDRESS ] [ dev STRING ] [ weight NUMBER ] NHFLAGS
OPTIONS := FLAGS [ mtu NUMBER ] [ advmss NUMBER ]
           [ rtt TIME ] [ rttvar TIME ] [ reordering NUMBER ]
           [ window NUMBER] [ cwnd NUMBER ] [ initcwnd NUMBER ]
           [ ssthresh NUMBER ] [ realms REALM ] [ src ADDRESS ]
           [ rto_min TIME ] [ hoplimit NUMBER ] [ initrwnd NUMBER ]
           [ quickack BOOL ]
TYPE := [ unicast | local | broadcast | multicast | throw | unreachable | prohibit | blackhole | nat ]
TABLE_ID := [ local | main | default | all | NUMBER ]
SCOPE := [ host | link | global | NUMBER ]
NHFLAGS := [ onlink | pervasive ]
RTPROTO := [ kernel | boot | static | NUMBER ]
TIME := NUMBER[s|ms]
BOOL := [1|0]
```

### Route TYPE

* unicast
  * the route entry describes real paths to the destinations covered by the route prefix.
* unreachable 
  * these destinations are unreachable. Packets are discarded and the ICMP message host unreachable is generated. The local senders get an EHOSTUNREACH error.
* blackhole 
  * these destinations are unreachable. Packets are discarded silently. The local senders get an EINVAL error.
* prohibit
  * these destinations are unreachable. Packets are discarded and the ICMP message communication administratively prohibited is generated. The local senders get an EACCES error.
* local
  * the destinations are assigned to this host. The packets are looped back and delivered locally.
* broadcast 
  * the destinations are broadcast addresses. The packets are sent as link broadcasts.
* throw 
  * a special control route used together with policy rules. If such a route is selected, lookup in this table is terminated pretending that no route was found. Without policy routing it is equivalent to the absence of the route in the routing table. The packets are dropped and the ICMP message net unreachable is generated. The local senders get an ENETUNREACH error.
* nat 
  * a special NAT route. Destinations covered by the prefix are considered to be dummy (or external) addresses which require translation to real (or internal) ones before forwarding. The addresses to translate to are selected with the attribute via. Warning: Route NAT is no longer supported in Linux 2.6.
* anycast 
  * not implemented the destinations are anycast addresses assigned to this host. They are mainly equivalent to local with one difference: such addresses are invalid when used as the source address of any packet.
* multicast
  * a special type used for multicast routing. It is not present in normal routing tables.

 
### 路由表

用户可以自定义从 1－252个路由表，其中，linux系统维护了4个路由表：

* 0
  * 系统保留表
* default(ID 253)
  * 路由表default是一个空表，它是为一些后续处理保留的。对于前面的缺省策略没有匹配到的数据包，系统使用这个策略进行处理。可删除。
* main(ID 254) 
  * 路由表main是一个通常的表，包含所有的无策略路由。系统管理员可删除或者使用另外的规则覆盖这条规则。
* local(ID 255) 
  * 路由表local是一个特殊的路由表，包含对于本地和广播地址的高优先级控制路由。rule 0非常特殊，不能被删除或者覆盖。  

  
### 路由操作常用参数

* dev NAME
  * the output device name.
* via [ FAMILY ] ADDRESS
  * the address of the nexthop router, in the address family FAMILY. 
* table TABLEID
  * the table to add this route to.
* src ADDRESS
  * the source address to prefer when sending to the destinations covered by the route prefix.
* nexthop NEXTHOP
  * the nexthop of a multipath route. NEXTHOP is a complex value with its own syntax similar to the top level argument lists:
    * via [ FAMILY ] ADDRESS - is the nexthop router.
    * dev NAME - is the output device.
    * weight NUMBER - is a weight for this element of a multipath route reflecting its relative bandwidth or quality.
* scope SCOPE_VAL
  * the scope of the destinations covered by the route prefix. 
    * scope global for all gatewayed unicast routes.
    * scope link for direct unicast and broadcast routes.
	* scope host for local routes.
* protocol RTPROTO
  * the routing protocol identifier of this route. 
    * redirect - the route was installed due to an ICMP redirect.
    * kernel - the route was installed by the kernel during autoconfiguration.
    * boot - the route was installed during the bootup sequence. If a routing daemon starts, it will purge all of them.
    * static - the route was installed by the administrator to override dynamic routing. Routing daemon will respect them and, probably, even advertise them to its peers.
    * ra - the route was installed by Router Discovery protocol.
  
  
### ip route命令示例

当不指定rable时，默认使用的是main表

```bash
//列出路由表条目
ip route show [table ID]
ip route list [table ID]
ip route ls [table ID]

//添加默认路由
ip route add default via 192.168.0.1 dev eth0 [table f5]

//删除默认路由
ip route del default via 192.168.0.1 dev eth0 [table f5]

//添加静态路由
ip route add 10.0.0/24 via 193.233.7.65 dev eth0 [table ID]

//删除静态路由
ip route del 10.0.0/24 via 193.233.7.65 dev eth0 [table 10]

//修改静态路由
ip route change 10.0.0/24 dev eth0

//添加负载均衡路由
ip route add default scope global nexthop via <GW0> dev <EXT_IF0> weight 1  via <GW1> dev <EXT_IF1> weight 1
```


## ip rule命令

```bash
ip rule [ list | add | del | flush ] SELECTOR ACTION
SELECTOR := [ not ] [ from PREFIX ] [ to PREFIX ] [ tos TOS ] [ fwmark FWMARK[/MASK] ]
            [ iif STRING ] [ oif STRING ] [ pref NUMBER ]
ACTION := [ table TABLE_ID ]
          [ prohibit | reject | unreachable ]
          [ realms [SRCREALM/]DSTREALM ]
          [ goto NUMBER ]
          SUPPRESSOR
SUPPRESSOR := [ suppress_prefixlength NUMBER ]
              [ suppress_ifgroup DEVGROUP ]
TABLE_ID := [ local | main | default | NUMBER ]
```

### SELECTOR说明

* pref PRI		    规则优先级（越小优先级越高）
* fwmark MARK		匹配报文fwmark值（等同于mark值）
* from PREFIX		匹配报文源IP地址，格式为：IP[/MASK]
* to PREFIX		    匹配报文目的IP地址，格式为：IP[/MASK]
* iif NAME		    匹配报文入端口
* oif NAME		    匹配报文出端口
* tos TOS			匹配TOS值，等同于dsfield TOS


### ACTION说明

* table TABLEID		如果规则选择符匹配，就选择该路由表查找路由
* prohibit			禁止
* reject			拒绝
* unreachable       不可达
* realms FROM/TO    如果规则匹配和路由表查询成功，选择的realms值
* goto NUMBER       
* nat ADDRESS		设置要进行网络地址转换的IP地址段


### 默认规则（优先级值越小优先级越高）

```bash
0:	from all lookup local 
32766:	from all lookup main 
32767:	from all lookup default 
```


### ip rule命令示例

```bash
# 列出路由规则
ip rule show 
ip rule ls 

# 创建基于源IP规则
ip rule add from 180.95.233.130/32 table 111

# 创建基于源IP规则，设定优先级为100
Ip rule add from 180.95.233.130/32 table 111 pref 100

# 删除路由规则
ip rule del from 180.95.233.130/32
```


## 应用场景

### iptables联动

```bash
# 根据端口将服务类的数据包打上标示
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -p tcp --dport 81 -j MARK --set-mark 2 

# 设置策略路由规则：标志为1的走出口1、标志位2的走出口2
ip rule add pref 10 fwmark 1 table 10
ip rule add pref 10 fwmark 2 table 20

# 设置两个策略路由表table10和table20
ip route add default via 10.0.1.1 table 10    (注意：这里不能使用dev eth0)
ip route add 192.168.3.0/24 dev eth2 table 10
ip route add default via 10.0.2.1 table 20    (注意：这里不能使用dev eth1)
ip route add 192.168.3.0/24 dev eth2 table 20
```

### 出口路由负载均衡

```bash
# 普通双ISP的设置 外网接口$IF1，IF1接口地址$IP1，ISP1网关地址$P1，ISP1的网络地址P1_NET
# 分别指定两条默认网关负责单独的上行流
# 源地址为IP1且目的为ISP1网段从IF1接口发出，将这条路由加入表T1
ip route add <P1_NET> dev <IF1> src <IP1> table <T1> 
ip route add default via <P1> table <T1>

# 源地址为IP2且目的为ISP2网段从IF2接口发出，将这条路由加入表T2
ip route add <P2_NET> dev <IF2> src <IP2> table <T2>
ip route add default via <P2> table <T2>

#加入路由到main路由表
ip route add <P1_NET> dev <IF1> src <IP1>
ip route add <P2_NET> dev <IF2> src <IP2>
ip route add default via <P1>

#设置路由规则
ip rule add from <IP1> table <T1>
ip rule add from <IP2> table <T2>

#设置负载均衡
ip route add default scope global nexthop via <P1> dev <IF1> weight 1 \
                                        nexthop via <P2> dev <IF2> weight 1
```


### Qdisc联动


```c
# 针对网络物理设备(如以太网卡eth0)绑定一个CBQ队列
tc qdisc add dev eth0 root handle 1: cbq bandwidth 10Mbit avpkt 1000 cell 8 mpu 64 

# 在该队列上建立分类
tc class add dev eth0 parent 1:0 classid 1:1 cbq bandwidth 10Mbit rate 10Mbit maxburst 20 allot 1514 prio 8 avpkt 1000 cell 8 weight 1Mbit 
tc class add dev eth0 parent 1:1 classid 1:2 cbq bandwidth 10Mbit rate 8Mbit maxburst 20 allot 1514 prio 2 avpkt 1000 cell 8 weight 800Kbit split 1:0 bounded 
tc class add dev eth0 parent 1:1 classid 1:3 cbq bandwidth 10Mbit rate 1Mbit maxburst 20 allot 1514 prio 1 avpkt 1000 cell 8 weight 100Kbit split 1:0
tc class add dev eth0 parent 1:1 classid 1:4 cbq bandwidth 10Mbit rate 1Mbit maxburst 20 allot 1514 prio 6 avpkt 1000 cell 8 weight 100Kbit split 1:0 

# 为每一分类建立一个基于路由的过滤器
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 2 flowid 1:2 
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 3 flowid 1:3 
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 4 flowid 1:4 

# 最后与过滤器相配合，建立特定的路由表
ip route add 192.168.1.24 dev eth0 via 192.168.1.66 realm 2 
ip route add 192.168.1.30 dev eth0 via 192.168.1.66 realm 3
ip route add 192.168.1.0/24 dev eth0 via 192.168.1.66 realm 4 
```


