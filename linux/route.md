# route

·����ϵͳʵ��IP������η��ͣ�ȷ����һ��ȥ���

## ·�ɸ���

* ·�ɣ���Խ��Դ������Ŀ��������һ������������ת�����ݰ��Ĺ���
* ·�������ܹ������ݰ�ת������ȷ��Ŀ�ĵأ�����ת��������ѡ�����·�����豸
* ·�ɱ���·������ά����·����Ŀ��·��������·�ɱ���·��ѡ��
* ֱ��·�ɣ�����·�����������˽ӿڵ�IP��ַ�����ҽӿ�״̬Ϊup��ʱ��·�ɱ��оͳ���ֱ��·����
* ��̬·�ɣ����ɹ���Ա�ֹ����õģ��ǵ����
* Ĭ��·�ɣ���·������·�ɱ����Ҳ���Ŀ�������·����Ŀʱ��·����������ת����Ĭ��·�ɽӿ� 


## ����·��

�ڲ��Ե�·�ɱȴ�ͳ·���ڹ����ϸ�ǿ��ʹ�ø�����ʹ�������Ա�����ܹ�����Ŀ�ĵ�ַ�����ܹ����ݱ��Ĵ�С��Ӧ�û�IPԴ��ַ��������ѡ��ת��·����


## ip route����

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

 
### ·�ɱ�

�û������Զ���� 1��252��·�ɱ����У�linuxϵͳά����4��·�ɱ�

* 0
  * ϵͳ������
* default(ID 253)
  * ·�ɱ�default��һ���ձ�����ΪһЩ�����������ġ�����ǰ���ȱʡ����û��ƥ�䵽�����ݰ���ϵͳʹ��������Խ��д�����ɾ����
* main(ID 254) 
  * ·�ɱ�main��һ��ͨ���ı��������е��޲���·�ɡ�ϵͳ����Ա��ɾ������ʹ������Ĺ��򸲸���������
* local(ID 255) 
  * ·�ɱ�local��һ�������·�ɱ��������ڱ��غ͹㲥��ַ�ĸ����ȼ�����·�ɡ�rule 0�ǳ����⣬���ܱ�ɾ�����߸��ǡ�  

  
### ·�ɲ������ò���

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
  
  
### ip route����ʾ��

����ָ��rableʱ��Ĭ��ʹ�õ���main��

```bash
//�г�·�ɱ���Ŀ
ip route show [table ID]
ip route list [table ID]
ip route ls [table ID]

//���Ĭ��·��
ip route add default via 192.168.0.1 dev eth0 [table f5]

//ɾ��Ĭ��·��
ip route del default via 192.168.0.1 dev eth0 [table f5]

//��Ӿ�̬·��
ip route add 10.0.0/24 via 193.233.7.65 dev eth0 [table ID]

//ɾ����̬·��
ip route del 10.0.0/24 via 193.233.7.65 dev eth0 [table 10]

//�޸ľ�̬·��
ip route change 10.0.0/24 dev eth0

//��Ӹ��ؾ���·��
ip route add default scope global nexthop via <GW0> dev <EXT_IF0> weight 1  via <GW1> dev <EXT_IF1> weight 1
```


## ip rule����

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

### SELECTOR˵��

* pref PRI		    �������ȼ���ԽС���ȼ�Խ�ߣ�
* fwmark MARK		ƥ�䱨��fwmarkֵ����ͬ��markֵ��
* from PREFIX		ƥ�䱨��ԴIP��ַ����ʽΪ��IP[/MASK]
* to PREFIX		    ƥ�䱨��Ŀ��IP��ַ����ʽΪ��IP[/MASK]
* iif NAME		    ƥ�䱨����˿�
* oif NAME		    ƥ�䱨�ĳ��˿�
* tos TOS			ƥ��TOSֵ����ͬ��dsfield TOS


### ACTION˵��

* table TABLEID		�������ѡ���ƥ�䣬��ѡ���·�ɱ����·��
* prohibit			��ֹ
* reject			�ܾ�
* unreachable       ���ɴ�
* realms FROM/TO    �������ƥ���·�ɱ��ѯ�ɹ���ѡ���realmsֵ
* goto NUMBER       
* nat ADDRESS		����Ҫ���������ַת����IP��ַ��


### Ĭ�Ϲ������ȼ�ֵԽС���ȼ�Խ�ߣ�

```bash
0:	from all lookup local 
32766:	from all lookup main 
32767:	from all lookup default 
```


### ip rule����ʾ��

```bash
# �г�·�ɹ���
ip rule show 
ip rule ls 

# ��������ԴIP����
ip rule add from 180.95.233.130/32 table 111

# ��������ԴIP�����趨���ȼ�Ϊ100
Ip rule add from 180.95.233.130/32 table 111 pref 100

# ɾ��·�ɹ���
ip rule del from 180.95.233.130/32
```


## Ӧ�ó���

### iptables����

```bash
# ���ݶ˿ڽ�����������ݰ����ϱ�ʾ
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -p tcp --dport 81 -j MARK --set-mark 2 

# ���ò���·�ɹ��򣺱�־Ϊ1���߳���1����־λ2���߳���2
ip rule add pref 10 fwmark 1 table 10
ip rule add pref 10 fwmark 2 table 20

# ������������·�ɱ�table10��table20
ip route add default via 10.0.1.1 table 10    (ע�⣺���ﲻ��ʹ��dev eth0)
ip route add 192.168.3.0/24 dev eth2 table 10
ip route add default via 10.0.2.1 table 20    (ע�⣺���ﲻ��ʹ��dev eth1)
ip route add 192.168.3.0/24 dev eth2 table 20
```

### ����·�ɸ��ؾ���

```bash
# ��ͨ˫ISP������ �����ӿ�$IF1��IF1�ӿڵ�ַ$IP1��ISP1���ص�ַ$P1��ISP1�������ַP1_NET
# �ֱ�ָ������Ĭ�����ظ��𵥶���������
# Դ��ַΪIP1��Ŀ��ΪISP1���δ�IF1�ӿڷ�����������·�ɼ����T1
ip route add <P1_NET> dev <IF1> src <IP1> table <T1> 
ip route add default via <P1> table <T1>

# Դ��ַΪIP2��Ŀ��ΪISP2���δ�IF2�ӿڷ�����������·�ɼ����T2
ip route add <P2_NET> dev <IF2> src <IP2> table <T2>
ip route add default via <P2> table <T2>

#����·�ɵ�main·�ɱ�
ip route add <P1_NET> dev <IF1> src <IP1>
ip route add <P2_NET> dev <IF2> src <IP2>
ip route add default via <P1>

#����·�ɹ���
ip rule add from <IP1> table <T1>
ip rule add from <IP2> table <T2>

#���ø��ؾ���
ip route add default scope global nexthop via <P1> dev <IF1> weight 1 \
                                        nexthop via <P2> dev <IF2> weight 1
```


### Qdisc����


```c
# ������������豸(����̫����eth0)��һ��CBQ����
tc qdisc add dev eth0 root handle 1: cbq bandwidth 10Mbit avpkt 1000 cell 8 mpu 64 

# �ڸö����Ͻ�������
tc class add dev eth0 parent 1:0 classid 1:1 cbq bandwidth 10Mbit rate 10Mbit maxburst 20 allot 1514 prio 8 avpkt 1000 cell 8 weight 1Mbit 
tc class add dev eth0 parent 1:1 classid 1:2 cbq bandwidth 10Mbit rate 8Mbit maxburst 20 allot 1514 prio 2 avpkt 1000 cell 8 weight 800Kbit split 1:0 bounded 
tc class add dev eth0 parent 1:1 classid 1:3 cbq bandwidth 10Mbit rate 1Mbit maxburst 20 allot 1514 prio 1 avpkt 1000 cell 8 weight 100Kbit split 1:0
tc class add dev eth0 parent 1:1 classid 1:4 cbq bandwidth 10Mbit rate 1Mbit maxburst 20 allot 1514 prio 6 avpkt 1000 cell 8 weight 100Kbit split 1:0 

# Ϊÿһ���ཨ��һ������·�ɵĹ�����
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 2 flowid 1:2 
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 3 flowid 1:3 
tc filter add dev eth0 parent 1:0 protocol ip prio 100 route to 4 flowid 1:4 

# ��������������ϣ������ض���·�ɱ�
ip route add 192.168.1.24 dev eth0 via 192.168.1.66 realm 2 
ip route add 192.168.1.30 dev eth0 via 192.168.1.66 realm 3
ip route add 192.168.1.0/24 dev eth0 via 192.168.1.66 realm 4 
```


