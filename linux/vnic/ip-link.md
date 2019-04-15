# ip link 命令

通过ip link可以创建vlan、vxlan、veth、macvlan、macvtap等等虚拟网卡设备。

## ip link命令

创建虚拟网卡（通用属性）:

```bash
ip link add 
[ name ] NAME                   #设备名称
type TYPE                       #设备类型
[ link DEVICE ] 		        #specifies the physical device to act operate on.
[ txqueuelen PACKETS ] 	        #设置发送队列
[ address LLADDR ] 		        #设置MAC地址
[ broadcast LLADDR ] 	        #设置广播地址
[ mtu MTU ]                     #设置MTU值
[ numtxqueues QUEUE_COUNT ] 	#specifies the number of transmit queues for new device.
[ numrxqueues QUEUE_COUNT ] 	#specifies the number of receive queues for new device.
[ ARGS ]                        #设备相关的参数
```

修改设备属性（通用属性）：
```bash
ip link set 
{DEVICE|group GROUP}         #待修改的设备
up|down                      #启动/停止设备，ifconfig eth0 up|down
arp on|arp off               #arp启动/arp关闭
promisc on|off               #混杂模式开关
allmulticast on|off
dynamic on|off 
multicast on|off 		
txqueuelen PACKETS           #设备队列长度，缩写为：txqlen
name NEWNAME                 #设备名字
address LLADDR               #MAC地址
broadcast LLADDR             #广播地址
mtu MTU	                     #MTU值，ifconfig eth0 mtu 1500
netns {PID | NETNSNAME}      #net name space值，相当于把设备加入到某个命名空间
alias NAME                   #设置alias名
```

删除设备：

```bash
ip link delete <dev> type <type>
```

查询设备信息：
```bash
ip [-s] link list       #-s可以多个，越多信息越丰富
ip [-s] link            #-s可以多个，越多信息越丰富
ip [-s] link ls <ethX>  #-s可以多个，越多信息越丰富
```

### type类型列表
```
bridge		Ethernet Bridge device 
can		    Controller Area Network interface 
dummy		Dummy network interface 
ifb		    Intermediate Functional Block device 
ipoib		IP over Infiniband device 
macvlan		Virtual interface base on link layer address
macvtap		Virtual interface based on link layer address(MAC) and TAP.
vcan		Virtual Controller Area Network interface
veth		Virtual ethernet interface
vlan		802.1q tagged virtual LAN interface
vxlan		Virtual eXtended LAN
ip6tnl		Virtual tunnel interface IPv4|IPv6 over IPv6
ipip		Virtual tunnel interface IPv4 over IPv4
sit		    Virtual tunnel interface IPv6 over IPv4
gre		    Virtual tunnel interface GRE over IPv4
gretap		Virtual L2 tunnel interface GRE over IPv4
ip6gre		Virtual tunnel interface GRE over IPv6
ip6gretap	Virtual L2 tunnel interface GRE over IPv6
vti		    Virtual tunnel interface
nlmon		Netlink monitoring device
ipvlan		Interface for L3 (IPv6/IPv4) based VLANs
lowpan		Interface for 6LoWPAN (IPv6) over IEEE 802.15.4
geneve		GEneric NEtwork Virtualization Encapsulation
```

## 虚拟网卡创建

不同类型的虚拟网卡支持不同的属性。

### vlan设备
```bash
ip link add link <DEVICE> name <NAME> type vlan 
id VLANID                       specifies the VLAN Identifer to use.
[ protocol VLAN_PROTO ]         either 802.1Q or 802.1ad
[ reorder_hdr { on | off } ] 	specifies whether ethernet headers are reordered or not (default is on).
[ gvrp { on | off } ]           specifies whether this VLAN should be registered using GARP VLAN Registration Protocol.
[ mvrp { on | off } ]           specifies whether this VLAN should be registered using Multiple VLAN Registration Protocol.
[ loose_binding { on | off } ] 	specifies whether the VLAN device state is bound to the physical device state.
[ ingress-qos-map QOS-MAP ]     defines a mapping of VLAN header prio field to the Linux internal packet priority on incoming frames.
[ egress-qos-map QOS-MAP ]      defines a mapping of Linux internal packet priority to VLAN header prio field but for outgoing frames.
```

### vxlan设备
```bash
ip link add <DEVICE> type vxlan 
id ID                           specifies the VXLAN Network Identifer (or VXLAN Segment Identifier) to use.
[ dev PHYS_DEV  ]               specifies the physical device to use for tunnel endpoint communication.
[ { group | remote } IPADDR ] 	specifies the multicast IP address to join.  This parameter cannot be specified with the remote parameter.
[ local { IPADDR | any } ]      specifies the source IP address to use in outgoing packets.
[ ttl TTL ]                     specifies the TTL value to use in outgoing packets.
[ tos TOS ]                     specifies the TOS value to use in outgoing packets.
[ flowlabel FLOWLABEL ]         specifies the flow label to use in outgoing packets.
[ dstport PORT ]                specifies the UDP destination port to communicate to the remote VXLAN tunnel endpoint.
[ srcport MIN MAX ]             specifies the range of port numbers to use as UDP source ports to communicate to the remote VXLAN tunnel endpoint.
[ [no]learning ]                specifies if unknown source link layer addresses and IP addresses are entered into the VXLAN device forwarding database.
[ [no]proxy ]                   specifies ARP proxy is turned on.
[ [no]rsc ]                     specifies if route short circuit is turned on.
[ [no]l2miss ]                  specifies if netlink LLADDR miss notifica-tions are generated.
[ [no]l3miss ]                  specifies if netlink IP ADDR miss notifica-tions are generated.
[ [no]udpcsum ]                 specifies if UDP checksum is calculated for transmitted packets over IPv4.
[ [no]udp6zerocsumtx ]          skip UDP checksum calculation for transmitted packets over IPv6.
[ [no]udp6zerocsumrx ]          allow incoming UDP packets over IPv6 with zero checksum field.
[ ageing SECONDS ]              specifies the lifetime in seconds of FDB entries learnt by the kernel.
[ maxaddress NUMBER ]           specifies the maximum number of FDB entries.
[ gbp ]	                        enables the Group Policy extension (VXLAN-GBP).
```

### veth设备
```bash
ip link add dev <veth_host> type veth peer name <veth_con>
```

### macvlan和macvtap设备
```bash
ip link add link <DEVICE> name <NAME> type macvlan [mode <MODE>]
ip link add link <DEVICE> name <NAME> type macvtap [mode <MODE>]
```

#### mode属性
|  mode | 作用 |
|:-----|:-----|
|private|在这种模式下，macvlan设备不能接受寄生在同一个物理网卡的其他macvlan设备的数据包，即使是其他macvlan设备通过物理网卡发送出去并通过hairpin设备返回的包|
|vepa|在这种模式下，macvlan设备不能直接接受寄生在同一个物理网卡的其他macvlan设备的数据包，但是其他macvlan设备可以将数据包通过物理网卡发送出去，然后通过hairpin设备返回的给其他macvlan设备|
|passthru|在这种模式下，每一个物理设备只能寄生一个macvlan设备|
|bridge|在这种模式下，寄生在同一个物理设备的macvlan设备可以直接通讯，不需要外接的hairpin设备帮助|
|source|在这种模式下，寄生在物理设备的这类macvlan设备，只能接受指定的源 mac source的数据包，其他数据包都不接受|

### ipvlan设备
```bash
ip link add link <master-dev> <slave-dev> 
type ipvlan 
mode { l2 | L3 }
```

#### mode属性
|  mode | 作用 |
|:-----|:-----|
|L2 mode|In this mode TX processing happens on the stack instance attached to the slave device and packets are switched and queued to the master device to send out. In this mode the slaves will RX/TX multicast and broadcast (if applicable) as well.|
|L3 mode|In this mode TX processing upto L3 happens on the stack instance attached to the slave device and packets are switched to the stack instance of the master device for the L2 processing and routing from that instance will be used before packets are queued on the outbound device. In this mode the slaves will not receive nor can send multicast / broadcast traffic.|


### gre/ipip/sit设备
```bash
ip link add DEVICE 
type { gre | ipip | sit }  	设备类型
remote ADDR                     specifies the remote address of the tun-nel.
local ADDR                      specifies the fixed local address for tun-neled packets.  It must be an address on another inter-face on this host.
[ encap { fou | gue | none } ] 	specifies type of secondary UDP encapsulation.
[ encap-sport { PORT | auto} ] 	specifies the source port in UDP encapsulation.
[ encap-dport PORT ]            specifies the dest port in UDP encapsulation.
[ [no]encap-csum ]              specifies if UDP checksums are enabled in the secondary encapsulation.
[ [no]encap-remc-sum ]          specifies if Remote Checksum Offload is enabled. This is only applicable for Generic UDP Encapsulation.
```

### geneve设备
```bash
ip link add DEVICE type geneve 
id VNI                   specifies the Virtual Network Identifer to use.
remote IPADDR            specifies the unicast destination IP address to use in outgoing packets.
[ ttl TTL ]              specifies the TTL value to use in outgoing packets.
[ tos TOS ]              specifies the TOS value to use in outgoing packets.
[ flowlabel FLOWLABEL ]	 specifies the flow label to use in outgoing packets.
```

### ipoib设备
```bash
ip link add DEVICE name NAME type ipoib 
[ pkey PKEY ] 	specifies the IB P-Key to use.
[ mode MODE ]	specifies the mode (datagram or connected) to use.
```
