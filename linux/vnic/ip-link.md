# ip link ����

ͨ��ip link���Դ���vlan��vxlan��veth��macvlan��macvtap�ȵ����������豸��

## ip link����

��������������ͨ�����ԣ�:

```bash
ip link add 
[ name ] NAME                   #�豸����
type TYPE                       #�豸����
[ link DEVICE ] 		        #specifies the physical device to act operate on.
[ txqueuelen PACKETS ] 	        #���÷��Ͷ���
[ address LLADDR ] 		        #����MAC��ַ
[ broadcast LLADDR ] 	        #���ù㲥��ַ
[ mtu MTU ]                     #����MTUֵ
[ numtxqueues QUEUE_COUNT ] 	#specifies the number of transmit queues for new device.
[ numrxqueues QUEUE_COUNT ] 	#specifies the number of receive queues for new device.
[ ARGS ]                        #�豸��صĲ���
```

�޸��豸���ԣ�ͨ�����ԣ���
```bash
ip link set 
{DEVICE|group GROUP}         #���޸ĵ��豸
up|down                      #����/ֹͣ�豸��ifconfig eth0 up|down
arp on|arp off               #arp����/arp�ر�
promisc on|off               #����ģʽ����
allmulticast on|off
dynamic on|off 
multicast on|off 		
txqueuelen PACKETS           #�豸���г��ȣ���дΪ��txqlen
name NEWNAME                 #�豸����
address LLADDR               #MAC��ַ
broadcast LLADDR             #�㲥��ַ
mtu MTU	                     #MTUֵ��ifconfig eth0 mtu 1500
netns {PID | NETNSNAME}      #net name spaceֵ���൱�ڰ��豸���뵽ĳ�������ռ�
alias NAME                   #����alias��
```

ɾ���豸��

```bash
ip link delete <dev> type <type>
```

��ѯ�豸��Ϣ��
```bash
ip [-s] link list       #-s���Զ����Խ����ϢԽ�ḻ
ip [-s] link            #-s���Զ����Խ����ϢԽ�ḻ
ip [-s] link ls <ethX>  #-s���Զ����Խ����ϢԽ�ḻ
```

### type�����б�
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

## ������������

��ͬ���͵���������֧�ֲ�ͬ�����ԡ�

### vlan�豸
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

### vxlan�豸
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

### veth�豸
```bash
ip link add dev <veth_host> type veth peer name <veth_con>
```

### macvlan��macvtap�豸
```bash
ip link add link <DEVICE> name <NAME> type macvlan [mode <MODE>]
ip link add link <DEVICE> name <NAME> type macvtap [mode <MODE>]
```

#### mode����
|  mode | ���� |
|:-----|:-----|
|private|������ģʽ�£�macvlan�豸���ܽ��ܼ�����ͬһ����������������macvlan�豸�����ݰ�����ʹ������macvlan�豸ͨ�������������ͳ�ȥ��ͨ��hairpin�豸���صİ�|
|vepa|������ģʽ�£�macvlan�豸����ֱ�ӽ��ܼ�����ͬһ����������������macvlan�豸�����ݰ�����������macvlan�豸���Խ����ݰ�ͨ�������������ͳ�ȥ��Ȼ��ͨ��hairpin�豸���صĸ�����macvlan�豸|
|passthru|������ģʽ�£�ÿһ�������豸ֻ�ܼ���һ��macvlan�豸|
|bridge|������ģʽ�£�������ͬһ�������豸��macvlan�豸����ֱ��ͨѶ������Ҫ��ӵ�hairpin�豸����|
|source|������ģʽ�£������������豸������macvlan�豸��ֻ�ܽ���ָ����Դ mac source�����ݰ����������ݰ���������|

### ipvlan�豸
```bash
ip link add link <master-dev> <slave-dev> 
type ipvlan 
mode { l2 | L3 }
```

#### mode����
|  mode | ���� |
|:-----|:-----|
|L2 mode|In this mode TX processing happens on the stack instance attached to the slave device and packets are switched and queued to the master device to send out. In this mode the slaves will RX/TX multicast and broadcast (if applicable) as well.|
|L3 mode|In this mode TX processing upto L3 happens on the stack instance attached to the slave device and packets are switched to the stack instance of the master device for the L2 processing and routing from that instance will be used before packets are queued on the outbound device. In this mode the slaves will not receive nor can send multicast / broadcast traffic.|


### gre/ipip/sit�豸
```bash
ip link add DEVICE 
type { gre | ipip | sit }  	�豸����
remote ADDR                     specifies the remote address of the tun-nel.
local ADDR                      specifies the fixed local address for tun-neled packets.  It must be an address on another inter-face on this host.
[ encap { fou | gue | none } ] 	specifies type of secondary UDP encapsulation.
[ encap-sport { PORT | auto} ] 	specifies the source port in UDP encapsulation.
[ encap-dport PORT ]            specifies the dest port in UDP encapsulation.
[ [no]encap-csum ]              specifies if UDP checksums are enabled in the secondary encapsulation.
[ [no]encap-remc-sum ]          specifies if Remote Checksum Offload is enabled. This is only applicable for Generic UDP Encapsulation.
```

### geneve�豸
```bash
ip link add DEVICE type geneve 
id VNI                   specifies the Virtual Network Identifer to use.
remote IPADDR            specifies the unicast destination IP address to use in outgoing packets.
[ ttl TTL ]              specifies the TTL value to use in outgoing packets.
[ tos TOS ]              specifies the TOS value to use in outgoing packets.
[ flowlabel FLOWLABEL ]	 specifies the flow label to use in outgoing packets.
```

### ipoib�豸
```bash
ip link add DEVICE name NAME type ipoib 
[ pkey PKEY ] 	specifies the IB P-Key to use.
[ mode MODE ]	specifies the mode (datagram or connected) to use.
```
