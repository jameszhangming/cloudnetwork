# Linux虚拟网卡

本章介绍Linux的虚拟网卡设备工作原理和管理方法。

## 虚拟网卡类型
* can，Controller Area Network interface 
* dummy，Dummy network interface 
* ifb，Intermediate Functional Block device 
* macvlan，Virtual interface base on link layer address
* macvtap，Virtual interface based on link layer address(MAC) and TAP.
* vcan，Virtual Controller Area Network interface
* veth，Virtual ethernet interface
* vlan，802.1q tagged virtual LAN interface
* vxlan，Virtual eXtended LAN
* ipip，Virtual tunnel interface IPv4 over IPv4
* gre，Virtual tunnel interface GRE over IPv4
* gretap，Virtual L2 tunnel interface GRE over IPv4
* vti，Virtual tunnel interface
* nlmon，Netlink monitoring device
* ipvlan，Interface for L3 (IPv6/IPv4) based VLANs
* geneve，GEneric NEtwork Virtualization Encapsulation

## 虚拟网卡操作
创建虚拟网卡设备：
```
ip link add 
[ name ] NAME 			// 设备名称
type TYPE 				// 设备类型
[ link DEVICE ] 		// specifies the physical device to act operate on.
[ txqueuelen PACKETS ] 	// 设置发送队列
[ address LLADDR ] 		// 设置MAC地址
[ broadcast LLADDR ] 	// 设置广播地址
[ mtu MTU ]			    // 设置MTU值
[ numtxqueues QUEUE_COUNT ] 	// specifies the number of transmit queues for new device.
[ numrxqueues QUEUE_COUNT ] 	// specifies the number of receive queues for new device.
[ ARGS ] 			   // 设备相关的参数
```
修改虚拟网卡设备:
```
ip link set 
{DEVICE|group GROUP}    // 待修改的设备
up|down				    // 启动/停止设备，ifconfig eth0 up|down
arp on|arp off			// arp启动/arp关闭
promisc on|off			// 混杂模式开关
allmulticast on|off
dynamic on|off 
multicast on|off 		
txqueuelen PACKETS 		// 设备队列长度，缩写为：txqlen
name NEWNAME			// 设备名字
address LLADDR 			// MAC地址
broadcast LLADDR 		// 广播地址
mtu MTU				    // MTU值，ifconfig eth0 mtu 1500
netns {PID | NETNSNAME}	// netnamespace值，相当于把设备加入到某个命名空间
alias NAME			    // 设置alias名
```