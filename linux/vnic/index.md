# Linux��������

���½���Linux�����������豸����ԭ��͹�������

## ������������
* can��Controller Area Network interface 
* dummy��Dummy network interface 
* ifb��Intermediate Functional Block device 
* macvlan��Virtual interface base on link layer address
* macvtap��Virtual interface based on link layer address(MAC) and TAP.
* vcan��Virtual Controller Area Network interface
* veth��Virtual ethernet interface
* vlan��802.1q tagged virtual LAN interface
* vxlan��Virtual eXtended LAN
* ipip��Virtual tunnel interface IPv4 over IPv4
* gre��Virtual tunnel interface GRE over IPv4
* gretap��Virtual L2 tunnel interface GRE over IPv4
* vti��Virtual tunnel interface
* nlmon��Netlink monitoring device
* ipvlan��Interface for L3 (IPv6/IPv4) based VLANs
* geneve��GEneric NEtwork Virtualization Encapsulation

## ������������
�������������豸��
```
ip link add 
[ name ] NAME 			// �豸����
type TYPE 				// �豸����
[ link DEVICE ] 		// specifies the physical device to act operate on.
[ txqueuelen PACKETS ] 	// ���÷��Ͷ���
[ address LLADDR ] 		// ����MAC��ַ
[ broadcast LLADDR ] 	// ���ù㲥��ַ
[ mtu MTU ]			    // ����MTUֵ
[ numtxqueues QUEUE_COUNT ] 	// specifies the number of transmit queues for new device.
[ numrxqueues QUEUE_COUNT ] 	// specifies the number of receive queues for new device.
[ ARGS ] 			   // �豸��صĲ���
```
�޸����������豸:
```
ip link set 
{DEVICE|group GROUP}    // ���޸ĵ��豸
up|down				    // ����/ֹͣ�豸��ifconfig eth0 up|down
arp on|arp off			// arp����/arp�ر�
promisc on|off			// ����ģʽ����
allmulticast on|off
dynamic on|off 
multicast on|off 		
txqueuelen PACKETS 		// �豸���г��ȣ���дΪ��txqlen
name NEWNAME			// �豸����
address LLADDR 			// MAC��ַ
broadcast LLADDR 		// �㲥��ַ
mtu MTU				    // MTUֵ��ifconfig eth0 mtu 1500
netns {PID | NETNSNAME}	// netnamespaceֵ���൱�ڰ��豸���뵽ĳ�������ռ�
alias NAME			    // ����alias��
```