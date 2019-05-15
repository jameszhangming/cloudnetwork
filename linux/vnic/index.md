# Linux虚拟网卡

本章介绍创建虚拟网卡设备的命令，并从代码角度来分析各类虚拟网卡的工作原理。


## 设备分类

* 隧道设备
  * vlan（vlan头）、vxlan（内层为MAC报文）、gre（内层为IP报文）、gretap（内层为MAC报文）、ipip（内层为IP报文）

* 一分多
  * macvlan（二层设备）、ipvlan（三层设备）、vlan（二层，复用MAC）

* 交换设备
  * macvlan（二层设备）、ipvlan（三层设备）


## 相关命令
* ip link
* tunctl




