# vlan

使用ip link创建vlan设备。

Linux 里 802.1.q VLAN 设备是以母子关系成对出现的，母设备相当于现实世界中的交换机 TRUNK 口，用于连接上级网络，子设备相当于普通接口用于连接下级网络。
母子设备之间是一对多的关系，一个母设备可以有多个子设备，一个子设备只有一个母设备。
当一个子设备有一包数据需要发送时，数据将被加入 VLAN Tag 然后从母设备发送出去。
当母设备收到一包数据时，它将会分析其中的 VLAN Tag，如果有对应的子设备存在，则把数据转发到那个子设备上并根据设置移除 VLAN Tag，否则丢弃该数据（否则应该是给母设备）。
母子设备的数据也是有方向的，子设备收到的数据不会进入母设备，同样母设备上请求发送的数据不会被转到子设备上。
母子 VLAN 设备拥有相同的 MAC 地址，可以把它当成现实世界中 802.1.q 交换机的 MAC，因此多个 VLAN 设备会共享一个 MAC。
当一个母设备拥有多个 VLAN 子设备时，子设备之间是隔离的，不存在 Bridge 那样的交换转发关系，原因如下：802.1.q VLAN 协议的主要目的是从逻辑上隔离子网。
现实世界中的 802.1.q 交换机存在多个 VLAN，每个 VLAN 拥有多个端口，同一 VLAN 端口之间可以交换转发，不同 VLAN 端口之间隔离，所以其包含两层功能：交换与隔离。
Linux VLAN device 实现的是隔离功能，没有交换功能。
一个 VLAN 母设备不可能拥有两个相同 ID 的 VLAN 子设备，因此也就不可能出现数据交换情况。


## vlan设备特有属性

id VLANID 						specifies the VLAN Identifer to use.
[ protocol VLAN_PROTO ] 		either 802.1Q or 802.1ad
[ reorder_hdr { on | off } ] 	specifies whether ethernet headers are reordered or not (default is on).
[ gvrp { on | off } ] 			specifies whether this VLAN should be registered using GARP VLAN Registration Protocol.
[ mvrp { on | off } ] 			specifies whether this VLAN should be registered using Multiple VLAN Registration Protocol.
[ loose_binding { on | off } ] 	specifies whether the VLAN device state is bound to the physical device state.
[ ingress-qos-map QOS-MAP ] 	defines a mapping of VLAN header prio field to the Linux internal packet priority on incoming frames.
[ egress-qos-map QOS-MAP ]		defines a mapping of Linux internal packet priority to VLAN header prio field but for outgoing frames.


## 示例命令

```bash
# 创建vlan设备，vlan id为10
ip link add link eth0 name eth0.10 type vlan id 10

# 删除vlan设备
ip link del eth0.10 type vlan
```


## 应用场景

```bash

```
