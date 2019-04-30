# MACVLAN & MACVTAP

使用ip link命令创建MACVLAN和MACVTAP设备。


## 设备特有参数

mode { private | vepa | bridge | passthru  [ nopromisc ] }   设备转发模式


### 模式定义

* mode private
  * Do not allow communication between macvlan instances on the same physical interface, even if the external switch supports hairpin mode.
* mode vepa 
  * Virtual Ethernet Port Aggregator mode. Data from one macvlan instance to the other on the same phys-ical interface is transmitted over the physical inter-face. Either the attached switch needs to support hair-pin mode, or there must be a TCP/IP router forwarding the packets in order to allow communication. This is thedefault mode.
* mode bridge
  * In bridge mode, all endpoints are directly connected to each other, communication is not redirected through the physical interface's peer.
* mode passthru [ nopromisc ] 
  * This mode gives more power to a single endpoint, usually in macvtap mode. It is not allowed for more than one endpoint on the same physical interface. All traffic will be forwarded to this end-point, allowing virtio guests to change MAC address or set promiscuous mode in order to bridge the interface or create vlan interfaces on top of it. By default, this mode forces the underlying interface into promiscuous mode. Passing the nopromisc flag prevents this, so the promisc flag may be controlled using standard tools.
* mode source
  * allows one to set a list of allowed mac address, which is used to match against source mac address from received frames on underlying interface. This allows creating mac based VLAN associations, instead of standard port or tag based. The feature is useful to deploy 802.1x mac based behavior, where drivers of underlying interfaces doesn't allows that.

### 模式解释

|  mode | 作用 |
|:-----|:-----|
|private|在这种模式下，macvlan设备不能接受寄生在同一个物理网卡的其他macvlan设备的数据包，即使是其他macvlan设备通过物理网卡发送出去并通过hairpin设备返回的包|
|vepa|在这种模式下，macvlan设备不能直接接受寄生在同一个物理网卡的其他macvlan设备的数据包，但是其他macvlan设备可以将数据包通过物理网卡发送出去，然后通过hairpin设备返回的给其他macvlan设备|
|passthru|在这种模式下，每一个物理设备只能寄生一个macvlan设备|
|bridge|在这种模式下，寄生在同一个物理设备的macvlan设备可以直接通讯，不需要外接的hairpin设备帮助|
|source|在这种模式下，寄生在物理设备的这类macvlan设备，只能接受指定的源 mac source的数据包，其他数据包都不接受。|


## 命令示例

```bash
# 创建macvlan设备
ip link add link <DEVICE> name <NAME> type macvlan [mode <MODE>]

# 创建macvtap设备
ip link add link <DEVICE> name <NAME> type macvtap [mode <MODE>]

# 删除macvlan设备
ip link del macvlan1 type macvlan
```


## 应用场景

### 容器网络方案

通过macvlan设备进行转发，是一个大二层的容器方案，性能好，但是依赖底层支持二层广播。

```bash
ip link add link eth0 name macvlan1 type macvlan mode bridge
ip link add link eth0 name macvlan2 type macvlan mode bridge

ip addr add 10.0.0.2/24 dev macvlan1 
ip addr add 10.0.0.3/24 dev macvlan2 

ip netns add ns1
ip link set macvlan1 netns ns1

ip netns add ns2
ip link set macvlan2 netns ns2
```

### 报文监控

使用source mode模式，来监听目标mac地址发送的报文。

```c

```

