# vxlan设备

使用ip link管理vxlan设备。


## vxlan设备特有信息

id ID 						    specifies the VXLAN Network Identifer (or VXLAN Segment Identifier) to use.
[ dev PHYS_DEV  ] 		        specifies the physical device to use for tunnel endpoint communication.
[ { group | remote } IPADDR ] 	specifies the multicast IP address to join.  This parameter cannot be specified with the remote parameter.
[ local { IPADDR | any } ] 		specifies the source IP address to use in outgoing packets.
[ ttl TTL ] 					specifies the TTL value to use in outgoing packets.
[ tos TOS ] 					specifies the TOS value to use in outgoing packets.
[ flowlabel FLOWLABEL ] 		specifies the flow label to use in outgoing packets.
[ dstport PORT ] 				specifies the UDP destination port to communicate to the remote VXLAN tunnel endpoint.
[ srcport MIN MAX ] 			specifies the range of port numbers to use as UDP source ports to communicate to the remote VXLAN tunnel endpoint.
[ [no]learning ] 				specifies if unknown source link layer addresses and IP addresses are entered into the VXLAN device forwarding database.
[ [no]proxy ] 					specifies ARP proxy is turned on.
[ [no]rsc ] 					specifies if route short circuit is turned on.
[ [no]l2miss ] 					specifies if netlink LLADDR miss notifica-tions are generated.
[ [no]l3miss ] 					specifies if netlink IP ADDR miss notifica-tions are generated.
[ [no]udpcsum ] 				specifies if UDP checksum is calculated for transmitted packets over IPv4.
[ [no]udp6zerocsumtx ] 			skip UDP checksum calculation for transmitted packets over IPv6.
[ [no]udp6zerocsumrx ] 			allow incoming UDP packets over IPv6 with zero checksum field.
[ ageing SECONDS ] 				specifies the lifetime in seconds of FDB entries learnt by the kernel.
[ maxaddress NUMBER ] 			specifies the maximum number of FDB entries.
[ gbp ]							enables the Group Policy extension (VXLAN-GBP).


## 命令示例

```bash
# 创建vxlan设备，仅指定vni
ip link add vtep0 type vxlan id 1001

# 创建vxlan设备，指定默认remote，指定本地出口设备
ip link add vtep0 type vxlan id 1001 dev eth0 remote 192.168.100.10

# 创建vxlan设备，指定使用非learning方式
ip link add vtep0 type vxlan id 1001 dev eth0 nolearning

# 删除vxlan设备
ip link del vtep0 type vxlan
```


## 应用场景

### vxlan + route + learning

```bash
# 主机1配置（192.168.100.8）
# 容器的IP段为10.0.0.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 remote 192.168.100.10 
ip addr add 10.10.10.10/24 dev vtep0  # 配置vtep0 IP地址
ip link set vtep0 up
ip route add 10.0.1.0/24 via 10.10.10.11 dev vtep0  # 配置路由，下一跳为另一端的vtep设备的IP地址

# 主机2配置（192.168.100.10）
# 容器的IP段为10.0.1.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 remote 192.168.100.8
ip addr add 10.10.10.11/24 dev vtep0
ip link set vtep0 up
ip route add 10.0.0.0/24 via 10.10.10.10 dev veth0 

# vtep设备的mac表项可以提前配置（可选）
ip neigh add 10.10.10.11 lladdr fa:8a:d3:6d:e7:6c dev vtep0 nud perm
ip neigh add 10.10.10.10 lladdr 9a:e0:10:c5:bf:28 dev vtep0 nud perm

# 如果节点比较多可以配置，两个主机上分别配置（可选）
bridge fdb append 00:00:00:00:00:00 dev vtep0 dst 192.168.100.11 
bridge fdb append 00:00:00:00:00:00 dev vtep0 dst 192.168.100.9
```


### vxlan + route + nolearning

nolearning的话就需要提前配置fdb表项

```bash
# 主机1配置（192.168.100.8）
# 容器的IP段为10.0.0.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 nolearning
ip addr add 10.10.10.10/24 dev vtep0  # 配置vtep0 IP地址
ip link set vtep0 up
ip route add 10.0.1.0/24 via 10.10.10.11 dev vtep0  # 配置路由，下一跳为另一端的vtep设备的IP地址

# 主机2配置（192.168.100.10）
# 容器的IP段为10.0.1.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 nolearning 
ip addr add 10.10.10.11/24 dev vtep0
ip link set vtep0 up
ip route add 10.0.0.0/24 via 10.10.10.10 dev veth0 

# 配置fdb表项（主机1）
bridge fdb append fa:8a:d3:6d:e7:6c dev vtep0 dst 192.168.100.10 

# 配置fdb表项（主机2）
bridge fdb append 9a:e0:10:c5:bf:28 dev vtep0 dst 192.168.100.8
```


### vxlan + bridge + learning

```bash
# 主机1配置（192.168.100.8）
# 容器的IP段为10.0.0.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 remote 192.168.100.10 learning
ip link set vtep0 up

# 主机2配置（192.168.100.10）
# 容器的IP段为10.0.1.0/24
ip link add vtep0 type vxlan id 1001 dev eth0 remote 192.168.100.8 learning
ip link set vtep0 up

# 如果节点比较多可以配置，两个主机上分别配置（可选）
bridge fdb append 00:00:00:00:00:00 dev vtep0 dst 192.168.100.11 
bridge fdb append 00:00:00:00:00:00 dev vtep0 dst 192.168.100.9
```
