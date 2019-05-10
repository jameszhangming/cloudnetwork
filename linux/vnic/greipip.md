# GRE IPIP

使用ip link命令创建gre和ipip设备，gre和ipip设备均为三层设备。


## 设备特有参数

remote ADDR 			        specifies the remote address of the tun-nel.
local ADDR 				        specifies the fixed local address for tun-neled packets.  It must be an address on another inter-face on this host.
[ encap { fou | gue | none } ] 	specifies type of secondary UDP encapsulation.
[ encap-sport { PORT | auto} ] 	specifies the source port in UDP encapsulation.
[ encap-dport PORT ] 		    specifies the dest port in UDP encapsulation.
[ [no]encap-csum ] 		        specifies if UDP checksums are enabled in the secondary encapsulation.
[ [no]encap-remc-sum ]		    specifies if Remote Checksum Offload is enabled. This is only applicable for Generic UDP Encapsulation.


## 操作示例

```bash
# 创建gre隧道
ip link add gre0 type gre remote 180.1.1.1 local 110.2.2.2

# 删除gre隧道
ip link del gre0 type gre

# 创建ipip设备
ip link add ipip0 type ipip remote 192.168.9.6 local 192.168.9.5

# 删除ipip设备
ip link del ipip0 type ipip
```


## 应用场景

### 使用gre构建虚拟专线

```bash
# site1（公网出口110.2.2.2，本地网段10.1.1.0/24）
ip link add gre0 type gre remote 180.1.1.1 local 110.2.2.2  #创建gre隧道
ip link set gre0 up
ip link set gre0 up mtu 1500
ip addr add 192.192.192.1/24 dev gre0  # 为gre0添加 ip 192.192.192.1
echo 1 > /proc/sys/net/ipv4/ip_forward
ip route add 192.168.1.0/24 dev gre0  # 添加路由，对端192.168.1.0/24网段通过gre0直达
iptables -t nat -A POSTROUTING -s 192.192.192.2 -d 10.1.0.0/16 -j SNAT --to 10.1.1.1 #设置SNAT，源IP为192.192.192.2，改成10.1.1.1，即本地网关地址
iptables -A FORWARD -s 192.192.192.2 -m state --state NEW -m tcp -p tcp --dport 3306 -j DROP   #禁止直接访问线上的3306，防止内网被破

# site2（公网出口180.1.1.1，本地网段192.168.1.0/24）
ip link add gre0 type gre remote 110.2.2.2 local 180.1.1.1 ttl 255
ip link set gre0 up                      #启动device gre0 
ip link set gre0 up mtu 1500             #设置 mtu 为1500
ip addr add 192.192.192.2/24 dev gre0    #为 gre0 添加ip 192.192.192.2
echo 1 > /proc/sys/net/ipv4/ip_forward   #让服务器支持转发
ip route add 10.1.1.0/24 dev gre0      #添加路由，含义是：到10.1.1.0/24的包，由gre0设备负责转发
iptables -t nat -A POSTROUTING -d 10.1.1.0/24 -j SNAT --to 192.192.192.2   #设置SNAT，本site访问10.1.1.0/24，源IP地址转化为gre0设备的IP地址
```


### 使用ipip构建虚拟专线

```bash
# A:
ip link add ipip0 type ipip remote 192.168.9.6 local 192.168.9.5
ip link set ipip0 up
ip addr add 192.168.200.1 brd 255.255.255.255 peer 192.168.200.2 dev ipip0
ip route add 192.168.200.0/24 via 192.168.200.1
ip route add 192.168.10.6/32 dev ipip0  # 对端的网络
# B：
ip link add ipip0 type ipip remote 192.168.9.5 local 192.168.9.6
ip link set ipip0 up
ip add add 192.168.200.2 brd 255.255.255.255 peer 192.168.200.1 dev ipip0
ip route add 192.168.200.0/24 via 192.168.200.2
ip route add 192.168.8.5/32 dev ipip0  # 对端的网络

#命令解释
#ip link add ipip0 type ipip remote 58.23.0.2 local 211.154.0.2
#建立ipip隧道，隧道名称为ipip0，remote 192.168.9.6远端设备的ip地址local 192.168.9.5本机的ip地址
#ip add add 192.168.200.1 brd 255.255.255.255 peer 192.168.200.2 dev ipip0 给设备ipip0增加一个ip地址，并且设置对端的ip地址为192.168.200.2
```

