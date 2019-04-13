# ovs-vsctl

ovs-vsctl是OVS交换机相关操作的命令。

## 数据库操作

命令格式：

```ovs-vsctl [list|set|get|add|remove|clear|destroy] <table> <record> <column> <value>```

参数说明：

* table：为ovsdb定义的表
  * bridge,controller,interface,mirror,netflow,open_vswitch,port,qos,queue,ssl,sflow
* record：名字或uid，可以标识table的一条记录
* column：表中的字段
* value：为column的值

> 不同table的column在openvswitch/vswitchd/vswitch.xml中定义

## 常用操作



### bridge操作
```
# 列出所有网桥
ovs-vsctl list-br

# 添加网桥
ovs-vsctl add-br br0

# 删除网桥
ovs-vsctl del-br br0

# 判断网桥是否存在
ovs-vsctl br-exists br0
```


### port操作
```
# 创建VXLAN端口
ovs-vsctl add-port br0 vxl1 -- set interface vxl1 type=vxlan options:remote_ip=192.168.100.99

# 创建GRE端口
ovs-vsctl add-port br0 gre1 -- set interface gre1 type=gre option:remote_ip=192.168.100.99

# 创建patch port
ovs-vsctl add-port br-test1  patch-ovs-1 -- set Interface patch-ovs-1 type=patch -- set Interface patch-ovs-1 options:peer=patch-ovs-2
ovs-vsctl add-port br-test2  patch-ovs-2 -- set Interface patch-ovs-2 type=patch -- set Interface patch-ovs-2 options:peer=patch-ovs-1

# 列出网桥上所有接口
ovs-vsctl list-ports br0

# 将接口挂接到网桥上
ovs-vsctl add-port br0 eth0

# 删除网桥上挂接的接口
ovs-vsctl del-port br0 eth0

# 列出挂接接口的网桥
ovs-vsctl port-to-br eth0

# 设置port vlan属性
ovs-vsctl set port vnet0 tag=101

# 清除port vlan属性
ovs-vsctl clear port vnet0 tag

```


### 端口镜像
```
# SPAN操作（把出入vnet0端口的报文镜像到vnet1）
ovs-vsctl -- set bridge br0 mirrors=@m \
  -- --id=@src get port vnet0 \
  -- --id=@dst get port vnet1 \
  -- --id=@m create mirror name=m1 select-dst-port=@src select-src-port=@src output-port=@dst 

# RSPAN操作（把出入vnet0端口的报文镜像到vlan110）
ovs-vsctl -- set bridge br0 mirrors=@m \
  -- --id=@src get port vnet0 \
  -- --id=@m create mirror name=m2 select-dst-port=@src select-src-port=@src output-vlan=110

# RSPAN操作（把从vlan110来的，都output到vlan111）
ovs-vsctl -- set bridge helloworld1 mirrors=@m \
  -- --id=@m create mirror name=m2 select-vlan=110 output-vlan=111
```


### DPDK操作
```
# 添加DPDK网桥
ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

# 创建DPDK端口
ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:01:00.0
ovs-vsctl add-port br0 dpdk-p1 -- set Interface dpdk-p1 type=dpdk options:dpdk-devargs=0000:01:00.1

# 物理网卡组bond
ovs-vsctl add-bond br-phy dpdkbond p0 p1 – set Interface p0 type=dpdk options:dpdk-devargs=0000:5f:00.0 – set Interface p1 type=dpdk options:dpdk-devargs=0000:5f:00.1

# 设置bond模式
ovs-vsctl set port dpdkbond bond_mode=balance-slb

```
