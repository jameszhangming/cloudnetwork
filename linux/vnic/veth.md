# Veth

使用ip link命令创建veth设备。

## 设备参数

peer name <veth_con>     指定veth对端的设备名


## 操作示例

```bash
# 创建veth设备
ip link add dev veth_host type veth peer name veth_con

# 删除veth设备
ip link del veth_host type veth
```


## 应用场景

### 容器方案

```bash
# 创建veth设备，把一端移入到ns
ip link add dev veth_host type veth peer name veth_con
ip netns add ns1
ip link set veth_con netns ns1
ip link set veth_host up

# 把veth设备的另一端挂载到网桥上
brctl addbr br0
brctl addif br0 veth_host
```

