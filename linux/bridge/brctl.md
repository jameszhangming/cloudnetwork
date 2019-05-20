# brctl

brctl 命令用户linux bridge管理。


## brctl命令

```bash
brctl [commands]
addbr           <bridge>                add bridge（创建bridge）
delbr           <bridge>                delete bridge（删除bridge）
addif           <bridge> <device>       add interface to bridge（attach设备到bridge）
delif           <bridge> <device>       delete interface from bridge（从bridge detach设备）
setageing       <bridge> <time>         set ageing time（设置老化时间，即生存周期）
setbridgeprio   <bridge> <prio>         set bridge priority（设置bridge的优先级）
setfd           <bridge> <time>         set bridge forward delay（设置bridge转发延迟时间）
sethello        <bridge> <time>         set hello time（设置hello时间）
setmaxage       <bridge> <time>         set max message age（设置消息的最大生命周期）
setpathcost     <bridge> <port> <cost>  set path cost（设置路径的权值）
setportprio     <bridge> <port> <prio>  set port priority（设置端口的优先级）
show                                    show a list of bridges（查询bridge信息）
showmacs        <bridge>                show a list of mac addrs（显示MAC地址）
showstp         <bridge>                show bridge stp info（显示bridge的stp信息）
stp             <bridge> {on|off}       turn stp on/off（开/关stp）
```


## 示例

```bash
# 创建网桥
brctl addbr br0

# 网桥添加网卡
brctl addif br0 eth0

# 网桥删除网卡
brctl delif br0 eth0

# 删除网桥
brctl delbr br0
```