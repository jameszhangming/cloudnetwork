# ovs-vsctl

ovs-vsctl��OVS��������ز��������

## ���ݿ����

�����ʽ��

```ovs-vsctl [list|set|get|add|remove|clear|destroy] <table> <record> <column> <value>```

����˵����

* table��Ϊovsdb����ı�
  * bridge,controller,interface,mirror,netflow,open_vswitch,port,qos,queue,ssl,sflow
* record�����ֻ�uid�����Ա�ʶtable��һ����¼
* column�����е��ֶ�
* value��Ϊcolumn��ֵ

> ��ͬtable��column��openvswitch/vswitchd/vswitch.xml�ж���

## ���ò���



### bridge����
```
# �г���������
ovs-vsctl list-br

# �������
ovs-vsctl add-br br0

# ɾ������
ovs-vsctl del-br br0

# �ж������Ƿ����
ovs-vsctl br-exists br0
```


### port����
```
# ����VXLAN�˿�
ovs-vsctl add-port br0 vxl1 -- set interface vxl1 type=vxlan options:remote_ip=192.168.100.99

# ����GRE�˿�
ovs-vsctl add-port br0 gre1 -- set interface gre1 type=gre option:remote_ip=192.168.100.99

# ����patch port
ovs-vsctl add-port br-test1  patch-ovs-1 -- set Interface patch-ovs-1 type=patch -- set Interface patch-ovs-1 options:peer=patch-ovs-2
ovs-vsctl add-port br-test2  patch-ovs-2 -- set Interface patch-ovs-2 type=patch -- set Interface patch-ovs-2 options:peer=patch-ovs-1

# �г����������нӿ�
ovs-vsctl list-ports br0

# ���ӿڹҽӵ�������
ovs-vsctl add-port br0 eth0

# ɾ�������ϹҽӵĽӿ�
ovs-vsctl del-port br0 eth0

# �г��ҽӽӿڵ�����
ovs-vsctl port-to-br eth0

# ����port vlan����
ovs-vsctl set port vnet0 tag=101

# ���port vlan����
ovs-vsctl clear port vnet0 tag

```


### �˿ھ���
```
# SPAN�������ѳ���vnet0�˿ڵı��ľ���vnet1��
ovs-vsctl -- set bridge br0 mirrors=@m \
  -- --id=@src get port vnet0 \
  -- --id=@dst get port vnet1 \
  -- --id=@m create mirror name=m1 select-dst-port=@src select-src-port=@src output-port=@dst 

# RSPAN�������ѳ���vnet0�˿ڵı��ľ���vlan110��
ovs-vsctl -- set bridge br0 mirrors=@m \
  -- --id=@src get port vnet0 \
  -- --id=@m create mirror name=m2 select-dst-port=@src select-src-port=@src output-vlan=110

# RSPAN�������Ѵ�vlan110���ģ���output��vlan111��
ovs-vsctl -- set bridge helloworld1 mirrors=@m \
  -- --id=@m create mirror name=m2 select-vlan=110 output-vlan=111
```


### DPDK����
```
# ���DPDK����
ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

# ����DPDK�˿�
ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:01:00.0
ovs-vsctl add-port br0 dpdk-p1 -- set Interface dpdk-p1 type=dpdk options:dpdk-devargs=0000:01:00.1

# ����������bond
ovs-vsctl add-bond br-phy dpdkbond p0 p1 �C set Interface p0 type=dpdk options:dpdk-devargs=0000:5f:00.0 �C set Interface p1 type=dpdk options:dpdk-devargs=0000:5f:00.1

# ����bondģʽ
ovs-vsctl set port dpdkbond bond_mode=balance-slb

```
