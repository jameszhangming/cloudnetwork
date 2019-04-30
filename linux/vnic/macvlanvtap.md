# MACVLAN & MACVTAP

ʹ��ip link�����MACVLAN��MACVTAP�豸��


## �豸���в���

mode { private | vepa | bridge | passthru  [ nopromisc ] }   �豸ת��ģʽ


### ģʽ����

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

### ģʽ����

|  mode | ���� |
|:-----|:-----|
|private|������ģʽ�£�macvlan�豸���ܽ��ܼ�����ͬһ����������������macvlan�豸�����ݰ�����ʹ������macvlan�豸ͨ�������������ͳ�ȥ��ͨ��hairpin�豸���صİ�|
|vepa|������ģʽ�£�macvlan�豸����ֱ�ӽ��ܼ�����ͬһ����������������macvlan�豸�����ݰ�����������macvlan�豸���Խ����ݰ�ͨ�������������ͳ�ȥ��Ȼ��ͨ��hairpin�豸���صĸ�����macvlan�豸|
|passthru|������ģʽ�£�ÿһ�������豸ֻ�ܼ���һ��macvlan�豸|
|bridge|������ģʽ�£�������ͬһ�������豸��macvlan�豸����ֱ��ͨѶ������Ҫ��ӵ�hairpin�豸����|
|source|������ģʽ�£������������豸������macvlan�豸��ֻ�ܽ���ָ����Դ mac source�����ݰ����������ݰ��������ܡ�|


## ����ʾ��

```bash
# ����macvlan�豸
ip link add link <DEVICE> name <NAME> type macvlan [mode <MODE>]

# ����macvtap�豸
ip link add link <DEVICE> name <NAME> type macvtap [mode <MODE>]

# ɾ��macvlan�豸
ip link del macvlan1 type macvlan
```


## Ӧ�ó���

### �������緽��

ͨ��macvlan�豸����ת������һ���������������������ܺã����������ײ�֧�ֶ���㲥��

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

### ���ļ��

ʹ��source modeģʽ��������Ŀ��mac��ַ���͵ı��ġ�

```c

```

