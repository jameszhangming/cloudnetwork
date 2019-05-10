# GRE IPIP

ʹ��ip link�����gre��ipip�豸��gre��ipip�豸��Ϊ�����豸��


## �豸���в���

remote ADDR 			        specifies the remote address of the tun-nel.
local ADDR 				        specifies the fixed local address for tun-neled packets.  It must be an address on another inter-face on this host.
[ encap { fou | gue | none } ] 	specifies type of secondary UDP encapsulation.
[ encap-sport { PORT | auto} ] 	specifies the source port in UDP encapsulation.
[ encap-dport PORT ] 		    specifies the dest port in UDP encapsulation.
[ [no]encap-csum ] 		        specifies if UDP checksums are enabled in the secondary encapsulation.
[ [no]encap-remc-sum ]		    specifies if Remote Checksum Offload is enabled. This is only applicable for Generic UDP Encapsulation.


## ����ʾ��

```bash
# ����gre���
ip link add gre0 type gre remote 180.1.1.1 local 110.2.2.2

# ɾ��gre���
ip link del gre0 type gre

# ����ipip�豸
ip link add ipip0 type ipip remote 192.168.9.6 local 192.168.9.5

# ɾ��ipip�豸
ip link del ipip0 type ipip
```


## Ӧ�ó���

### ʹ��gre��������ר��

```bash
# site1����������110.2.2.2����������10.1.1.0/24��
ip link add gre0 type gre remote 180.1.1.1 local 110.2.2.2  #����gre���
ip link set gre0 up
ip link set gre0 up mtu 1500
ip addr add 192.192.192.1/24 dev gre0  # Ϊgre0��� ip 192.192.192.1
echo 1 > /proc/sys/net/ipv4/ip_forward
ip route add 192.168.1.0/24 dev gre0  # ���·�ɣ��Զ�192.168.1.0/24����ͨ��gre0ֱ��
iptables -t nat -A POSTROUTING -s 192.192.192.2 -d 10.1.0.0/16 -j SNAT --to 10.1.1.1 #����SNAT��ԴIPΪ192.192.192.2���ĳ�10.1.1.1�����������ص�ַ
iptables -A FORWARD -s 192.192.192.2 -m state --state NEW -m tcp -p tcp --dport 3306 -j DROP   #��ֱֹ�ӷ������ϵ�3306����ֹ��������

# site2����������180.1.1.1����������192.168.1.0/24��
ip link add gre0 type gre remote 110.2.2.2 local 180.1.1.1 ttl 255
ip link set gre0 up                      #����device gre0 
ip link set gre0 up mtu 1500             #���� mtu Ϊ1500
ip addr add 192.192.192.2/24 dev gre0    #Ϊ gre0 ���ip 192.192.192.2
echo 1 > /proc/sys/net/ipv4/ip_forward   #�÷�����֧��ת��
ip route add 10.1.1.0/24 dev gre0      #���·�ɣ������ǣ���10.1.1.0/24�İ�����gre0�豸����ת��
iptables -t nat -A POSTROUTING -d 10.1.1.0/24 -j SNAT --to 192.192.192.2   #����SNAT����site����10.1.1.0/24��ԴIP��ַת��Ϊgre0�豸��IP��ַ
```


### ʹ��ipip��������ר��

```bash
# A:
ip link add ipip0 type ipip remote 192.168.9.6 local 192.168.9.5
ip link set ipip0 up
ip addr add 192.168.200.1 brd 255.255.255.255 peer 192.168.200.2 dev ipip0
ip route add 192.168.200.0/24 via 192.168.200.1
ip route add 192.168.10.6/32 dev ipip0  # �Զ˵�����
# B��
ip link add ipip0 type ipip remote 192.168.9.5 local 192.168.9.6
ip link set ipip0 up
ip add add 192.168.200.2 brd 255.255.255.255 peer 192.168.200.1 dev ipip0
ip route add 192.168.200.0/24 via 192.168.200.2
ip route add 192.168.8.5/32 dev ipip0  # �Զ˵�����

#�������
#ip link add ipip0 type ipip remote 58.23.0.2 local 211.154.0.2
#����ipip������������Ϊipip0��remote 192.168.9.6Զ���豸��ip��ַlocal 192.168.9.5������ip��ַ
#ip add add 192.168.200.1 brd 255.255.255.255 peer 192.168.200.2 dev ipip0 ���豸ipip0����һ��ip��ַ���������öԶ˵�ip��ַΪ192.168.200.2
```

