# Netfilter������

Netfilter��Linux����ǽ���ں�ʵ��

## Netfilter Hook�㶨��

Netfilter ��������5��Hook�㣺

```
enum nf_inet_hooks {
	NF_INET_PRE_ROUTING,
	NF_INET_LOCAL_IN,
	NF_INET_FORWARD,
	NF_INET_LOCAL_OUT,
	NF_INET_POST_ROUTING,
	NF_INET_NUMHOOKS
};
```

### Hook���ں����

![netfilter-flow](images/netfilter-flow.png "netfilter-flow")


## Netfilter CT��ص�Hook��

CT��ص�Hook�㣬��NF_INET_PRE_ROUTING��NF_INET_LOCAL_IN��NF_INET_LOCAL_OUT��NF_INET_POST_ROUTING���ĸ��㡣

�����г��ĸ���hook�㣬����hook���������ȼ���������ԽС�������ȼ�Խ�ߣ�

```bash
NF_INET_PRE_ROUTING
ipv4_conntrack_defrag��NF_IP_PRI_CONNTRACK_DEFRAG��-400��
NF_IP_PRI_RAW��-300   //�û�����ӹ���
ipv4_conntrack_in��NF_IP_PRI_CONNTRACK��-200��
NF_IP_PRI_MANGLE��-150  //�û�����ӹ���
iptable_nat_ipv4_in��NF_IP_PRI_NAT_DST��-100��
NF_IP_PRI_NAT_DST��-100  //�û�����ӹ���
NF_IP_PRI_FILTER��0  //�û�����ӹ���

NF_INET_LOCAL_IN
NF_IP_PRI_RAW��-300  //�û�����ӹ���
NF_IP_PRI_MANGLE��-150  //�û�����ӹ���
NF_IP_PRI_FILTER��0  //�û�����ӹ���
NF_IP_PRI_NAT_SRC��100  //�û�����ӹ���
iptable_nat_ipv4_fn��NF_IP_PRI_NAT_SRC��100��
ipv4_helper��NF_IP_PRI_CONNTRACK_HELPER��300��
ipv4_confirm��NF_IP_PRI_CONNTRACK_CONFIRM��MAX��

NF_INET_LOCAL_OUT
ipv4_conntrack_defrag��NF_IP_PRI_CONNTRACK_DEFRAG��-400��
NF_IP_PRI_RAW��-300
ipv4_conntrack_local��NF_IP_PRI_CONNTRACK��-200��
NF_IP_PRI_MANGLE��-150
iptable_nat_ipv4_local_fn��NF_IP_PRI_NAT_DST��-100��
NF_IP_PRI_NAT_DST��-100
NF_IP_PRI_FILTER��0

NF_INET_POST_ROUTING
NF_IP_PRI_RAW��-300
NF_IP_PRI_MANGLE��-150
NF_IP_PRI_FILTER��0
NF_IP_PRI_NAT_SRC��100
iptable_nat_ipv4_out��NF_IP_PRI_NAT_SRC��100��
ipv4_helper��NF_IP_PRI_CONNTRACK_HELPER:300��
ipv4_confirm��NF_IP_PRI_CONNTRACK_CONFIRM��MAX��

```