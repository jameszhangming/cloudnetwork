# Flannel�������緽��

Flannel���������������緽����Flannel UDP��Flannel VXLAN�ɺ�Flannel VXLAN�¡�

## Flannel UDP����

Flannel UDP���������£�

![flannel-udp](images/flannel-udp.png "flannel-udp")

### ͬ�ڵ�����ͨ��

����A��������B���������������£�

1. ����A������B����ͬ���磬ֱ�ӷ���
2. ����A������B����ARP����br0������flood��ARP����
3. ����B���յ�ARP���󣬲���Ӧ
4. br0������flood��ARP��Ӧ
4. ����A���յ�ARP��Ӧ����װ���㱨�Ĳ�����
5. br0������ֱ��ת�����ĵ�����B
6. ����B���յ�����


### ��ڵ�����ͨ��

����A��������D���������������£�

1. ����A������D�ڲ�ͬ���磬ͨ������ת��
2. ����A����ARP��������أ�10.10.1.1��
3. �ڵ�1�ں���ӦARP���󣬲����͵�br0��
4. br0������ת��ARP��Ӧ������A
5. ����A�յ�ARP���󣬷�װ���㱨�ģ�Ŀ��MACΪ���ص�MAC��������������
6. ����ͨ��veth�豸����br0����ͨ��br0�ӿ��������ڵ��ں�
7. Host1�ں˸��ݱ���Ŀ��IP��ַ���ж���Ҫ·��ת��������·�ɱ�ƥ�䣬ͨ��tunX�豸ֱ���ʹ�
8. Host1�ں˷���ARP���������D�������͵�tunX�豸��
9. flanneld������tunX�豸��socket��flanned�յ�ARP������
10. flanneld��ӦARP���󣬲�ͨ��tunX socket����ARP��Ӧ������Ӧ���ĻᱻtunX�豸���ղ�����Э��ջ
11. Host1�ں��յ�ARP��Ӧ���޸ı��Ķ���ͷ�������͸�tunXX�豸
12. flanneld�յ��ñ��ģ�������������Ϣ���Ѹñ��ķ�װ��UDP�У�flanneld����UDP���ĸ�Host2
13. Host2���յ�UDP���ģ�����Э��ջ���͸�flanneld����
14. flanneld�����㱨�ģ������ڲ㱨��ͨ��tunXX�豸���͸��ں�
15. Host2�ں˸��ݱ��ĵ�Ŀ��IP��ַ������·�ɣ�����ͨ��br0����ֱ��
16. Host2�ں˷���ARP���������D�������͸�br0�ӿ�
17. br0������ת��ARP���������D������D��ӦARP����ARP��Ӧͨ��br0�ӿ����͵�Э��ջ
18. Host2�ں˸��±��ĵĶ���ͷ�������ͱ��ĵ�br0�ӿ�
19. br0������ת�����ĸ�����D
20. ����D���յ�����

flanneld���յ�ARP����������Ӧ��������������

* �ԶԶ�tunXX�豸��MAC��ַ��Ӧ
* �̶�tunXX�豸��MAC��ַ�������Ըõ�ַ����Ӧ


### Flannel UDP�����ܽ�

* �������ܲ�
  * ʹ��socket���Ʊ���ת�������У�����ں�̬�л����û�̬��
  * �����ݽ���������װ���ں˶�UDP��װû���Ż���
* ����֧�����ݼ���
  * flanneld�������ܶඨ�ƻ��Ĺ�����������չ


## Flannel VXLAN�ɰ淽��

Flannel VXLAN�ɰ����������£�

![flannel-vxlan-old](images/flannel-vxlan-old.png "flannel-vxlan-old")


### ͬ�ڵ�����ͨ��

����A��������B���������������£�ͬFlannel UDP����

1. ����A������B����ͬ���磬ֱ�ӷ���
2. ����A������B����ARP����br0������flood��ARP����
3. ����B���յ�ARP���󣬲���Ӧ
4. br0������flood��ARP��Ӧ
4. ����A���յ�ARP��Ӧ����װ���㱨�Ĳ�����
5. br0������ֱ��ת�����ĵ�����B
6. ����B���յ�����


### ��ڵ�����ͨ��

����A��������D���������������£�

1. ����A������D��ͬһ������
2. ����Aֱ�ӷ���ARP����
3. br0������flood ARP����
4. vxlan�豸���յ�ARP����
5. ����vxlan�豸������arp proxy�������ں�ARP������δ�ҵ������ϱ�L3MISS
6. flanneld���յ�L3MISS������������Ϣ���ں������ARP����
7. ����A����δ�յ�ARP��Ӧ�������ٴη���ARP���󣬴�ʱvxlan�豸�ܹ���Ӧ��ARP�����ں�����Ӹ�ARP���
8. ����A�յ�ARP��Ӧ����װ���㱨�ģ�������
9. br0ת���ñ��ĵ�vxlan�˿�
10. vxlan��װ���vxlanͷ��udpͷ��IPͷ��macͷ������Ŀ��IP��Ҫ�����ڲ㱨��Ŀ��MAC����ȡ
11. vxlan�豸���ں�FDBת�������Ŀ��MAC��ת���δ�ҵ������ϱ�L2MISS
12. flanneld���յ�L2MISS��Ϣ������������Ϣ�����ں������FDB����
13. �˱���δ�ɹ����ͣ�����A�ط�����
14. vxlan�豸��ʱ�ܹ���ȷ�ط�װ��㱨�ģ������ͱ���
15. Host2���յ����ģ�ͨ��UDP Socket�������뵽VXLAN�������������Ϊvxlan�豸�հ�����vxlan�豸���ص�br0������
16. br0������ת�����ĸ�����D


����L3MISS��L2MISS�����ϵĽ��ܸպ��뷨��������VXLAN�豸����ARP����Ĵ���Ƭ�Σ�

```    
	n = neigh_lookup(&arp_tbl, &tip, dev);	//���ұ���ARP����

	if (n) {
		struct vxlan_fdb *f;
		struct sk_buff	*reply;

		......

		if (netif_rx_ni(reply) == NET_RX_DROP)	
			dev->stats.rx_dropped++;
	} else if (vxlan->flags & VXLAN_F_L3MISS) {
		union vxlan_addr ipa = {
			.sin.sin_addr.s_addr = tip,
			.sin.sin_family = AF_INET,
		};

		vxlan_ip_miss(dev, &ipa);
	}
```    

���´�����VXLAN�豸��װ���IPͷʱ����ȡĿ��IP�Ĵ���Ƭ�Σ�

```    
	f = vxlan_find_mac(vxlan, eth->h_dest);  //��Ŀ��mac����FDB��
	did_rsc = false;

	if (f && (f->flags & NTF_ROUTER) && (vxlan->flags & VXLAN_F_RSC) &&
	    (ntohs(eth->h_proto) == ETH_P_IP ||
	     ntohs(eth->h_proto) == ETH_P_IPV6)) {
		did_rsc = route_shortcircuit(dev, skb);
		if (did_rsc)
			f = vxlan_find_mac(vxlan, eth->h_dest);
	}

	if (f == NULL) {
		f = vxlan_find_mac(vxlan, all_zeros_mac);  //��ȫ��mac����FDB��
		if (f == NULL) {
			if ((vxlan->flags & VXLAN_F_L2MISS) &&
			    !is_multicast_ether_addr(eth->h_dest))
				vxlan_fdb_miss(vxlan, eth->h_dest);	    //�ϱ�L2MISS

			dev->stats.tx_dropped++;
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}
```    

### Flannel VXLAN�ɰ淽���ܽ�

* ����L2MISS��L3MISS���ƣ��װ����ᱻ����������Ӱ���װ�����ʱ
* L2MISS��L3MISS����network link���ƣ����ܵ�
* ����Ϊ��������磬��֧�ֶ������
* �Խڵ��������������Ѿ�����װ���ڵ����磩
* ����Ҫһ��vtep�豸��ͨ��FDB��ȷ��Ŀ��vtep�豸
* ÿ��������һ��ARP��¼�����ģʱ�ڵ��ϵ�ARP�������
* FDB��¼�����������������ȣ����ģʱ�ڵ��ϵ�FDB�������


## Flannel VXLAN�°淽��

Flannel VXLAN�°����������£�

![flannel-vxlan-new](images/flannel-vxlan-new.png "flannel-vxlan-new")

### ͬ�ڵ�����ͨ��

����A��������B���������������£�ͬFlannel UDP����

1. ����A������B����ͬ���磬ֱ�ӷ���
2. ����A������B����ARP����br0������flood��ARP����
3. ����B���յ�ARP���󣬲���Ӧ
4. br0������flood��ARP��Ӧ
4. ����A���յ�ARP��Ӧ����װ���㱨�Ĳ�����
5. br0������ֱ��ת�����ĵ�����B
6. ����B���յ�����


### ��ڵ�����ͨ��

����A��������D���������������£�

1. ����A������D�ڲ�ͬ���磬ͨ������ת��
2. ����A����ARP��������أ�10.10.1.1��
3. �ڵ�1�ں���ӦARP���󣬲����͵�br0�ӿ�
4. br0������ת��ARP��Ӧ������A
5. ����A�յ�ARP���󣬷�װ���㱨�ģ�Ŀ��MACΪ���ص�MAC��������������
6. br0������ת�����ĸ�br0�ӿڣ������뵽Э��ջ
7. Host1�ں˲���·�ɱ���Ҫ10.10.2.0ת����������ͨ��vtep0�豸
8. Host1�ں˲���ARP���������10.10.2.0��MAC���ֱ�ӷ�װ���㱨�ģ������͵�vtep0�豸
9. vtep0�豸����FDB������10.10.2.0MAC�ı���
10. vtep0��װ���vxlanͷ��udpͷ��ipͷ��macͷ�����ڽڵ���ͬһ�����磬mac����ͨ��ARP�����ȡ��
11. vtep0���ͱ���
12. Host2���յ����ģ�ͨ��UDP Socket�������뵽VXLAN�������������vtep0�հ������뵽Э��ջ
13. Host2�ں˲���·�ɱ�����ͨ��br0����ֱ�ӵ���
14. Host2�ں˷���ARP���������D�������͸�br0�ӿ�
15. br0������ת��ARP���������D������D��ӦARP����ARP��Ӧͨ��br0�ӿ����͵�Э��ջ
16. Host2�յ�ARP��Ӧ���޸ı��ĵĶ���ͷ�������͵�br0�ӿ�
17. br0������ת�����ĸ�����D
18. ����D���յ�����

> ����Ŀ��vtep�豸��MAC��ַ��FDB�����Ҫflanneld��Ԥ��

### Flannel VXLAN�°淽���ܽ�

* ÿ���ڵ����һ������CIDR
* ��֧�ִ�������ʱָ��IP��ַ
* �ڵ��·�ɱ��������٣��ͽڵ���������
* �Խڵ��������������Ѿ�����װ���ڵ����磩
* ÿ���ڵ����Ҫһ��vtep�豸��ͨ��FDB��ȷ��Ŀ��vtep�豸

