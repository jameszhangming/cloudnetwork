# Dockerԭ���������緽��

Dockerԭ�����������������緽����Docker NAT��Docker Overlay��

## Docker NAT����

Docker NAT���������£�

![docker-nat](images/docker-nat.png "docker-nat")

### ͬ�ڵ�����ͨ��

����A��������B���������������£�

1. ����A������B����ͬ���磬ֱ�ӷ���
2. ����A������B����ARP����docker0������flood��ARP����
   1. ����B�յ�ARP����󣬻���ӦARP����
   2. docker0�ӿ��յ�ARP���������Ӧ
3. docker0������ת��ARP��Ӧ������A
4. ����A���յ�ARP��Ӧ����װ���㱨�Ĳ�����
5. docker0������ֱ��ת�����ĵ�����B
6. ����B���յ�����


### ��ڵ�����ͨ��

����A��������D��Docker NATģʽ��֧������֮��֮��ͨ�ţ���Ҫͨ���ѵ�ַת��Ϊ�ڵ�IP��ַ��

1. ��������A��������D:80����������Dʱӳ��ö˿ڵ��ڵ㣬����ӳ�䵽�ڵ��ϵ�Ҳ��80�˿ڣ�
2. ʵ������A��192.168.0.102:80���ͱ���
3. ����192.168.0.102������A�ڲ�ͬ���磬����··�ɣ�ƥ�䵽·��ͨ��10.10.10.10�ɴ�
4. ����A��10.10.10.10����ARP����
5. docker0�������ѱ���ת����docker0�ӿڣ���������Э��ջ��Э��ջ��ӦARP����
6. docker0������ת��ARP��Ӧ������A
7. ����A�յ�ARP��Ӧ����װ���㱨�Ĳ�������docker0������ת�����ĵ�docker0�ӿڣ���������Э��ջ
8. Host1�ں��жϱ�����Ҫת��������ͨ��eth0����ֱ�ӵ���
9. Host1�ں�IP�㷢�ͱ���ʱ���ᾭ����POSTROUTING hook�㣬���ĵ�ԴIP��ַ�ᱻת��Ϊ192.168.0.101
10. ���ķ��͵�Host2�ڵ�
11. Host2�յ����ģ�������ip�㴦�����ᾭ��PREROUTING hook�㣬Ŀ��IP�ᱻ�޸�Ϊ����D��IP��ַ��Ŀ�Ķ˿ڻᱻ�޸�Ϊ�����Ķ˿�
12. Host2�ں��жϸñ�����Ҫת�������ҵ�·�ɱ���ͨ��docker0�ӿڿ���ֱ��
13. Host2�ں˷���ARP����docker0�ӿڣ���ǰ����ARP����ɱ���˴�ARP����
14. docker0������flood ARP����
15. ����D�յ�ARP������Ӧ
16. docker0������ת��ARP��docker0�ӿڣ���������Э��ջ
17. Э��ջ���±��ĵĶ���ͷ�������͵�docker0�ӿڣ�docker0������ת�����ĸ�����D
18. ����D�յ����ģ�����Ӧ����Ӧ���ĵ�Ŀ��IPΪ192.168.0.101��
19. docker0ת�����ĵ�docker0�ӿڣ���������Э��ջ
20. Host2Э��ջ����POSTROUTING hook�㣬��ԴIP��Դ�˿��޸�Ϊ�ڵ�IP�ͽڵ�˿ڣ�TCʵ�֣�
21. Host1�յ����ģ�Host1�ں�IP�㷢�ͱ���ʱ���ᾭ����PREROUTING hook�㣬����Ŀ��IP�޸�Ϊ����A��IP��ַ���˿��޸�Ϊ����A�Ķ˿�
22. Host1��ѯ����·�ɣ��ҵ�ͨ��docker0ֱ�ӿ��Ե���
23. Host1�޸Ķ��㱨��ͷ�������ͱ��ĵ�docker0�ӿ�
24. docker0������ת�����ĵ�����A
25. ����A���յ���Ӧ����


### Docker NAT�����ܽ�

* ������etcd�ȷֲ�ʽ���
* ����iptables��ܣ�������Ӱ��Ƚϴ�


## Docker Overlay����

Docker Overlay���������£�

![docker-overlay](images/docker-overlay.png "docker-overlay")


### ͬ�ڵ�����ͨ��

����A��������B���������������£�ͬFlannel UDP����

1. ����A������B����ͬ���磬ֱ�ӷ���
2. ����A������B����ARP����br0������flood��ARP����
   1. ����B�յ�ARP����󣬻���ӦARP����
   2. �����ӿ��յ�ARP����󣬲�����ARP��Ӧ
3. br0������ת��ARP��Ӧ������A
4. ����A���յ�ARP��Ӧ����װ���㱨�Ĳ�����
5. weave������ֱ��ת�����ĵ�����B
6. ����B���յ�����


### ��ڵ�����ͨ��

����A��������D���������������£�����Flannel VXLAN�ɰ棩��

1. ����A������D����ͬͬ���磬ֱ�ӷ���
2. ����A������D����ARP����
3. br0�㲥��ARP����
4. vtep0�յ�ARP����
5. vtep0�豸��װ���vxlan��UDP��IP��MACͷ�������ַ���
   1. vtep0����arp proxy�������ں�ARP�������ӦӦ��
   2. vtep0����ARP�������еĶԶ�vtep0�������Ǵ��֣�
6. Host2 ���յ�ARP�����ģ�ͨ��UDP Socket�������뵽VXLAN���������������Ϊvxlan�豸�հ�������vxlan�豸���ص�br0������
7. br0������flood��ARP����
8. ����D���յ�ARP���󣬲���Ӧ��br0������ת��ARP��Ӧ���ĵ�vtep0�豸
9. ����vtep0�豸������learning����ʱvtep0֪���Զ�vtep0����192.168.0.101
10. vtep0��װvxlan���Ĳ�������Host1
11. Host1���յ�ARP��Ӧ���ģ�ͨ��UDP Socket�������뵽VXLAN���������������Ϊvxlan�豸�հ�������vxlan�豸���ص�br0������
12. br0������ת��ARP��Ӧ���ĸ�����A
13. ����A��װ���㱨��ͷ��������
14. br0������ת�����ĵ�vtep0�豸
15. vtep0�豸������learning����ʱvtep0֪���Զ�vtep0����192.168.0.102
16. vtep0��װvxlan���Ĳ�������Host2
17. Host2���յ����ģ�ͨ��UDP Socket�������뵽VXLAN�������������br0������
18. br0������ת�����ĸ�����D
19. ����D���յ�����

### Docker Overlay�����ܽ�
* ������etcd�ȷֲ�ʽ���
* ������ͬ�����������ҪԤ����Ϣ
* ����vxlanѧϰ�ķ�ʽ���װ���ʱ��ϴ�


## ����Ķ�


