# OVS�������������

OVS����������������������ܵĹؼ�������Ŀ���Ǹ���SKB���Ŀ���ƥ�䵽����OVS�������Ƶ������

* ������������̫��
  * ��Ҫ�ṩ�����ϻ��Ļ���
  * �����ϻ���δƥ�䵽�������upcall���û�̬���·�����
* �������Ӳ������
  * ʹ��skb->hashֵ�����п�������ƥ��
* ����ʱ���ϵ�������
  * ��һ����ƥ�䣬��������ƥ��
* ����ƥ���Ż�
  * ͨ���������ڴ�ƥ���������ֶε�ƥ��

## ��Ҫ���ݽṹ

![flow-object](images/flow-object.png "flow-object")

��Ҫ��������˵����

* mask_cache_entry
  * per_cpu���ԣ�֧��ͨ��skb->hash���ٲ���mask
* table_instance
  * �����������
* mask_array
  * ���mask����ͨ��mask��key����flow


## �����������

![flow-progress](images/flow-progress.png "flow-progress")

��������������£�

1. �ҵ�mask_index
  1. ���skb->hash��ֵ��ֱ�Ӹ��ݸ�ֵ�ҵ���Ӧ��entry�����ͨ����entryδ�鵽�������0�ſ�ʼ����mask_cache_entry���飨����ѯ��
  2. ���skb->hashδ���ã���0�ſ�ʼ����mask_cache_entry���飨����ѯ��
2. ����ǰһ����entry��mask_index��Ա�ҵ�mask�����ͨ����maskδ�ҵ�flow������������mask���飨����ѯ��
3. ����mask��key�õ�masked_key��
4. ����masked_key��mask�����hash��
5. ����hashֵ�ҵ�bucket������bucket�ҵ�flow����
6. ����flow�����ҵ�ƥ���flow��flow->mask����mask��flow->hash����hask��flow���ݺ�masked_key��ͬ��
7. ˢ��mask_cache_entry�����mask_indexֵ���´�ͬ�౨�Ŀ��Կ���ƥ�䣩

### OVS��������ܽ�

* mask����Ҫ��
  * mask��������������ҵ�����Ӱ��ǳ���Ҫ��������mask������
  * mask��������������ʹ�õ��ֶ�������أ�Ҫ���ٲ�ͬ�����ֶ�ƥ�������
* ���Ľ���OVSʱȫ����key�����е��˷�


## �ں��������

![flow-update](images/flow-update.png "flow-update")