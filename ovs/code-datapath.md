# OVS������

OVS��������ڣ�

![datapath](images/datapath.png "datapath")


OVS��������Ҫ��������ڣ�

* VLXAN�ӿ�
  * ͨ��UDP Socketע���vxlan_udp_encap_recv��������OVS
* ��������
  * ͨ�������������ص�OVS����ʱ��ע���rx_handler����netdev_frame_hook
* internal�˿�
  * ͨ��internal�˿ڵ�����������������internal_dev_xmit����
