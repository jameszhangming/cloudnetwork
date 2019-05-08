# ESP in UDP

## 系统入口

```c
int xfrm4_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	struct udphdr *uh;
	struct iphdr *iph;
	int iphlen, len;

	__u8 *udpdata;
	__be32 *udpdata32;
	__u16 encap_type = up->encap_type;	

	/* if this is not encapsulated socket, then just return now */
	if (!encap_type)	//在udp_lib_setsockopt函数中设置，该值为UDP_ENCAP_ESPINUDP或UDP_ENCAP_ESPINUDP_NON_IKE
		return 1;

	/* If this is a paged skb, make sure we pull up
	 * whatever data we need to look at. */
	len = skb->len - sizeof(struct udphdr);		//UDP报文的数据长度，当前skb指向IP头
	if (!pskb_may_pull(skb, sizeof(struct udphdr) + min(len, 8)))
		return 1;

	/* Now we can get the pointers */
	uh = udp_hdr(skb);				//UDP头， udp相关指针在ip层处理完成前设置
	udpdata = (__u8 *)uh + sizeof(struct udphdr);	//指向udp数据的8位指针
	udpdata32 = (__be32 *)udpdata;			//指向udp数据的32位指针

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			goto drop;
		} else if (len > sizeof(struct ip_esp_hdr) && udpdata32[0] != 0) {
			/* ESP Packet without Non-ESP header */
			len = sizeof(struct udphdr);
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		/* Check if this is a keepalive packet.  If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {	//keepalive packet，可以丢弃
			goto drop;
		} else if (len > 2 * sizeof(u32) + sizeof(struct ip_esp_hdr) &&
			   udpdata32[0] == 0 && udpdata32[1] == 0) {

			/* ESP Packet with Non-IKE marker */
			len = sizeof(struct udphdr) + 2 * sizeof(u32);	// |IP HEADER|UDP HEADER|64位|ESP头|内部数据
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	}

	/* At this point we are sure that this is an ESPinUDP packet,
	 * so we need to remove 'len' bytes from the packet (the UDP
	 * header and optional ESP marker bytes) and then modify the
	 * protocol to ESP, and then call into the transform receiver.
	 */
	if (skb_unclone(skb, GFP_ATOMIC))
		goto drop;

	/* Now we can update and verify the packet length... */
	iph = ip_hdr(skb);
	iphlen = iph->ihl << 2;
	iph->tot_len = htons(ntohs(iph->tot_len) - len);	//ip头的总长度重新，减掉UDP头+额外长度
	if (skb->len < iphlen + len) {
		/* packet is too small!?! */
		goto drop;
	}

	/* pull the data buffer up to the ESP header and set the
	 * transport header to point to ESP.  Keep UDP on the stack
	 * for later.
	 */
	__skb_pull(skb, len);	//skb指向ESP头（处理掉UDP头+额外长度）
	skb_reset_transport_header(skb);	//设置transport_header，实际该指针指向了ESP头

	/* process ESP */
	return xfrm4_rcv_encap(skb, IPPROTO_ESP, 0, encap_type);

drop:
	kfree_skb(skb);
	return 0;
}
```

## xfrm4_rcv_encap

```c
int xfrm4_rcv_encap(struct sk_buff *skb, int nexthdr, __be32 spi,
		    int encap_type)
{
	int ret;
	struct xfrm4_protocol *handler;
	struct xfrm4_protocol __rcu **head = proto_handlers(nexthdr);

	XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = NULL;
	XFRM_SPI_SKB_CB(skb)->family = AF_INET;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct iphdr, daddr);

	if (!head)
		goto out;
	
	
	// ESP Protocol, input_handler函数为xfrm_input
	// AH  Protocol, input_handler函数为xfrm_input
	for_each_protocol_rcu(*head, handler)
		if ((ret = handler->input_handler(skb, nexthdr, spi, encap_type)) != -EINVAL)
			return ret;

out:
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;
}
```

