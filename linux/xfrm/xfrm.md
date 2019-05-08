# XFRM 配置

## ip xfrm state

```bash
ip xfrm state { add | update } ID [ ALGO-LIST ] [ mode MODE ] [ mark MARK [ mask MASK ] ] 
    [ reqid REQID ] [ seq SEQ ] [ replay-window SIZE ] [ replay-seq SEQ ] [ replay-oseq SEQ ] 
	[ replay-seq-hi SEQ ] [ replay-oseq-hi SEQ ] [ flag FLAG-LIST ] [ sel SELECTOR ] [ LIMIT-LIST ] 
	[ encap ENCAP ] [ coa ADDR[/PLEN] ] [ ctx CTX ] [ extra-flag EXTRA-FLAG-LIST ] [ output-mark OUTPUT-MARK ]

ip xfrm state allocspi ID [ mode MODE ] [ mark MARK [ mask MASK ] ] 
    [ reqid REQID ] [ seq SEQ ] [ min SPI max SPI ]

ip xfrm state { delete | get } ID [ mark MARK [ mask MASK ] ]

ip xfrm state { deleteall | list } [ ID ] [ mode MODE ] [ reqid REQID ] [ flag FLAG-LIST ]

ip xfrm state flush [ proto XFRM-PROTO ]

ip xfrm state count

ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
XFRM-PROTO := esp | ah | comp | route2 | hao
ALGO-LIST := [ ALGO-LIST ] ALGO
ALGO := { enc | auth } ALGO-NAME ALGO-KEYMAT |
          auth-trunc ALGO-NAME ALGO-KEYMAT ALGO-TRUNC-LEN |
          aead ALGO-NAME ALGO-KEYMAT ALGO-ICV-LEN |
          comp ALGO-NAME
MODE := transport | tunnel | beet | ro | in_trigger
FLAG-LIST := [ FLAG-LIST ] FLAG
FLAG := noecn | decap-dscp | nopmtudisc | wildrecv | icmp | af-unspec | align4 | esn
SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]
UPSPEC := proto { PROTO |
               { tcp | udp | sctp | dccp } [ sport PORT ] [ dport PORT ] |
               { icmp | ipv6-icmp | mobility-header } [ type NUMBER ] [ code
               NUMBER ] | gre [ key { DOTTED-QUAD | NUMBER } ] }
LIMIT-LIST := [ LIMIT-LIST ] limit LIMIT
LIMIT := { time-soft | time-hard | time-use-soft | time-use-hard }
            SECONDS | { byte-soft | byte-hard } SIZE | { packet-soft | packet-hard } COUNT
ENCAP := { espinudp | espinudp-nonike } SPORT DPORT OADDR
EXTRA-FLAG-LIST := [ EXTRA-FLAG-LIST ] EXTRA-FLAG
EXTRA-FLAG := dont-encap-dscp
```

## ip xfrm policy

```bash
ip xfrm policy { add | update } SELECTOR dir DIR [ ctx CTX ] 
    [ mark MARK [ mask MASK ] ] [ index INDEX ] [ ptype PTYPE ] 
	[ action ACTION ] [ priority PRIORITY ] [ flag FLAG-LIST ] 
	[ LIMIT-LIST ] [ TMPL-LIST ]

ip xfrm policy { delete | get } { SELECTOR | index INDEX } dir DIR 
    [ ctx CTX ] [ mark MARK [ mask MASK ] ] [ ptype PTYPE ]

ip xfrm policy { deleteall | list } [ nosock ] [ SELECTOR ] 
    [ dir DIR ] [ index INDEX ] [ ptype PTYPE ] [ action ACTION ] 
	[ priority PRIORITY ] [ flag FLAG-LIST]

ip xfrm policy flush [ ptype PTYPE ]

ip xfrm policy count

ip xfrm policy set [ hthresh4 LBITS RBITS ] [ hthresh6 LBITS RBITS ]

SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]
UPSPEC := proto { PROTO |
               { tcp | udp | sctp | dccp } [ sport PORT ] [ dport PORT ] |
               { icmp | ipv6-icmp | mobility-header } [ type NUMBER ] [ code
               NUMBER ] |
               gre [ key { DOTTED-QUAD | NUMBER } ] }
DIR := in | out | fwd
PTYPE := main | sub
ACTION := allow | block
FLAG-LIST := [ FLAG-LIST ] FLAG
FLAG := localok | icmp
LIMIT-LIST := [ LIMIT-LIST ] limit LIMIT
LIMIT := { time-soft | time-hard | time-use-soft | time-use-hard }
            SECONDS | { byte-soft | byte-hard } 
			SIZE | { packet-soft | packet-hard } COUNT
TMPL-LIST := [ TMPL-LIST ] tmpl TMPL
TMPL := ID [ mode MODE ] [ reqid REQID ] [ level LEVEL ]
ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
XFRM-PROTO := esp | ah | comp | route2 | hao
MODE := transport | tunnel | beet | ro | in_trigger
LEVEL := required | use
```

## ip xfrm monitor

```bash
ip xfrm monitor [ all-nsid ] [ all | LISTofXFRM-OBJECTS ]

LISTofXFRM-OBJECTS := [ LISTofXFRM-OBJECTS ] XFRM-OBJECT
XFRM-OBJECT := acquire | expire | SA | policy | aevent | report
```

## 示例

```bash
# 配置192.168.18.101
ip xfrm state add src 192.168.18.101 dst 192.168.18.102 proto esp spi 0x00000301 mode tunnel auth md5 0x96358c90783bbfa3d7b196ceabe0536b enc des3_ede 0xf6ddb555acfd9d77b03ea3843f2653255afe8eb5573965df
ip xfrm state add src 192.168.18.102 dst 192.168.18.101 proto esp spi 0x00000302 mode tunnel auth md5 0x99358c90783bbfa3d7b196ceabe0536b enc des3_ede 0xffddb555acfd9d77b03ea3843f2653255afe8eb5573965df
ip xfrm state get src 192.168.18.101 dst 192.168.18.102 proto esp spi 0x00000301

ip xfrm policy add src 192.168.18.101 dst 192.168.18.102 dir out ptype main tmpl src 192.168.18.101 dst 192.168.18.102 proto esp mode tunnel
ip xfrm policy add src 192.168.18.102 dst 192.168.18.101 dir in ptype main tmpl src 192.168.18.102 dst 192.168.18.101 proto esp mode tunnel
ip xfrm policy ls

# 配置192.168.18.102
ip xfrm state add src 192.168.18.101 dst 192.168.18.102 proto esp spi 0x00000301 mode tunnel auth md5 0x96358c90783bbfa3d7b196ceabe0536b enc des3_ede 0xf6ddb555acfd9d77b03ea3843f2653255afe8eb5573965df
ip xfrm state add src 192.168.18.102 dst 192.168.18.101 proto esp spi 0x00000302 mode tunnel auth md5 0x99358c90783bbfa3d7b196ceabe0536b enc des3_ede 0xffddb555acfd9d77b03ea3843f2653255afe8eb5573965df
ip xfrm state get src 192.168.18.101 dst 192.168.18.102 proto esp spi 0x00000301

ip xfrm policy add src 192.168.18.101 dst 192.168.18.102 dir in ptype main tmpl src 192.168.18.101 dst 192.168.18.102 proto esp mode tunnel
ip xfrm policy add src 192.168.18.102 dst 192.168.18.101 dir out ptype main tmpl src 192.168.18.102 dst 192.168.18.101 proto esp mode tunnel
ip xfrm policy ls

# 在192.168.18.101上执行
ping 192.168.18.102

# 在192.168.18.102上抓包
tcpdump -p esp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
11:12:00.771364 IP 192.168.18.101 > 192.168.18.102: ESP(spi=0x00000301,seq=0x41d), length 116
11:12:00.771498 IP 192.168.18.102 > 192.168.18.101: ESP(spi=0x00000302,seq=0x183), length 116
11:12:01.773378 IP 192.168.18.101 > 192.168.18.102: ESP(spi=0x00000301,seq=0x41e), length 116
11:12:01.773787 IP 192.168.18.102 > 192.168.18.101: ESP(spi=0x00000302,seq=0x184), length 116
11:12:02.774682 IP 192.168.18.101 > 192.168.18.102: ESP(spi=0x00000301,seq=0x41f), length 116
11:12:02.774793 IP 192.168.18.102 > 192.168.18.101: ESP(spi=0x00000302,seq=0x185), length 116
```



