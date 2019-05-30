# OpenFlow Message

OpenFlow定义了三种消息类型：controller-to-switch消息、asynchronous消息和symmetric消息，通过这些消息实现controller对switch的管理和控制。


## Controller-to-Switch 

Controller-to-Switch是Controller发起的消息，根据消息类型不同，switch可返回response或没有response，消息类型包括：

* Features
  * Controller请求swtich支持的特性列表。
* Configuration
  * Controller设置或查询switch的参数设置。
* Modify-State
  * Controller修改switch状态，例如修改流表、修改group、设置端口属性等等。
* Read-State
  * Controller读取swtich状态，例如流表信息、group表信息，统计信息，端口属性等等。
* Packet-out
  * 使交换机的指定端口发送数据包，可以用来转发来自“packet-in”消息的数据包。
* Barrier
  * Controller用来保证“消息依赖”（message dependencies）已经满足，或者是用来通知控制器某个操作已经完成。
* Role-Request
  * Controller用来设置switch的角色，主要用switch连接多个controller。
* Asynchronous-Configuration
  * Controller用来设置额外的“异步消息过滤器”的，通过此设定，OpenFlow通道可以接收它想要的异步消息。


## Asynchronous

异步消息由交换机向控制器发送，用来指示数据包的到来，出错或者交换机状态改变。

* Packet-in
  * 通知控制器有消息要到来，如交换机的table miss消息要发送给控制器或者TTL检查等事件都会事先发送Packet-in消息。注意，如果交换机有足够缓存，整个packet-in事件中不需要发送整个数据包而只需发送一些头部片段和buffer ID，控制器在发送packet-out消息对其进行控制（含有一个action list），如果没有足够缓存或者不支持内部缓存，就需要将整个消息发送给控制器。
* Flow-Removed
  * 通知控制器有流表项从流表中删除。只有设置了 OFPFF_SEND_FLOW_REM 标记（flag）的“流表项”在删除时才会发送 Flow-Removed 消息。生成这种消息，一来，作为控制器“删除流表项”请求完成情况的响应信息；二来，用作流表项超时，交换机将其删除，向控制器发送的通知。
* Port-status
  * 通知控制器交换机的端口状态有变化。交换机在端口配置或端口状态发生改变时，应该向控制器发送 Port-status 消息。产生这个消息的事件有：“端口配置改变”，例如，端口被用户关闭、链路断开。
* Error
  * 交换机通过 error 消息通知控制器出现问题（或故障）。
  
  
## Symmertric

对称消息 交换机和控制器任意一方发送。

* Hello
  * 当建立连接时，在控制器和交换机之间交换 Hello 消息。
* Echo
  * Echo request 消息可以从交换机发出，也可以从控制器发出，收到此消息后必须以 Echo reply 消息回复。此消息用以验证 controller-switch 连接存在，也可用来测量此连接的延时及带宽。
* Experimenter
  * experimenter 消息为交换机提供一个标准的方式，用以在 OpenFlow 现有消息类型范围外，添加额外的功能。这也是为将来的 OpenFlow 修订设计的筹划区域。


## 消息处理

* Message Delivery
  * 消息传输通道是高可靠的，不存在个别消息丢失。
* Message Processing
  * switch必须处理所有controller发送的消息，当有消息处理失败时，必须发送error消息给controller。 switch必须发送异步消息当switch状态变化的时候。
* Message Ordering
  * 一般交换机会任意重排消息已达到性能最优，可以通过controller-to-switch中的barrier消息来指定相应的顺序。当发送barrier消息时，之前发送的所有消息必须处理完才会处理接下来的消息。


## 多控制器

通过支持多控制器，实现控制器的高可用。

控制器有多种状态：

* OFPCR_ROLE_EQUAL
  * 默认权限，控制器有所有权限，和其他的所有控制器相同。
* OFPCR_ROLE_SLAVE
  * 控制器拥有只读权限，默认情况下该控制器不会收到异步消息。
* OFPCR_ROLE_MASTER
  * 和OFPCR_ROLE_EQUAL的权限相同，需要保证只有一个控制器为master。当一个controller变成master时，switch会发送消息给其他controller，其他controller状态变为slave。
  

# 消息数据结构

```c
/* Header on all OpenFlow packets. */
struct ofp_header {
  uint8_t version; /* OFP_VERSION. */
  uint8_t type;    /* One of the OFPT_ constants. */
  uint16_t length; /* Length including this ofp_header. */
  uint32_t xid;    /* Transaction id associated with this packet. Replies use the same id as was in the request to facilitate pairing. */
};
OFP_ASSERT(sizeof(struct ofp_header) == 8);

enum ofp_type {
  /* Immutable messages. */
  OFPT_HELLO = 0,        /* Symmetric message */
  OFPT_ERROR = 1,        /* Symmetric message */
  OFPT_ECHO_REQUEST = 2, /* Symmetric message */
  OFPT_ECHO_REPLY = 3,   /* Symmetric message */
  OFPT_EXPERIMENTER = 4, /* Symmetric message */

  /* Switch configuration messages. */
  OFPT_FEATURES_REQUEST = 5,   /* Controller/switch message */
  OFPT_FEATURES_REPLY = 6,     /* Controller/switch message */
  OFPT_GET_CONFIG_REQUEST = 7, /* Controller/switch message */
  OFPT_GET_CONFIG_REPLY = 8,   /* Controller/switch message */
  OFPT_SET_CONFIG = 9,         /* Controller/switch message */

  /* Asynchronous messages. */
  OFPT_PACKET_IN = 10,    /* Async message */
  OFPT_FLOW_REMOVED = 11, /* Async message */
  OFPT_PORT_STATUS = 12,  /* Async message */

  /* Controller command messages. */
  OFPT_PACKET_OUT = 13, /* Controller/switch message */
  OFPT_FLOW_MOD = 14,   /* Controller/switch message */
  OFPT_GROUP_MOD = 15,  /* Controller/switch message */
  OFPT_PORT_MOD = 16,   /* Controller/switch message */
  OFPT_TABLE_MOD = 17,  /* Controller/switch message */

  /* Multipart messages. */
  OFPT_MULTIPART_REQUEST = 18, /* Controller/switch message */
  OFPT_MULTIPART_REPLY = 19,   /* Controller/switch message */

  /* Barrier messages. */
  OFPT_BARRIER_REQUEST = 20, /* Controller/switch message */
  OFPT_BARRIER_REPLY = 21,   /* Controller/switch message */

  /* Queue Configuration messages. */
  OFPT_QUEUE_GET_CONFIG_REQUEST = 22, /* Controller/switch message */
  OFPT_QUEUE_GET_CONFIG_REPLY = 23,   /* Controller/switch message */

  /* Controller role change request messages. */
  OFPT_ROLE_REQUEST = 24, /* Controller/switch message */
  OFPT_ROLE_REPLY = 25,   /* Controller/switch message */

  /* Asynchronous message configuration. */
  OFPT_GET_ASYNC_REQUEST = 26, /* Controller/switch message */
  OFPT_GET_ASYNC_REPLY = 27,   /* Controller/switch message */
  OFPT_SET_ASYNC = 28,         /* Controller/switch message */

  /* Meters and rate limiters configuration messages. */
  OFPT_METER_MOD = 29, /* Controller/switch message */
};
```


# Controller-to-Switch Messages


## Handshake

```c
/* Switch features. */
struct ofp_switch_features {
  struct ofp_header header;
  uint64_t datapath_id;  /* Datapath unique ID. The lower 48-bits are for a MAC address, while the upper 16-bits are implementer-defined. */
  uint32_t n_buffers;    /* Max packets buffered at once. */
  uint8_t n_tables;      /* Number of tables supported by datapath. */
  uint8_t auxiliary_id;  /* Identify auxiliary connections */
  uint8_t pad[2];        /* Align to 64-bits. */
  /* Features. */
  uint32_t capabilities; /* Bitmap of support "ofp_capabilities". */
  uint32_t reserved;
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);

enum ofp_capabilities {
  OFPC_FLOW_STATS = 1 << 0,  /* Flow statistics. */
  OFPC_TABLE_STATS = 1 << 1, /* Table statistics. */
  OFPC_PORT_STATS = 1 << 2,  /* Port statistics. */
  OFPC_GROUP_STATS = 1 << 3, /* Group statistics. */
  OFPC_IP_REASM = 1 << 5,    /* Can reassemble IP fragments. */
  OFPC_QUEUE_STATS = 1 << 6, /* Queue statistics. */
  OFPC_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
};
```


## Switch Configuration

```c
struct ofp_switch_config {
  struct ofp_header header;
  uint16_t flags;         /* OFPC_* flags. */
  uint16_t miss_send_len; /* Max bytes of packet that datapath should send to the controller. See ofp_controller_max_len for valid values.*/
};
OFP_ASSERT(sizeof(struct ofp_switch_config) == 12);

enum ofp_config_flags {
  /* Handling of IP fragments. */
  OFPC_FRAG_NORMAL = 0,     /* No special handling for fragments. */
  OFPC_FRAG_DROP = 1 << 0,  /* Drop fragments. */
  OFPC_FRAG_REASM = 1 << 1, /* Reassemble (only if OFPC_IP_REASM set). */
  OFPC_FRAG_MASK = 3,
};
```


## Flow Table Configuration

```c
enum ofp_table {
  /* Last usable table number. */
  OFPTT_MAX = 0xfe,
  /* Fake tables. */
  OFPTT_ALL = 0xff /* Wildcard table used for table config, flow stats and flow deletes. */
};

/* Configure/Modify behavior of a flow table */
struct ofp_table_mod {
  struct ofp_header header;
  uint8_t table_id;  /* ID of the table, OFPTT_ALL indicates all tables */
  uint8_t pad[3];    /* Pad to 32 bits */
  uint32_t config;   /* Bitmap of OFPTC_* flags */
};
OFP_ASSERT(sizeof(struct ofp_table_mod) == 16);

/* Flags to configure the table. Reserved for future use. */
enum ofp_table_config {
  OFPTC_DEPRECATED_MASK = 3, /* Deprecated bits */
};
```


## Modify State Messages

### Modify Flow Entry Message

```c
/* Flow setup and teardown (controller -> datapath). */
struct ofp_flow_mod {
  struct ofp_header header;
  uint64_t cookie;       /* Opaque controller-issued identifier. */
  uint64_t cookie_mask;  /* Mask used to restrict the cookie bits that must match when the command is OFPFC_MODIFY* or OFPFC_DELETE*. A value of 0 indicates no restriction. */
  /* Flow actions. */
  uint8_t table_id;      /* ID of the table to put the flow in. For OFPFC_DELETE_* commands, OFPTT_ALL can also be used to delete matching flows from all tables. */
  uint8_t command;       /* One of OFPFC_*. */
  uint16_t idle_timeout; /* Idle time before discarding (seconds). */
  uint16_t hard_timeout; /* Max time before discarding (seconds). */
  uint16_t priority;     /* Priority level of flow entry. */
  uint32_t buffer_id;    /* Buffered packet to apply to, or OFP_NO_BUFFER. Not meaningful for OFPFC_DELETE*. */
  uint32_t out_port;     /* For OFPFC_DELETE* commands, require matching entries to include this as an output port. A value of OFPP_ANY indicates no restriction. */
  uint32_t out_group;    /* For OFPFC_DELETE* commands, require matching entries to include this as an output group. A value of OFPG_ANY indicates no restriction. */
  uint16_t flags;        /* One of OFPFF_*. */
  uint8_t pad[2];
  struct ofp_match match; /* Fields to match. Variable size. */
  //struct ofp_instruction instructions[0]; /* Instruction set */
};
OFP_ASSERT(sizeof(struct ofp_flow_mod) == 56);

enum ofp_flow_mod_command {
  OFPFC_ADD = 0,           /* New flow. */
  OFPFC_MODIFY = 1,        /* Modify all matching flows. */
  OFPFC_MODIFY_STRICT = 2, /* Modify entry strictly matching wildcards and priority. */
  OFPFC_DELETE = 3,        /* Delete all matching flows. */
  OFPFC_DELETE_STRICT = 4, /* Delete entry strictly matching wildcards and priority. */
};

enum ofp_flow_mod_flags {
  OFPFF_SEND_FLOW_REM = 1 << 0, /* Send flow removed message when flow expires or is deleted. */
  OFPFF_CHECK_OVERLAP = 1 << 1, /* Check for overlapping entries first. */
  OFPFF_RESET_COUNTS = 1 << 2,  /* Reset flow packet and byte counts. */
  OFPFF_NO_PKT_COUNTS = 1 << 3, /* Don't keep track of packet count. */
  OFPFF_NO_BYT_COUNTS = 1 << 4, /* Don't keep track of byte count. */
};
```


### Modify Group Entry Message

```c
/* Group setup and teardown (controller -> datapath). */
struct ofp_group_mod {
  struct ofp_header header;
  uint16_t command; /* One of OFPGC_*. */
  uint8_t type; /* One of OFPGT_*. */
  uint8_t pad; /* Pad to 64 bits. */
  uint32_t group_id; /* Group identifier. */
  struct ofp_bucket buckets[0]; /* The length of the bucket array is inferred from the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_group_mod) == 16);

/* Group commands */
enum ofp_group_mod_command {
  OFPGC_ADD = 0,    /* New group. */
  OFPGC_MODIFY = 1, /* Modify all matching groups. */
  OFPGC_DELETE = 2, /* Delete all matching groups. */
};

/* Group types. Values in the range [128, 255] are reserved for experimental use. */
enum ofp_group_type {
  OFPGT_ALL = 0,      /* All (multicast/broadcast) group. */
  OFPGT_SELECT = 1,   /* Select group. */
  OFPGT_INDIRECT = 2, /* Indirect group. */
  OFPGT_FF = 3,       /* Fast failover group. */
};

/* Group numbering. Groups can use any number up to OFPG_MAX. */
enum ofp_group {
  /* Last usable group number. */
  OFPG_MAX = 0xffffff00,
  /* Fake groups. */
  OFPG_ALL = 0xfffffffc, /* Represents all groups for group delete commands. */
  OFPG_ANY = 0xffffffff  /* Wildcard group used only for flow stats requests. Selects all flows regardless of group (including flows with no group).*/
};

/* Bucket for use in groups. */
struct ofp_bucket {
  uint16_t len;         /* Length the bucket in bytes, including this header and any padding to make it 64-bit aligned. */
  uint16_t weight;      /* Relative weight of bucket. Only defined for select groups. */
  uint32_t watch_port;  /* Port whose state affects whether this bucket is live. Only required for fast failover groups. */
  uint32_t watch_group; /* Group whose state affects whether this bucket is live. Only required for fast failover groups. */
  uint8_t pad[4];
  struct ofp_action_header actions[0]; /* The action length is inferred from the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_bucket) == 16);
```


### Port Modification Message

```c
/* Modify behavior of the physical port */
struct ofp_port_mod {
  struct ofp_header header;
  uint32_t port_no;
  uint8_t pad[4];
  uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not configurable. This is used to sanity-check the request, so it must be the same as returned in an ofp_port struct. */
  uint8_t pad2[2];               /* Pad to 64 bits. */
  uint32_t config;               /* Bitmap of OFPPC_* flags. */
  uint32_t mask;                 /* Bitmap of OFPPC_* flags to be changed. */
  uint32_t advertise;            /* Bitmap of OFPPF_*. Zero all bits to prevent any action taking place. */
  uint8_t pad3[4];               /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_port_mod) == 40);
```


### Meter Modification Message

```c
/* Meter configuration. OFPT_METER_MOD. */
struct ofp_meter_mod {
  struct ofp_header header;
  uint16_t command;     /* One of OFPMC_*. */
  uint16_t flags;       /* One of OFPMF_*. */
  uint32_t meter_id;    /* Meter instance. */
  struct ofp_meter_band_header bands[0]; /* The bands length is inferred from the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_meter_mod) == 16);

/* Meter numbering. Flow meters can use any number up to OFPM_MAX. */
enum ofp_meter {
  /* Last usable meter. */
  OFPM_MAX = 0xffff0000,
  /* Virtual meters. */
  OFPM_SLOWPATH = 0xfffffffd,   /* Meter for slow datapath. */
  OFPM_CONTROLLER = 0xfffffffe, /* Meter for controller connection. */
  OFPM_ALL = 0xffffffff,        /* Represents all meters for stat requestscommands. */
};

/* Meter commands */
enum ofp_meter_mod_command {
  OFPMC_ADD,    /* New meter. */
  OFPMC_MODIFY, /* Modify specified meter. */
  OFPMC_DELETE, /* Delete specified meter. */
};

/* Meter configuration flags */
enum ofp_meter_flags {
  OFPMF_KBPS = 1 << 0,  /* Rate value in kb/s (kilo-bit per second). */
  OFPMF_PKTPS = 1 << 1, /* Rate value in packet/sec. */
  OFPMF_BURST = 1 << 2, /* Do burst size. */
  OFPMF_STATS = 1 << 3, /* Collect statistics. */
};

/* Common header for all meter bands */
struct ofp_meter_band_header {
  uint16_t type;       /* One of OFPMBT_*. */
  uint16_t len;        /* Length in bytes of this band. */
  uint32_t rate;       /* Rate for this band. */
  uint32_t burst_size; /* Size of bursts. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_header) == 12);

/* Meter band types */
enum ofp_meter_band_type {
  OFPMBT_DROP = 1,             /* Drop packet. */
  OFPMBT_DSCP_REMARK = 2,      /* Remark DSCP in the IP header. */
  OFPMBT_EXPERIMENTER = 0xFFFF /* Experimenter meter band. */
};

/* OFPMBT_DROP band - drop packets */
struct ofp_meter_band_drop {
  uint16_t type;       /* OFPMBT_DROP. */
  uint16_t len;        /* Length in bytes of this band. */
  uint32_t rate;       /* Rate for dropping packets. */
  uint32_t burst_size; /* Size of bursts. */
  uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_meter_band_drop) == 16);

/* OFPMBT_DSCP_REMARK band - Remark DSCP in the IP header */
struct ofp_meter_band_dscp_remark {
  uint16_t type;       /* OFPMBT_DSCP_REMARK. */
  uint16_t len;        /* Length in bytes of this band. */
  uint32_t rate;       /* Rate for remarking packets. */
  uint32_t burst_size; /* Size of bursts. */
  uint8_t prec_level;  /* Number of drop precedence level to add. */
  uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_meter_band_dscp_remark) == 16);

struct ofp_meter_band_experimenter {
  uint16_t type;         /* One of OFPMBT_*. */
  uint16_t len;          /* Length in bytes of this band. */
  uint32_t rate;         /* Rate for this band. */
  uint32_t burst_size;   /* Size of bursts. */
  uint32_t experimenter; /* Experimenter ID which takes the same form as in struct ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_experimenter) == 16);
```


## Multipart Messages

```c
struct ofp_multipart_request {
  struct ofp_header header;
  uint16_t type;   /* One of the OFPMP_* constants. */
  uint16_t flags;  /* OFPMPF_REQ_* flags. */
  uint8_t pad[4];
  uint8_t body[0]; /* Body of the request. */
};
OFP_ASSERT(sizeof(struct ofp_multipart_request) == 16);

enum ofp_multipart_request_flags {
  OFPMPF_REQ_MORE = 1 << 0 /* More requests to follow. */
};

struct ofp_multipart_reply {
  struct ofp_header header;
  uint16_t type;   /* One of the OFPMP_* constants. */
  uint16_t flags;  /* OFPMPF_REPLY_* flags. */
  uint8_t pad[4];
  uint8_t body[0]; /* Body of the reply. */
};
OFP_ASSERT(sizeof(struct ofp_multipart_reply) == 16);

enum ofp_multipart_reply_flags {
  OFPMPF_REPLY_MORE = 1 << 0 /* More replies to follow. */
};

enum ofp_multipart_types {
  /* Description of this OpenFlow switch.
  * The request body is empty.
  * The reply body is struct ofp_desc. */
  OFPMP_DESC = 0,
  /* Individual flow statistics.
  * The request body is struct ofp_flow_stats_request.
  * The reply body is an array of struct ofp_flow_stats. */
  OFPMP_FLOW = 1,
  /* Aggregate flow statistics.
  * The request body is struct ofp_aggregate_stats_request.
  * The reply body is struct ofp_aggregate_stats_reply. */
  OFPMP_AGGREGATE = 2,
  /* Flow table statistics.
  * The request body is empty.
  * The reply body is an array of struct ofp_table_stats. */
  OFPMP_TABLE = 3,
  /* Port statistics.
  * The request body is struct ofp_port_stats_request.
  * The reply body is an array of struct ofp_port_stats. */
  OFPMP_PORT_STATS = 4,
  /* Queue statistics for a port
  * The request body is struct ofp_queue_stats_request.
  * The reply body is an array of struct ofp_queue_stats */
  OFPMP_QUEUE = 5,
  /* Group counter statistics.
  * The request body is struct ofp_group_stats_request.
  * The reply is an array of struct ofp_group_stats. */
  OFPMP_GROUP = 6,
  /* Group description.
  * The request body is empty.
  * The reply body is an array of struct ofp_group_desc_stats. */
  OFPMP_GROUP_DESC = 7,
  /* Group features.
  * The request body is empty.
  * The reply body is struct ofp_group_features. */
  OFPMP_GROUP_FEATURES = 8,
  /* Meter statistics.
  * The request body is struct ofp_meter_multipart_requests.
  * The reply body is an array of struct ofp_meter_stats. */
  OFPMP_METER = 9,
  /* Meter configuration.
  * The request body is struct ofp_meter_multipart_requests.
  * The reply body is an array of struct ofp_meter_config. */
  OFPMP_METER_CONFIG = 10,
  /* Meter features.
  * The request body is empty.
  * The reply body is struct ofp_meter_features. */
  OFPMP_METER_FEATURES = 11,
  /* Table features.
  * The request body is either empty or contains an array of
  * struct ofp_table_features containing the controller's
  * desired view of the switch. If the switch is unable to
  * set the specified view an error is returned.
  * The reply body is an array of struct ofp_table_features. */
  OFPMP_TABLE_FEATURES = 12,
  /* Port description.
  * The request body is empty.
  * The reply body is an array of struct ofp_port. */
  OFPMP_PORT_DESC = 13,
  /* Experimenter extension.
  * The request and reply bodies begin with
  * struct ofp_experimenter_multipart_header.
  * The request and reply bodies are otherwise experimenter-defined. */
  OFPMP_EXPERIMENTER = 0xffff
};
```

### Description

```c
/* Body of reply to OFPMP_DESC request. Each entry is a NULL-terminated ASCII string. */
struct ofp_desc {
  char mfr_desc[DESC_STR_LEN];     /* Manufacturer description. */
  char hw_desc[DESC_STR_LEN];      /* Hardware description. */
  char sw_desc[DESC_STR_LEN];      /* Software description. */
  char serial_num[SERIAL_NUM_LEN]; /* Serial number. */
  char dp_desc[DESC_STR_LEN];      /* Human readable description of datapath. */
};
OFP_ASSERT(sizeof(struct ofp_desc) == 1056);
```


### Individual Flow Statistics

```c
/* Body for ofp_multipart_request of type OFPMP_FLOW. */
struct ofp_flow_stats_request {
  uint8_t table_id;       /* ID of table to read (from ofp_table_stats), OFPTT_ALL for all tables. */
  uint8_t pad[3];         /* Align to 32 bits. */
  uint32_t out_port;      /* Require matching entries to include this as an output port. A value of OFPP_ANY indicates no restriction. */
  uint32_t out_group;     /* Require matching entries to include this as an output group. A value of OFPG_ANY indicates no restriction. */
  uint8_t pad2[4];        /* Align to 64 bits. */
  uint64_t cookie;        /* Require matching entries to contain this cookie value */
  uint64_t cookie_mask;   /* Mask used to restrict the cookie bits that must match. A value of 0 indicates no restriction. */
  struct ofp_match match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats_request) == 40);

/* Body of reply to OFPMP_FLOW request. */
struct ofp_flow_stats {
  uint16_t length;        /* Length of this entry. */
  uint8_t table_id;       /* ID of table flow came from. */
  uint8_t pad;
  uint32_t duration_sec;  /* Time flow has been alive in seconds. */
  uint32_t duration_nsec; /* Time flow has been alive in nanoseconds beyond duration_sec. */
  uint16_t priority;      /* Priority of the entry. */
  uint16_t idle_timeout;  /* Number of seconds idle before expiration. */
  uint16_t hard_timeout;  /* Number of seconds before expiration. */
  uint16_t flags;         /* One of OFPFF_*. */
  uint8_t pad2[4];        /* Align to 64-bits. */
  uint64_t cookie;        /* Opaque controller-issued identifier. */
  uint64_t packet_count;  /* Number of packets in flow. */
  uint64_t byte_count;    /* Number of bytes in flow. */
  struct ofp_match match; /* Description of fields. Variable size. */
  //struct ofp_instruction instructions[0]; /* Instruction set. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats) == 56);
```


### Aggregate Flow Statistics

```c
/* Body for ofp_multipart_request of type OFPMP_AGGREGATE. */
struct ofp_aggregate_stats_request {
  uint8_t table_id;       /* ID of table to read (from ofp_table_stats) OFPTT_ALL for all tables. */
  uint8_t pad[3];         /* Align to 32 bits. */
  uint32_t out_port;      /* Require matching entries to include this as an output port. A value of OFPP_ANY indicates no restriction. */
  uint32_t out_group;     /* Require matching entries to include this as an output group. A value of OFPG_ANY indicates no restriction. */
  uint8_t pad2[4];        /* Align to 64 bits. */
  uint64_t cookie;        /* Require matching entries to contain this cookie value */
  uint64_t cookie_mask;   /* Mask used to restrict the cookie bits that must match. A value of 0 indicates no restriction. */
  struct ofp_match match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_request) == 40);

/* Body of reply to OFPMP_AGGREGATE request. */
struct ofp_aggregate_stats_reply {
  uint64_t packet_count; /* Number of packets in flows. */
  uint64_t byte_count;   /* Number of bytes in flows. */
  uint32_t flow_count;   /* Number of flows. */
  uint8_t pad[4];        /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_reply) == 24)
```


### Table Statistics

```c
/* Body of reply to OFPMP_TABLE request. */
struct ofp_table_stats {
  uint8_t table_id;       /* Identifier of table. Lower numbered tables are consulted first. */
  uint8_t pad[3];         /* Align to 32-bits. */
  uint32_t active_count;  /* Number of active entries. */
  uint64_t lookup_count;  /* Number of packets looked up in table. */
  uint64_t matched_count; /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp_table_stats) == 24);
```


### Table Features

```c
/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES. Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofp_table_features {
  uint16_t length;   /* Length is padded to 64 bits. */
  uint8_t table_id;  /* Identifier of table. Lower numbered tables are consulted first. */
  uint8_t pad[5];    /* Align to 64-bits. */
  char name[OFP_MAX_TABLE_NAME_LEN];
  uint64_t metadata_match; /* Bits of metadata table can match. */
  uint64_t metadata_write; /* Bits of metadata table can write. */
  uint32_t config;         /* Bitmap of OFPTC_* values */
  uint32_t max_entries;    /* Max number of entries supported. */
  /* Table Feature Property list */
  struct ofp_table_feature_prop_header properties[0];
};
OFP_ASSERT(sizeof(struct ofp_table_features) == 64);

/* Table Feature property types.
* Low order bit cleared indicates a property for a regular Flow Entry.
* Low order bit set indicates a property for the Table-Miss Flow Entry.
*/
enum ofp_table_feature_prop_type {
  OFPTFPT_INSTRUCTIONS = 0,           /* Instructions property. */
  OFPTFPT_INSTRUCTIONS_MISS = 1,      /* Instructions for table-miss. */
  OFPTFPT_NEXT_TABLES = 2,            /* Next Table property. */
  OFPTFPT_NEXT_TABLES_MISS = 3,       /* Next Table for table-miss. */
  OFPTFPT_WRITE_ACTIONS = 4,          /* Write Actions property. */
  OFPTFPT_WRITE_ACTIONS_MISS = 5,     /* Write Actions for table-miss. */
  OFPTFPT_APPLY_ACTIONS = 6,          /* Apply Actions property. */
  OFPTFPT_APPLY_ACTIONS_MISS = 7,     /* Apply Actions for table-miss. */
  OFPTFPT_MATCH = 8,                  /* Match property. */
  OFPTFPT_WILDCARDS = 10,             /* Wildcards property. */
  OFPTFPT_WRITE_SETFIELD = 12,        /* Write Set-Field property. */
  OFPTFPT_WRITE_SETFIELD_MISS = 13,   /* Write Set-Field for table-miss. */
  OFPTFPT_APPLY_SETFIELD = 14,        /* Apply Set-Field property. */
  OFPTFPT_APPLY_SETFIELD_MISS = 15,   /* Apply Set-Field for table-miss. */
  OFPTFPT_EXPERIMENTER = 0xFFFE,      /* Experimenter property. */
  OFPTFPT_EXPERIMENTER_MISS = 0xFFFF, /* Experimenter for table-miss. */
};

/* Common header for all Table Feature Properties */
struct ofp_table_feature_prop_header {
  uint16_t type;   /* One of OFPTFPT_*. */
  uint16_t length; /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_header) == 4);

/* Instructions property */
struct ofp_table_feature_prop_instructions {
  uint16_t type;   /* One of OFPTFPT_INSTRUCTIONS, OFPTFPT_INSTRUCTIONS_MISS. */
  uint16_t length; /* Length in bytes of this property. */
  struct ofp_instruction instruction_ids[0]; /* List of instructions */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_instructions) == 4);

/* Next Tables property */
struct ofp_table_feature_prop_next_tables {
  uint16_t type;   /* One of OFPTFPT_NEXT_TABLES, OFPTFPT_NEXT_TABLES_MISS. */
  uint16_t length; /* Length in bytes of this property. */
  uint8_t next_table_ids[0];
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_next_tables) == 4);

/* Actions property */
struct ofp_table_feature_prop_actions {
  uint16_t type;   /* One of OFPTFPT_WRITE_ACTIONS, OFPTFPT_WRITE_ACTIONS_MISS, OFPTFPT_APPLY_ACTIONS, OFPTFPT_APPLY_ACTIONS_MISS. */
  uint16_t length; /* Length in bytes of this property. */
  struct ofp_action_header action_ids[0]; /* List of actions */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_actions) == 4);

/* Match, Wildcard or Set-Field property */
struct ofp_table_feature_prop_oxm {
  uint16_t type;       /* One of OFPTFPT_MATCH, OFPTFPT_WILDCARDS, OFPTFPT_WRITE_SETFIELD, OFPTFPT_WRITE_SETFIELD_MISS, OFPTFPT_APPLY_SETFIELD, OFPTFPT_APPLY_SETFIELD_MISS. */
  uint16_t length;     /* Length in bytes of this property. */
  uint32_t oxm_ids[0]; /* Array of OXM headers */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_oxm) == 4);

/* Experimenter table feature property */
struct ofp_table_feature_prop_experimenter {
  uint16_t type;         /* One of OFPTFPT_EXPERIMENTER, OFPTFPT_EXPERIMENTER_MISS. */
  uint16_t length;       /* Length in bytes of this property. */
  uint32_t experimenter; /* Experimenter ID which takes the same form as in struct ofp_experimenter_header. */
  uint32_t exp_type;     /* Experimenter defined. */
  uint32_t experimenter_data[0];
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_experimenter) == 12);
```


### Port Statistics

```c
/* Body for ofp_multipart_request of type OFPMP_PORT. */
struct ofp_port_stats_request {
  uint32_t port_no; /* OFPMP_PORT message must request statistics either for a single port (specified in port_no) or for all ports (if port_no == OFPP_ANY). */
  uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_port_stats_request) == 8);

/* Body of reply to OFPMP_PORT request. If a counter is unsupported, set the field to all ones. */
struct ofp_port_stats {
  uint32_t port_no;
  uint8_t pad[4];         /* Align to 64-bits. */
  uint64_t rx_packets;    /* Number of received packets. */
  uint64_t tx_packets;    /* Number of transmitted packets. */
  uint64_t rx_bytes;      /* Number of received bytes. */
  uint64_t tx_bytes;      /* Number of transmitted bytes. */
  uint64_t rx_dropped;    /* Number of packets dropped by RX. */
  uint64_t tx_dropped;    /* Number of packets dropped by TX. */
  uint64_t rx_errors;     /* Number of receive errors. This is a super-set of more specific receive errors and should be greater than or equal to the sum of all rx_*_err values. */
  uint64_t tx_errors;     /* Number of transmit errors. This is a super-set of more specific transmit errors and should be greater than or equal to the sum of all tx_*_err values (none currently defined.) */
  uint64_t rx_frame_err;  /* Number of frame alignment errors. */
  uint64_t rx_over_err;   /* Number of packets with RX overrun. */
  uint64_t rx_crc_err;    /* Number of CRC errors. */
  uint64_t collisions;    /* Number of collisions. */
  uint32_t duration_sec;  /* Time port has been alive in seconds. */
  uint32_t duration_nsec; /* Time port has been alive in nanoseconds beyond duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp_port_stats) == 112);
```


### Port Description

```c
/* Description of a port */
struct ofp_port {
  uint32_t port_no;
  uint8_t pad[4];
  uint8_t hw_addr[OFP_ETH_ALEN];
  uint8_t pad2[2];                  /* Align to 64 bits. */
  char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
  uint32_t config;                  /* Bitmap of OFPPC_* flags. */
  uint32_t state;                   /* Bitmap of OFPPS_* flags. */
  /* Bitmaps of OFPPF_* that describe features. All bits zeroed if unsupported or unavailable. */
  uint32_t curr;       /* Current features. */
  uint32_t advertised; /* Features being advertised by the port. */
  uint32_t supported;  /* Features supported by the port. */
  uint32_t peer;       /* Features advertised by peer. */
  uint32_t curr_speed; /* Current port bitrate in kbps. */
  uint32_t max_speed;  /* Max port bitrate in kbps */
};
OFP_ASSERT(sizeof(struct ofp_port) == 64);
```


### Queue Statistics

```c
struct ofp_queue_stats_request {
  uint32_t port_no;  /* All ports if OFPP_ANY. */
  uint32_t queue_id; /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats_request) == 8);

struct ofp_queue_stats {
  uint32_t port_no;
  uint32_t queue_id;       /* Queue i.d */
  uint64_t tx_bytes;       /* Number of transmitted bytes. */
  uint64_t tx_packets;     /* Number of transmitted packets. */
  uint64_t tx_errors;      /* Number of packets dropped due to overrun. */
  uint32_t duration_sec;   /* Time queue has been alive in seconds. */
  uint32_t duration_nsec;  /* Time queue has been alive in nanoseconds beyond duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats) == 40);
```


### Group Statistics

```c
/* Body of OFPMP_GROUP request. */
struct ofp_group_stats_request {
  uint32_t group_id; /* All groups if OFPG_ALL. */
  uint8_t pad[4];    /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_group_stats_request) == 8);

/* Body of reply to OFPMP_GROUP request. */
struct ofp_group_stats {
  uint16_t length;        /* Length of this entry. */
  uint8_t pad[2];         /* Align to 64 bits. */
  uint32_t group_id;      /* Group identifier. */
  uint32_t ref_count;     /* Number of flows or groups that directly forward to this group. */
  uint8_t pad2[4];        /* Align to 64 bits. */
  uint64_t packet_count;  /* Number of packets processed by group. */
  uint64_t byte_count;    /* Number of bytes processed by group. */
  uint32_t duration_sec;  /* Time group has been alive in seconds. */
  uint32_t duration_nsec; /* Time group has been alive in nanoseconds beyond duration_sec. */
  struct ofp_bucket_counter bucket_stats[0];
};
OFP_ASSERT(sizeof(struct ofp_group_stats) == 40);

/* Used in group stats replies. */
struct ofp_bucket_counter {
  uint64_t packet_count; /* Number of packets processed by bucket. */
  uint64_t byte_count;   /* Number of bytes processed by bucket. */
};
OFP_ASSERT(sizeof(struct ofp_bucket_counter) == 16);
```


### Group Description

```c
/* Body of reply to OFPMP_GROUP_DESC request. */
struct ofp_group_desc_stats {
  uint16_t length;   /* Length of this entry. */
  uint8_t type;      /* One of OFPGT_*. */
  uint8_t pad;       /* Pad to 64 bits. */
  uint32_t group_id; /* Group identifier. */
  struct ofp_bucket buckets[0];
};
OFP_ASSERT(sizeof(struct ofp_group_desc_stats) == 8);
```


### Group Features

```c
/* Body of reply to OFPMP_GROUP_FEATURES request. Group features. */
struct ofp_group_features {
  uint32_t types;         /* Bitmap of OFPGT_* values supported. */
  uint32_t capabilities;  /* Bitmap of OFPGFC_* capability supported. */
  uint32_t max_groups[4]; /* Maximum number of groups for each type. */
  uint32_t actions[4];    /* Bitmaps of OFPAT_* that are supported. */
};
OFP_ASSERT(sizeof(struct ofp_group_features) == 40);

/* Group configuration flags */
enum ofp_group_capabilities {
  OFPGFC_SELECT_WEIGHT = 1 << 0,   /* Support weight for select groups */
  OFPGFC_SELECT_LIVENESS = 1 << 1, /* Support liveness for select groups */
  OFPGFC_CHAINING = 1 << 2,        /* Support chaining groups */
  OFPGFC_CHAINING_CHECKS = 1 << 3, /* Check chaining for loops and delete */
};
```


### Meter Statistics

```c
/* Body of OFPMP_METER and OFPMP_METER_CONFIG requests. */
struct ofp_meter_multipart_request {
  uint32_t meter_id; /* Meter instance, or OFPM_ALL. */
  uint8_t pad[4];    /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_meter_multipart_request) == 8);

/* Body of reply to OFPMP_METER request. Meter statistics. */
struct ofp_meter_stats {
  uint32_t meter_id;        /* Meter instance. */
  uint16_t len;             /* Length in bytes of this stats. */
  uint8_t pad[6];
  uint32_t flow_count;      /* Number of flows bound to meter. */
  uint64_t packet_in_count; /* Number of packets in input. */
  uint64_t byte_in_count;   /* Number of bytes in input. */
  uint32_t duration_sec;    /* Time meter has been alive in seconds. */
  uint32_t duration_nsec;   /* Time meter has been alive in nanoseconds beyond duration_sec. */
  struct ofp_meter_band_stats band_stats[0]; /* The band_stats length is inferred from the length field. */
};
OFP_ASSERT(sizeof(struct ofp_meter_stats) == 40);

/* Statistics for each meter band */
struct ofp_meter_band_stats {
  uint64_t packet_band_count; /* Number of packets in band. */
  uint64_t byte_band_count;   /* Number of bytes in band. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_stats) == 16);
```


### Meter Configuration Statistics

```c
/* Body of OFPMP_METER and OFPMP_METER_CONFIG requests. */
struct ofp_meter_multipart_request {
  uint32_t meter_id; /* Meter instance, or OFPM_ALL. */
  uint8_t pad[4];    /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_meter_multipart_request) == 8);

/* Body of reply to OFPMP_METER_CONFIG request. Meter configuration. */
struct ofp_meter_config {
  uint16_t length;     /* Length of this entry. */
  uint16_t flags;      /* All OFPMC_* that apply. */
  uint32_t meter_id;   /* Meter instance. */
  struct ofp_meter_band_header bands[0]; /* The bands length is inferred from the length field. */
};
OFP_ASSERT(sizeof(struct ofp_meter_config) == 8);
```


### Meter Features Statistics

```c
/* Body of reply to OFPMP_METER_FEATURES request. Meter features. */
struct ofp_meter_features {
  uint32_t max_meter;    /* Maximum number of meters. */
  uint32_t band_types;   /* Bitmaps of OFPMBT_* values supported. */
  uint32_t capabilities; /* Bitmaps of "ofp_meter_flags". */
  uint8_t max_bands;     /* Maximum bands per meters */
  uint8_t max_color;     /* Maximum color value */
  uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_meter_features) == 16);
```


### Experimenter Multipart

```c
/* Body for ofp_multipart_request/reply of type OFPMP_EXPERIMENTER. */
struct ofp_experimenter_multipart_header {
  uint32_t experimenter; /* Experimenter ID which takes the same form as in struct ofp_experimenter_header. */
  uint32_t exp_type;     /* Experimenter defined. */
  /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_experimenter_multipart_header) == 8);
```


## Queue Configuration Messages

```c
/* Query for port queue configuration. */
struct ofp_queue_get_config_request {
  struct ofp_header header;
  uint32_t port; /* Port to be queried. Should refer to a valid physical port (i.e. < OFPP_MAX), or OFPP_ANY to request all configured queues.*/
  uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_queue_get_config_request) == 16);

/* Queue configuration for a given port. */
struct ofp_queue_get_config_reply {
  struct ofp_header header;
  uint32_t port;
  uint8_t pad[4];
  struct ofp_packet_queue queues[0]; /* List of configured queues. */
};
OFP_ASSERT(sizeof(struct ofp_queue_get_config_reply) == 16);
```


## Packet-Out Message

```c
/* Send packet (controller -> datapath). */
struct ofp_packet_out {
  struct ofp_header header;
  uint32_t buffer_id;   /* ID assigned by datapath (OFP_NO_BUFFER if none). */
  uint32_t in_port;     /* Packet's input port or OFPP_CONTROLLER. */
  uint16_t actions_len; /* Size of action array in bytes. */
  uint8_t pad[6];
  struct ofp_action_header actions[0]; /* Action list. */
};
OFP_ASSERT(sizeof(struct ofp_packet_out) == 24);
```

## Role Request Message

```c
/* Role request and reply message. */
struct ofp_role_request {
  struct ofp_header header; /* Type OFPT_ROLE_REQUEST/OFPT_ROLE_REPLY. */
  uint32_t role;            /* One of NX_ROLE_*. */
  uint8_t pad[4];           /* Align to 64 bits. */
  uint64_t generation_id;   /* Master Election Generation Id */
};
OFP_ASSERT(sizeof(struct ofp_role_request) == 24);

/* Controller roles. */
enum ofp_controller_role {
  OFPCR_ROLE_NOCHANGE = 0, /* Don't change current role. */
  OFPCR_ROLE_EQUAL = 1,    /* Default role, full access. */
  OFPCR_ROLE_MASTER = 2,   /* Full access, at most one master. */
  OFPCR_ROLE_SLAVE = 3,    /* Read-only access. */
};
```


## Set Asynchronous Configuration Message

```c
/* Asynchronous message configuration. */
struct ofp_async_config {
  struct ofp_header header;     /* OFPT_GET_ASYNC_REPLY or OFPT_SET_ASYNC. */
  uint32_t packet_in_mask[2];   /* Bitmasks of OFPR_* values. */
  uint32_t port_status_mask[2]; /* Bitmasks of OFPPR_* values. */
  uint32_t flow_removed_mask[2];/* Bitmasks of OFPRR_* values. */
};
OFP_ASSERT(sizeof(struct ofp_async_config) == 32);
```


# Asynchronous Messages


## Packet-In Message

```c
/* Packet received on port (datapath -> controller). */
struct ofp_packet_in {
  struct ofp_header header;
  uint32_t buffer_id;     /* ID assigned by datapath. */
  uint16_t total_len;     /* Full length of frame. */
  uint8_t reason;         /* Reason packet is being sent (one of OFPR_*) */
  uint8_t table_id;       /* ID of the table that was looked up */
  uint64_t cookie;        /* Cookie of the flow entry that was looked up. */
  struct ofp_match match; /* Packet metadata. Variable size. */
  //uint8_t pad[2];       /* Align to 64 bit + 16 bit */
  //uint8_t data[0];      /* Ethernet frame */
};
OFP_ASSERT(sizeof(struct ofp_packet_in) == 32);

/* Why is this packet being sent to the controller? */
enum ofp_packet_in_reason {
  OFPR_NO_MATCH = 0,    /* No matching flow (table-miss flow entry). */
  OFPR_ACTION = 1,      /* Action explicitly output to controller. */
  OFPR_INVALID_TTL = 2, /* Packet has invalid TTL */
};
```


## Flow Removed Message

```c
/* Flow removed (datapath -> controller). */
struct ofp_flow_removed {
  struct ofp_header header;
  uint64_t cookie;        /* Opaque controller-issued identifier. */
  uint16_t priority;      /* Priority level of flow entry. */
  uint8_t reason;         /* One of OFPRR_*. */
  uint8_t table_id;       /* ID of the table */
  uint32_t duration_sec;  /* Time flow was alive in seconds. */
  uint32_t duration_nsec; /* Time flow was alive in nanoseconds beyond duration_sec. */
  uint16_t idle_timeout;  /* Idle timeout from original flow mod. */
  uint16_t hard_timeout;  /* Hard timeout from original flow mod. */
  uint64_t packet_count;
  uint64_t byte_count;
  struct ofp_match match; /* Description of fields. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_flow_removed) == 56);

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
  OFPRR_IDLE_TIMEOUT = 0, /* Flow idle time exceeded idle_timeout. */
  OFPRR_HARD_TIMEOUT = 1, /* Time exceeded hard_timeout. */
  OFPRR_DELETE = 2,       /* Evicted by a DELETE flow mod. */
  OFPRR_GROUP_DELETE = 3, /* Group was removed. */
};
```

## Port Status Message

```c
/* A physical port has changed in the datapath */
struct ofp_port_status {
  struct ofp_header header;
  uint8_t reason; /* One of OFPPR_*. */
  uint8_t pad[7]; /* Align to 64-bits. */
  struct ofp_port desc;
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 80);

/* What changed about the physical port */
enum ofp_port_reason {
  OFPPR_ADD = 0,    /* The port was added. */
  OFPPR_DELETE = 1, /* The port was removed. */
  OFPPR_MODIFY = 2, /* Some attribute of the port has changed. */
};
```


## Error Message

```c
/* OFPT_ERROR: Error message (datapath -> controller). */
struct ofp_error_msg {
  struct ofp_header header;
  uint16_t type;
  uint16_t code;
  uint8_t data[0]; /* Variable-length data. Interpreted based on the type and code. No padding. */
};
OFP_ASSERT(sizeof(struct ofp_error_msg) == 12);

/* Values for 'type' in ofp_error_message. These values are immutable: they
* will not change in future versions of the protocol (although new values may
* be added). */
enum ofp_error_type {
  OFPET_HELLO_FAILED = 0,           /* Hello protocol failed. */
  OFPET_BAD_REQUEST = 1,            /* Request was not understood. */
  OFPET_BAD_ACTION = 2,             /* Error in action description. */
  OFPET_BAD_INSTRUCTION = 3,        /* Error in instruction list. */
  OFPET_BAD_MATCH = 4,              /* Error in match. */
  OFPET_FLOW_MOD_FAILED = 5,        /* Problem modifying flow entry. */
  OFPET_GROUP_MOD_FAILED = 6,       /* Problem modifying group entry. */
  OFPET_PORT_MOD_FAILED = 7,        /* Port mod request failed. */
  OFPET_TABLE_MOD_FAILED = 8,       /* Table mod request failed. */
  OFPET_QUEUE_OP_FAILED = 9,        /* Queue operation failed. */
  OFPET_SWITCH_CONFIG_FAILED = 10,  /* Switch config request failed. */
  OFPET_ROLE_REQUEST_FAILED = 11,   /* Controller Role request failed. */
  OFPET_METER_MOD_FAILED = 12,      /* Error in meter. */
  OFPET_TABLE_FEATURES_FAILED = 13, /* Setting table features failed. */
  OFPET_EXPERIMENTER = 0xffff       /* Experimenter error messages. */
};

/* ofp_error_msg 'code' values for OFPET_HELLO_FAILED. 'data' contains an
* ASCII text string that may give failure details. */
enum ofp_hello_failed_code {
  OFPHFC_INCOMPATIBLE = 0, /* No compatible version. */
  OFPHFC_EPERM = 1,        /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_REQUEST. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp_bad_request_code {
  OFPBRC_BAD_VERSION = 0,                /* ofp_header.version not supported. */
  OFPBRC_BAD_TYPE = 1,                   /* ofp_header.type not supported. */
  OFPBRC_BAD_MULTIPART = 2,              /* ofp_multipart_request.type not supported. */
  OFPBRC_BAD_EXPERIMENTER = 3,           /* Experimenter id not supported (in ofp_experimenter_header or ofp_multipart_request or ofp_multipart_reply). */
  OFPBRC_BAD_EXP_TYPE = 4,               /* Experimenter type not supported. */
  OFPBRC_EPERM = 5,                      /* Permissions error. */
  OFPBRC_BAD_LEN = 6,                    /* Wrong request length for type. */
  OFPBRC_BUFFER_EMPTY = 7,               /* Specified buffer has already been used. */
  OFPBRC_BUFFER_UNKNOWN = 8,             /* Specified buffer does not exist. */
  OFPBRC_BAD_TABLE_ID = 9,               /* Specified table-id invalid or does not exist. */
  OFPBRC_IS_SLAVE = 10,                  /* Denied because controller is slave. */
  OFPBRC_BAD_PORT = 11,                  /* Invalid port. */
  OFPBRC_BAD_PACKET = 12,                /* Invalid packet in packet-out. */
  OFPBRC_MULTIPART_BUFFER_OVERFLOW = 13, /* ofp_multipart_request overflowed the assigned buffer. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_ACTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp_bad_action_code {
  OFPBAC_BAD_TYPE = 0,            /* Unknown action type. */
  OFPBAC_BAD_LEN = 1,             /* Length problem in actions. */
  OFPBAC_BAD_EXPERIMENTER = 2,    /* Unknown experimenter id specified. */
  OFPBAC_BAD_EXP_TYPE = 3,        /* Unknown action for experimenter id. */
  OFPBAC_BAD_OUT_PORT = 4,        /* Problem validating output port. */
  OFPBAC_BAD_ARGUMENT = 5,        /* Bad action argument. */
  OFPBAC_EPERM = 6,               /* Permissions error. */
  OFPBAC_TOO_MANY = 7,            /* Can't handle this many actions. */
  OFPBAC_BAD_QUEUE = 8,           /* Problem validating output queue. */
  OFPBAC_BAD_OUT_GROUP = 9,       /* Invalid group id in forward action. */
  OFPBAC_MATCH_INCONSISTENT = 10, /* Action can't apply for this match, or Set-Field missing prerequisite. */
  OFPBAC_UNSUPPORTED_ORDER = 11,  /* Action order is unsupported for the action list in an Apply-Actions instruction */
  OFPBAC_BAD_TAG = 12,            /* Actions uses an unsupported tag/encap. */
  OFPBAC_BAD_SET_TYPE = 13,       /* Unsupported type in SET_FIELD action. */
  OFPBAC_BAD_SET_LEN = 14,        /* Length problem in SET_FIELD action. */
  OFPBAC_BAD_SET_ARGUMENT = 15,   /* Bad argument in SET_FIELD action. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_INSTRUCTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp_bad_instruction_code {
  OFPBIC_UNKNOWN_INST = 0,        /* Unknown instruction. */
  OFPBIC_UNSUP_INST = 1,          /* Switch or table does not support the instruction. */
  OFPBIC_BAD_TABLE_ID = 2,        /* Invalid Table-ID specified. */
  OFPBIC_UNSUP_METADATA = 3,      /* Metadata value unsupported by datapath. */
  OFPBIC_UNSUP_METADATA_MASK = 4, /* Metadata mask value unsupported by datapath. */
  OFPBIC_BAD_EXPERIMENTER = 5,    /* Unknown experimenter id specified. */
  OFPBIC_BAD_EXP_TYPE = 6,        /* Unknown instruction for experimenter id. */
  OFPBIC_BAD_LEN = 7,             /* Length problem in instructions. */
  OFPBIC_EPERM = 8,               /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_MATCH. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp_bad_match_code {
  OFPBMC_BAD_TYPE = 0,         /* Unsupported match type specified by the match */
  OFPBMC_BAD_LEN = 1,          /* Length problem in match. */
  OFPBMC_BAD_TAG = 2,          /* Match uses an unsupported tag/encap. */
  OFPBMC_BAD_DL_ADDR_MASK = 3, /* Unsupported datalink addr mask - switch does not support arbitrary datalink address mask. */
  OFPBMC_BAD_NW_ADDR_MASK = 4, /* Unsupported network addr mask - switch does not support arbitrary network address mask. */
  OFPBMC_BAD_WILDCARDS = 5,    /* Unsupported combination of fields masked or omitted in the match. */
  OFPBMC_BAD_FIELD = 6,        /* Unsupported field type in the match. */
  OFPBMC_BAD_VALUE = 7,        /* Unsupported value in a match field. */
  OFPBMC_BAD_MASK = 8,         /* Unsupported mask specified in the match,
  OFPBMC_BAD_PREREQ = 9,       /* A prerequisite was not met. */
  OFPBMC_DUP_FIELD = 10,       /* A field type was duplicated. */
  OFPBMC_EPERM = 11,           /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_flow_mod_failed_code {
  OFPFMFC_UNKNOWN = 0,      /* Unspecified error. */
  OFPFMFC_TABLE_FULL = 1,   /* Flow not added because table was full. */
  OFPFMFC_BAD_TABLE_ID = 2, /* Table does not exist */
  OFPFMFC_OVERLAP = 3,      /* Attempted to add overlapping flow with CHECK_OVERLAP flag set. */
  OFPFMFC_EPERM = 4,        /* Permissions error. */
  OFPFMFC_BAD_TIMEOUT = 5,  /* Flow not added because of unsupported idle/hard timeout. */
  OFPFMFC_BAD_COMMAND = 6,  /* Unsupported or unknown command. */
  OFPFMFC_BAD_FLAGS = 7,    /* Unsupported or unknown flags. */
};

/* ofp_error_msg 'code' values for OFPET_GROUP_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_group_mod_failed_code {
  OFPGMFC_GROUP_EXISTS = 0,         /* Group not added because a group ADD attempted to replace an already-present group. */
  OFPGMFC_INVALID_GROUP = 1,        /* Group not added because Group specified is invalid. */
  OFPGMFC_WEIGHT_UNSUPPORTED = 2,   /* Switch does not support unequal load sharing with select groups. */
  OFPGMFC_OUT_OF_GROUPS = 3,        /* The group table is full. */
  OFPGMFC_OUT_OF_BUCKETS = 4,       /* The maximum number of action buckets for a group has been exceeded. */
  OFPGMFC_CHAINING_UNSUPPORTED = 5, /* Switch does not support groups that forward to groups. */
  OFPGMFC_WATCH_UNSUPPORTED = 6,    /* This group cannot watch the watch_port or watch_group specified. */
  OFPGMFC_LOOP = 7,                 /* Group entry would cause a loop. */
  OFPGMFC_UNKNOWN_GROUP = 8,        /* Group not modified because a group MODIFY attempted to modify a non-existent group. */
  OFPGMFC_CHAINED_GROUP = 9,        /* Group not deleted because another group is forwarding to it. */
  OFPGMFC_BAD_TYPE = 10,            /* Unsupported or unknown group type. */
  OFPGMFC_BAD_COMMAND = 11,         /* Unsupported or unknown command. */
  OFPGMFC_BAD_BUCKET = 12,          /* Error in bucket. */
  OFPGMFC_BAD_WATCH = 13,           /* Error in watch port/group. */
  OFPGMFC_EPERM = 14,               /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_PORT_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_port_mod_failed_code {
  OFPPMFC_BAD_PORT = 0,      /* Specified port number does not exist. */
  OFPPMFC_BAD_HW_ADDR = 1,   /* Specified hardware address does not match the port number. */
  OFPPMFC_BAD_CONFIG = 2,    /* Specified config is invalid. */
  OFPPMFC_BAD_ADVERTISE = 3, /* Specified advertise is invalid. */
  OFPPMFC_EPERM = 4,         /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_TABLE_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_table_mod_failed_code {
  OFPTMFC_BAD_TABLE = 0,  /* Specified table does not exist. */
  OFPTMFC_BAD_CONFIG = 1, /* Specified config is invalid. */
  OFPTMFC_EPERM = 2,      /* Permissions error. */
};

/* ofp_error msg 'code' values for OFPET_QUEUE_OP_FAILED. 'data' contains
* at least the first 64 bytes of the failed request */
enum ofp_queue_op_failed_code {
  OFPQOFC_BAD_PORT = 0,  /* Invalid port (or port does not exist). */
  OFPQOFC_BAD_QUEUE = 1, /* Queue does not exist. */
  OFPQOFC_EPERM = 2,     /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_SWITCH_CONFIG_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_switch_config_failed_code {
  OFPSCFC_BAD_FLAGS = 0, /* Specified flags is invalid. */
  OFPSCFC_BAD_LEN = 1,   /* Specified len is invalid. */
  OFPSCFC_EPERM = 2,     /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_ROLE_REQUEST_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_role_request_failed_code {
  OFPRRFC_STALE = 0,    /* Stale Message: old generation_id. */
  OFPRRFC_UNSUP = 1,    /* Controller role change unsupported. */
  OFPRRFC_BAD_ROLE = 2, /* Invalid role. */
};

/* ofp_error_msg 'code' values for OFPET_METER_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_meter_mod_failed_code {
  OFPMMFC_UNKNOWN = 0,        /* Unspecified error. */
  OFPMMFC_METER_EXISTS = 1,   /* Meter not added because a Meter ADD attempted to replace an existing Meter. */
  OFPMMFC_INVALID_METER = 2,  /* Meter not added because Meter specified is invalid. */
  OFPMMFC_UNKNOWN_METER = 3,  /* Meter not modified because a Meter MODIFY attempted to modify a non-existent Meter. */
  OFPMMFC_BAD_COMMAND = 4,    /* Unsupported or unknown command. */
  OFPMMFC_BAD_FLAGS = 5,      /* Flag configuration unsupported. */
  OFPMMFC_BAD_RATE = 6,       /* Rate unsupported. */
  OFPMMFC_BAD_BURST = 7,      /* Burst size unsupported. */
  OFPMMFC_BAD_BAND = 8,       /* Band unsupported. */
  OFPMMFC_BAD_BAND_VALUE = 9, /* Band value unsupported. */
  OFPMMFC_OUT_OF_METERS = 10, /* No more meters available. */
  OFPMMFC_OUT_OF_BANDS = 11,  /* The maximum number of properties for a meter has been exceeded. */
};

/* ofp_error_msg 'code' values for OFPET_TABLE_FEATURES_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp_table_features_failed_code {
  OFPTFFC_BAD_TABLE = 0,    /* Specified table does not exist. */
  OFPTFFC_BAD_METADATA = 1, /* Invalid metadata mask. */
  OFPTFFC_BAD_TYPE = 2,     /* Unknown property type. */
  OFPTFFC_BAD_LEN = 3,      /* Length problem in properties. */
  OFPTFFC_BAD_ARGUMENT = 4, /* Unsupported property value. */
  OFPTFFC_EPERM = 5,        /* Permissions error. */
};

/* OFPET_EXPERIMENTER: Error message (datapath -> controller). */
struct ofp_error_experimenter_msg {
  struct ofp_header header;
  uint16_t type;         /* OFPET_EXPERIMENTER. */
  uint16_t exp_type;     /* Experimenter defined. */
  uint32_t experimenter; /* Experimenter ID which takes the same form as in struct ofp_experimenter_header. */
  uint8_t data[0];       /* Variable-length data. Interpreted based on the type and code. No padding. */
};
OFP_ASSERT(sizeof(struct ofp_error_experimenter_msg) == 16);
```


# Symmetric Messages


## Hello

```c
/* OFPT_HELLO. This message includes zero or more hello elements having
* variable size. Unknown elements types must be ignored/skipped, to allow
* for future extensions. */
struct ofp_hello {
  struct ofp_header header;
  /* Hello element list */
  struct ofp_hello_elem_header elements[0];
};
OFP_ASSERT(sizeof(struct ofp_hello) == 8);

/* Hello elements types. */
enum ofp_hello_elem_type {
  OFPHET_VERSIONBITMAP = 1, /* Bitmap of version supported. */
};

/* Common header for all Hello Elements */
struct ofp_hello_elem_header {
  uint16_t type;   /* One of OFPHET_*. */
  uint16_t length; /* Length in bytes of this element. */
};
OFP_ASSERT(sizeof(struct ofp_hello_elem_header) == 4);

/* Version bitmap Hello Element */
struct ofp_hello_elem_versionbitmap {
  uint16_t type;       /* OFPHET_VERSIONBITMAP. */
  uint16_t length;     /* Length in bytes of this element. */
  uint32_t bitmaps[0]; /* List of bitmaps - supported versions */
};
OFP_ASSERT(sizeof(struct ofp_hello_elem_versionbitmap) == 4);
```


## Experimenter

```c
/* Experimenter extension. */
struct ofp_experimenter_header {
  struct ofp_header header; /* Type OFPT_EXPERIMENTER. */
  uint32_t experimenter;    /* Experimenter ID: - MSB 0: low-order bytes are IEEE OUI. - MSB != 0: defined by ONF. */
  uint32_t exp_type;        /* Experimenter defined. */
  /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_experimenter_header) == 16);
```

