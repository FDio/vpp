/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2017-2019 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_upf_h__
#define __included_upf_h__

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/policer/policer.h>
#include <vnet/session/session_types.h>

#include "pfcp.h"
#include "flowtable.h"

#define ip4_address_initializer { 0 }
#define ip6_address_initializer {{ 0 }}

/* UPF buffer opaque definition */
typedef struct
{
  struct
  {
    u64 pad[1];
    u32 teid;
    u32 session_index;
    u16 ext_hdr_len;
    u16 data_offset;		/* offset relative to ip hdr */
    u8 flags;
    u8 is_reverse:1;
    u8 is_proxied:1;
    u32 pdr_idx;
    u32 flow_id;
  } gtpu;
} upf_buffer_opaque_t;

STATIC_ASSERT (sizeof (upf_buffer_opaque_t) <=
	       STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
	       "upf_buffer_opaque_t too large for vnet_buffer_opaque2_t");

#define upf_buffer_opaque(b)                           \
  ((upf_buffer_opaque_t *)((u8 *)((b)->opaque2) +       \
STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

#define BUFFER_HAS_GTP_HDR  (1<<4)
#define BUFFER_HAS_UDP_HDR  (1<<5)
#define BUFFER_HAS_IP4_HDR  (1<<6)
#define BUFFER_HAS_IP6_HDR  (1<<7)
#define BUFFER_HDR_MASK     (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP4_HDR | BUFFER_HAS_IP6_HDR)
#define BUFFER_GTP_UDP_IP4  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP4_HDR)
#define BUFFER_GTP_UDP_IP6  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP6_HDR)
#define BUFFER_UDP_IP4      (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP4_HDR)
#define BUFFER_UDP_IP6      (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP6_HDR)


/**
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		          Version	PT	(*)	E	S	PN
 * 2		Message Type
 * 3		Length (1st Octet)
 * 4		Length (2nd Octet)
 * 5		Tunnel Endpoint Identifier (1st Octet)
 * 6		Tunnel Endpoint Identifier (2nd Octet)
 * 7		Tunnel Endpoint Identifier (3rd Octet)
 * 8		Tunnel Endpoint Identifier (4th Octet)
 * 9		Sequence Number (1st Octet)1) 4)
 * 10		Sequence Number (2nd Octet)1) 4)
 * 11		N-PDU Number2) 4)
 * 12		Next Extension Header Type3) 4)
**/

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;			/* length in octets of the payload */
  u32 teid;
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
} gtpu_header_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  u8 type;
  u8 len;
  u16 pad;
}) gtpu_ext_header_t;
/* *INDENT-ON* */

#define GTPU_V1_HDR_LEN   8

#define GTPU_VER_MASK (7<<5)
#define GTPU_PT_BIT   (1<<4)
#define GTPU_E_BIT    (1<<2)
#define GTPU_S_BIT    (1<<1)
#define GTPU_PN_BIT   (1<<0)
#define GTPU_E_S_PN_BIT  (7<<0)

#define GTPU_V1_VER   (1<<5)

#define GTPU_PT_GTP    (1<<4)
#define GTPU_TYPE_ECHO_REQUEST  1
#define GTPU_TYPE_ECHO_RESPONSE 2
#define GTPU_TYPE_ERROR_IND    26
#define GTPU_TYPE_END_MARKER  254
#define GTPU_TYPE_GTPU  255

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;	       /* 8 bytes */
}) ip4_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;     /* 8 bytes */
}) ip6_gtpu_header_t;
/* *INDENT-ON* */

/* Packed so that the mhash key doesn't include uninitialized pad bytes */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip46_address_t addr;
  u32 fib_index;
}) ip46_address_fib_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: src intf and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src_intf;
      u32 teid;
    };
    u64 as_u64;
  };
}) gtpu_intf_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 dst;
      u32 teid;
    };
    u64 as_u64;
  };
}) gtpu4_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  gtpu4_tunnel_key_t key;
  u32 rule_index;
} gtpu4_endp_rule_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  ip6_address_t dst;
  u32 teid;
}) gtpu6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  gtpu6_tunnel_key_t key;
  u32 rule_index;
} gtpu6_endp_rule_t;

typedef struct
{
  u32 teid;
  ip46_address_t addr;
  u16 port;
} gtp_error_ind_t;

typedef struct
{
  ip46_address_t address;
  u8 mask;
} ipfilter_address_t;

typedef struct
{
  u16 min;
  u16 max;
} ipfilter_port_t;

typedef struct
{
  enum
  {
    IPFILTER_WILDCARD = 0,
    IPFILTER_IPV4,
    IPFILTER_IPV6,
  } type;
  enum
  {
    ACL_PERMIT,
    ACL_DENY
  } action;
  enum
  {
    ACL_IN,
    ACL_OUT
  } direction;
  u8 proto;
  ipfilter_address_t address[2];
  ipfilter_port_t port[2];
} acl_rule_t;

#define IPFILTER_RULE_FIELD_SRC 0
#define IPFILTER_RULE_FIELD_DST 1

#define ACL_ADDR_ANY				\
  (ipfilter_address_t){				\
    .address.as_u64 = {(u64)~0, (u64)~0},	\
    .mask = 0,					\
  }

#define acl_addr_is_any(ip)			\
  ((~0 == (ip)->address.as_u64[0]) &&		\
   (~0 == (ip)->address.as_u64[1]) &&		\
   ((u8)0 == (ip)->mask))

#define ACL_ADDR_ASSIGNED			\
  (ipfilter_address_t){				\
    .address.as_u64 = {(u64)~0, (u64)~0},	\
    .mask = (u8)~0,				\
  }

#define acl_addr_is_assigned(ip)		\
  ((~0 == (ip)->address.as_u64[0]) &&		\
   (~0 == (ip)->address.as_u64[1]) &&		\
   ((u8)~0 == (ip)->mask))

#define INTF_INVALID	((u8)~0)

typedef enum
{
  UPF_UL = 0,
  UPF_DL,
  UPF_DIRECTION_MAX
} upf_direction_t;

typedef struct
{
  u32 application_id;
  u32 db_id;
  u32 flags;
} adr_rule_t;

typedef struct
{
  u8 protocol;
  ip46_address_t address[2];
  u16 port[2];
} upf_acl_5tuple_t;

typedef struct
{
  u32 precedence;

  int is_ip4:1;
  int match_teid:1;
  int match_ue_ip:3;
  int match_sdf:1;

  u32 fib_index;
  u32 teid;			// TEID
  ip46_address_t ue_ip;		// UE-IP

  /* SDF */
  upf_acl_5tuple_t mask;
  upf_acl_5tuple_t match;

  /* volatile struct members, not used for sorting */
  u32 pdr_idx;
} upf_acl_t;

#define UPF_ACL_FIELD_SRC 0
#define UPF_ACL_FIELD_DST 1
#define UPF_ACL_UL 1
#define UPF_ACL_DL 2

/* Packet Detection Information */
typedef struct
{
  pfcp_source_interface_t src_intf;
  u32 nwi_index;

  u32 fields;
#define F_PDI_LOCAL_F_TEID    0x0001
#define F_PDI_UE_IP_ADDR      0x0004
#define F_PDI_SDF_FILTER      0x0008
#define F_PDI_APPLICATION_ID  0x0010

  pfcp_f_teid_t teid;
  pfcp_ue_ip_address_t ue_addr;
  acl_rule_t *acl;
  adr_rule_t adr;
} upf_pdi_t;

/* Packet Detection Rules */
typedef struct
{
  u32 id;
  u16 precedence;

  upf_pdi_t pdi;
  u8 outer_header_removal;
  u16 far_id;
  u16 *urr_ids;
  u32 *qer_ids;
} upf_pdr_t;

/* Forward Action Rules - Forwarding Parameters */
typedef struct
{
  u16 flags;
#define FAR_F_REDIRECT_INFORMATION	BIT(0)
#define FAR_F_OUTER_HEADER_CREATION	BIT(1)

  pfcp_destination_interface_t dst_intf;
  u32 dst_sw_if_index;
  u32 nwi_index;

  pfcp_redirect_information_t redirect_information;
  pfcp_outer_header_creation_t outer_header_creation;

  u32 peer_idx;
  u8 *rewrite;
} upf_far_forward_t;

/* Forward Action Rules */
typedef struct
{
  u16 id;
  u16 apply_action;
#define FAR_DROP       0x0001
#define FAR_FORWARD    0x0002
#define FAR_BUFFER     0x0004
#define FAR_NOTIFY_CP  0x0008
#define FAR_DUPLICATE  0x0010

  union
  {
    upf_far_forward_t forward;
    u16 bar_id;
  };
} upf_far_t;

typedef struct
{
  u16 far_id;
  u32 fib_index;
  u32 dpoi_index;
} send_end_marker_t;

/* Counter */

#define URR_OK                  0
#define URR_QUOTA_EXHAUSTED     BIT(0)
#define URR_THRESHOLD_REACHED   BIT(1)
#define URR_START_OF_TRAFFIC    BIT(2)

/* TODO: measure if more optimize cache line aware layout
 *       of the counters and quotas has any performance impcat */
typedef struct
{
  u64 ul;
  u64 dl;
  u64 total;
} urr_counter_t;

typedef struct
{
  urr_counter_t packets;
  urr_counter_t bytes;
  urr_counter_t consumed;
} urr_measure_t;

typedef struct
{
  urr_measure_t measure;
  urr_counter_t threshold;
  urr_counter_t quota;
} urr_volume_t;

typedef struct
{
  f64 base;
  u32 period;			/* relative duration in seconds */
  f64 expected;
  u32 handle;
} urr_time_t;

typedef struct
{
  f64 unix_time;
  f64 vlib_time;
} urr_abs_time_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip46_address_t ip;
  //TODO: timeout
  f64 first_seen;
} upf_urr_traffic_t;

/* Usage Reporting Rules */
typedef struct
{
  u16 id;
  u16 methods;
#define PFCP_URR_TIME   0x0001
#define PFCP_URR_VOLUME 0x0002
#define PFCP_URR_EVENT  0x0004

  u16 triggers;

  u8 status;
#define URR_OVER_QUOTA                  BIT(0)
#define URR_AFTER_MONITORING_TIME       BIT(1)

  u8 update_flags;
#define PFCP_URR_UPDATE_VOLUME_QUOTA		BIT(0)
#define PFCP_URR_UPDATE_TIME_QUOTA		BIT(1)
#define PFCP_URR_UPDATE_TIME_THRESHOLD		BIT(2)
#define PFCP_URR_UPDATE_MONITORING_TIME		BIT(3)
#define PFCP_URR_UPDATE_MEASUREMENT_PERIOD	BIT(4)

  u32 seq_no;
  f64 start_time;

  f64 time_of_first_packet;
  f64 time_of_last_packet;
  urr_volume_t volume;

  urr_time_t measurement_period;	/* relative duration in seconds */
  urr_time_t time_threshold;	/* relative duration in seconds */
  urr_time_t time_quota;	/* relative duration in seconds */
  urr_time_t quota_holding_time;	/* relative duration in seconds */
  urr_abs_time_t monitoring_time;	/* absolute UTC ts since 1900-01-01 00:00:00 */

  struct
  {
    f64 start_time;
    f64 time_of_first_packet;
    f64 time_of_last_packet;
    urr_measure_t volume;
  } usage_before_monitoring_time;

  /* pool of urr traffic info */
  upf_urr_traffic_t *traffic;
  uword *traffic_by_ue;
  urr_time_t traffic_timer;

  pfcp_linked_urr_id_t *linked_urr_ids;
  uword *liusa_bitmap;
} upf_urr_t;

/* QoS Enforcement Rules */
typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  policer_read_response_type_st policer[UPF_DIRECTION_MAX];

  u64 ref_cnt;
  pfcp_mbr_t mbr;
} upf_qer_policer_t;

typedef struct
{
  u32 id;

  u8 flags;
#define PFCP_QER_MBR				BIT(0)

  u8 gate_status[UPF_DIRECTION_MAX];

  pfcp_mbr_t mbr;
  clib_bihash_kv_8_8_t policer;
} upf_qer_t;

typedef struct
{
  ip46_address_t addr;
  u32 fib_index;
  u32 sw_if_index;
} ue_ip_t;

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* most updated fields first */
  clib_spinlock_t lock;
  f64 last_ul_traffic;

  ip46_address_t up_address;
  u64 cp_seid;
  ip46_address_t cp_address;

  struct
  {
    u32 node;
    u32 next;
    u32 prev;
  } assoc;

  uint32_t flags;
#define PFCP_UPDATING    0x8000

  volatile int active;

  struct rules
  {
    /* vector of Packet Detection Rules */
    upf_pdr_t *pdr;
    upf_far_t *far;
    upf_urr_t *urr;
    upf_qer_t *qer;
    uint32_t flags;
#define PFCP_SDF_IPV4	BIT(0)
#define PFCP_SDF_IPV6	BIT(1)
#define PFCP_ADR		BIT(2)
#define PFCP_CLASSIFY	BIT(3)

    u16 proxy_precedence;
    u32 proxy_pdr_idx;

    upf_acl_t *v4_acls;
    upf_acl_t *v6_acls;

    ue_ip_t *ue_src_ip;
    ue_ip_t *ue_dst_ip;
    gtpu4_endp_rule_t *v4_teid;
    gtpu6_endp_rule_t *v6_teid;

    send_end_marker_t *send_end_marker;
    urr_time_t inactivity_timer;
  } rules[2];
#define PFCP_ACTIVE  0
#define PFCP_PENDING 1

  /** FIFO to hold the DL pkts for this session */
  vlib_buffer_t *dl_fifo;

  /* DPO locks */
  u32 dpo_locks;

  f64 unix_time_start;
} upf_session_t;


typedef enum
{
#define upf_gtpu_error(n,s) UPF_GTPU_ERROR_##n,
#include <upf/upf_gtpu_error.def>
#undef upf_gtpu_error
  UPF_GTPU_N_ERROR,
} upf_gtpu_input_error_t;

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  uword ref_cnt;

  fib_forward_chain_type_t forw_type;
  u32 encap_index;

  /* The FIB index for src/dst addresses (vrf) */
  u32 encap_fib_index;

  /* FIB DPO for IP forwarding of gtpu encap packet */
  dpo_id_t next_dpo;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /* The FIB entry for sending unicast gtpu encap packets */
  fib_node_index_t fib_entry_index;

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;
} upf_peer_t;

typedef struct
{
  ip46_address_fib_t key;
} upf_pfcp_endpoint_t;

typedef struct
{
  ip4_address_t ip4;
  ip6_address_t ip6;
  u32 nwi_index;
  u8 intf;
  u32 teid;
  u32 mask;
} upf_upip_res_t;

typedef struct
{
  u8 *name;
  u32 fib_index[FIB_PROTOCOL_IP_MAX];

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;
} upf_nwi_t;

typedef struct
{
  /* Required for pool_get_aligned  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  pfcp_node_id_t node_id;
  pfcp_recovery_time_stamp_t recovery_time_stamp;

  session_handle_t session_handle;
  ip46_address_t rmt_addr;
  ip46_address_t lcl_addr;

  u32 sessions;
  u32 heartbeat_handle;
} upf_node_assoc_t;

typedef u8 *regex_t;

typedef struct
{
  u32 id;			/* bit 31 == 1 indicates PFD from CP */
  regex_t regex;
} upf_adr_t;

typedef struct
{
  u8 *name;
  u32 flags;
  uword *rules_by_id;		/* hash over rules id */
  upf_adr_t *rules;		/* vector of rules definition */
  u32 db_index;			/* index in ADR pool */
} upf_adf_app_t;

#define UPF_ADR_PROXY   BIT(0)

#define UPF_ADR_PROTO_HTTP  1
#define UPF_ADR_PROTO_HTTPS 2

typedef enum
{
 ADR_FAIL = 0,
 ADR_OK,
 ADR_NEED_MORE_DATA
} adr_result_t;

/* bihash buckets are cheap, only 8 bytes per bucket */
#define UPF_MAPPING_BUCKETS      (64 * 1024)

/* 128 MB per hash max memory,
 *    ~ max. 64k per bucket
 *    ~ 1024 pages with 4 values each
 * 8 million entries total.
 *
 * A older setting with max 1M entries run out of memory with 200k entries
 * Pages are grown to contain log2 entries, the memory fragmentation caused
 * by smaller pages that are keept arround eats significant amount of memory
 * from bihash.
 */
#define UPF_MAPPING_MEMORY_SIZE  (2 << 27)

typedef struct
{
  upf_pfcp_endpoint_t *pfcp_endpoints;
  mhash_t pfcp_endpoint_index;

  /* vector of network instances */
  upf_nwi_t *nwis;
  uword *nwi_index_by_name;

  /* Free vlib hw_if_indices */
  u32 *free_nwi_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *nwi_index_by_sw_if_index;

  /* pool of network instances */
  upf_upip_res_t *upip_res;
  mhash_t upip_res_index;

  /* vector of encap tunnel instances */
  upf_session_t *sessions;

  /* lookup tunnel by key */
  uword *session_by_id;		/* keyed session id */

  /* lookup tunnel by TEID */
  clib_bihash_8_8_t v4_tunnel_by_key;	/* keyed session id */
  clib_bihash_24_8_t v6_tunnel_by_key;	/* keyed session id */

  /* lookup session by ingress VRF and UE (src) IP */
  //  clib_bihash_8_8_t *session_by_tdf_ue_ip;
  u32 *tdf_ul_table[FIB_PROTOCOL_IP_MAX];

  /* policer pool, aligned */
  upf_qer_policer_t *qer_policers;
  clib_bihash_8_8_t qer_by_id;

  /* list of remote GTP-U peer ref count used to stack FIB DPO objects */
  upf_peer_t *peers;
  clib_bihash_24_8_t peer_index_by_ip;	/* remote GTP-U peer keyed on it's ip addr and vrf */

  /* vector of associated PFCP nodes */
  upf_node_assoc_t *nodes;
  /* lookup PFCP nodes */
  mhash_t node_index_by_ip;
  uword *node_index_by_fqdn;

#if 0
  uword *vtep4;
  uword *vtep6;
#endif

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;

  /* adf apps hash */
  uword *upf_app_by_name;
  /* adf apps vector */
  upf_adf_app_t *upf_apps;
} upf_main_t;

extern const fib_node_vft_t upf_vft;
extern upf_main_t upf_main;

extern vlib_node_registration_t upf_gtpu4_input_node;
extern vlib_node_registration_t upf_gtpu6_input_node;
extern vlib_node_registration_t upf4_encap_node;
extern vlib_node_registration_t upf6_encap_node;

typedef enum
{
  UPF_FORWARD_NEXT_DROP,
  UPF_FORWARD_NEXT_GTP_IP4_ENCAP,
  UPF_FORWARD_NEXT_GTP_IP6_ENCAP,
  UPF_FORWARD_NEXT_IP_INPUT,
  UPF_FORWARD_NEXT_PROXY_ACCEPT,
  UPF_FORWARD_N_NEXT,
} upf_forward_next_t;

typedef struct
{
  u32 session_index;
  u32 teid;
} upf_encap_trace_t;

u8 *format_upf_encap_trace (u8 * s, va_list * args);
u32 upf_gtpu_end_marker (u32 fib_index, u32 dpoi_index, u8 * rewrite,
			 int is_ip4);

int vnet_upf_pfcp_endpoint_add_del (ip46_address_t * ip, u32 fib_index,
				    u8 add);
int vnet_upf_nwi_add_del (u8 * name, u32 ip4_table_id, u32 ip6_table_id,
			  u8 add);
int vnet_upf_upip_add_del (ip4_address_t * ip4, ip6_address_t * ip6,
			   u8 * name, u8 intf, u32 teid, u32 mask, u8 add);

int vnet_upf_tdf_ul_enable_disable (fib_protocol_t fproto, u32 sw_if_index,
				    int is_en);
int vnet_upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto,
				   u32 table_id, u8 add);

void upf_session_dpo_add_or_lock (dpo_proto_t dproto, upf_session_t * sx,
				  dpo_id_t * dpo);

#endif /* __included_upf_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
