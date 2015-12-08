/* 
 *------------------------------------------------------------------
 * nat64_defs.h - NAT64 structure definiitions
 *
 * Copyright (c) 2007-2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __NAT64_DEFS_H__
#define __NAT64_DEFS_H__

#ifdef TOBE_PORTED
#include "spp_platform_common.h"
#include "cgse_defs.h"
#include "xlat_defs.h"
#endif
#include "cnat_cli.h"
#include "cnat_ports.h"
#include "tcp_header_definitions.h"
#include "nat64_tcp_sm.h"
#include "cnat_db.h"

#define NAT64_MAX_FRAG_ID_COUNTERS (256)

#define NAT64_MAX_NAT64_ENTRIES 500

#define NAT64_MAX_ID      (NAT64_MAX_NAT64_ENTRIES-1)

#define NAT64_INVALID_ID  (0)

#define NAT64_MAX_CFG_INSTANCES 64

#define NAT64_TABLE_ENTRY_DELETED      0
#define NAT64_TABLE_ENTRY_ACTIVE       1
#define NAT64_TABLE_ENTRY_DORMANT      2
#define NAT64_TABLE_ENTRY_INVALID_UIDB 3

#define NAT64_MAX_TRANSLATION_ENTRIES PLATFORM_MAX_TRANSLATION_ENTRIES

#define NAT64_WKP_PREFIX_LEN  96
#define NAT64_WKP_PREFIX_0    0x0064FF9B
#define NAT64_WKP_PREFIX_1    0x00000000
#define NAT64_WKP_PREFIX_2    0x00000000
#define NAT64_WKP_PREFIX_3    0x00000000


/* Reset the expiry time only if it is not 0
**  if it is 0 - then queue for delete by clear command
**/

#define  NAT64_TIMEOUT_RST(db)  \
                 if(PREDICT_TRUE(db->entry_expires !=0 )) \
                        db->entry_expires = cnat_current_time;  

extern u32 nat64_config_debug_level;
extern u32 nat64_data_path_debug_level;

extern u32 nat64_translation_create_count[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_translation_delete_count[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_translation_create_rate[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_translation_delete_rate[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_in2out_forwarding_count[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_in2out_forwarding_rate[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_out2in_forwarding_count[NAT64_MAX_NAT64_ENTRIES];
extern u32 nat64_out2in_forwarding_rate[NAT64_MAX_NAT64_ENTRIES];

extern u32  nat64_translation_create_count_old[NAT64_MAX_NAT64_ENTRIES];
extern u32  nat64_translation_delete_count_old[NAT64_MAX_NAT64_ENTRIES];
extern u32  nat64_in2out_forwarding_count_old[NAT64_MAX_NAT64_ENTRIES];
extern u32  nat64_out2in_forwarding_count_old[NAT64_MAX_NAT64_ENTRIES];

extern u16 *nat64_frag_id_counter_ptr;

typedef struct {
    u64 v6_to_v4_tcp_input_count;
    u64 v6_to_v4_tcp_non_translatable_drop_count;
    u64 v6_to_v4_tcp_state_drop_count;
    u64 v6_to_v4_tcp_no_db_drop_count;
    u64 v6_to_v4_tcp_output_count;
} nat64_v6_to_v4_tcp_counter_t;

typedef struct {
    u64 v4_to_v6_tcp_input_count;
    u64 v4_to_v6_tcp_no_db_drop_count;
    u64 v4_to_v6_tcp_v4_init_policy_drop_count;
    u64 v4_to_v6_tcp_state_drop_count;
    u64 v4_to_v6_tcp_output_count;
    u64 v4_to_v6_tcp_filter_drop_count;
} nat64_v4_to_v6_tcp_counter_t;

typedef struct {
    u64 v6_to_v4_udp_input_count;
    u64 v6_to_v4_udp_non_translatable_drop_count;
    u64 v6_to_v4_udp_no_db_drop_count;
    u64 v6_to_v4_udp_output_count;
    u64 v6_to_v4_udp_checksum_zero_count;
} nat64_v6_to_v4_udp_counter_t;

typedef struct {
    u64 v4_to_v6_udp_input_count;
    u64 v4_to_v6_udp_no_db_drop_count;
    u64 v4_to_v6_udp_filter_drop_count;
    u64 v4_to_v6_udp_output_count;
    u64 v4_to_v6_udp_crc_zero_drop_count;
    u64 v4_to_v6_udp_frag_crc_zero_drop_count;
    u64 v4_to_v6_udp_crc_zero_recycle_sent_count;
    u64 v4_to_v6_udp_crc_zero_recycle_drop_count;
} nat64_v4_to_v6_udp_counter_t;

typedef struct {
    u64 v6_to_v4_icmp_input_count;
    u64 v6_to_v4_icmp_no_db_drop_count;
    u64 v6_to_v4_icmp_non_translatable_drop_count;
    u64 v6_to_v4_icmp_qry_output_count;
} nat64_v6_to_v4_icmp_counter_t;

typedef struct {
    u64 v4_to_v6_icmp_input_count;
    u64 v4_to_v6_icmp_no_db_drop_count;
    u64 v4_to_v6_icmp_filter_drop;
    u64 v4_to_v6_icmp_qry_output_count;
} nat64_v4_to_v6_icmp_counter_t;

typedef struct {
    u64 v6_to_v4_icmp_error_input_count;
    u64 v6_to_v4_icmp_error_no_db_drop_count;
    u64 v6_to_v4_icmp_error_invalid_next_hdr_drop_count;
    u64 v6_to_v4_icmp_error_non_translatable_drop_count;
    u64 v6_to_v4_icmp_error_unsupported_type_drop_count;
    u64 v6_to_v4_icmp_error_output_count;
} nat64_v6_to_v4_icmp_error_counter_t;

typedef struct {
    u64 v4_to_v6_icmp_error_input_count;
    u64 v4_to_v6_icmp_error_no_db_drop_count;
    u64 v4_to_v6_icmp_error_unsupported_type_drop_count;
    u64 v4_to_v6_icmp_error_unsupported_protocol_drop_count;
    u64 v4_to_v6_icmp_error_output_count;
} nat64_v4_to_v6_icmp_error_counter_t;



typedef struct {
    u64 nat64_v4_frag_input_count;
    u64 nat64_v4_frag_forward_count;
    u64 nat64_v4_frag_drop_count;
    u64 nat64_v4_frag_throttled_count;
    u64 nat64_v4_frag_timeout_drop_count;
    u64 nat64_v4_frag_tcp_input_count;
    u64 nat64_v4_frag_udp_input_count;
    u64 nat64_v4_frag_icmp_input_count;

    u64 nat64_v6_frag_input_count;
    u64 nat64_v6_frag_forward_count;
    u64 nat64_v6_frag_drop_count;
    u64 nat64_v6_frag_throttled_count;
    u64 nat64_v6_frag_timeout_drop_count;
    u64 nat64_v6_frag_tcp_input_count;
    u64 nat64_v6_frag_udp_input_count;
    u64 nat64_v6_frag_icmp_input_count;
    u64 nat64_v6_frag_invalid_input_count;
} nat64_frag_counter_t;

typedef struct {
    u64 v6_to_v4_options_input_count;
    u64 v6_to_v4_options_drop_count;
    u64 v6_to_v4_options_forward_count;
    u64 v6_to_v4_options_no_db_drop_count;
    u64 v6_to_v4_unsupp_proto_count;

    u64 v4_to_v6_options_input_count;
    u64 v4_to_v6_options_drop_count;
    u64 v4_to_v6_options_forward_count;
    u64 v4_to_v6_options_no_db_drop_count;
    u64 v4_to_v6_unsupp_proto_count;
} nat64_options_counter_t;

typedef struct {
    u64 v4_icmp_gen_count;
    u64 v6_icmp_gen_count;
} nat64_icmp_gen_counter_t;

typedef struct{
    u32 nat64_num_translations;
    u32 nat64_num_dynamic_translations;
    u32 nat64_num_static_translations;
    u32 nat64_sessions;
    u64 nat64_port_limit_exceeded;
    u64 nat64_system_limit_reached;
    u64 nat64_resource_depletion_drops;
    u64 nat64_no_translation_entry_drops;
    u64 nat64_filtering_drops ;
    u64 nat64_invalid_ipv6_prefix_drops;
    u32 num_subscribers;
    u32 dummy;
    u64 drops_sessiondb_limit_exceeded;
} nat64_inst_gen_counter_t;

typedef struct {

    nat64_v6_to_v4_tcp_counter_t  v64_tcp_counters;
    nat64_v4_to_v6_tcp_counter_t  v46_tcp_counters;
    nat64_v6_to_v4_udp_counter_t  v64_udp_counters;
    nat64_v4_to_v6_udp_counter_t  v46_udp_counters;
    nat64_v6_to_v4_icmp_counter_t  v64_icmp_counters;
    nat64_v4_to_v6_icmp_counter_t v46_icmp_counters;
    nat64_v6_to_v4_icmp_error_counter_t  v64_icmp_error_counters;
    nat64_v4_to_v6_icmp_error_counter_t v46_icmp_error_counters;
    nat64_frag_counter_t           nat64_frag_counters;
    nat64_options_counter_t        nat64_options_counters;
    nat64_icmp_gen_counter_t       nat64_icmp_gen_counters;

} nat64_counters_t;

/*
 * nat64_portmap_v2_t
 * This structure stores information about the IP address and ports 
 * available for NAT for this nat64 instance. 
 */

typedef struct {
    u32 delete_time;
    u32 last_sent_timestamp;
    u32 inuse;
    u32 ipv4_address;           /* native bit order */
    uword bm[(BITS_PER_INST + BITS(uword)-1)/BITS(uword)];
} nat64_portmap_t;

/*
 * nat64_v4_db_key_t
 * This structure gives information about the v4 transport address 
 * (ipv4, port, protocol)
 */
typedef struct {
    u32 ipv4;
    u16 port;
    u16 vrf;  //bit0-12:inst_id, bit13:unused, bit14-15:protocol
} nat64_v4_db_key_t;

/* Union will be easier while compare/hash */
typedef union {
    nat64_v4_db_key_t k;
    u64 key64;
} nat64_v4_key_t;
/*
 * nat64_v6_db_key_t
 * This structure gives information about the v6 transport address 
 * (ipv6, port, protocol)
 */
typedef struct {
    u32 ipv6[4];
    u16 port;
    u16 vrf;  //bit0-12:inst_id, bit13:unused, bit14-15:protocol
} nat64_v6_key_t;


typedef struct  {
    u16 udp_timeout;
    u16 tcp_trans_timeout;
    u16 tcp_est_timeout;
    u16 tcp_v4_init_timeout;
    u16 frag_timeout;
    u16 icmp_timeout;
} nat64_timeout_info_t;

#define NAT64_UDP_DEF             300 /* 5min */
#define NAT64_TCP_TRANS_DEF       240 /* 4min */
#define NAT64_TCP_EST_DEF        7200 /* 2Hrs */
#define NAT64_TCP_V4_DEF            6 /* 6 sec */
#define NAT64_FRAG_DEF              2 /* 2 sec */
#define NAT64_ICMP_DEF             60 /* 60 sec */

/* 
 * nat64_table_entry_t
 * This structure is used to store information regarding every nat64 instance. 
 */

/* structure will hold the L4 information, of a particular frag stream set 
 *  src_port - holds the original src port
 *  dst_port - holds the original dst port
 *  total_len - useful only in ICMP nodes
 *  cnat_port - vlaue used for looksups
 *  next_prot - Protocol after translation   */
 
typedef struct l4_frag_info {
  u16 next_node_idx;
  u16 src_port;
  u16 dst_port;
  u16 total_length;
  u8  protocol;
  u16  cnat_prot;
  u16  next_prot;    
} l4_frag_info_t;

typedef struct {
    u16 state;
    u16 nat64_id; /* nat64_id value for this table entry - for easy access */

    u16 v4_uidb_index;     /* V4 uidb index */
    u16 v6_uidb_index;     /* V6 uidb index */

    u8  octet0_position;
    u8  octet1_position;
    u8  octet2_position;
    u8  octet3_position;

    u16 v4_to_v6_tcp_mss;     /* TCP MSS */
    u16 v6_to_v4_tcp_mss;     /* TCP MSS */

    /*
     * V6 NAT64 prefix value and mask size
     */
    u32 v6_prefix[4];
    u32 v6_prefix_mask[4];

    u8  v6_prefix_mask_len;
    u8  ubits_reserved_on;
#define IPV4_TOS_OVERRIDE_FLAG 0x1
#define IPV6_TOS_OVERRIDE_FLAG 0x2
#define NAT64_STFUL_RTSP_ALG_ENABLE  0x4
    u8  feature_flags;

    u8 ipv4_tos_value;
    u8 ipv6_tos_value;
    u8 df_bit_clear;
    u8 ipv6_mtu_set;

    u8 filtering_policy;
#define NAT64_ADDRESS_DEPENDENT_ENABLE  1
    u8 tcp_policy;
#define NAT64_TCP_SECURITY_FLAG_DISABLE 1
    u8 ftp_flags;

    u8 tcp_v4_init_enable;
#define NAT64_TCP_V4_INIT_ENABLE        1

    u8  logging_policy;
#define NAT64_BIB_LOG_ENABLE 0  /* Default */
#define NAT64_SESSION_LOG_ENABLE 1

#define NAT64_BIDIR_REFRESH   1     /* 1 - timer refresh in both direction */
#define NAT64_UNIDIR_REFRESH  0     /*  0 - default (only v6 side refresh timer)*/

    u8  nat64_refresh_both_direction; /* 0 - default (only v6 side refresh timer) */
#define NAT64_BIDIR_REFRESH   1     /* 1 - timer refresh in both direction */

    u8  udp_zero_checksum; /* 0 - default (calc checksum) */
#define NAT64_UDP_ZERO_CHECKSUM_DROP  1  /* 1 -drop */ 

    u16 port_limit;

    cnat_portmap_v2_t *port_map;

    u32 logging_index;
   
    nat64_timeout_info_t timeout_info;
    /*
     * These fields are not used much, let us keep it in the end
     */
    u32 v4_vrf_id;  /* V4 vrf id */
    u32 v6_vrf_id;  /* V6 vrf id */

    u32 v4_if_num;  /* V4 SVI ifnum */
    u32 v6_if_num;  /* V6 SVI ifnum */

    u16 dyn_start_port;

    u16 pcp_server_port;
    u32 pcp_server_addr[4];
    u32 rseed_ip;
#define NAT64_FRAG_ENABLE     1
#define NAT64_FRAG_DISABLE    0
     u8  frag_state;
     u8  nat64_enable; /* Enable/Disable this instance. */

     u16 rtsp_port;

}  nat64_table_entry_t;



extern nat64_table_entry_t         nat64_table_array[NAT64_MAX_NAT64_ENTRIES];
extern nat64_table_entry_t         *nat64_table_ptr;
extern nat64_counters_t    nat64_all_counters[NAT64_MAX_NAT64_ENTRIES];
extern nat64_inst_gen_counter_t       nat64_inst_gen_counters[NAT64_MAX_NAT64_ENTRIES];

typedef struct nat64_common_pipeline_data_ {
#ifdef TOBE_PORTED
    spp_node_main_vector_t *nmv;
#endif

    u16                *nat64_id_ptr;

    nat64_table_entry_t *nat64_entry_ptr;

} nat64_common_pipeline_data_t;

typedef struct nat64_v6_to_v4_pipeline_data_ {
    nat64_common_pipeline_data_t common_data;

    u32                 bib_bucket;
    u32                 session_bucket;

    nat64_v6_key_t      v6_in_key;
    nat64_v6_key_t      v6_dest_key;

    /*
     * IPv6 Data, everthing in host order except for the addr fields
     */
    u32                 version_trafficclass_flowlabel;

    u16                 payload_length;
    u8                  next_header;
    u8                  hop_limit;

    /*
     * These Address fields are in Network Order, so that
     * it is easy to extract the IPv4 address from them
     */
    u32                 ipv6_src[4];

    u32                 ipv6_dst[4];

    u8                  frag_next_header;
    u8                  frag_reserved;
    u16                 frag_offset_res_m;
    u32                 frag_identification;

    ipv4_header         *ipv4_header;
    union {
        struct _v4_l4_info {
            u8                 *ipv4_l4_header;
            u8                 pad0;
            u8                 pad1;
            u8                 pad2;
            u8                 pad3;
        } v4_l4_info;
        struct _v4_icmp_info {
            icmp_v4_t           *ipv4_icmp_header;
            u8                  old_icmp_type;
            u8                  new_icmp_type;
            u8                  old_icmp_code;
            u8                  new_icmp_code;
            u16                 checksum;
            u16                 old_iden; // length (ICMP extn), ptr (param)
            u16                 new_iden; // ----- do -------------
            u16                 old_seq; // MTU for PTB case
            u16                 new_seq; // ----- do -------------
        } v4_icmp_info;
        struct _v4_udp_info {
            udp_hdr_type_t      *ipv4_udp_header;
            u8                  pad0;
            u8                  pad1;
            u8                  pad2;
            u8                  pad3;
        } v4_udp_info;
        struct _v4_tcp_info {
            tcp_hdr_type        *ipv4_tcp_header;
            u16                 old_src_port;
            u16                 new_src_port;
            u16                 dest_port;
            nat64_tcp_events    tcp_event;
        } v4_tcp_info;
    } l4_u;


   l4_frag_info_t      *frag_info; /* port for tcp/udp, ident - icmp */


    /* Counters will be added here */
    union {
        nat64_v6_to_v4_tcp_counter_t  *tcp_counter;
        nat64_v6_to_v4_udp_counter_t  *udp_counter;
        nat64_v6_to_v4_icmp_counter_t *icmp_counter;
        nat64_v6_to_v4_icmp_error_counter_t *icmp_error_counter;
        nat64_frag_counter_t          *frag_counter;
        nat64_options_counter_t       *options_counter;
    } nat64_ctr_u;
    nat64_icmp_gen_counter_t      *icmp_gen_counter;
} nat64_v6_to_v4_pipeline_data_t;


typedef struct nat64_v4_to_v6_pipeline_data_ {
    nat64_common_pipeline_data_t common_data;

    u32                 bib_bucket;
    u32                 session_bucket;

    nat64_v4_key_t      v4_src_key; /* Will be translated using Prefix */
    nat64_v4_key_t      v4_dest_key; /* will be the out key for NAT64 */

    /*
     * IPv4 data
     */
    u8                  version_hdr_len_words;
    u8                  tos;
    u16                 total_len_bytes;

    u16                 identification;
    u16                 frag_flags_offset;

    u8                  ttl;
    u8                  protocol;
    u16                 l4_checksum;

    u32                 ipv4_src_addr;
    u32                 ipv4_dst_addr;

    /*
     * Pointers to IPv6 headers
     */
    ipv6_header_t       *ipv6_header;
    ipv6_frag_header_t  *ipv6_frag_header;

    union {
        struct _v6_l4_info {
            u8                  *ipv6_l4_header;
            u8                  pad0;
            u8                  pad1;
            u8                  pad2;
            u8                  pad3;
        } v6_l4_info;
        struct _v6_icmp_info {
            icmp_v6_t           *ipv6_icmp_header;
            u8                  old_icmp_type;
            u8                  new_icmp_type;
            u8                  old_icmp_code;
            u8                  new_icmp_code;
            u16                 old_iden; // length (ICMP extn), ptr (param)
            u16                 new_iden; // ----- do -------------
            u16                 old_seq; // MTU for PTB case
            u16                 new_seq; // ----- do -------------
        } v6_icmp_info;
        struct _v6_udp_info {
            udp_hdr_type_t      *ipv6_udp_header;
            u8                  pad0;
            u8                  pad1;
            u8                  pad2;
            u8                  pad3;
        } v6_udp_info;
        struct _v6_tcp_info {
            tcp_hdr_type        *ipv6_tcp_header;
            u16                 old_dest_port;
            u16                 new_dest_port;
            u16                 src_port;
            nat64_tcp_events    tcp_event;
        } v6_tcp_info;
    } l4_u;

    l4_frag_info_t      *frag_info; /* port for tcp/udp, ident - icmp */

    /* Need to add counters here */
    union {
        nat64_v4_to_v6_tcp_counter_t  *tcp_counter;
        nat64_v4_to_v6_udp_counter_t  *udp_counter;
        nat64_v4_to_v6_icmp_counter_t *icmp_counter;
        nat64_v4_to_v6_icmp_error_counter_t *icmp_error_counter;
        nat64_frag_counter_t          *frag_counter;
        nat64_options_counter_t       *options_counter;
    } nat64_ctr_u;
    nat64_icmp_gen_counter_t      *icmp_gen_counter;

} nat64_v4_to_v6_pipeline_data_t;

#endif
