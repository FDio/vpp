/* 
 *------------------------------------------------------------------
 * dslite_defs.h - DSLITE structure definiitions
 *
 * Copyright (c) 2011-2012 Cisco and/or its affiliates.
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

#ifndef __DSLITE_DEFS_H__
#define __DSLITE_DEFS_H__

#ifdef TOBE_PORTED
#include "spp_platform_common.h"
#include "cgse_defs.h"
#endif
#include "cnat_cli.h"
#include "cnat_config.h"
#include "cnat_ports.h"
#include "cnat_bulk_port_defs.h"

extern u32 ds_lite_config_debug_level;

#define SWAP_IPV6_ADDR(ipv6_hdr, dslite_entry_ptr) \
    ipv6_hdr->dst_addr[0] = ipv6_hdr->src_addr[0]; \
    ipv6_hdr->dst_addr[1] = ipv6_hdr->src_addr[1]; \
    ipv6_hdr->dst_addr[2] = ipv6_hdr->src_addr[2]; \
    ipv6_hdr->dst_addr[3] = ipv6_hdr->src_addr[3]; \
    ipv6_hdr->src_addr[0] = spp_host_to_net_byte_order_32(dslite_entry_ptr->AFTR_v6_address[0]); \
    ipv6_hdr->src_addr[1] = spp_host_to_net_byte_order_32(dslite_entry_ptr->AFTR_v6_address[1]); \
    ipv6_hdr->src_addr[2] = spp_host_to_net_byte_order_32(dslite_entry_ptr->AFTR_v6_address[2]); \
    ipv6_hdr->src_addr[3] = spp_host_to_net_byte_order_32(dslite_entry_ptr->AFTR_v6_address[3]); 

#define DSLITE_SET_TX_PKT_TYPE(type)            {               \
    ctx->ru.tx.packet_type = type;                            \
}

#define DSLITE_INC_STATS_V4(PTR, COUNTER, IPV4_SRC_ADDR) {            \
    PTR->COUNTER++; \
} 

#define DSLITE_INC_STATS_V6(PTR, COUNTER, IPV6_DEST_ADDR) {           \
    PTR->COUNTER++;                                                 \
}


#define DSLITE_INVALID_UIDX 0xffff /*invalid svi app uidb index */
#define DSLITE_INVALID_VRFID 0xffffffff /*invalid vrf id */

#define DSLITE_VRF_MASK 0x3fff
#define DSLITE_MAX_VRFMAP_ENTRIES  (DSLITE_VRF_MASK + 1)

#define DSLITE_VRFMAP_ENTRY_INVALID 0xffff

#define DSLITE_V6_PREFIX_MASK_MIN       16 
#define DSLITE_V6_PREFIX_MASK_MAX       96 
#define DSLITE_V6_PREFIX_MASK_MULTIPLE  8

#define DSLITE_TUNNEL_MTU_MIN 1280
#define DSLITE_TUNNEL_MTU_MAX 9216 

#define DSLITE_TUNNEL_TTL_MIN 0
#define DSLITE_TUNNEL_TTL_MAX 255

#define DSLITE_TUNNEL_TOS_MIN 0
#define DSLITE_TUNNEL_TOS_MAX 255 

#define DSLITE_V4_MASK_MAX       32

//#define XLAT_MAX_FRAG_ID_COUNTERS (256)
#define DSLITE_AFTR_IPV4_ADDR 0xC0000001

#define DSLITE_MAX_TAP_RG_ENTRIES 2
#define DSLITE_MAX_DSLITE_ENTRIES (256)
#define DSLITE_MAX_DSLITE_ID      (DSLITE_MAX_DSLITE_ENTRIES-1)
/* Define the below value as 64 if first 64 entries are for NAT44 */
#define DSLITE_INDEX_OFFSET        1 

#define DSLITE_INVALID_DSLITE_ID  (0)

#define DSLITE_TABLE_ENTRY_DELETED 0
#define DSLITE_TABLE_ENTRY_ACTIVE  1
#define DSLITE_TABLE_ENTRY_DORMANT 2
#define DSLITE_TABLE_ENTRY_INVALID_UIDB 3

typedef struct  {
    u16 tcp_initial_setup_timeout;
    u16 tcp_active_timeout;
    u16 udp_init_session_timeout;
    u16 udp_act_session_timeout;
    u16 icmp_session_timeout;
    u16 temp;
} dslite_timeout_info_t;


typedef struct {

    u16 state;     /* To use nat44 enums ?? TBD */
    u16 dslite_id;   /* DSLITE_ID value for this table entry - for easy access */

    u16 i_vrf;     /* V6 uidb index */
    u16 o_vrf;     /* V4 uidb index */

    u16 cnat_main_db_max_ports_per_user; /* port limit */
    u16 tcp_mss;   /*tcp max segment size for this inside vrf */

    u32 delete_time;

    cnat_portmap_v2_t *portmap_list;

    u32 nfv9_logging_index;
    u32 syslog_logging_index; 
    u32 AFTR_v6_address[4];

#define DSLITE_IPV4_TOS_OVERRIDE_FLAG 0x00000001
#define DSLITE_IPV6_TOS_OVERRIDE_FLAG 0x00000002
#define DSLITE_IPV4_TTL_OVERRIDE_FLAG 0x00000004
#define DSLITE_IPV6_TTL_OVERRIDE_FLAG 0x00000008
#define DSLITE_IPV6_FRAG_REASSEMB_ENG 0x00000010
#define DSLITE_FTP_ALG_ENABLE         0x00000020 
#define DSLITE_RTSP_ALG_ENABLE        0x00000040
#define DSLITE_NETFLOW_ENABLE 0x00000080
#define DSLITE_SYSLOG_ENABLE  0x00000100

    u16  feature_flags;
    u16  tunnel_mtu;

    u8  ipv4_ttl_value;
    u8  ipv6_ttl_value;
    u8  ipv4_tos_value;
    u8  ipv6_tos_value;

    u32 v4_if_num;  /* V4 SVI ifnum */
    u32 v6_if_num;  /* V6 SVI ifnum */
    u32 i_vrf_id;  //inside vrf id
    u32 o_vrf_id;  //outside vrf id
 
    dslite_timeout_info_t timeout_info;
    u16 cnat_static_port_range;
    u16 dyn_start_port; 

    u32 AFTR_v4_addr;    
    bulk_alloc_size_t bulk_size;  /* should be equivalent to u16 - 2 bytes */
    u32 pcp_server_addr;
    u16 pcp_server_port;
    u8 mapping_refresh_both_direction;
    u8 pad;
    u16 rtsp_port;
#define DSLITE_BIDIR_REFRESH   1
    u8 dslite_enable;  /* DS-Lite enable check flag */
    u8 syslog_logging_policy;  /* DS-Lite Session Logging check flag */
    u8 nf_logging_policy;

    u8 temp1;
    u16 temp2;
    u32 temp3;
    u32 rseed_ip;
} dslite_table_entry_t;

typedef struct {
    u64 v4_to_v6_invalid_uidb_drop_count;
    u64 v6_to_v4_invalid_uidb_drop_count;
    u64 v4_to_v6_frag_invalid_uidb_drop_count;
} dslite_global_counters_t;

typedef struct {
    u32 tap_enable; 
    u32 ipv4_addr;
    u32 ipv6_addr[4];
} dslite_tap_rg_t;

extern dslite_table_entry_t  *dslite_table_db_ptr;


#define DSLITE_ADD_UIDB_INDEX_DSLITE_ID_MAPPING(uidb_index, dslite_id) \
    *(cgse_uidb_index_cgse_id_mapping_ptr + uidb_index) = dslite_id;

extern u8 my_instance_number;

extern void dslite_clear_counters(u16 dslite_id);
extern void dslite_clear_per_RG_counters();
extern dslite_global_counters_t dslite_global_counters;
extern u32 dslite_config_debug_level;
extern u32 dslite_data_path_debug_level;
extern u32 dslite_defrag_debug_level;
extern u32 dslite_debug_level;

typedef struct {
    u64 v6_to_v4_tcp_input_count;
    u64 v6_to_v4_tcp_nat_error;
    u64 v6_to_v4_tcp_output_count;
} dslite_v6_to_v4_tcp_counter_t;

typedef struct {
    u64 v4_to_v6_tcp_input_count;
    u64 v4_to_v6_tcp_no_entry;
    u64 v4_to_v6_tcp_output_count;
} dslite_v4_to_v6_tcp_counter_t;

typedef struct {
    u64 v6_to_v4_udp_input_count;
    u64 v6_to_v4_udp_nat_error;
    u64 v6_to_v4_udp_output_count;
} dslite_v6_to_v4_udp_counter_t;

typedef struct {
    u64 v4_to_v6_udp_input_count;
    u64 v4_to_v6_udp_no_entry;
    u64 v4_to_v6_udp_output_count;
} dslite_v4_to_v6_udp_counter_t;

typedef struct {
    u64 v6_to_v4_icmp_qry_input_count;
    u64 v6_to_v4_icmp_qry_nat_error;
    u64 v6_to_v4_icmp_qry_output_count;
} dslite_v6_to_v4_icmp_qry_counter_t;

typedef struct {
    u64 v4_to_v6_icmp_qry_input_count;
    u64 v4_to_v6_icmp_qry_no_nat_entry;
    u64 v4_to_v6_icmp_qry_output_count;
} dslite_v4_to_v6_icmp_qry_counter_t;

typedef struct {
    u64 v6_to_v4_icmp_error_input_count;
    u64 v6_to_v4_icmp_error_nat_error;
    u64 v6_to_v4_icmp_error_output_count;
} dslite_v6_to_v4_icmp_error_counter_t;

typedef struct {
    u64 v4_to_v6_icmp_error_input_count;
    u64 v4_to_v6_icmp_error_no_nat_entry;
    u64 v4_to_v6_icmp_error_output_count;
} dslite_v4_to_v6_icmp_error_counter_t;

typedef struct {
    u64 v6_icmp_error_input_count;
    u64 v6_AFTR_echo_reply_count;
    u64 v6_to_v4_icmp_error_unsupported_type_drop_count;
    u64 v6_to_v4_icmp_error_no_db_entry_count;
    u64 v6_to_v4_icmp_err_throttled_count;
    u64 v6_to_v4_icmp_error_xlated_count;
} dslite_v6_icmp_error_counter_t;

typedef struct {
    u64 v4_to_v6_ttl_gen_count;
    u64 v4_to_v6_icmp_throttle_count;
    u64 v4_to_v6_ptb_gen_count;
    u64 v4_to_v6_aftr_v4_echo_reply_count;
    u64 v6_to_v4_ttl_gen_count;
    u64 v6_to_v4_icmp_throttle_count;
    u64 v6_to_v4_admin_prohib_icmp_count;
    u64 v6_to_v4_aftr_v4_echo_reply_count;
    u64 v6_icmp_gen_count;
} dslite_icmp_gen_counter_t;

typedef struct {
    u64 dslite_input_tunnel_pkt;
    u64 dslite_encap_count;
    u64 dslite_decap_count;
    u64 dslite_sec_check_failed;
    u64 dslite_unsupp_packet;
} dslite_common_counter_t;

typedef struct {

    dslite_v6_to_v4_tcp_counter_t  v64_tcp_counters;
    dslite_v4_to_v6_tcp_counter_t  v46_tcp_counters;
    dslite_v6_to_v4_udp_counter_t  v64_udp_counters;
    dslite_v4_to_v6_udp_counter_t  v46_udp_counters;
    dslite_v6_to_v4_icmp_qry_counter_t v64_icmp_counters;
    dslite_v4_to_v6_icmp_qry_counter_t v46_icmp_counters;
    dslite_v6_to_v4_icmp_error_counter_t  v64_icmp_error_counters;
    dslite_v4_to_v6_icmp_error_counter_t v46_icmp_error_counters;
    dslite_v6_icmp_error_counter_t  dslite_v6_icmp_err_counters;
    dslite_icmp_gen_counter_t       dslite_icmp_gen_counters;
    dslite_common_counter_t         dslite_common_counters;
} dslite_counters_t;

typedef struct {
    u32 active_translations;
    u32 translation_create_rate;
    u32 translation_delete_rate;
    u32 in2out_forwarding_rate;
    u32 out2in_forwarding_rate;
    u32 in2out_drops_port_limit_exceeded;
    u32 in2out_drops_system_limit_reached;
    u32 in2out_drops_resource_depletion;
    u32 no_translation_entry_drops;
    u32 pool_address_totally_free;
    u32 num_subscribers;
    u32 dummy;
    u64 drops_sessiondb_limit_exceeded;
} dslite_common_stats_t;

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 pad[5];
    dslite_counters_t  counters;
} dslite_show_statistics_summary_resp;


#define CMD_GENERATE_PTB 0x1
#define CMD_GENERATE_TTL 0x2

/*
 * This structure is to provide abstraction for data exchanged from one
 * VPP node to its disposition or further in the dslite node graph.
 */
typedef struct {
    u32 icmp_gen_type; // ctx->feature_data[0]
    u32 reserved1;     // ctx->feature_data[1]
    u32 reserved2;     // ctx->feature_data[2]
    u32 reserved3;     // ctx->feature_data[3]
} dslite_feature_data_t;

extern dslite_counters_t    dslite_all_counters[DSLITE_MAX_DSLITE_ENTRIES];
//extern dslite_inst_gen_counter_t       dslite_inst_gen_counters[DSLITE_MAX_DSLITE_ENTRIES];


  extern void dslite_show_config(void);
#define STAT_PORT_RANGE_FROM_INST_PTR(inst) ((inst)->cnat_static_port_range)

#endif /* __DSLITE_DEFS_H__ */

