/* 
 *------------------------------------------------------------------
 * cnat_show_response.h show command response structs
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

#ifndef __CNAT_SHOW_RESPONSE_H__
#define __CNAT_SHOW_RESPONSE_H__ 

/*
 * Flags indicating the type of translation entry
 */
#define CNAT_TRANSLATION_ENTRY_ALL     0x0
#define CNAT_TRANSLATION_ENTRY_STATIC  0x1
#define CNAT_TRANSLATION_ENTRY_ALG     0x2
#define CNAT_TRANSLATION_ENTRY_DYNAMIC 0x4

/* for PCP support */
#define CNAT_TRANSLATION_ENTRY_PCPI_DYNAMIC 0x08
#define CNAT_TRANSLATION_ENTRY_PCPE_DYNAMIC 0x10

#define MAX_NODE_NAME_LEN  18
#define MAX_CTR_NAME_LEN   10

/*
 * show translation entry response structures
 */
typedef struct {
    u16 call_id;
    u16 cnat_call_id; /* mapped call Id */
    u16 dst_call_id; /* dest call id */
} cnat_v4_show_gre_entry;

typedef struct {
    u16 msg_id;
    u16 rc; /* o/p parameter. */
    u16 num_entries; /* Number of entries sent as output */
    u16 vrf_id; /* vrf  id */
    u32 pns_ip;
    cnat_v4_show_gre_entry entries[0];
} cnat_v4_show_gre_entry_resp;

/*
 * show translation entry response structures 
 */
typedef struct {
    u32 ipv4_addr;
    u16 src_port;
    u16 cnat_port; /* port which replaced the src port */
    u8 protocol; 
    u8 pad;
    u16 flags; 
    u16 nsessions;
    u32 in2out_packets; 
    u32 out2in_packets; 
} cnat_v4_show_translation_entry;

typedef struct {
    u16 msg_id;
    u8 rc; /* o/p parameter. */
    u8 num_entries; /* Number of entries sent as output */
    u16 vrf_id; /* vrf  id */
    u16 pad;
    cnat_v4_show_translation_entry entries[0];
} cnat_v4_show_entry_resp;

/*
 * show free/used ipv4 address/port response structure 
 */
typedef struct { 
    u32 ip_addr; 	
    u32 free_used_ports; 
} cnat_v4_show_free_used_entry;

typedef struct {
    u16 msg_id;
    u8 rc; 	
    u8 count; 
    u32 max_ports;
    cnat_v4_show_free_used_entry entry_list[0]; 
} cnat_v4_show_free_used_entry_resp; 

/*
 * Node name to id mapping
 */
typedef struct  {
    u8  node_id;
    u8  pad;
    char node_name[MAX_NODE_NAME_LEN];
} cnat_statistics_node_name;

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 num_nodes;
    cnat_statistics_node_name node_name_array[0];
} cnat_statistics_node_name_mapping_resp;

/*
 * Counter name to id mapping
 */
typedef struct  {
    u8 node_id;
    u8 counter_id;
    char counter_name[MAX_CTR_NAME_LEN];
} cnat_statistics_counter_name;

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 num_counters;
    cnat_statistics_counter_name counter_name_array[0];
} cnat_statistics_counter_name_mapping_resp;


/*
 * Node name to id mapping
 */ 
typedef struct {
    u16 msg_id;
    u8 rc;
    u8 num_nodes;
    u32 pad;
    u64 counters [0];
} cnat_statistics_counter_values;

/*
 * Summary Stats
 */
typedef struct {
    u32 eaddr;
    u32 ports_used;
} pool_address_usage_t;

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 pad;
    u16 max_pkt_size;
    u16 pool_address_copied;
    u32 active_translations;
    u32 translation_create_rate;
    u32 translation_delete_rate;
    u32 in2out_forwarding_rate;
    u32 out2in_forwarding_rate;
    u32 dummy;
    u64 in2out_drops_port_limit_exceeded;
    u64 in2out_drops_system_limit_reached;
    u64 in2out_drops_resource_depletion;
    u64 no_translation_entry_drops;
    u64 pptp_active_tunnels;
    u64 pptp_active_channels;
    u64 pptp_ctrlmsg_drops;
    u32 no_sessions;

    u32 pool_address_totally_free;
    u32 pool_address_used; /* The following array size will be lesser of
                              (pool_address_used, 200) */
    u32 num_subscribers;
    u64 drops_sessiondb_limit_exceeded;
    u64 in2out_drops_src_ip_no_config;    // for deterministic nat on brahmos
    pool_address_usage_t pool_address_usage[0];
} cnat_show_statistics_summary_resp;


typedef struct {
    u16 msg_id;
    u8  rc;
    u8  pad;
    u64 o2i_tcp_seq_mismatch_drop;
    u64 o2i_tcp_seq_mismatch;
    u64 o2i_sessions_created;
    u64 o2i_end_point_filter_drop;
} cnat_show_counters_summary_resp;


typedef struct {
    u16 msg_id;
    u8 rc;
    u8 pad;

    /*
     * XLAT statistics
     */
    u64 v6_to_v4_tcp_input_count; 
    u64 v6_to_v4_tcp_non_translatable_drop_count;
    u64 v6_to_v4_tcp_invalid_next_hdr_drop_count;
    u64 v6_to_v4_tcp_no_db_drop_count;
    u64 v6_to_v4_tcp_output_count;

    u64 v4_to_v6_tcp_input_count;
    u64 v4_to_v6_tcp_no_db_drop_count;
    u64 v4_to_v6_tcp_output_count;

    u64 v6_to_v4_udp_input_count; 
    u64 v6_to_v4_udp_non_translatable_drop_count;
    u64 v6_to_v4_udp_invalid_next_hdr_drop_count;
    u64 v6_to_v4_udp_no_db_drop_count;
    u64 v6_to_v4_udp_output_count;

    u64 v4_to_v6_udp_input_count;
    u64 v4_to_v6_udp_no_db_drop_count;
    u64 v4_to_v6_udp_output_count;
    u64 v4_to_v6_udp_frag_crc_zero_drop_count;
    u64 v4_to_v6_udp_crc_zero_recycle_sent_count;
    u64 v4_to_v6_udp_crc_zero_recycle_drop_count;

    u64 v6_to_v4_icmp_qry_input_count;
    u64 v6_to_v4_icmp_no_db_drop_count;
    u64 v6_to_v4_icmp_frag_drop_count;
    u64 v6_to_v4_icmp_invalid_next_hdr_drop_count;
    u64 v6_to_v4_icmp_non_translatable_drop_count;
    u64 v6_to_v4_icmp_non_translatable_fwd_count;
    u64 v6_to_v4_icmp_unsupported_type_drop_count;
    u64 v6_to_v4_icmp_err_output_count;
    u64 v6_to_v4_icmp_qry_output_count;

    u64 v4_to_v6_icmp_qry_input_count;
    u64 v4_to_v6_icmp_no_db_drop_count;
    u64 v4_to_v6_icmp_frag_drop_count;
    u64 v4_to_v6_icmp_unsupported_type_drop_count;
    u64 v4_to_v6_icmp_err_output_count;
    u64 v4_to_v6_icmp_qry_output_count;

    u64 v6_to_v4_subsequent_frag_input_count;
    u64 v6_to_v4_subsequent_frag_non_translatable_drop_count;
    u64 v6_to_v4_subsequent_frag_invalid_next_hdr_drop_count;
    u64 v6_to_v4_subsequent_frag_no_db_drop_count;
    u64 v6_to_v4_subsequent_frag_output_count;

    u64 v4_to_v6_subsequent_frag_input_count;
    u64 v4_to_v6_subsequent_frag_no_db_drop_count;
    u64 v4_to_v6_subsequent_frag_output_count;

    u64 v4_to_v6_subsequent_frag_drop_count;
    u64 v4_to_v6_subsequent_frag_throttled_count;
    u64 v4_to_v6_subsequent_frag_timeout_drop_count;
    u64 v4_to_v6_subsequent_frag_tcp_input_count;
    u64 v4_to_v6_subsequent_frag_udp_input_count;
    u64 v4_to_v6_subsequent_frag_icmp_input_count;

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
   
    u64 v4_icmp_gen_count;
    u64 v6_icmp_gen_count;
} xlat_show_statistics_summary_resp;

typedef struct {
    u16 msg_id;
    u8  rc;
    u8  pad;
    /* Total v4 packets to BR */
    u64 v4_to_v6_input_total_count;
    /* Total v4 tunneled packets to BR */
    u64 v4_to_v6_41_input_total_count;
    /* proto 41 packets without minimum, of 40, v6 payload */
    u64 v4_to_v6_41_insuff_v6payld_count;
    /* total proto 41 packets being considered for decap */
    u64 v4_to_v6_41_valid_count;
    /* proto 41 packets that failed security check*/
    u64 v4_to_v6_41_sec_check_fail_count;
    /* packets with no active db entry */
    u64 v4_to_v6_no_db_drop_count;
    /* proto 41 packets actually getting decapped */
    u64 v4_to_v6_41_decap_count;
    /* total v4 packets which are neither icmp nor 41 */
    u64 v4_to_v6_unsupported_protocol_count;
    /* v4 tunneled packets with invalid v6 source address */
    u64 v4_to_v6_41_invalid_v6_source;
    /* total icmpv4 packets destined to BR */
    u64 v4_forus_icmp_input_count;
    /* total icmpv4 echo replies by BR */
    u64 v4_icmp_reply_count;
    /* total icmpv4 error messages translated to icmpv6 by BR */
    u64 v4_to_v6_icmp_translation_count;
    /* total packets with icmpv4 type/code which are not supported by BR */
    u64 v4_icmp_unsupported_count;
    /* total icmpv4 packets which are rate-limited by BR */
    u64 v4_icmp_throttled_count;
    /* total ICMPv4 error messages which could not be translated */
    u64 v4_icmp_non_translatable_drop_count;

    /* ipv4 defrag stats */
    u64 v4_to_v6_frag_input_count;
    u64 v4_to_v6_frag_sec_check_fail_count;
    u64 v4_to_v6_frag_reassem_count;
    u64 v4_to_v6_frag_timeout_drop_count;
    u64 v4_to_v6_frag_icmp_input_count;
    u64 v4_to_v6_frag_41_insuff_v6payld_count;
    u64 v4_to_v6_frag_no_db_drop_count;
    u64 v4_to_v6_frag_unsupported_protocol_count;
    u64 v4_to_v6_frag_41_invalid_v6_source;
    u64 v4_to_v6_frag_throttled_count;
    u64 v4_to_v6_frag_dup_count;
    u64 v4_to_v6_frag_reassem_frag_count;
    u64 v4_to_v6_frag_disable_count;
    u64 v4_to_v6_frag_drop_count;

    /* total v6 packets input to BR */
    u64 v6_to_v4_total_input_count;
    /* v6 packets with no active db entry */
    u64 v6_to_v4_no_db_drop_count;
    /* forus v6 packets with next header other than icmpv6 */
    u64 v6_to_v4_forus_unsupp_proto_count;
    /* total v6 packets that got tunneled */
    u64 v6_to_v4_encap_count;
    /* total icmpv6 packets destined to BR */
    u64 v6_forus_icmp_input_count;
    /* total icmpv6 echo replies by BR */
    u64 v6_icmp_reply_count;
    /* total icmpv6 PTB messages generated by BR */
    u64 v6_ptb_generated_count;
    /* total ipv6 packets for which PTBv6 was NOT generated by BR */
    u64 v6_ptb_not_generated_drop_count;
    /* total icmpv6 Neighbor Advertisements generated by BR */
    u64 v6_na_generated_count;
    /* total icmpv6 TTL expiry messages generated by BR */
    u64 v6_ttl_expiry_generated_count;
    /* total ICMPv6 fragments, which are dropped by BR */
    u64 v6_to_v4_frag_icmp_input_count;
    /* total packets with icmpv6 type/code which are not supported by BR */
    u64 v6_icmp_unsupported_count;
    /* total icmpv6 packets which are rate-limited by BR */
    u64 v6_icmp_throttled_count;
} v6rd_show_statistics_summary_resp;

typedef struct {
    u16 msg_id;
    u8  rc;
    u8  pad;

    /* Total Incoming Count */
    u64 v4_input_count;
    /* Total Drop Count */
    u64 v4_drop_count;
    /* Total Output Count */
    u64 v4_to_v6_output_count;
    /* TCP Incoming Count */
    u64 v4_tcp_input_count;
    /* TCP Output Count */
    u64 v4_tcp_output_count;
    /* UDP Incoming Count */
    u64 v4_udp_input_count;
    /* UDP Output Count */ 
    u64 v4_udp_output_count;
    /* ICMPv4 Incoming Count */
    u64 v4_icmp_input_count;
    /* ICMPv4 Output Count */ 
    u64 v4_to_v6_icmp_output_count;
    /* Invalid UIDB Drop Count */
    u64 v4_invalid_uidb_drop_count; 
    /* NoDb Drop Count */
    u64 v4_no_db_drop_count; 
    /* TTL Expire Drop Count */
    u64 v4_ttl_expire_drop_count;
    /* Invalid IP Destination Drop Count */
    u64 v4_invalid_destination_prefix_drop_count;
    /* Packet Execeeding Path MTU Drop Count */
    u64 v4_path_mtu_exceed_count;
    /* Unsupported Protocol Drop Count */
    u64 v4_invalid_proto_type_drop_count;
    /* ICMPv4 Generated for TTL Expire Count */
    u64 v4_ttl_expiry_generated_count;
    /* ICMPv4 Generated for Error Count */
    u64 v4_icmp_error_gen_count;
    /* ICMPv4 Packets Rate-Limited Count */
    u64 v4_icmp_throttled_drop_count;
    /* TCP MSS Changed Count */
    u64 v4_tcp_mss_changed_count;

    /* Total Incoming Count */
    u64 v6_input_count;
    /* Total Drop Count */
    u64 v6_drop_count;
    /* Total Output Count */
    u64 v6_to_v4_output_count;
    /* TCP Incoming Count */
    u64 v6_tcp_input_count;
    /* TCP Output Count */
    u64 v6_tcp_output_count;
    /* UDP Incoming Count */
    u64 v6_udp_input_count;
    /* UDP Output Count */
    u64 v6_udp_output_count;
    /* ICMPv4 Incoming Count */
    u64 v6_icmpv4_input_count;
    /* ICMPv4 Output Count */
    u64 v6_icmpv4_output_count;
    /* Invalid UIDB Drop Count */ 
    u64 v6_invalid_uidb_drop_count;
    /* NoDb Drop Count */
    u64 v6_no_db_drop_count;
    /* TTL Expire Drop Count */
    u64 v6_ttl_expire_drop_count;
    /* Invalid IPv6 Destination Drop Count */
    u64 v6_invalid_destination_drop_count;
    /* Invalid Source Prefix Drop Count */
    u64 v6_invalid_source_prefix_drop_count;
    /* Unsupported Protocol Drop Count */ 
    u64 v6_invalid_proto_type_drop_count;
    /* ICMPv6 Input Count */
    u64 v6_icmp_input_count;
    /* ICMPv6 Invalid UIDB Drop Count */
    u64 v6_icmp_invalid_uidb_drop_count;
    /* ICMPv6 NoDb Drop Count */
    u64 v6_icmp_no_db_drop_count;
    /* ICMPv6 TTL Expire Drop Count */
    u64 v6_icmp_ttl_expire_drop_count;
    /* ICMPv6 Invalid IPv6 Destination Drop Count */
    u64 v6_icmp_invalid_destination_drop_count;
    /* ICMPv6 Unsupported Type Drop Count */
    u64 v6_icmp_unsupported_type_drop_count;
    /* ICMPv6 Invalid NxtHdr Drop Count*/
    u64 v6_icmp_unsupported_nxthdr_drop_count;
    /* ICMPv6 Frag Drop Count */
    u64 v6_icmp_frag_drop_count;
    /* ICMPv6 Forus Count */
    u64 v6_forus_icmp_input_count;
    /* ICMPv6 Echo Response Received Count */
    u64 v6_received_echo_response_count;
    /* ICMPv6 Echo Replies Count */
    u64 v6_echo_reply_count;
    /* ICMPv6 Translated to ICMPV4 Output Count*/
    u64 v6_to_v4_icmp_output_count;
    /* ICMPv6 Generated for TTL Expire Count */
    u64 v6_ttl_expiry_generated_count;
    /* ICMPv6 Generated for Error Count */
    u64 v6_icmp_error_gen_count;
    /* ICMPv6 Packets Rate-Limited Count */
    u64 v6_icmp_throttled_drop_count;
    /* TCP MSS Changed Count */
    u64 v6_tcp_mss_changed_count;

    /*Total Input Count*/
    u64 v4_to_v6_frag_input_count;
   /*Total Drop Count*/
    u64 v4_to_v6_frag_drop_count;
    /*Reassembled Output Count*/
    u64 v4_to_v6_frag_reassem_count;

    /*TCP Input Count*/
    u64 v4_to_v6_frag_tcp_input_count;
    /*UDP Input Count*/
    u64 v4_to_v6_frag_udp_input_count;
    /*ICMPv4 Input Count*/
    u64 v4_to_v6_frag_icmp_input_count;

    /*Invalid UIDB Drop Count */
    u64 v4_to_v6_frag_invalid_uidb_drop_count;
    /*NoDb Drop Count*/
    u64 v4_to_v6_frag_no_db_drop_count;
    /*Unsupported Protocol Drop Count*/
    u64 v4_to_v6_frag_invalid_proto_type_drop_count;
    /*Throttled Count*/
    u64 v4_to_v6_frag_throttled_count;
    /*Timeout Drop Count*/
    u64 v4_to_v6_frag_timeout_drop_count;
    /*Duplicates Drop Count*/
    u64 v4_to_v6_frag_dup_count;

    /*Total Input Count*/
    u64 v6_to_v4_inner_frag_input_count;
    /*Total Drop Count*/
    u64 v6_to_v4_inner_frag_drop_count;
    /*Total Output Count*/
    u64 v6_to_v4_inner_frag_output_count;

    /*TCP Input Count*/
    u64 v6_to_v4_inner_frag_tcp_input_count;
    /*UDP Input Count*/
    u64 v6_to_v4_inner_frag_udp_input_count;
    /*ICMPv4 Input Count*/
    u64 v6_to_v4_inner_frag_icmp_input_count;

    /*Invalid Source Prefix Drop Count*/
    u64 v6_to_v4_inner_frag_invalid_source_prefix_drop_count;
    /*Unsupported Protocol Drop Count*/
    u64 v6_to_v4_inner_frag_invalid_proto_type_drop_count;
    /*Throttled Count*/
    u64 v6_to_v4_inner_frag_throttled_count;
    /*Timeout Drop Count*/
    u64 v6_to_v4_inner_frag_timeout_drop_count;
    /*Duplicates Drop Count*/
    u64 v6_to_v4_inner_frag_dup_count;

    /*ICMPv6 Generated for Error Count */
    u64 v6_to_v4_inner_frag_icmp_error_gen_count;
    /*ICMPv6 Packets Rate-Limited Count */
    u64 v6_to_v4_inner_frag_icmp_throttled_drop_count;

    /*TCP MSS Changed Count */
    u64 v6_to_v4_inner_frag_tcp_mss_changed_count;

} mape_show_statistics_summary_resp;

/*
 * The following are the command types for Generic Command cases
 */
#define CNAT_DEBUG_GENERIC_COMMAND_READ_MEM  1
#define CNAT_DEBUG_GENERIC_COMMAND_WRITE_MEM 2
#define CNAT_DEBUG_GENERIC_COMMAND_DB_SUMMARY 3
#define CNAT_DEBUG_GENERIC_COMMAND_USER_DB_PM 4
#define CNAT_DEBUG_GET_CGN_DB_SUMMARY 5

typedef enum { 
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_POLICY,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_MAIN_DB,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_USER_DB,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_HASHES_DB,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_VRF_MAP,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_SUMMARY_DB,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_STATS,
    CNAT_DEBUG_GENERIC_COMMAND_CLEAR_STATS,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_NODE_COUNTER,
    CNAT_DEBUG_GENERIC_COMMAND_CLEAR_NODE_COUNTER,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_CNAT_COUNTER,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_VA,
    CNAT_DEBUG_GENERIC_COMMAND_SHOW_CONFIG,
    CNAT_DEBUG_GENERIC_COMMAND_SHOW_NFV9,
    CNAT_DEBUG_GENERIC_COMMAND_SHOW_IVRF,
    CNAT_DEBUG_GENERIC_COMMAND_SHOW_OVRF,
    CNAT_DEBUG_SPP_LOG,
    CNAT_DEBUG_GENERIC_COMMAND_DEBUG_OPTIONS,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_DEBUG_LEVELS,
    CNAT_DEBUG_GENERIC_COMMAND_DEBUG_FLAGS,
    CNAT_READ_TEMP_SENSORS,
    CNAT_BLOCK_OCTEON_SENSOR_READ,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_MAIN_DB_SUMMARY,
    CNAT_DEBUG_GENERIC_COMMAND_DUMP_USER_DB_SUMMARY,
    CNAT_DEBUG_DUMP_6RD_STATS,
    CNAT_DEBUG_TIMEOUT_DB_SUMMARY,
    CNAT_NAT64_STFUL_DEBUG_COMMAND,
    CNAT_DEBUG_SET_BULK_SIZE,
    CNAT_DEBUG_SHOW_BULK_STAT,
    CNAT_DEBUG_CLEAR_BULK_STAT,
    CNAT_DEBUG_SHOW_BULK_ALLOC,
    CNAT_DEBUG_NAT64,
    CNAT_DEBUG_NAT44_IN2OUT_FRAG_STATS,
} cnat_debug_dump_type_t;

typedef enum {
    CNAT_DEBUG_FLAG_UDP_INSIDE_CHECKSUM_MODIFY,
    CNAT_DEBUG_FLAG_UDP_OUTSIDE_CHECKSUM_MODIFY,
    CNAT_DEBUG_FLAG_UDP_INSIDE_PACKET_DUMP,
    CNAT_DEBUG_FLAG_UDP_OUTSIDE_PACKET_DUMP,
} cnat_debug_flag_type_t;

typedef struct {
    u16 spp_msg_id;
    u8 rc;
    u8 core;
    u32 num_bytes;
    u8 raw_data[0];
} cnat_generic_command_resp;

extern u32 db_free_entry (void * p);
#endif  /*__CNAT_SHOW_RESPONSE_H__*/
