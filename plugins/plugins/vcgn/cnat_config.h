/* 
 *------------------------------------------------------------------
 * cnat_config.h - configuration database definitions
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

#ifndef __CNAT_CONFIG_H__
#define __CNAT_CONFIG_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "cnat_bulk_port_defs.h"

/* default policy value */
#define V4_DEF_ICMP_S_TO      60   /*icmp session timeout */
#define V4_DEF_UDP_IS_TO      30   /*udp init session timeout */
#define V4_DEF_UDP_AS_TO      120  /*udp active session timeout */
#define V4_DEF_TCP_IS_TO      120  /*tcp init session timeout */
#define V4_DEF_TCP_AS_TO      1800 /*tcp active session timeout, 30 min */
#define V4_DEF_TCP_MSS        1460 /*tcp mss */
#define V4_DEF_MAX_PORTS      100  /*max port limit per user */
#define DEF_RATE_LIMIT        PLATFORM_MAX_CORES    /* No of packets/sec icmp generated */
#define DEF_RATE_LIMIT_CORE   1    /* No of packets/sec icmp generated (per core) */
#define RATE_LIMIT_UDP_CORE   1000    /* Max allowed udp crc zero packets/sec/core */

#define NAT44_RESERVED_INST_ID 1 
#define DSLITE_START_ID (NAT44_RESERVED_INST_ID + 1)
#define V4_DEF_VRF_MAX_PORTS      0  /*max port limit per vrf user;
                                       0 means use the global port limit for user*/
/*Hardcoded . TBD - can be made configurable */

#define V4_DEF_ENABLE         1    /* feature enable */
#define V4_DEF_DISABLE         0    /* feature disable */

#define CNAT_DEF_STATIC_PORT_RANGE  1024 /* Default range for static ports */
/*
 * If TCP MSS is not configured, store the maximum possible value
 */
#define V4_TCP_MSS_NOT_CONFIGURED_VALUE 0xffff

/* default timeout for fragments in seconds set to 2
 * in case its not configured
 */
#define CNAT_IPV4_FRAG_TIMEOUT_DEF    2
/* other */
/* max db entries to be scaned */
#define MAX_DB_ENTRY_PER_SCAN PLATFORM_MAX_DB_ENTRY_PER_SCAN
/* max db entries selected per scan */
#define MAX_DB_ENTRY_SELECTED_PER_SCAN PLATFORM_MAX_DB_ENTRY_SELECTED_PER_SCAN

#define ICMP_MSG_RATE_LIMIT   3     /* rate limit for icmp message */
#define V4_CONFIG_DELETE_TO          600   /* timeout for entry to be deleted */

/* session timeout */

extern u16 tcp_initial_setup_timeout;
extern u16 tcp_active_timeout;
extern u16 udp_init_session_timeout;
extern u16 udp_act_session_timeout;
extern u16 icmp_session_timeout;

extern u8  timeout_dirty_flag;

/* mapping refresh direction,
 * 0 outbound only refresh,
 * 1 inbound and outbound refresh
 */
extern u8 mapping_refresh_both_direction;


extern u16 cnat_main_db_max_ports_per_user;
extern u32 cnat_main_db_icmp_rate_limit;
extern u32 cnat_main_db_icmp_rate_limit_core;
extern u32 crc_zero_udp_rate_limit_core;

extern u16 cnat_static_port_range;

typedef enum {
    LOG_FORMAT_UNDEFINED =0,
    LOG_FORMAT_COMPACT,
    LOG_FORMAT_NF9,
    LOG_FORMAT_MAX,     /* keep this as last */
} log_format_t;

typedef enum {
    CNAT_CONFIG_DEL_OP = 0,
    CNAT_CONFIG_ADD_OP,
} cnat_op_flag_t;

extern u8 ftp_alg_enabled;
extern u16 rtsp_alg_port_num;

/*
 * load balancing debug mode
 */
extern u8 lb_debug_enable;

/* good or evil mode
 * 0 endpoint-independnet filter, good mode
 * 1 address depedent filter, evil mode
 */
extern u8 address_dependent_filtering;

extern u16 per_user_icmp_msg_limit;

/* vrfmap or portmap holding time 
 * after delete 
 */
extern u16 config_delete_timeout;

/*
 * Bit map for various configuration in the POLICY KNOB case
 */
#define BIDIR_REFRESH_ENABLE                0x01
#define BIDIR_REFRESH_DISABLE               0x02
#define FTP_ALG_ENABLE                      0x04
#define FTP_ALG_DISABLE                     0x08
#define DEFAULT_NFV9_LOGGING_SERVER_ENABLE  0x10
#define DEFAULT_NFV9_LOGGING_SERVER_DISABLE 0x20


/*
 * This structure contains a single VRF map configuration
 * from a bulk message.  This structure is in conformanace
 * with the following structures defined in cnat_config_api.h
 *   - spp_api_cnat_v4_bulk_vrf_map_t
 *
 * Any change in the above structures should be propagated here
 */
typedef struct _spp_api_cnat_v4_single_vrf_map_req {
    u32 i_vrf_id;
    u32 o_vrf_id;

    u16 i_vrf;
    u16 o_vrf;

    u32 start_addr;
    u32 end_addr;

    u16 vrf_policy_enable;
#define TCP_MSS_ENABLE       0x0001
#define TCP_MSS_DISABLE      0x0002
#define NFV9_LOGGING_ENABLE  0x0004
#define NFV9_LOGGING_DISABLE 0x0008
#define VRF_MAP_DELETE       0x0010
#define VRF_MAP_ADD          0x0020
#define BULK_ALLOC_CHANGE    0x0040   

    u16 tcp_mss_value;
    u32 vrf_nfv9_logging_ipv4_address;
    u16 vrf_nfv9_logging_udp_port;
    u16 vrf_nfv9_refresh_rate;
    u16 vrf_nfv9_timeout_rate;
    u16 vrf_nfv9_path_mtu;
#ifndef NO_BULK_LOGGING
    bulk_alloc_size_t bulk_size;
#endif /* NO_BULK_LOGGING */
} spp_api_cnat_v4_single_vrf_map_req;

typedef struct _spp_api_cnat_v4_single_vrf_map_rc {
    u8 vrf_map_rc;
    u8 tcp_mss_rc;
    u8 nfv9_logging_rc;
    u8 pad;
} spp_api_cnat_v4_single_vrf_map_rc;

/*
 * Bulk Response for the VRF map request
 */
typedef struct _spp_api_cnat_v4_bulk_vrf_map_resp {
    u16 _spp_msg_id;
    u8 bulk_rc;
    u8 pad;

    u32 num_vrfmap_entries;

    spp_api_cnat_v4_single_vrf_map_rc vrf_map_rc;

} spp_api_cnat_v4_bulk_vrf_map_resp;

/*
 * Bulk Response for the Policy Knob request
 */
typedef struct _spp_api_cnat_v4_bulk_policy_knob_resp {
    u16 _spp_msg_id;
    u8 bulk_rc; /* Global rc code */
    u8 pad;

    u8 port_limit_rc;
    u8 icmp_timeout_rc;
    u8 udp_init_timeout_rc;
    u8 udp_act_timeout_rc;

    u8 tcp_init_timeout_rc;
    u8 tcp_act_timeout_rc;
    u8 nfv9_logging_rc;
    u8 pad2;
} spp_api_cnat_v4_bulk_policy_knob_resp;


/* PPTP ALG defs and structures */

/* dont change the order..
   maintened at offset mapped to msg ids */

typedef struct pptp_ctrl_msg_ctrs_t {
  u64 dummy; 
  u64 sccr; 
  u64 sccrp; 
  u64 stccrq; 
  u64 stccrp; 
  u64 erq; 
  u64 erp; 
  u64 ocrq; 
  u64 ocrp; 
  u64 icrq; 
  u64 icrp; 
  u64 iccn; 
  u64 cclr; 
  u64 cdn; 
  u64 wen; 
  u64 sli; 
}pptp_ctrl_msg_ctrs_t;

#define PPTP_INCR(ctr) pptp_cfg.counters.pptp_##ctr++
#define PPTP_DECR(ctr) pptp_cfg.counters.pptp_##ctr--

typedef struct  pptp_counters_t {

  u64 pptp_ctrl_msg_drops;
  u64 pptp_active_tunnels;
  u64 pptp_active_channels;
  u64 pptp_in2out_gre_drops;
  u64 pptp_out2in_gre_drops;
  u64 pptp_in2out_gre_fwds;
  u64 pptp_out2in_gre_fwds;
  pptp_ctrl_msg_ctrs_t ctrl_ctrs;  

} pptp_counters_t;

#define CNAT_PPTP_ENABLE        1
#define CNAT_PPTP_DEF_TIMEOUT   60 /* secs */

typedef struct cnat_pptp_config_t {
    u8 enable;
    u16 timeout;
    pptp_counters_t counters;

} cnat_pptp_config_t;


#define CNAT_PPTP_ENABLE_FLAG    0x01
#define CNAT_PPTP_TIMEOUT_FLAG   0x02

/* pptp config msg resp */
typedef struct _spp_api_cnat_v4_config_pptp_alg_resp {
    u16 _spp_msg_id;
    u8 bulk_rc; 
    u8 pad;

} spp_api_cnat_v4_config_pptp_alg_resp_t; 

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 pad[5];

    /* better to have a group structures rather than individual
       variables, any change in counters is will automatically
       reflect here */
    pptp_counters_t counters;
} pptp_show_counters_resp_t ;


extern cnat_pptp_config_t pptp_cfg;


/* ========= 6RD declarations =============================== */

#define V6RD_ENTRY_DELETE                   0x00
#define IPV4_TUNNEL_SRC_CONFIG              0x04
#define TUNNEL_MTU_CONFIG                   0x08
#define IPV4_PREFIXMASK_LEN_CONFIG          0x10
#define IPV4_SUFFIXMASK_LEN_CONFIG          0x20
#define TTL_CONFIG                          0x40
#define TOS_CONFIG                          0x80
#define V6RD_IPV6_PREFIX_CONFIG             0x100
#define V6RD_RESET_DF_BIT_CONFIG            0x200
#define V6RD_UNICAST_ADDR_CONFIG            0x400
#define V6RD_REASSEMB_CONFIG                0x800

#define TTL_ENABLE        0x1
#define TOS_ENABLE        0x2
#define RESET_DF_BIT      0x4
#define REASSEMBLY_ENABLE 0x8

/* ========= 6RD declarations =============================== */

/*
 * Single Request for XLAT config
 */
typedef struct _spp_api_cnat_v4_single_xlat_config_req {

    /*
     * Indicates the xlat instance id - How big will this value be
     * Can we restrict it between 0..255, that way the APP code
     * can use an array to store the xlat instances.
     */
    u32 xlat_id;

#define XLAT_ENTRY_DELETE                             0x0000
#define IPV6_SVI_IF_NUM_CONFIG                        0x0001
#define IPV4_SVI_IF_NUM_CONFIG                        0x0002
#define IPV4_TO_IPV6_TCP_MSS_CONFIG                   0x0004
#define IPV6_TO_IPV4_TCP_MSS_CONFIG                   0x0008
#define IPV6_PREFIX_CONFIG                            0x0010
#define IPV6_UBIT_ON_CONFIG                           0x0020
#define IPV6_NON_TRANSLATABLE_PREFIX_MAP_CONFIG       0x0040
#define IPV4_TOS_SETTING_CONFIG                       0x0080
#define IPV6_TOS_SETTING_CONFIG                       0x0100
#define IPV4_DFBIT_CLEAR_CONFIG                       0x0200
#define ICMPV6_PTB_MTU_SET_CONFIG                     0x0400
#define IPV6_NON_TRANSLATABLE_PREFIX_MAP_ALG_CONFIG   0x0800
#define CPE_V4_PREFIX_CONFIG                          0x1000  /* for map-t */
#define CPE_V6_PREFIX_CONFIG                          0x2000  /* for map-t */
#define EXTERNAL_V6_PREFIX_CONFIG                     0x4000  /* for map-t */
#define PORT_SHARING_RATIO_CONFIG                     0x8000  /* for map-t */
#define CONSECUTIVE_PORTS_CONFIG                      0x10000 /* for map-t */

    u32 xlat_config_fields_enable;

    /*
     * If numbers of the IPv6 and IPv4 SVI interfaces
     */
    u32 ipv6_svi_if_num;
    u32 ipv4_svi_if_num;

    /*
     * TCP MSS values for the 2 XLAT directions
     */
    u16 v4_to_v6_tcp_mss;
    u16 v6_to_v4_tcp_mss;

    /*
     * XLAT IPv6 prefix
     */
    u32 v6_prefix[4];

    /*
     * XLAT IPv6 prefix mask
     */
    u8 v6_prefix_mask_len;

    /*
     * Set to non-zero if UBITs are reserved
     */
#define UBITS_ON           0x01
#define IPV4_DF_BIT_CLEAR  0x02
#define ICMPV6_MTU_SET     0x04
#define IPV4_TOS_SET_ENABLED     0x08
#define IPV6_TC_SET_ENABLED      0x10

    u8 feature_enable_bits;

    u8 v4_prefix_mask_len;

#define IPV6_NON_TRANSLATABLE_PREFIX_MAP_ALG_HASH     0x1
#define IPV6_NON_TRANSLATABLE_PREFIX_MAP_ALG_TTL      0x2
#define IPV6_NON_TRANSLATABLE_PREFIX_MAP_ALG_RANDOM  0x3
    u8 non_translatable_v6_prefix_v4_map_prefix_alg;

    u8 ipv6_tos_value;

    u8 ipv4_tos_value;

    u8 pad2;

    u8 pad3;

    u32 v4_prefix;

    /*
     * MAP-T/MAP-E specific parameters 
     */
    u8 xlat_type;

    u32 cpe_domain_v6_prefix[4];
    u8  cpe_domain_v6_prefix_len;

    u32 cpe_domain_v4_prefix;
    u8  cpe_domain_v4_prefix_len;

    u32 external_domain_v6_prefix[4];
    u8  external_domain_v6_prefix_len;

    u8 port_sharing_ratio_bits;
    u8 consecutive_ports_bits;

} spp_api_cnat_v4_single_xlat_config_req;

/*
 * Single Response for the xlat config request
 */
typedef struct _spp_api_cnat_v4_single_xlat_config_resp {
   u8 v4_if_num_rc;
   u8 v6_if_num_rc;
   u8 v4_to_v6_tcp_mss_rc;
   u8 v6_to_v4_tcp_mss_rc;

   u8 v6_prefix_rc;
   u8 ubit_on_rc;
   u8 v4_prefix_rc;
   u8 xlat_id_rc;

   u8 non_translatable_v6_prefix_v4_map_alg_rc;
   u8 ipv4_dfbit_clear_rc;
   u8 icmpv6_ptb_mtu_set_rc;
   u8 ipv4_tos_set_rc;

   u8 ipv6_tos_set_rc;
   u8 pad1;
   u8 pad2;
   u8 pad3;
} spp_api_cnat_v4_single_xlat_config_resp;

/*
 * Bulk Response for the xlat config request
 */
typedef struct _spp_api_cnat_v4_bulk_xlat_config_resp {
    u16 _spp_msg_id;
    u16 pad;

    u32 bulk_rc;

    u32 num_xlat_entries;

    spp_api_cnat_v4_single_xlat_config_resp xlat_config_resp;

} spp_api_cnat_v4_bulk_xlat_config_resp;

typedef struct _spp_api_v6rd_v4_single_v6rd_config_resp {
    u8 v6rd_id_rc;
    u8 v4_if_num_rc;
    u8 v6_if_num_rc;
    u8 tunnel_source_rc;
    u8 tunnel_mtu_rc;
    u8 ipv4masklen_prefix_rc;
    u8 ipv4masklen_suffix_rc;
    u8 ttl_rc;
    u8 tos_rc;
    u8 anycast_rc;
    u8 v6_prefix_rc;
    u8 v6_br_unicast_rc;
    u8 reassembly_rc;
    u8 pad1;
    u8 pad2;
    u8 pad3;
} spp_api_v6rd_v4_single_v6rd_config_resp_t;

typedef struct _spp_api_v6rd_v4_bulk_v6rd_config_resp {
    u16 _spp_msg_id;
    u16 pad;
    u32 bulk_rc;
    u32 num_v6rd_entries;
    spp_api_v6rd_v4_single_v6rd_config_resp_t v6rd_config_resp[0];
} spp_api_v6rd_v4_bulk_v6rd_config_resp_t;

/*
 * Single Request for MAPE config
 */
typedef struct _spp_api_mape_single_config_req {

    /*
     * Indicates the mape instance id - How big will this value be
     * Can we restrict it between 0..255, that way the APP code
     * can use an array to store the xlat instances.
     */
    u32 mape_id;

#define MAPE_ENTRY_DELETE                             0x0000
#define MAPE_IPV4_SVI_IF_NUM_CONFIG                   0x0001
#define MAPE_IPV6_SVI_IF_NUM_CONFIG                   0x0002
#define MAPE_IPV4_TO_IPV6_TCP_MSS_CONFIG              0x0004
#define MAPE_IPV6_TO_IPV4_TCP_MSS_CONFIG              0x0008
#define MAPE_CPE_V4_PREFIX_CONFIG                     0x0010
#define MAPE_CPE_V6_PREFIX_CONFIG                     0x0020
#define MAPE_PORT_SHARING_RATIO_CONFIG                0x0040
#define MAPE_CONSECUTIVE_PORTS_CONFIG                 0x0080
#define MAPE_PATH_MTU                                 0x0100
#define MAPE_TUNNEL_ENDPOINT_V6_CONFIG                0x0200

    u32 mape_config_fields_enable;

    /*
     * If numbers of the IPv6 and IPv4 SVI interfaces
     */
    u32 ipv6_svi_if_num;
    u32 ipv4_svi_if_num;

    /*
     * TCP MSS values for the 2 XLAT directions
     */
    u16 v4_to_v6_tcp_mss;
    u16 v6_to_v4_tcp_mss;

    /*
     * Path v6 MTU.
     */
    u32 path_mtu;

    /*
     * CPE IPv6 prefix and mask len.
     */
    u32 cpe_domain_v6_prefix[4];
    u8 cpe_domain_v6_prefix_len;

    /*
     * CPE IPv4 prefix and mask len.
     */
    u32 cpe_domain_v4_prefix;
    u8 cpe_domain_v4_prefix_len;

    /*
     * BR IPv6 tunnel end point V6 prefix and mask len.
     */
    u32 aftr_tunnel_endpoint_address_v6[4];
    u8 aftr_tunnel_endpoint_address_v6_len;

    /*
     * BR IPv6 tunnel end point V6 prefix and mask len.
     */
    u8 port_sharing_ratio_bits;
    u8 consecutive_ports_bits;

} spp_api_mape_single_config_req;


/*
 * Single Response for the mape config response 
 */
typedef struct _spp_api_mape_single_config_resp {
   u8 v4_if_num_rc;
   u8 v6_if_num_rc;
   u8 v4_to_v6_tcp_mss_rc;
   u8 v6_to_v4_tcp_mss_rc;
   u8 mape_id_rc;
   u8 path_mtu_rc; 
   u8 cpe_v6_prefix_rc;
   u8 cpe_v4_prefix_rc;
   u8 tunnel_endpoint_prefix_rc;
   u8 port_sharing_ratio_rc;
   u8 port_contiguous_rc;
   u8 pad1;
} spp_api_mape_single_config_resp;

/*
 * Bulk Response for the mape config request
 */
typedef struct _spp_api_mape_bulk_config_resp {
    u16 _spp_msg_id;
    u16 pad;
    u32 bulk_rc;
    u32 num_mape_entries;
    spp_api_mape_single_config_resp mape_config_resp;
} spp_api_mape_bulk_config_resp;


#endif /* __CNAT_CONFIG_H__ */
