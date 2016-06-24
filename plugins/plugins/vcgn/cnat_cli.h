/* *------------------------------------------------------------------
 * cnat_cli.h - CLI definitions
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

#ifndef __CNAT_CLI_H__
#define __CNAT_CLI_H__

#include "cnat_config_api.h"
#include "cnat_show_api.h"

/* from iox cli error */
typedef enum {
    CNAT_SUCCESS = 0,
    CNAT_NO_CONFIG, 
    CNAT_NO_VRF_RUN,
    CNAT_NO_POOL_ANY,
    CNAT_NO_PORT_ANY,
#ifndef NO_BULK_LOGGING
    CNAT_NO_PORT_FROM_BULK,
    CNAT_NO_PRE_ALLOCATED_BULK_PORTS,
#endif /* NO_BULK_LOGGING */
    CNAT_BAD_INUSE_ANY,
    CNAT_NOT_FOUND_ANY, 
    CNAT_INV_PORT_DIRECT,
    CNAT_DEL_PORT_DIRECT,
    CNAT_BAD_INUSE_DIRECT,
    CNAT_NOT_FOUND_DIRECT,
    CNAT_OUT_LIMIT,
    CNAT_MAIN_DB_LIMIT,
    CNAT_USER_DB_LIMIT,
    CNAT_NOT_STATIC_PORT,
    CNAT_BAD_STATIC_PORT_REQ,
    CNAT_NOT_THIS_CORE,
    CNAT_ERR_PARSER,
    CNAT_ERR_INVALID_MSG_ID,
    CNAT_ERR_INVALID_MSG_SIZE,
    CNAT_ERR_INVALID_PAYLOAD_SIZE,
    CNAT_ERR_BAD_TCP_UDP_PORT,
    CNAT_ERR_BULK_SINGLE_FAILURE,
    CNAT_ERR_XLAT_ID_INVALID,
    CNAT_ERR_XLAT_V6_PREFIX_INVALID,
    CNAT_ERR_XLAT_V4_PREFIX_INVALID,
    CNAT_ERR_XLAT_TCP_MSS_INVALID,
    CNAT_ERR_6RD_ID_INVALID,
    CNAT_ERR_6RD_V4_TUNNEL_SRC_INVALID,
    CNAT_ERR_6RD_V6_PREFIX_INVALID, 
    CNAT_ERR_6RD_V6_BR_UNICAST_INVALID,
    CNAT_ERR_6RD_V4_PREFIX_MASK_LEN_INVALID,
    CNAT_ERR_6RD_V4_SUFFIX_MASK_LEN_INVALID,
    CNAT_ERR_6RD_V4_COMBO_MASK_LEN_INVALID,
    CNAT_ERR_6RD_TUNNEL_MTU_INVALID,
    CNAT_ERR_6RD_TUNNEL_TTL_INVALID,
    CNAT_ERR_6RD_TUNNEL_TOS_INVALID,
    CNAT_ERR_NAT64_NO_VRF_RUN,
    CNAT_ERR_NAT64_ID_INVALID,
    CNAT_ERR_NAT64_V6_PREFIX_INVALID,
    CNAT_ERR_NAT64_V4_PREFIX_INVALID,
    CNAT_ERR_NAT64_TCP_MSS_INVALID,
#ifdef CGSE_DS_LITE
    CNAT_ERR_DS_LITE_ID_INVALID,
#endif /* CGSE_DS_LITE */
    CNAT_ERR_NO_SESSION_DB,  	
    CNAT_ERR_MAPE_ID_INVALID,
    CNAT_ERR_MAX
} cnat_errno_t;

#define CNAT_TRUE  1
#define CNAT_FALSE 0


#define CNAT_DEBUG_NONE         (0) 
#define CNAT_DEBUG_GLOBAL_ERR   (1 << 0) 
#define CNAT_DEBUG_DROP_TCP     (1 << 0)   
#define CNAT_DEBUG_DROP_UDP     (1 << 1) 
#define CNAT_DEBUG_DROP_ICMP    (1 << 2) 
#define CNAT_DEBUG_ERR_TCP      (1 << 3) 
#define CNAT_DEBUG_ERR_UDP      (1 << 4) 
#define CNAT_DEBUG_ERR_ICMP     (1 << 5)
#define CNAT_DEBUG_ERR_ALG      (1 << 6)
#define CNAT_DEBUG_GLOBAL_ALL   (1 << 7) 
#define CNAT_DEBUG_FTP_ALG      (1 << 8)



#define CNAT_DEBUG_ALL  0x1FF /*all of above*/
#define CNAT_DEBUG_ERR_ALL   0x38

#define CNAT_DB_CLEAR_SPECIFIC (0)
#define CNAT_DB_CLEAR_ALL      (1 << 0)
#define CNAT_DB_CLEAR_VRF      (1 << 1)
#define CNAT_DB_CLEAR_ADDR     (1 << 2)
#define CNAT_DB_CLEAR_PROTO    (1 << 3)
#define CNAT_DB_CLEAR_PORT     (1 << 4)


#define MAX_UIDX 0x3fff    /*the max svi app uidb index */
/* address mask per core */
#define ADDR_MASK_PER_CORE PLATFORM_ADDR_MASK_PER_CORE
#define ADDR_MASK_PER_CORE_PER_PARTITION \
            PLATFORM_ADDR_MASK_PER_CORE_PER_PARTITION

#define MAX_CORES          PLATFORM_MAX_CORES
#define MAX_CORES_PER_PARTITION          PLATFORM_MAX_CORES_PER_PARTITION

/*
 * Maximum pool size that is supported by platform
 */
#define CNAT_MAX_ADDR_POOL_SIZE PLATFORM_CNAT_MAX_ADDR_POOL_SIZE
#define CNAT_MAX_ADDR_POOL_SIZE_PER_CORE \
            (CNAT_MAX_ADDR_POOL_SIZE / MAX_CORES_PER_PARTITION)

#define BOUNDARY_VALUE 256
 
#define BOUNDARY_VALUE_MASK 0xff
 
#define NUM_ADDR_IN_RANGE(range, value, instance) \
    ((range / value) + ((instance % MAX_CORES_PER_PARTITION) < (range%value) ? 1 : 0))

typedef enum {
    CNAT_DEBUG_FLAGS_DUMP = 0,
    CNAT_DEBUG_FLAG_UDP_INSIDE_CHECKSUM_DISABLE, 
    CNAT_DEBUG_FLAG_UDP_OUTSIDE_CHECKSUM_DISABLE,
    CNAT_DEBUG_FLAG_UDP_OUTSIDE_PKT_DUMP_ENABLE,
    CNAT_DEBUG_FLAG_UDP_INSIDE_PKT_DUMP_ENABLE,
    CNAT_DEBUG_FLAG_ICMP_PKT_DUMP_ENABLE,
    CNAT_DEBUG_FLAG_FRAG_PKT_DUMP_ENABLE,
    CNAT_DEBUG_FLAG_CONFIG_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_GLOBAL_DEBUG_ALL_ENABLE,
    CNAT_DEBUG_FLAG_SUMMARY_STATS_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_SHOW_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_XLAT_CONFIG_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_XLAT_DATA_PATH_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_TCP_LOGGING_ENABLE,
    CNAT_DEBUG_FLAG_NFV9_LOGGING_DUMP_ENABLE,
    CNAT_DEBUG_FLAG_SYSLOG_LOGGING_DUMP_ENABLE,
    CNAT_DEBUG_SET_STATIC_PORT_RANGE,
    CNAT_DEBUG_FLAG_V6RD_DATA_PATH_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_V6RD_CONFIG_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_V6RD_DEFRAG_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_NAT64_CONFIG_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_NAT64_DATA_PATH_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_DSLITE_DP_ENABLE, 
    CNAT_DEBUG_FLAG_DSLITE_CONFIG_DEBUG_ENABLE, 
    CNAT_DEBUG_FLAG_CONFIG_PPTP_ENABLE = 24, 
    CNAT_DEBUG_FLAG_CONFIG_PCP_ENABLE = 25, 
    CNAT_DEBUG_FLAG_MAPE_CONFIG_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_MAPE_DATA_PATH_DEBUG_ENABLE,
    CNAT_DEBUG_FLAG_MAX,
} cnat_debug_variable_value;

/*
 * Don't use too small values for PATH MTU 
 */
#define MIN_NFV9_PATH_MTU 100

extern u32 global_debug_flag;
extern u16 debug_i_vrf;
extern u32 debug_i_flag;
extern u32 debug_i_addr_start;
extern u32 debug_i_addr_end;
extern u16 debug_o_vrf;
extern u32 debug_o_flag;
extern u32 debug_o_addr_start;
extern u32 debug_o_addr_end;
extern u32 tcp_logging_enable_flag;
extern u32 nfv9_logging_debug_flag;

extern u32 udp_inside_checksum_disable;
extern u32 udp_outside_checksum_disable;
extern u32 udp_inside_packet_dump_enable;
extern u32 udp_outside_packet_dump_enable;

extern u32 icmp_debug_flag;
extern u32 frag_debug_flag;

extern u32 summary_stats_debug_flag;

extern u32 config_debug_level;
extern u32 show_debug_level;


/* CLI API prototypes called from vcgn_classify.c */
extern void cnat_nat44_add_vrf_map_t_handler(spp_api_cnat_v4_add_vrf_map_t *mp,
                                            vlib_main_t *vm);
extern void cnat_nat44_handle_show_stats(vlib_main_t *vm);
extern void cnat_nat44_handle_show_config(vlib_main_t *vm);
extern void cnat_nat44_set_protocol_timeout_value(u16 active, 
                           u16 init, u8 *proto, u8 reset, vlib_main_t *vm);
extern void cnat_v4_show_inside_entry_req_t_handler
(spp_api_cnat_v4_show_inside_entry_req_t *mp, vlib_main_t *vm);

#endif /* __CNAT_CLI_H__ */
