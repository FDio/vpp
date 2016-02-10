/*
 *------------------------------------------------------------------
 * spp_platform_trace_log.h
 *
 * Copyright (c) 2009-2013 Cisco and/or its affiliates.
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

#ifndef __SPP_PLATFORM_TRACE_LOG_H__ 
#define __SPP_PLATFORM_TRACE_LOG_H__ 

#include <stdio.h>
#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>

#include "spp_ctx.h"
#include "spp_timers.h"


typedef enum {
    SPP_LOG_LTRACE,
    SPP_LOG_MAX
} spp_log_type_t;

typedef struct {
    u32 num_traces;
} spp_trace_log_hdr_t;

typedef struct {
    u16 error_code;
    u16 num_args;
    u32 arg[0];
} spp_trace_log_t;

#define DUMP_PKT_IDX 61
#define OCTEON_SENSOR_READ 62

typedef enum {
    CNAT_ERROR_SUCCESS,
    CNAT_NO_CONFIG_ERROR,
    CNAT_NO_VRF_RUN_ERROR,
    CNAT_NO_POOL_FOR_ANY_ERROR,
    CNAT_NO_PORT_FOR_ANY_ERROR,
    CNAT_BAD_INUSE_ANY_ERROR,
    CNAT_NOT_FOUND_ANY_ERROR,
    CNAT_INV_PORT_FOR_DIRECT_ERROR,
    CNAT_BAD_INUSE_DIRECT_ERROR,
    CNAT_NOT_FOUND_DIRECT_ERROR,
    CNAT_OUT_OF_PORT_LIMIT_ERROR,
    CNAT_MAIN_DB_CREATE_ERROR,
    CNAT_LOOKUP_ERROR,
    CNAT_INDEX_MISMATCH_ERROR,
    CNAT_PACKET_DROP_ERROR,
    CNAT_INV_UNUSED_USR_INDEX,
    CNAT_INVALID_VRFMAP_INDEX,
    CNAT_USER_OUT_OF_PORTS,
    CNAT_EXT_PORT_THRESH_EXCEEDED,
    CNAT_EXT_PORT_THRESH_NORMAL,
    CNAT_NO_EXT_PORT_AVAILABLE,
    CNAT_SESSION_THRESH_EXCEEDED,
    CNAT_SESSION_THRESH_NORMAL,
    WQE_ALLOCATION_ERROR,
    ERROR_PKT_DROPPED,
    SYSMGR_PD_KEY_CREATION_ERROR,
    SYSMGR_PD_SHMEM_ID_ERROR,
    SYSMGR_PD_SHMEM_ATTACH_ERROR,
    OCTEON_CKHUM_SKIPPED,
    PK0_SEND_STATUS,
    CMD_BUF_ALLOC_ERR,
    SPP_CTX_ALLOC_FAILED,
    SPP_MAX_DISPATCH_REACHED,
    HA_SIGCHILD_RECV,
    SIGACTION_ERR,
    HA_INVALID_SEQ_OR_CONFIG_OR_TYPE,
    NODE_CREATION_ERROR,
    CNAT_CLI_INVALID_INPUT, /* new adds as part of CSCto04510, see sub codes below */
    CNAT_DUMMY_HANDLER_HIT, /* Has sub codes , see spp_dummy_handler_sub_cdes_t */
    CNAT_CONFIG_ERROR, /* has subcodes-see spp_config_error_sub_codes_t below */
    CNAT_NFV9_ERROR, /* Has sub codes see spp_nfv9_error_sub_codes_t below */
    CNAT_CMVX_TWSI_READ_WRITE_FAIL, /* Hassub codes see spp_cmvx_error_sub_codes_t */
    CNAT_TEMP_SENSOR_TIMEOUT,
    CNAT_TEMP_SENSOR_DATA_MISMATCH,
    CNAT_TEMP_SENSOR_CONFIG_FAILED,
    HA_APP_NOT_RESPONDING,
    HA_DATA_PATH_TEST_FAILED,
    CNAT_WRONG_PORT_ALLOC_TYPE,
    CNAT_NEW_PORT_ALLOC_ERROR,
    CNAT_INVALID_INDEX_TO_FREE_PORT,
    CNAT_DELETE_DB_ENTRY_NO_PORTMAP,
    CNAT_MAIN_DB_LIMIT_ERROR,
    CNAT_USER_DB_LIMIT_ERROR,
    CNAT_FRAG_DB_ERROR, /* see spp_frag_db_error_sub_codes_t below */

    DROP_PKT_DUMP,
    CNAT_NAT64_SYSTEM_LIMIT_ERROR,
    CNAT_ERROR_MAX
} spp_error_codes_t;

typedef enum {

    TCP_MSS_INVALID_IVRF = 10, /* 1 param - vrf id */
    NFV9_LOG_INVALID_IP_OR_PORT = 20, /* 2 params - nfv9 server ip and port */
    NFV9_LOG_INVALID_PARAMS_OTHERS, /* 3 params, ref rate, time out, path mtu */
    NFV9_LOG_PATH_MTU_TOO_SMALL, /* 1 param, path mtu passed */
    NFV9_LOG_CANNOT_ADD_VRF_NOT_FOUND, /* 1 param, in vrf id */

    VRF_MAP_ADDR_POOL_START_ADDR_GT_END_ADDR = 30, /* 2 params, start and end addr */
    VRF_MAP_ADDR_POOL_ADDR_POOL_TOO_LARGE, /* 2 params, start and end addr */
    VRF_MAP_ADDR_POOL_INVALID_IN_OR_OUT_VRF, /* 2 params, in vrf and out vrf */
    VRF_MAP_ADDR_POOL_TOO_LARGE_FOR_CORE, /* 2 params, pool size, core instance */
    VRF_MAP_DEL_POOL_START_ADDR_GT_END_ADDR, /* 2 params, start and end addr */
    VRF_MAP_DEL_POOL_ADDR_POOL_NOT_FOUND, /* 2 params, start and end addr */
    VRF_MAP_DEL_POOL_VRF_MAP_EMPTY, /* 2 params, start and end addr */

    ADD_SVI_ADDR_INVALID_VRF = 40, /* 2 params, vrf passed and ipv4 addr */
    ADD_SVI_INDEX_INVALID_VRF, /* 2 params, vrf, uidb_index */

    MAPPED_STAT_PORT_INVALID_OUTPUT_PARAMS = 50,
    /* 3 params, out vrf, out ip, out port */
    MAPPED_STAT_PORT_UDP_PORT_POLARITY_MISMATCH, /* 2 params, in port and out port */
    MAPPED_STAT_PORT_IN_VRF_MAP_EMPTY, /* 1 param, in vrf id passed */
    MAPPED_STAT_PORT_VRF_MAP_NOT_IN_S_RUN, /* 1 param, vrf map status */
    MAPPED_STAT_PORT_INVALID_OUT_VRF_ID, /* 1 param, out vrf id passed */
    MAPPED_STAT_PORT_FAILED_TO_ADD_STAT_PORT, /* 4 params, in vrf, in ip, in port, error code */

   STAT_PORT_INVALID_IN_PARAMS = 60, /* 4 params, in vrf, in ip, in port, proto */
   STAT_PORT_FAILED_TO_ADD_STAT_PORT, /* 4 params, in vrf, in ip, in port, error code */
   STAT_PORT_CONFIG_IN_USE, /* 4 params, in vrf, in ip, in port, proto */

   DEL_STAT_PORT_IN_VRF_MAP_EMPTY = 70, /* 1 param, in vrf id passed */
   DEL_STAT_PORT_INVALID_IN_PARAMS, /* 4 params, in vrf, in ip, in port, proto */
   DEL_STAT_PORT_CANNOT_DELETE_NO_ENTRY, /* 4 params, in vrf, in ip, in port, proto */
   DEL_STAT_PORT_CANNOT_DELETE_NOT_STATIC_PORT, /* 4 params, in vrf, in ip, in port, proto*/

   XLAT_SVI_CFG_INVALID_INDEX = 80,   /* 1 param - uidb_index */
   XLAT_WRONG_V6_PREFIX_MASK, /* 1 param - v6 prefix mask */
   XLAT_INVALID_XLAT_ID_ERROR, /* 1 param - id */

   V6RD_INVALID_6RD_ID_ERROR = 90, /*1 param - id */
   MAPE_INVALID_MAPE_ID_ERROR = 100 /* param - id */
} spp_config_error_sub_codes_t;

typedef enum {
    CONFIG_DUMMY,
    CONFIG_DUMMY_MAX,
    SHOW_DUMMY,
    SHOW_DUMMY_MAX,
    DEBUG_DUMMY,
    DEBUG_DUMMY_MAX
} spp_dummy_handler_sub_cdes_t;

typedef enum {
    CMVX_READ,
    CMVX_WRITE
} spp_cmvx_error_sub_codes_t;

typedef enum {
    FRAG_DB_INVALID_BUCKET,
    FRAG_DB_NO_ENTRY
} spp_frag_db_error_sub_codes_t;

typedef enum {
    CLI_INVALID_PAYLOAD_SIZE,
    CLI_INVALID_MSG_ID
} spp_cli_error_sub_codes_t;

typedef enum {
    NFV9_DOWNSTREAM_CONGESTION,
    NFV9_FAILED_TO_CREATE_CONTEXT
} spp_nfv9_error_sub_codes_t;

typedef struct spp_cnat_logger_tbl_t_ {
    u16        error_code;      // The thread id stored by software
    u16        num_args;
    u16        rate_limit_time;   // If we need to rate_limit logging
    u8         param_name[7][32];// Parameter name for debug purposes
} spp_cnat_logger_tbl_t;

extern spp_cnat_logger_tbl_t spp_cnat_logger_table[];

/*
 * This corresponds to the length of the IMETRO SHIM Header for RODDICK
 * For non-roddick cases, introduce an Ethernet header as well
 */
#if defined(RODDICK)
#define SPP_TRACE_LOG_SHIM_HDR_OFFSET   8
#define SPP_TRACE_LOG_ENCAPS_OFFSET  0
#else
#define SPP_TRACE_LOG_SHIM_HDR_OFFSET   0
#define SPP_TRACE_LOG_ENCAPS_OFFSET 16
#endif

#define SPP_LOG_TRACE_HEADER_LENGTH \
            (sizeof(spp_trace_log_hdr_t))


#define SPP_TRACE_LOG_IP_HDR_OFFSET \
            (SPP_TRACE_LOG_ENCAPS_OFFSET + \
             SPP_TRACE_LOG_SHIM_HDR_OFFSET)


#define SPP_TRACE_LOG_UDP_HDR_OFFSET \
    (SPP_TRACE_LOG_IP_HDR_OFFSET + sizeof(ipv4_header))

#define SPP_TRACE_LOG_HDR_OFFSET \
    (SPP_TRACE_LOG_UDP_HDR_OFFSET + sizeof(udp_hdr_type_t))

#define SPP_TRACE_LOG_RECORD_LENGTH  4

/*
 * Let us put the maximum length of the log data to be 1400
 */
#define SPP_TRACE_LOG_MAX_PKT_LENGTH 800

/* Structures and defines to store log info for MSC */
#define SPP_TRACE_LOG_INVALID_LOGGING_INDEX  0xffffffff

/*
 * This structure stores the  Logging information on per LOG TYPE
 *  basis. This structure is allocated from a pool and index
 * to this structure based on log type
 */
typedef struct {
    /*
     * This field determines the maximum size of the Netflow V9 information
     * that can be stored in a logging packet
     */
    u16 max_length_minus_max_record_size;

    u32 sequence_num; /* Sequence number of the logging packet */
    u32 last_pkt_sent_count;
    u16 pkt_length;         /* Length of the currently NFv9 information */
    u16 log_record_length;  /* Length of add record */
    u16 total_record_length; /* number of trace records */
    u16 total_record_count;
    spp_log_type_t log_type;
    /*
     * current logging context
     */
    spp_ctx_t *current_logging_context;

    /*
     * Timestamp in UNIX seconds corresponding to when the current
     * logging packet was created
     */
    u32 current_logging_context_timestamp;

    /*
     * Queued logging context waiting to be sent to the l3 infra node
     */
    spp_ctx_t *queued_logging_context;

    /*
     * Headers corresponding to various records in this
     * current nfv9 logging context
     */
    spp_trace_log_t              *log_record;
    spp_trace_log_hdr_t          *log_header;
    u8                            *next_data_ptr;

} spp_trace_log_info_t;

typedef struct {
    /*
     * spp_ctx_alloc() call failed
     */
    u64 spp_trace_log_context_creation_fail_count;

    /*
     * Cannot send the existing logging pkt, so cannot create
     * any additional packets for logging purposes
     */
    u64 spp_trace_log_context_creation_deferred_count;

    /*
     * Cannot send the existing logging pkt due to cnat_rewrite_output
     * superframe being full.
     */
    u64 spp_trace_log_downstream_constipation_count;
} spp_global_counters_t;


/*
 * Global structure for SPP LOGS 
 */
typedef struct {
    /* A timer structure to periodically send log packets
     * that have been waiting to be full for a long time.  This will
     * ensure event/error logs don't get delayed too much before they
     * are sent to the MSC.
     */
    spp_timer_t log_timer;

    /*
     * Node index corresponding to the infra L3 output node
     * to which the nfv9 logging node will send the packet
     */
    u16 spp_trace_log_disp_node_index;

    /*
     * Whether we have initialized the NFv9 information
     */
    u8 spp_trace_log_init_done;

    /*
     * pool index in global pool based on log type
     */
    u32 spp_log_pool_index[SPP_LOG_MAX];

} spp_trace_log_global_info_t;


extern spp_timer_t sensor_timer; 
extern spp_trace_log_info_t spp_default_trace_log_info;
extern spp_trace_log_info_t *spp_trace_log_info_pool;

extern spp_trace_log_global_info_t  spp_trace_log_global_info;

void spp_trace_logger(u16 error_code, u16 num_args, u32 *arg);
void spp_trace_log_init(void);
void init_trace_log_buf_pool(void);
void spp_printf(u16 error_code, u16 num_args, u32 *arg);

/*
 * The following 2 functions are temporary hacks until
 * we have RTC support from the PD nodes
 */
#if 0
inline
u32 spp_trace_log_get_sys_up_time_in_ms (void);
#endif
extern
u32 spp_trace_log_get_unix_time_in_seconds (void);

enum {
    TEMPERATURE_SENSOR_TEST_MODE,
    TEMPERATURE_SENSOR_QUIET_MODE,
};

extern int temperature_read_blocked;

void read_octeon_sensors(u8 mode);
void Init_temperature_sensors();
#endif /* __SPP_PLATFORM_TRACE_LOG_H__ */
