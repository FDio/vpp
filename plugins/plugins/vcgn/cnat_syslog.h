/*
 *------------------------------------------------------------------
 * cnat_syslog.h
 *
 * Copyright (c) 2011-2013 Cisco and/or its affiliates.
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

#ifndef __CNAT_SYSLOG_H__ 
#define __CNAT_SYSLOG_H__ 

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include "cnat_db.h"
#include "nat64_db.h"
#include "cnat_log_common.h"
#include "dslite_defs.h"

#define SYSLOG_CONFIG_DEBUG_PRINTF(level, ...)  \
    if (config_debug_level > level) PLATFORM_DEBUG_PRINT(__VA_ARGS__);


/* one time call at the beginning */
void cnat_syslog_logging_init(); 

/* 
 * unconditional call
 * will check logging config inside
 */
void cnat_syslog_log_mapping_create(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap);

/* 
 * unconditional call
 * will check logging config inside
 */
void cnat_syslog_log_mapping_delete(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap);

void cnat_syslog_ds_lite_mapping_create(cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
        , int bulk_alloc
#endif
    );

void cnat_syslog_ds_lite_port_limit_exceeded(
   dslite_key_t   * key,
   dslite_table_entry_t *dslite_entry);

#define SYSLOG_TIMESTAMP_LENGTH 20

#define CNAT_SYSLOG_VERSION_NUMBER        1
#define CNAT_SYSLOG_PRIORITY              16*8+6  
/* facility = local0 + severity = info */

#define MAX_SYSLOG_HOSTNAME_LEN          32

/* 6 for priority + space
 * 2 for version + space
 * 21  YYYY MMM DD HH:MM:SS + space
 * 33 for hostname + space
 * 4 for App Name (-) + space + Proc ID (-) + space
 * 7 for Msg ID (DSLite is the longest Msg ID so far  + space
 * 2 for Structured data (-) + space
 */
#define MAX_SYSLOG_HEADER_LEN           75

/* 18 for Event Name (Portblockrunout is the longest as of now) 
 * 3 for L4 (including space)
 * 16 for original souce IP + space
 * 33 for inside vrf name + space
 * 40 for original source IPV6 + space
 * 16 for translated source IP + space
 * 6 for original port + space
 * 6 for translated first source port + space
 * 5 for translated last source port
 * 2 for [] enclosure
 */
#define MAX_SYSLOG_RECORD_LEN 145

typedef enum {
    NAT44,
    DSLite
} syslog_service_type_t; 

typedef enum {
    userbased_assign,
    userbased_withdraw,
    sessionbased_assign,
    sessionbased_withdraw,
    sessionbased_assignD,
    sessionbased_withdrawD,
    port_block_runout,
    tcp_seq_mismatch,
    max_syslog_event_type
} syslog_event_type_t;

/*
 * This structure store the Syslog Logging information on per 
 * collector basis. This structure is allocated from a pool and index
 * to this structure is stored VRF MAP structures
 */
typedef struct {
    /* 
     * nat64_id will be 0 for nat44 config and i_vrf_id, i_vrf will be 0
     * for nat64 config. Nat64_id will be used while nat64 collector is 
     * search and i_vrf* for nat44 collector
     */
     /* Similarly for ds_lite, ds_lite_id will be used and nat64_id, 
      * ivrf_id shall be set to 0 
      */
    u32 i_vrf_id; /* Inside VRF ID corresponding to this collector */
    u16 i_vrf;    /* Inside VRF (uidb_index) corresponding to this collector */
    u16 ds_lite_id; /* DS Lite instance for this collector */
    u16 port;     /* Destination port number of the collector */

    /*
     * This field determines the maximum size of the Syslog information
     * that can be stored in a logging packet
     */
    u16 max_length_minus_max_record_size;
    u32 ipv4_address; /* Destination IP address of the collector */
    /*
     * Timestamp in UNIX seconds corresponding to when the current
     * logging packet was created
     */
    u32 current_logging_context_timestamp;

    /*
     * Indicates if the entry is already deleted
     */
    u8 deleted;

    u8 header_priority;
    u16 pkt_length;

    char header_hostname[MAX_SYSLOG_HOSTNAME_LEN];
    char vrf_name[VRF_NAME_LEN_STORED];
    u16  vrf_name_len;
    u8   logging_policy;
    /*
     * current logging context
     */
    spp_ctx_t *current_logging_context;
    spp_ctx_t *queued_logging_context;

} cnat_syslog_logging_info_t;


/*
 * Global structure for CGN APP configuration
 */
typedef struct {

    u16 cnat_syslog_disp_node_index;

    /*
     * Whether we have initialized the Syslog information
     */
    u8 cnat_syslog_init_done;

} cnat_syslog_global_info_t;

typedef struct {
    u64 logging_context_creation_fail_count;
    u64 downstream_constipation_count;
    u64 logging_context_creation_deferred_count;
} cnat_syslog_global_counters_t;

extern cnat_syslog_logging_info_t *cnat_syslog_logging_info_pool;
extern cnat_syslog_global_info_t cnat_syslog_global_info;

#define SYSLOG_DEF_PATH_MTU     1500

#endif /* __CNAT_SYSLOG_H__ */
