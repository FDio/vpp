/*
 *------------------------------------------------------------------
 * cnat_logging.h
 *
 * Copyright (c) 2009, 2012 Cisco and/or its affiliates.
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

#ifndef __CNAT_LOGGING_H__ 
#define __CNAT_LOGGING_H__ 

#include <stdio.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>

#include "nat64_db.h"
#include "cnat_log_common.h"
#include "dslite_defs.h"

#define NFV9_DEF_PATH_MTU   1500
#define NFV9_VRF_NAME_LEN   12

/* one time call at the beginning */
void cnat_nfv9_logging_init();

/* 
 * unconditional call
 * will check logging config inside
 */
void cnat_nfv9_log_mapping_create(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
                                  , int bulk_alloc
#endif
                                  );

void cnat_nfv9_nat44_log_session_create(cnat_main_db_entry_t * db,
                                  cnat_session_entry_t * sdb,
                                  cnat_vrfmap_t *vrfmap);

void cnat_nfv9_nat44_log_session_delete(cnat_main_db_entry_t * db,
                                  cnat_session_entry_t * sdb,
                                  cnat_vrfmap_t *vrfmap);


/* 
 * unconditional call
 * will check logging config inside
 */
void cnat_nfv9_log_mapping_delete(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
                                  , int bulk_alloc
#endif
                                  );

/* nat44 syslog APIs */
void cnat_syslog_nat44_mapping_create(cnat_main_db_entry_t *db,
                        cnat_vrfmap_t *vrfmap, cnat_session_entry_t * sdb
#ifndef NO_BULK_LOGGING
                       , int bulk_alloc
#endif
                       );

void cnat_syslog_nat44_mapping_delete(cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
        , int bulk_alloc
#endif
        );

/* 
 * dslite
 */
void cnat_nfv9_ds_lite_mapping_create(cnat_main_db_entry_t *db,
                           dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
                           , int bulk_alloc
#endif
                              );

void cnat_nfv9_ds_lite_mapping_delete(cnat_main_db_entry_t *db,
                           dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
                           , int bulk_alloc
#endif
                              );
void cnat_nfv9_ds_lite_log_session_create(cnat_main_db_entry_t * db,
                                dslite_table_entry_t *dslite_entry,
				cnat_session_entry_t * sdb);

void cnat_nfv9_ds_lite_log_session_delete(cnat_main_db_entry_t * db,
                                dslite_table_entry_t *dslite_entry,
                                cnat_session_entry_t * sdb); 

/* 
 * nat64
 */

void cnat_nfv9_bib_mapping_create (nat64_bib_entry_t *db,
                       nat64_table_entry_t *nat64_entry);

void cnat_nfv9_session_mapping_create (nat64_bib_entry_t *bdb,
                       nat64_session_entry_t *sdb,
                       nat64_table_entry_t *nat64_entry_ptr);

void cnat_nfv9_bib_mapping_delete (nat64_bib_entry_t *db,
                       nat64_table_entry_t *nat64_entry);

void cnat_nfv9_session_mapping_delete (nat64_bib_entry_t *bdb,
                       nat64_session_entry_t *sdb,
                       nat64_table_entry_t *nat64_entry_ptr);

typedef enum {
    RECORD_INVALID = 0,
    NAT44_ADD_RECORD,
    NAT44_DEL_RECORD,
    NAT64_ADD_BIB_RECORD,
    NAT64_DEL_BIB_RECORD,
    NAT64_ADD_SESSION_RECORD,
    NAT64_DEL_SESSION_RECORD,
    DS_LITE_ADD_RECORD,
    DS_LITE_DEL_RECORD,
    NAT44_BULK_ADD_RECORD,
    NAT44_BULK_DEL_RECORD,
    DS_LITE_BULK_ADD_RECORD,
    DS_LITE_BULK_DEL_RECORD,
    INGRESS_VRF_ID_NAME_RECORD,
    NAT44_ADD_SESSION_RECORD,
    NAT44_DEL_SESSION_RECORD,
    DS_LITE_ADD_SESSION_RECORD,
    DS_LITE_DEL_SESSION_RECORD,
    MAX_RECORDS
} netflow_record;

typedef enum {
    TEMPLATE_SENT_FALSE = 0,
    TEMPLATE_SENT_TRUE = 1
} netflow_template_sent;

#define cnat_nfv9_get_sys_up_time_in_ms cnat_get_sys_up_time_in_ms

#define cnat_nfv9_get_unix_time_in_seconds cnat_get_unix_time_in_seconds

#define cnat_nfv9_dump_time_change_logs cnat_dump_time_change_logs


/*
 * Netflow V9 Specific Defines and structures
 */

#define CNAT_NFV9_VERSION_NUMBER                        9

#define CNAT_NFV9_TEMPLATE_FLOWSET_ID   		0
#define CNAT_NFV9_OPTION_TEMPLATE_FLOWSET_ID            1

#define CNAT_NFV9_ADD_FIELD_COUNT       		7
#define CNAT_NFV9_DEL_FIELD_COUNT       		4
#define CNAT_NFV9_DS_LITE_ADD_FIELD_COUNT               8
#define CNAT_NFV9_DS_LITE_DEL_FIELD_COUNT               5
#define CNAT_NFV9_NAT64_ADD_BIB_FIELD_COUNT             5
#define CNAT_NFV9_NAT64_DEL_BIB_FIELD_COUNT             3
#define CNAT_NFV9_NAT64_ADD_SESSION_FIELD_COUNT         8
#define CNAT_NFV9_NAT64_DEL_SESSION_FIELD_COUNT         5
#define CNAT_NFV9_NAT44_ADD_SESSION_FIELD_COUNT         9
#define CNAT_NFV9_NAT44_DEL_SESSION_FIELD_COUNT         6
#define CNAT_NFV9_DS_LITE_ADD_SESSION_FIELD_COUNT       10
#define CNAT_NFV9_DS_LITE_DEL_SESSION_FIELD_COUNT       7

#define CNAT_NFV9_ADD_TEMPLATE_ID                       256
#define CNAT_NFV9_DEL_TEMPLATE_ID                       257
#define CNAT_NFV9_NAT64_ADD_BIB_TEMPLATE_ID             258
#define CNAT_NFV9_NAT64_DEL_BIB_TEMPLATE_ID             259
#define CNAT_NFV9_NAT64_ADD_SESSION_TEMPLATE_ID         260
#define CNAT_NFV9_NAT64_DEL_SESSION_TEMPLATE_ID         261
#define CNAT_NFV9_INGRESS_VRF_ID_NAME_TEMPLATE_ID       262
#define CNAT_NFV9_DS_LITE_ADD_TEMPLATE_ID               267
#define CNAT_NFV9_DS_LITE_DEL_TEMPLATE_ID               268 
#define CNAT_NFV9_NAT44_ADD_SESSION_TEMPLATE_ID         271
#define CNAT_NFV9_NAT44_DEL_SESSION_TEMPLATE_ID         272
#define CNAT_NFV9_DS_LITE_ADD_SESSION_TEMPLATE_ID       273
#define CNAT_NFV9_DS_LITE_DEL_SESSION_TEMPLATE_ID       274

#ifndef NO_BULK_LOGGING
#define CNAT_NFV9_NAT44_BULK_ADD_TEMPLATE_ID     	265
#define CNAT_NFV9_NAT44_BULK_DEL_TEMPLATE_ID     	266
#define CNAT_NFV9_DS_LITE_BULK_ADD_TEMPLATE_ID          269 
#define CNAT_NFV9_DS_LITE_BULK_DEL_TEMPLATE_ID          270

#define CNAT_NFV9_NAT44_BULK_ADD_FIELD_COUNT            6
#define CNAT_NFV9_NAT44_BULK_DEL_FIELD_COUNT            3
#define CNAT_NFV9_DS_LITE_BULK_ADD_FIELD_COUNT          7
#define CNAT_NFV9_DS_LITE_BULK_DEL_FIELD_COUNT          4

#define CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_TYPE   	361
#define CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_SIZE      2

#define CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_TYPE        362
#define CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_SIZE        2

#endif /* #ifndef NO_BULK_LOGGING */

#define CNAT_NFV9_INGRESS_VRF_NAME_FIELD_TYPE           236
#define CNAT_NFV9_INGRESS_VRF_NAME_FIELD_SIZE           12
/* 4 byte for vrf_id + 4 byte for vrf_name (option fields) */
#define CNAT_NFV9_INGRESS_VRF_ID_NAME_OPTION_LEN        8 
extern u16 cnat_template_id[MAX_RECORDS]; 

#define CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE         	234
#define CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE            	4

#define CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE         	235
#define CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE           	4

#define CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE          	8
#define CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE          	4

#define CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE       	225
#define CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE         	4

#define CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE          	7
#define CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE          	2

#define CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE       	227
#define CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE         	2

#define CNAT_NFV9_PROTOCOL_FIELD_TYPE                	4
#define CNAT_NFV9_PROTOCOL_FIELD_SIZE                	1

/* IPv6 related info */

#define CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE   	27
#define CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE   	16
    
#define CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_TYPE   	28
#define CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_SIZE   	16

#define CNAT_NFV9_OUTSIDE_IP_DST_ADDR_FIELD_TYPE   	226
#define CNAT_NFV9_OUTSIDE_IP_DST_ADDR_FIELD_SIZE     	4
    
#define CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE   		11
#define CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE    	2

#define CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_TYPE    	12
#define CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_SIZE     	4


typedef struct {
    u16 version;
    u16 count;
    u32 sys_up_time; /* time in ms since system was booted */
    u32 timestamp;   /* UNIX time in seconds since 1970 */
    u32 sequence_num;
    u32 source_id;
} nfv9_header_t;

/*
 * Hardcoded - need to be fixed 
 */
#define CNAT_NFV9_SOURCE_ID_VALUE  0x1234

typedef struct {
    u16 flowset_id;
    u16 length;

    u16 ingress_vrfid_name_map_template_id;
    u16 ingress_vrfid_name_map_scope_len;
    u16 ingress_vrfid_name_map_option_len;
    u16 ingress_vrfid_name_map_vrfid_option_type;
    u16 ingress_vrfid_name_map_vrfid_option_len;
    u16 ingress_vrfid_name_map_vrfname_option_type;
    u16 ingress_vrfid_name_map_vrfname_option_len;
    /*
     * Adding the padding so as to make the tempalate 
     * structure end on a 4 byte boundary
     */
    u16 padding1;

} cnat_nfv9_option_template_t;

/*
 * The following structure defines the Netflow Template that
 * will be exported to the Netflow Collector
 */

typedef struct {
    u16 flowset_id;
    u16 length;

    u16 add_template_id;
    u16 add_field_count;
    u16 add_inside_vrf_id_field_type;
    u16 add_inside_vrf_id_field_size;
    u16 add_outside_vrf_id_field_type;
    u16 add_outside_vrf_id_field_size;
    u16 add_inside_ip_addr_field_type;
    u16 add_inside_ip_addr_field_size;
    u16 add_outside_ip_addr_field_type;
    u16 add_outside_ip_addr_field_size;
    u16 add_inside_ip_port_field_type;
    u16 add_inside_ip_port_field_size;
    u16 add_outside_ip_port_field_type;
    u16 add_outside_ip_port_field_size;
    u16 add_protocol_field_type;
    u16 add_protocol_field_size;

    u16 del_template_id;
    u16 del_field_count;
    u16 del_inside_vrf_id_field_type;
    u16 del_inside_vrf_id_field_size;
    u16 del_inside_ip_addr_field_type;
    u16 del_inside_ip_addr_field_size;
    u16 del_inside_ip_port_field_type;
    u16 del_inside_ip_port_field_size;
    u16 del_protocol_field_type;
    u16 del_protocol_field_size;
#if 0
    /* NAT64 related info */
    u16 nat64_add_bib_template_id;
    u16 nat64_add_bib_field_count;
    u16 nat64_add_bib_inside_ipv6_addr_field_type;
    u16 nat64_add_bib_inside_ipv6_addr_field_size;
    u16 nat64_add_bib_outside_ip_addr_field_type;
    u16 nat64_add_bib_outside_ip_addr_field_size;
    u16 nat64_add_bib_inside_ip_port_field_type;
    u16 nat64_add_bib_inside_ip_port_field_size;
    u16 nat64_add_bib_outside_ip_port_field_type;
    u16 nat64_add_bib_outside_ip_port_field_size;
    u16 nat64_add_bib_protocol_field_type;
    u16 nat64_add_bib_protocol_field_size;

    u16 nat64_del_bib_template_id;
    u16 nat64_del_bib_field_count;
    u16 nat64_del_bib_inside_ip_addr_field_type;
    u16 nat64_del_bib_inside_ip_addr_field_size;
    u16 nat64_del_bib_inside_ip_port_field_type;
    u16 nat64_del_bib_inside_ip_port_field_size;
    u16 nat64_del_bib_protocol_field_type;
    u16 nat64_del_bib_protocol_field_size;


    u16 nat64_add_session_template_id;
    u16 nat64_add_session_field_count;
    u16 nat64_add_session_inside_ipv6_src_addr_field_type;
    u16 nat64_add_session_inside_ipv6_src_addr_field_size;
    u16 nat64_add_session_outside_ip_src_addr_field_type;
    u16 nat64_add_session_outside_ip_src_addr_field_size;
    u16 nat64_add_session_inside_ipv6_dst_addr_field_type;
    u16 nat64_add_session_inside_ipv6_dst_addr_field_size;
    u16 nat64_add_session_outside_ip_dst_addr_field_type;
    u16 nat64_add_session_outside_ip_dst_addr_field_size;
    u16 nat64_add_session_inside_ip_src_port_field_type;
    u16 nat64_add_session_inside_ip_src_port_field_size;
    u16 nat64_add_session_outside_ip_src_port_field_type;
    u16 nat64_add_session_outside_ip_src_port_field_size;
    u16 nat64_add_session_ip_dest_port_field_type;
    u16 nat64_add_session_ip_dest_port_field_size;
    u16 nat64_add_session_protocol_field_type;
    u16 nat64_add_session_protocol_field_size;

    u16 nat64_del_session_template_id;
    u16 nat64_del_session_field_count;
    u16 nat64_del_session_inside_ip_src_addr_field_type;
    u16 nat64_del_session_inside_ip_src_addr_field_size;
    u16 nat64_del_session_inside_ip_dst_addr_field_type;
    u16 nat64_del_session_inside_ip_dst_addr_field_size;
    u16 nat64_del_session_inside_ip_src_port_field_type;
    u16 nat64_del_session_inside_ip_src_port_field_size;
    u16 nat64_del_session_inside_ip_dst_port_field_type;
    u16 nat64_del_session_inside_ip_dst_port_field_size;
    u16 nat64_del_session_protocol_field_type;
    u16 nat64_del_session_protocol_field_size;

    /*
     * Ds-Lite specific info
     */
    u16 add_dslite_template_id;
    u16 add_dslite_field_count;
    u16 add_dslite_inside_vrf_id_field_type;
    u16 add_dslite_inside_vrf_id_field_size;
    u16 add_dslite_outside_vrf_id_field_type;
    u16 add_dslite_outside_vrf_id_field_size;
    u16 add_dslite_inside_ip_addr_field_type;
    u16 add_dslite_inside_ip_addr_field_size;
    u16 add_dslite_inside_ipv6_addr_field_type;
    u16 add_dslite_inside_ipv6_addr_field_size;
    u16 add_dslite_outside_ip_addr_field_type;
    u16 add_dslite_outside_ip_addr_field_size;
    u16 add_dslite_inside_ip_port_field_type;
    u16 add_dslite_inside_ip_port_field_size;
    u16 add_dslite_outside_ip_port_field_type;
    u16 add_dslite_outside_ip_port_field_size;
    u16 add_dslite_protocol_field_type;
    u16 add_dslite_protocol_field_size;

    u16 del_dslite_template_id;
    u16 del_dslite_field_count;
    u16 del_dslite_inside_vrf_id_field_type;
    u16 del_dslite_inside_vrf_id_field_size;
    u16 del_dslite_inside_ip_addr_field_type;
    u16 del_dslite_inside_ip_addr_field_size;
    u16 del_dslite_inside_ipv6_addr_field_type;
    u16 del_dslite_inside_ipv6_addr_field_size;
    u16 del_dslite_inside_ip_port_field_type;
    u16 del_dslite_inside_ip_port_field_size;
    u16 del_dslite_protocol_field_type;
    u16 del_dslite_protocol_field_size;
#endif
    
//#ifndef NO_BULK_LOGGING /* commenting for time being */
#if 0
    u16 bulk_add_template_id;
    u16 bulk_add_field_count;
    u16 bulk_add_inside_vrf_id_field_type;
    u16 bulk_add_inside_vrf_id_field_size;
    u16 bulk_add_outside_vrf_id_field_type;
    u16 bulk_add_outside_vrf_id_field_size;
    u16 bulk_add_inside_ip_addr_field_type;
    u16 bulk_add_inside_ip_addr_field_size;
    u16 bulk_add_outside_ip_addr_field_type;
    u16 bulk_add_outside_ip_addr_field_size;
    u16 bulk_add_outside_start_port_field_type;
    u16 bulk_add_outside_start_port_field_size;
    u16 bulk_add_outside_end_port_field_type;
    u16 bulk_add_outside_end_port_field_size;

    u16 bulk_del_template_id;
    u16 bulk_del_field_count;
    u16 bulk_del_inside_vrf_id_field_type;
    u16 bulk_del_inside_vrf_id_field_size;
    u16 bulk_del_inside_ip_addr_field_type;
    u16 bulk_del_inside_ip_addr_field_size;
    u16 bulk_del_outside_start_port_field_type;
    u16 bulk_del_outside_start_port_field_size;

    /* ds-lite bulk logging create delete event */

    u16 bulk_dslite_add_template_id;
    u16 bulk_dslite_add_field_count;
    u16 bulk_dslite_add_inside_vrf_id_field_type;
    u16 bulk_dslite_add_inside_vrf_id_field_size;
    u16 bulk_dslite_add_outside_vrf_id_field_type;
    u16 bulk_dslite_add_outside_vrf_id_field_size;
    u16 bulk_dslite_add_inside_ip_addr_field_type;
    u16 bulk_dslite_add_inside_ip_addr_field_size;
    u16 bulk_dslite_add_inside_ipv6_addr_field_type;
    u16 bulk_dslite_add_inside_ipv6_addr_field_size;
    u16 bulk_dslite_add_outside_ip_addr_field_type;
    u16 bulk_dslite_add_outside_ip_addr_field_size;
    u16 bulk_dslite_add_outside_start_port_field_type;
    u16 bulk_dslite_add_outside_start_port_field_size;
    u16 bulk_dslite_add_outside_end_port_field_type;
    u16 bulk_dslite_add_outside_end_port_field_size;

    u16 bulk_dslite_del_template_id;
    u16 bulk_dslite_del_field_count;
    u16 bulk_dslite_del_inside_vrf_id_field_type;
    u16 bulk_dslite_del_inside_vrf_id_field_size;
    u16 bulk_dslite_del_inside_ip_addr_field_type;
    u16 bulk_dslite_del_inside_ip_addr_field_size;
    u16 bulk_dslite_del_inside_ipv6_addr_field_type;
    u16 bulk_dslite_del_inside_ipv6_addr_field_size;
    u16 bulk_dslite_del_outside_start_port_field_type;
    u16 bulk_dslite_del_outside_start_port_field_size;

#endif /* NO_BULK_LOGGING */

    u16 nat44_session_add_template_id;
    u16 nat44_session_add_field_count;
    u16 nat44_session_add_inside_vrf_id_field_type;
    u16 nat44_session_add_inside_vrf_id_field_size;
    u16 nat44_session_add_outside_vrf_id_field_type;
    u16 nat44_session_add_outside_vrf_id_field_size;
    u16 nat44_session_add_inside_ip_addr_field_type;
    u16 nat44_session_add_inside_ip_addr_field_size;
    u16 nat44_session_add_outside_ip_addr_field_type;
    u16 nat44_session_add_outside_ip_addr_field_size;
    u16 nat44_session_add_inside_ip_port_field_type;
    u16 nat44_session_add_inside_ip_port_field_size;
    u16 nat44_session_add_outside_ip_port_field_type;
    u16 nat44_session_add_outside_ip_port_field_size;
    u16 nat44_session_add_dest_ip_addr_field_type;
    u16 nat44_session_add_dest_ip_addr_field_size;
    u16 nat44_session_add_dest_port_field_type;
    u16 nat44_session_add_dest_port_field_size;
    u16 nat44_session_add_protocol_field_type;
    u16 nat44_session_add_protocol_field_size;

    u16 nat44_session_del_template_id;
    u16 nat44_session_del_field_count;
    u16 nat44_session_del_inside_vrf_id_field_type;
    u16 nat44_session_del_inside_vrf_id_field_size;
    u16 nat44_session_del_inside_ip_addr_field_type;
    u16 nat44_session_del_inside_ip_addr_field_size;
    u16 nat44_session_del_dest_ip_addr_field_type;
    u16 nat44_session_del_dest_ip_addr_field_size;
    u16 nat44_session_del_inside_ip_port_field_type;
    u16 nat44_session_del_inside_ip_port_field_size;
    u16 nat44_session_del_dest_port_field_type;
    u16 nat44_session_del_dest_port_field_size;
    u16 nat44_session_del_protocol_field_type;
    u16 nat44_session_del_protocol_field_size;

#if 0
    u16 add_dslite_session_template_id;
    u16 add_dslite_session_field_count;
    u16 add_dslite_session_inside_vrf_id_field_type;
    u16 add_dslite_session_inside_vrf_id_field_size;
    u16 add_dslite_session_outside_vrf_id_field_type;
    u16 add_dslite_session_outside_vrf_id_field_size;
    u16 add_dslite_session_inside_ip_addr_field_type;
    u16 add_dslite_session_inside_ip_addr_field_size;
    u16 add_dslite_session_inside_ipv6_addr_field_type;
    u16 add_dslite_session_inside_ipv6_addr_field_size;
    u16 add_dslite_session_outside_ip_addr_field_type;
    u16 add_dslite_session_outside_ip_addr_field_size;
    u16 add_dslite_session_inside_ip_port_field_type;
    u16 add_dslite_session_inside_ip_port_field_size;
    u16 add_dslite_session_outside_ip_port_field_type;
    u16 add_dslite_session_outside_ip_port_field_size;
    u16 add_dslite_session_dest_ip_addr_field_type;
    u16 add_dslite_session_dest_ip_addr_field_size;
    u16 add_dslite_session_dest_port_field_type;
    u16 add_dslite_session_dest_port_field_size;
    u16 add_dslite_session_protocol_field_type;
    u16 add_dslite_session_protocol_field_size;
    
    u16 del_dslite_session_template_id;
    u16 del_dslite_session_field_count;
    u16 del_dslite_session_inside_vrf_id_field_type;
    u16 del_dslite_session_inside_vrf_id_field_size;
    u16 del_dslite_session_inside_ip_addr_field_type;
    u16 del_dslite_session_inside_ip_addr_field_size;
    u16 del_dslite_session_inside_ipv6_addr_field_type;
    u16 del_dslite_session_inside_ipv6_addr_field_size;
    u16 del_dslite_session_dest_ip_addr_field_type;
    u16 del_dslite_session_dest_ip_addr_field_size;
    u16 del_dslite_session_inside_ip_port_field_type;
    u16 del_dslite_session_inside_ip_port_field_size;
    u16 del_dslite_session_dest_port_field_type;
    u16 del_dslite_session_dest_port_field_size;
    u16 del_dslite_session_protocol_field_type;
    u16 del_dslite_session_protocol_field_size;
#endif

    /*
     * Netflow option template
     * Ingress VRF ID - Name mapping
     * This template will be sent under flowset id 1
     */
    cnat_nfv9_option_template_t cnat_nfv9_option_template;
} cnat_nfv9_template_t;

/*
 * The Dataflow header for each add/delete record group
 */
typedef struct {
    u16 dataflow_template_id;
    u16 dataflow_length;
} nfv9_dataflow_record_header_t;

/*
 * NFv9 Add record definition
 */
 
/* 
 * pad bytes needed to make the structure a multiple of 4 bytes
 */
#define CNAT_NFV9_ADD_RECORD_PAD_BYTES (3)
#define CNAT_NFV9_DEL_RECORD_PAD_BYTES (1)

#define CNAT_NFV9_NAT64_ADD_BIB_RECORD_PAD_BYTES (3)
#define CNAT_NFV9_NAT64_DEL_BIB_RECORD_PAD_BYTES (1)
#define CNAT_NFV9_NAT64_ADD_SESSION_RECORD_PAD_BYTES (1)
#define CNAT_NFV9_NAT64_DEL_SESSION_RECORD_PAD_BYTES (3)
#define CNAT_NFV9_NAT44_ADD_SESSION_RECORD_PAD_BYTES (1)
#define CNAT_NFV9_NAT44_DEL_SESSION_RECORD_PAD_BYTES (3)

#define CNAT_NFV9_DS_LITE_ADD_RECORD_PAD_BYTES (3)
#define CNAT_NFV9_DS_LITE_DEL_RECORD_PAD_BYTES (1)
#define CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_PAD_BYTES (1)
#define CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_PAD_BYTES (3)

#define CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_PAD_BYTES (0)

typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 outside_ip_addr;
    u16 inside_ip_port;
    u16 outside_ip_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_ADD_RECORD_PAD_BYTES]; 
} nfv9_add_record_t;

/*
 * NFv9 Delete record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u16 inside_ip_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_DEL_RECORD_PAD_BYTES];
} nfv9_del_record_t;

#ifndef NO_BULK_LOGGING

#define CNAT_NFV9_BULK_ADD_RECORD_PAD_BYTES (0)
#define CNAT_NFV9_BULK_DEL_RECORD_PAD_BYTES (2)

typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 outside_ip_addr;
    u16 outside_ip_port_start;
    u16 outside_ip_port_end;
    u8  pad[CNAT_NFV9_BULK_ADD_RECORD_PAD_BYTES]; 
} nfv9_bulk_add_record_t;

/*
 * NFv9 Delete record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u16 outside_ip_port_start;
    u8  pad[CNAT_NFV9_BULK_DEL_RECORD_PAD_BYTES];
} nfv9_bulk_del_record_t;

/*
 * DS-lite bulk port (user based) add record definition
 */

#define CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_PAD_BYTES (0)
#define CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_PAD_BYTES (2)

typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u32 outside_ip_addr;
    u16 outside_ip_port_start;
    u16 outside_ip_port_end;
    u8  pad[CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_PAD_BYTES]; 
} nfv9_ds_lite_bulk_add_record_t;


/*
 * DS-lite bulk port (user based) delete record definition
 */

typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u16 outside_ip_port_start;
    u8  pad[CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_PAD_BYTES];
} nfv9_ds_lite_bulk_del_record_t;

#endif /* NO_BULK_LOGGING */

/* NAT64 related structures */

typedef struct {
    u32 inside_v6_src_addr[4];
    u32 outside_v4_src_addr;
    u16 inside_src_port;
    u16 outside_src_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT64_ADD_BIB_RECORD_PAD_BYTES];
} nfv9_nat64_add_bib_record_t;


typedef struct {
    u32 inside_v6_src_addr[4];
    u32 outside_v4_src_addr;
    u32 inside_v6_dest_addr[4];
    u32 outside_v4_dest_addr;
    u16 inside_src_port;
    u16 outside_src_port;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT64_ADD_SESSION_RECORD_PAD_BYTES];
} nfv9_nat64_add_session_record_t;


typedef struct {
    u32 inside_v6_src_addr[4];
    u16 inside_src_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT64_DEL_BIB_RECORD_PAD_BYTES];
} nfv9_nat64_del_bib_record_t;


typedef struct {
    u32 inside_v6_src_addr[4];
    u32 inside_v6_dest_addr[4];
    u16 inside_src_port;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT64_DEL_SESSION_RECORD_PAD_BYTES];
} nfv9_nat64_del_session_record_t;

/*
 * NFv9 Session based Add record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 outside_ip_addr;
    u16 inside_ip_port;
    u16 outside_ip_port;
    u32 dest_ip_addr;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT44_ADD_SESSION_RECORD_PAD_BYTES];
} nfv9_add_session_record_t;

/*
 * NFv9 Session based del record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u32 dest_ip_addr;
    u16 inside_ip_port;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_NAT44_DEL_SESSION_RECORD_PAD_BYTES];
} nfv9_del_session_record_t;

/*
 * DS-lite NFv9 create record structure
 */
typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u32 outside_ip_addr;
    u16 inside_ip_port;
    u16 outside_ip_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_DS_LITE_ADD_RECORD_PAD_BYTES]; 
} nfv9_ds_lite_add_record_t;

typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u16 inside_ip_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_DS_LITE_DEL_RECORD_PAD_BYTES];
} nfv9_ds_lite_del_record_t;

/*
 * NFv9 Session based Add record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 outside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u32 outside_ip_addr;
    u16 inside_ip_port;
    u16 outside_ip_port;
    u32 dest_ip_addr;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_PAD_BYTES];
} nfv9_ds_lite_add_session_record_t;

/*
 * NFv9 Session based del record definition
 */
typedef struct {
    u32 inside_vrf_id;
    u32 inside_ip_addr;
    u32 inside_v6_src_addr[4];
    u32 dest_ip_addr;
    u16 inside_ip_port;
    u16 dest_port;
    u8  protocol;
    u8  pad[CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_PAD_BYTES];
} nfv9_ds_lite_del_session_record_t;


typedef struct {
    u32 ingress_vrf_id;
    u8  ingress_vrf_name[NFV9_VRF_NAME_LEN];
    u8  pad[CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_PAD_BYTES];
} nfv9_ingress_vrfid_name_record_t;

#define CNAT_NFV9_TEMPLATE_OFFSET \
    (CNAT_NFV9_HDR_OFFSET + sizeof(nfv9_header_t))

#define CNAT_NFV9_TEMPLATE_LENGTH (sizeof(cnat_nfv9_template_t))
#define CNAT_NFV9_OPTION_TEMPLATE_LENGTH (sizeof(cnat_nfv9_option_template_t))

#define CNAT_NFV9_DATAFLOW_RECORD_HEADER_LENGTH \
            (sizeof(nfv9_dataflow_record_header_t))

/*
 * No padding is needed for the add/delete records - reduce padding bytes
 */

#define CNAT_NFV9_ADD_RECORD_LENGTH (sizeof(nfv9_add_record_t) - \
                                     CNAT_NFV9_ADD_RECORD_PAD_BYTES)

#define CNAT_NFV9_DEL_RECORD_LENGTH (sizeof(nfv9_del_record_t) - \
                                     CNAT_NFV9_DEL_RECORD_PAD_BYTES)

#define CNAT_NFV9_DS_LITE_ADD_RECORD_LENGTH (sizeof(nfv9_ds_lite_add_record_t) - \
                                     CNAT_NFV9_DS_LITE_ADD_RECORD_PAD_BYTES)
#define CNAT_NFV9_DS_LITE_DEL_RECORD_LENGTH (sizeof(nfv9_ds_lite_del_record_t) - \
                                     CNAT_NFV9_DS_LITE_DEL_RECORD_PAD_BYTES)
#ifndef NO_BULK_LOGGING
#define CNAT_NFV9_BULK_ADD_RECORD_LENGTH (sizeof(nfv9_bulk_add_record_t) - \
                                    CNAT_NFV9_BULK_ADD_RECORD_PAD_BYTES)
#define CNAT_NFV9_BULK_DEL_RECORD_LENGTH (sizeof(nfv9_bulk_del_record_t) - \
                                      CNAT_NFV9_BULK_DEL_RECORD_PAD_BYTES)

#define CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_LENGTH (sizeof(nfv9_ds_lite_bulk_add_record_t) - \
                                    CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_PAD_BYTES)
#define CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_LENGTH (sizeof(nfv9_ds_lite_bulk_del_record_t) - \
                                      CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_PAD_BYTES)


#endif /* NO_BULK_LOGGING */

#define CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_LENGTH (sizeof(nfv9_ingress_vrfid_name_record_t) - \
                                      CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_PAD_BYTES)
                                                                
#define CNAT_NFV9_NAT64_ADD_BIB_RECORD_LENGTH  \
    (sizeof(nfv9_nat64_add_bib_record_t) -  \
     CNAT_NFV9_NAT64_ADD_BIB_RECORD_PAD_BYTES)

#define CNAT_NFV9_NAT64_DEL_BIB_RECORD_LENGTH  \
    (sizeof(nfv9_nat64_del_bib_record_t) - \
     CNAT_NFV9_NAT64_DEL_BIB_RECORD_PAD_BYTES)

#define CNAT_NFV9_NAT64_ADD_SESSION_RECORD_LENGTH  \
    (sizeof(nfv9_nat64_add_session_record_t) -  \
     CNAT_NFV9_NAT64_ADD_SESSION_RECORD_PAD_BYTES)

#define CNAT_NFV9_NAT64_DEL_SESSION_RECORD_LENGTH  \
    (sizeof(nfv9_nat64_del_session_record_t) - \
     CNAT_NFV9_NAT64_DEL_SESSION_RECORD_PAD_BYTES)

#define CNAT_NFV9_MAX_SINGLE_RECORD_LENGTH \
    (sizeof(nfv9_ds_lite_add_session_record_t) - \
     CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_PAD_BYTES)
     
#define CNAT_NFV9_NAT44_ADD_SESSION_RECORD_LENGTH \
                    (sizeof(nfv9_add_session_record_t) -\
                    CNAT_NFV9_NAT44_ADD_SESSION_RECORD_PAD_BYTES)

#define CNAT_NFV9_NAT44_DEL_SESSION_RECORD_LENGTH \
                    (sizeof(nfv9_del_session_record_t) -\
                    CNAT_NFV9_NAT44_DEL_SESSION_RECORD_PAD_BYTES)

#define CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_LENGTH \
                    (sizeof(nfv9_ds_lite_add_session_record_t) -\
                    CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_PAD_BYTES)

#define CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_LENGTH \
                    (sizeof(nfv9_ds_lite_del_session_record_t) -\
                    CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_PAD_BYTES)

/*
 * Minimum value of the path MTU value
 */
#define CNAT_NFV9_MIN_RECORD_SIZE (60 +                                      \
                                   CNAT_NFV9_DATAFLOW_RECORD_HEADER_LENGTH + \
                                   CNAT_NFV9_TEMPLATE_LENGTH  +              \
                                   CNAT_NFV9_MAX_SINGLE_RECORD_LENGTH)

/*
 * Let us put the maximum length of the netflow data to be 1400
 */
#define CNAT_NFV9_MAX_PKT_LENGTH 1400

/*
 * Data structures and defines to store NFV9 specific info
 */
#define CNAT_NFV9_INVALID_LOGGING_INDEX  0xffffffff

/*
 * Padding value between ADD and DELETE records.  This can be atmost 3 bytes
 */
#define NFV9_PAD_VALUE (3)

typedef struct {
    /* NFV9 server specific info
     * For now, it will maintain only package sequence count.
     * Later it will maintain server address, port, etc.
     * Though it currently has server address and port, it is only for 
     * cross refernce
     */
    u32 ipv4_address; /* Destination IP address of the collector */
    u16 port;     /* Destination port number of the collector */
    u16 refresh_rate; /* Refresh rate in packets after which template is sent */
    u16 timeout_rate; /* Timeout rate in seconds after which template is sent */
    u16 ref_count; /* Num of instances using this data */
    u32 sequence_num; /* Sequence number of the logging packet */
    /*
     * Keep track of the time and packets since last template send
     */
    u32 last_template_sent_time;
    u32 pkts_since_last_template;
    u8  template_sent; /* used while sending vrfid-name mapping */

} nfv9_server_info_t;

/*
 * This structure store the Netflow Logging information on per NFv9
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
    u16 nat64_id; /* NAT64 instance for to this collector */
    u16 ds_lite_id; /* DS Lite instance for this collector */

    /*
     * This field determines the maximum size of the Netflow V9 information
     * that can be stored in a logging packet
     */
    u16 max_length_minus_max_record_size;

    /*
     * Indicates if the entry is already deleted
     */
    u16 deleted;

    u16 pkt_length;         /* Length of the currently NFv9 information */
    u16 record_length[MAX_RECORDS];  /* Length of delete record */
    u16 total_record_count; /* Total number of records including templates */

    u8  logging_policy;

    /*
     * Keep track of the time and packets since last template send
     */
    u32 last_template_sent_time;
    u32 pkts_since_last_template;

    /* Server info */
    u32 server_index;

    /*
     * current logging context
     */
    vlib_buffer_t *current_logging_context;

    /*
     * Timestamp in UNIX seconds corresponding to when the current
     * logging packet was created
     */
    u32 current_logging_context_timestamp;

    /*
     * Queued logging context waiting to be sent to the l3 infra node
     */
    vlib_buffer_t *queued_logging_context;

    /*
     * Headers corresponding to various records in this
     * current nfv9 logging context
     */
    nfv9_header_t                  *nfv9_header;
    cnat_nfv9_template_t           *nfv9_template_header;
    nfv9_dataflow_record_header_t  *dataflow_header;
    u8                             *record[MAX_RECORDS];
    u8                             *next_data_ptr;
    u8                             last_record;
    u32                            nfv9_logging_next_index;
    u32 ip4_input_node_index; 
    vlib_frame_t                 *f;
    u32                          *to_next;
} cnat_nfv9_logging_info_t;


/*
 * Global structure for CGN APP configuration
 */
typedef struct {
    /*
     * Global NFv9 Logging Collector Index
     */
    u32 cnat_nfv9_global_collector_index;

    /*
     * Node index corresponding to the infra L3 output node
     * to which the nfv9 logging node will send the packet
     */
    u16 cnat_nfv9_disp_node_index;

    /*
     * Whether we have initialized the NFv9 information
     */
    u8 cnat_nfv9_init_done;
} cnat_nfv9_global_info_t;

typedef enum {
    cnat_nfv9_template_add_default,
    cnat_nfv9_template_add_always
} cnat_nfv9_template_add_flag_t;

extern cnat_nfv9_template_t cnat_nfv9_template_info;

extern cnat_nfv9_logging_info_t cnat_default_nfv9_logging_info;
extern cnat_nfv9_logging_info_t *cnat_nfv9_logging_info_pool;

extern cnat_nfv9_global_info_t  cnat_nfv9_global_info;
extern nfv9_server_info_t *nfv9_server_info_pool;

/* #define DEBUG_NF_SERVER_CONFIG 1 */
static inline void nfv9_delete_server_info(cnat_nfv9_logging_info_t *nfv9_info)
{
    nfv9_server_info_t *server =  nfv9_server_info_pool +
        nfv9_info->server_index;
    if(nfv9_info->server_index == EMPTY) {
#ifdef DEBUG_NF_SERVER_CONFIG
        if(my_instance_number == 1) { 
            PLATFORM_DEBUG_PRINT("Deleting empty server info\n");
        }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
        return;
    }

    /* Check if this server is not used by anyone.. if not delete */
    /* Caller of this function does not need it..so decrement ref count */
    server->ref_count--;
    if(!(server->ref_count)) {
#ifdef DEBUG_NF_SERVER_CONFIG
        if(my_instance_number == 1) { 
            PLATFORM_DEBUG_PRINT("Deleting nfv9 server %x, %d at %d\n",
            server->ipv4_address, 
            server->port,
            nfv9_info->server_index);
        }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
        pool_put(nfv9_server_info_pool, server);
        nfv9_info->server_index = EMPTY; 
    }
#ifdef DEBUG_NF_SERVER_CONFIG
    else {  
        if(my_instance_number == 1) { 
            PLATFORM_DEBUG_PRINT("Not Deleting nfv9 server %x, %d rc %d\n",
            server->ipv4_address,
            server->port,
            server->ref_count);
        }
    }
#endif /* #ifdef DEBUG_NF_SERVER_CONFIG */
    return;
}

void handle_pending_nfv9_pkts();
#endif /* __CNAT_LOGGING_H__ */
