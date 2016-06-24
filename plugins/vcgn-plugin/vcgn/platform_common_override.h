/*
 *---------------------------------------------------------------------------
 * platform_common_override.h -- Files has actual platform specific defines. 
 *                               Will only included by platform_common.h
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
 *---------------------------------------------------------------------------
 */

#ifndef __PLATFORM_COMMON_OVERRIDE_H__
#define __PLATFORM_COMMON_OVERRIDE_H__

extern unsigned char my_octeon_id;

#undef PLATFORM_DBL_SUPPORT
#define PLATFORM_DBL_SUPPORT  1 // Destination Based logging support
                                // NAT44 session table required.

#undef PLATFORM_ADDR_MASK_PER_CORE
/* commenting this. Currently we are considering only single core */
//#define PLATFORM_ADDR_MASK_PER_CORE 0x3f // Using 64 cores
#define PLATFORM_ADDR_MASK_PER_CORE 0x01 

#undef MAX_COMBINED_DB_ENTRIES_PER_SCAN
#define MAX_COMBINED_DB_ENTRIES_PER_SCAN 128 

#undef PLATFORM_MAX_CORES
#define PLATFORM_MAX_CORES (PLATFORM_ADDR_MASK_PER_CORE + 1)

// Roddick does not have any partition of cores
#undef PLATFORM_ADDR_MASK_PER_CORE_PER_PARTITION
#define PLATFORM_ADDR_MASK_PER_CORE_PER_PARTITION \
            PLATFORM_ADDR_MASK_PER_CORE

#undef PLATFORM_MAX_CORES_PER_PARTITION
#define PLATFORM_MAX_CORES_PER_PARTITION PLATFORM_MAX_CORES

#undef PLATFORM_CNAT_INSTS
//#define PLATFORM_CNAT_INSTS  64
#define PLATFORM_CNAT_INSTS  1  /* currently its only single instance */

#undef PLATFORM_MAX_NAT_ENTRIES
//#define PLATFORM_MAX_NAT_ENTRIES 20000000 // 20M
#define PLATFORM_MAX_NAT_ENTRIES 1666660 // ~80M/48 (79999680/48)

#undef PLATFORM_MAX_USER_ENTRIES
#define PLATFORM_MAX_USER_ENTRIES 20800 // ~1M/48 (998400/48)


/* 524288:
         (20000000 translations) / (64 CNAT INSTANCES) = 312500
         nearest higher number which is power of 2 next to 312500
*/
#undef PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE
//#define PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE 524288
#define PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE (5<<20) 
/* 4096:
         (200000 users) / (64 CNAT INSTANCES) = 3125
         nearest higher number which is power of 2 next to 3125
*/
#undef PLATFORM_CNAT_USER_PRELIM_HASH_SIZE
#define PLATFORM_CNAT_USER_PRELIM_HASH_SIZE 4096

#undef PLATFORM_CNAT_MAX_ADDR_POOL_SIZE
#define PLATFORM_CNAT_MAX_ADDR_POOL_SIZE 0x10000 // max /16

#undef PLATFORM_MAX_DB_ENTRY_PER_SCAN
#define PLATFORM_MAX_DB_ENTRY_PER_SCAN 400

#undef PLATFORM_MAX_DB_ENTRY_SELECTED_PER_SCAN
#define PLATFORM_MAX_DB_ENTRY_SELECTED_PER_SCAN 100 // 1/4th of above

#undef PLATFORM_CNAT_TIMEOUT_IPPROT_MASK
#define PLATFORM_CNAT_TIMEOUT_IPPROT_MASK   0xFFFFFFFF0000FFFF

#undef PLATFORM_CNAT_TIMEOUT_PORTPROT_MASK
#define PLATFORM_CNAT_TIMEOUT_PORTPROT_MASK 0x00000000FFFFFFFF

#ifdef TARGET_RODDICK /* EVB doesnt need it */
#undef PLATFORM_FILL_DST_ADDR_PORT_TABLE
#define PLATFORM_FILL_DST_ADDR_PORT_TABLE  fill_dst_addr_port_table();
#endif


#ifndef RODDICK_ON_LINUX_OR_EVB
#undef PLATFORM_SET_CTX_RU_TX_FROM_NODE
#undef PLATFORM_SET_CTX_RU_TX_DST_IPPORT_IDX
#undef PLATFORM_SET_CTX_RU_TX_PKT_TYPE

#define PLATFORM_SET_CTX_RU_TX_FROM_NODE(ctx, value)      \
                             (vnet_buffer(ctx))->vcgn_uii.ru.tx.from_node = value;
#define PLATFORM_SET_CTX_RU_TX_DST_IPPORT_IDX(ctx, value)  \
                             (vnet_buffer(ctx))->vcgn_uii.ru.tx.dst_ip_port_idx = value;
#define PLATFORM_SET_CTX_RU_TX_PKT_TYPE(ctx, type)   \
                             (vnet_buffer(ctx))->vcgn_uii.ru.tx.packet_type = type; 
#endif

#undef PLATFORM_SET_RX_VRF
#undef  PLATFORM_SET_TX_VRF
#ifdef TARGET_RODDICK
#define PLATFORM_SET_RX_VRF(ctx, rx_vrf, hardcode, mask)     \
                                    rx_vrf = (ctx->ru.rx.uidb_index & CNAT_VRF_MASK);
#define PLATFORM_SET_TX_VRF(ctx, tx_vrf)      \
               ctx->ru.tx.uidb_index = tx_vrf;
#else /*EVB */
#define PLATFORM_SET_RX_VRF(ctx, rx_vrf, hardcode, mask)     \
                rx_vrf = hardcode;
#define PLATFORM_SET_TX_VRF(ctx, tx_vrf)
#endif

#undef PLATFORM_CNAT_SET_RX_VRF
#undef PLATFORM_CNAT_SET_TX_VRF

#define PLATFORM_CNAT_SET_RX_VRF(if_index, rx_vrf, proto) \
    rx_vrf = proto | ((if_index) & CNAT_VRF_MASK);

#define PLATFORM_CNAT_SET_TX_VRF(if_index, tx_vrf) \
    (if_index) = ((tx_vrf) & CNAT_VRF_MASK);



#undef PLATFORM_NAT64_SET_RX_VRF

#ifdef TARGET_RODDICK

#define PLATFORM_NAT64_SET_RX_VRF(rx_vrf, proto, inst_id) \
    rx_vrf = proto | (inst_id & CNAT_VRF_MASK);

#else /* EVB */

#define PLATFORM_NAT64_SET_RX_VRF(rx_vrf, proto, inst_id) \
    rx_vrf = proto | inst_id;

#endif

#ifdef TARGET_EVB
#define VRF_MAP_CONFIG
#endif

#undef PLATFORM_PRINT_TESTING_PG
#if defined(TARGET_LINUX_UDVR) || defined(CNAT_PG)
#define  PLATFORM_PRINT_TESTING_PG()   printf("testing pg\n");
#else
#define  PLATFORM_PRINT_TESTING_PG() 
#endif

#ifdef TARGET_RODDICK
#undef PLATFORM_INIT_TEMP_SENSORS
#undef PLATFORM_READ_CPU_SENSORS
#undef PLATFORM_SET_TEMP_READ_BLOCK

#define  PLATFORM_INIT_TEMP_SENSORS()        Init_temperature_sensors();
#define  PLATFORM_READ_CPU_SENSORS(value)    read_octeon_sensors(value);
#define  PLATFORM_SET_TEMP_READ_BLOCK(var, val) var = &val->param[0];
#endif

#undef PLATFORM_HANDLE_ICMP_TTL_EXPIRED
#define PLATFORM_HANDLE_ICMP_TTL_EXPIRED 1 // handle TTL in NAT44 Application (for AVSM)

#undef  PLATFORM_NFV9_DISP_NODE_IDX
#ifdef TARGET_RODDICK
#define PLATFORM_NFV9_DISP_NODE_IDX   "roddick_infra_l3_tx"
#else /* EVB */
#define PLATFORM_NFV9_DISP_NODE_IDX   "cnat_rewrite_output"
#endif

#undef PLATFORM_CNAT_DB_DUMP_POLICY_PRINT
#define PLATFORM_CNAT_DB_DUMP_POLICY_PRINT() \
    printf("my instance:%d\n" \
           "icmp timeout %d udp init timeout %d act timeout %d\n" \
           "tcp init timeout %d act timeout %d mapping refresh %d\n" \
           "port limit per user %d ftp alg %d lb debug %d\n" \
           "icmp rate limit 0x%x config delete timer 0x%x\n" \
           "global debug flag 0x%x\n" \
           "icmp rate limit (pkts/per sec) %d\n" \
           "dynamic port range start %d\n" \
           "debug ivrf 0x%x flag 0x%x start_addr 0x%x end_addr 0x%x\n" \
           "debug ovrf 0x%x flag 0x%x start_addr 0x%x end_addr 0x%x\n", \
            my_instance_number, \
            icmp_session_timeout, udp_init_session_timeout, udp_act_session_timeout, \
            tcp_initial_setup_timeout, tcp_active_timeout, \
            mapping_refresh_both_direction, cnat_main_db_max_ports_per_user, \
            ftp_alg_enabled, lb_debug_enable, per_user_icmp_msg_limit, \
            config_delete_timeout, \
            global_debug_flag, \
            cnat_main_db_icmp_rate_limit, \
            cnat_static_port_range, \
            debug_i_vrf, debug_i_flag, debug_i_addr_start, debug_i_addr_end, \
            debug_o_vrf, debug_o_flag, debug_o_addr_start, debug_o_addr_end); 


#undef PLATFORM_PRINT_CTX_VALUES
#ifdef TARGET_RODDICK
#define PLATFORM_PRINT_CTX_VALUES(ctx) \
        printf("\nAFTER: %s cur_hdr %p, uidb %d, pkt_type %d, cur_len %d\n", \
               type_str, \
               ctx->current_header, \
               ctx->ru.tx.uidb_index, \
               ctx->ru.tx.packet_type, \
               ctx->current_length);
#else /* EVB */
#define PLATFORM_PRINT_CTX_VALUES(ctx) \
        printf("\nAFTER: %s cur_hdr %p, cur_len %d\n", \
               type_str,\
               ctx->current_header, \
               ctx->current_length);
#endif

#undef PLATFORM_ADD_VRF_MAP_HANDLE_PARTITION
#define PLATFORM_ADD_VRF_MAP_HANDLE_PARTITION(uidb_index, partition_id)

#undef PLATFORM_DEL_VRF_MAP_HANDLE_PARTITION
#define PLATFORM_DEL_VRF_MAP_HANDLE_PARTITION(uidb_index, partition_id)

#undef PLATFORM_ALLOC_NFV9_PKT_BUFFER
#define PLATFORM_ALLOC_NFV9_PKT_BUFFER(ctx, to_lc_cpu)

#undef PLATFORM_CNAT_NFV9_SHIM_HDR_OFFSET
#ifdef TARGET_RODDICK
// This corresponds to the length of the IMETRO SHIM Header for RODDICK
#define PLATFORM_CNAT_NFV9_SHIM_HDR_OFFSET 8
#else
#define PLATFORM_CNAT_NFV9_SHIM_HDR_OFFSET 0
#endif

#undef PLATFORM_CNAT_NFV9_L2_ENCAPS_OFFSET
#ifdef TARGET_RODDICK
#define PLATFORM_CNAT_NFV9_L2_ENCAPS_OFFSET 0
#else
#define PLATFORM_CNAT_NFV9_L2_ENCAPS_OFFSET 16
#endif

#undef PLATFORM_MAX_SHOW_BUFFER_SIZE
#undef PLATFORM_MAX_TRANSLATION_ENTRIES
#undef PLATFORM_MAX_UTIL_ENTRIES

#define PLATFORM_MAX_SHOW_BUFFER_SIZE 1700
#define PLATFORM_MAX_TRANSLATION_ENTRIES (50)
#define PLATFORM_NAT64_MAX_TRANSLATION_ENTRIES (30)
#define PLATFORM_MAX_UTIL_ENTRIES (100)


#undef PLATFORM_NAT64_MAX_SESSIONS         
#undef PLATFORM_NAT64_TIMEOUT_HASH_SIZE    
#define PLATFORM_NAT64_MAX_SESSIONS         20000000
#define PLATFORM_NAT64_TIMEOUT_HASH_SIZE    24001 /* Ref: CSCtr36242 */

#undef PLATFORM_CHECK_DSLITE_ENABLE_FLAG
#define PLATFORM_CHECK_DSLITE_ENABLE_FLAG 1

/* Fragment hold limit is Platform specific */
/* For Roddick, it is 63 due to hardware limitation */
#undef PLATFORM_IPV4_FRAG_FRAG_HOLD_LIMIT
#define PLATFORM_IPV4_FRAG_FRAG_HOLD_LIMIT 63

#undef PLATFORM_MAX_IPV4_CTX_ENTRIES
#define PLATFORM_MAX_IPV4_CTX_ENTRIES 80

#undef PLATFORM_DIRN_IN_TO_OUT
#undef PLATFORM_DIRN_OUT_TO_IN
#undef PLATFORM_SET_SVI_PARAMS_FIELD

#define PLATFORM_DIRN_IN_TO_OUT 
#define PLATFORM_DIRN_OUT_TO_IN
#define PLATFORM_SET_SVI_PARAMS_FIELD(var, value)

#undef PLATFORM_GET_NFV9_L3_HDR_OFFSET
#define PLATFORM_GET_NFV9_L3_HDR_OFFSET \
        ((u8 *)ctx + ctx->data + CNAT_NFV9_IP_HDR_OFFSET);

#undef PLATFORM_GET_NFV9_L4_HDR_OFFSET
#define PLATFORM_GET_NFV9_L4_HDR_OFFSET \
        ((u8 *) ctx + ctx->data + CNAT_NFV9_UDP_HDR_OFFSET);

#undef PLATFORM_MEMSET_CNAT_LOG_PKT_DATA
#define PLATFORM_MEMSET_CNAT_LOG_PKT_DATA

/*
  Index 0 -- SE_P2MP
  Index 1 -- HA Destination 1
  Index 2 -- HA Destination 2
  Index 3 -- EXT_LOG_SRVR
*/
enum {
    NODE_CGNCFG,
    NODE_HA,
    NODE_PD_CONFIG,
    NODE_LOGGING,
    NODE_TRACE_BACKUP,
    NODE_MAX,
};

#endif /* __PLATFORM_COMMON_OVERRIDE_H__ */
