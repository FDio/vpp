/*
 *---------------------------------------------------------------------------
 * platform_common.h -- file has all platform related macros defined as NULL
 *                      included "platform_common_override.h will have actual
 *                      platform specific defines
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
#ifndef __PLATFORM_COMMON_H__
#define __PLATFORM_COMMON_H__

/* $$$ FIXME causes printf format warnings */
#define PLATFORM_DEBUG_PRINT(...) /* printf(__VA_ARGS__) */
#define PLATFORM_FILL_DST_ADDR_PORT_TABLE  
#define PLATFORM_SET_CTX_RU_TX_FROM_NODE(ctx, value)
#define PLATFORM_SET_CTX_RU_TX_DST_IPPORT_IDX(ctx, value)
#define PLATFORM_SET_CTX_RU_TX_PKT_TYPE(ctx, type)  
#define PLATFORM_SET_RX_VRF(ctx, rx_vrf, hardcode, mask)  
#define PLATFORM_SET_TX_VRF(ctx, tx_vrf)
/* PLATFORM_CNAT_SET_RX_VRF definition is not same as PLATFORM_SET_RX_VRF,
 * So, maintaining two different definitions
 */   
#define PLATFORM_CNAT_SET_RX_VRF(ctx, rx_vrf, proto)
#define PLATFORM_CNAT_SET_TX_VRF(ctx, tx_vrf)

#define PLATFORM_PRINT_TESTING_PG()  
#define PLATFORM_INIT_TEMP_SENSORS() 
#define PLATFORM_READ_CPU_SENSORS(value) 
#define PLATFORM_SET_TEMP_READ_BLOCK(var, val)
#define PLATFORM_NFV9_DISP_NODE_IDX


/* Assumption is, syslog packets
 * are sent out via same channel as that of NFV9.
 * Has to be overridden if this assumption is false.
 */
#define PLATFORM_SYSLOG_DISP_NODE_IDX   PLATFORM_NFV9_DISP_NODE_IDX

#define PLATFORM_CNAT_DB_DUMP_POLICY_PRINT() 
#define PLATFORM_PRINT_CTX_VALUES(ctx)
#define PLATFORM_ADD_VRF_MAP_HANDLE_PARTITION(uidb_index, partition_id)
#define PLATFORM_DEL_VRF_MAP_HANDLE_PARTITION(uidb_index, partition_id)
#define PLATFORM_ALLOC_NFV9_PKT_BUFFER(ctx, to_lc_cpu)
#define PLATFORM_SET_DSLITE_ENABLE_FLAG(uidb_index, dslite_id) 
#define PLATFORM_CHECK_DSLITE_ENABLE_FLAG

#define PLATFORM_CNAT_INSTS 1
#define PLATFORM_HANDLE_TTL_DECREMENT 0 // Don't handle TTL in NAT44 Application (default). 

// For ISM, we need to copy the ipv6->hop_limit to ipv4 ttl.
#define PLATFORM_6RD_COPY_TTL_IPV6_TO_IPV4 0

//For ISM case, need to allow as the TTL decrement happens at ingress LC
#define PLATFORM_6RD_ALLOW_TTL_1 0 

#define PLATFORM_HANDLE_ICMP_TTL_EXPIRED 0 // Don't handle ICMP_ERROR msg for TTL <=1 in NAT44 App (default).

#define PLATFORM_IPV4_FRAG_FRAG_HOLD_LIMIT 1 
#define PLATFORM_MAX_IPV4_CTX_ENTRIES  1 
#define PLATFORM_MAPE_FRAG 0

#define PLATFORM_ADDR_MASK_PER_CORE 0
#define PLATFORM_ADDR_MASK_PER_CORE_PER_PARTITION 0
#define PLATFORM_MAX_CORES 1
#define PLATFORM_MAX_CORES_PER_PARTITION 1
#define PLATFORM_MAX_NAT_ENTRIES 1
#define PLATFORM_MAX_USER_ENTRIES 1
#define PLATFORM_CNAT_MAX_ADDR_POOL_SIZE 0x1
#define PLATFORM_DBL_SUPPORT  0 /* Default no DBL support, no NAT44 session table */

#define PLATFORM_MAX_DB_ENTRY_PER_SCAN 1
#define PLATFORM_MAX_DB_ENTRY_SELECTED_PER_SCAN 1
#define MAX_COMBINED_DB_ENTRIES_PER_SCAN 0

#define PLATFORM_CNAT_TIMEOUT_IPPROT_MASK 0
#define PLATFORM_CNAT_TIMEOUT_PORTPROT_MASK 0

#define PLATFORM_MAX_SHOW_BUFFER_SIZE 1700
#define PLATFORM_MAX_TRANSLATION_ENTRIES (50)
#define PLATFORM_MAX_UTIL_ENTRIES (100)
#define PLATFORM_MAX_NAT44_UTIL_ENTRIES ((64)/PLATFORM_MAX_CORES)

#define PLATFORM_CNAT_NFV9_SHIM_HDR_OFFSET 0
#define PLATFORM_CNAT_NFV9_L2_ENCAPS_OFFSET 0


/* Below are nat64 statful related define */
#define PLATFORM_NAT64_SET_RX_VRF(rx_vrf, proto, inst_id) \
    rx_vrf = proto | (inst_id & CNAT_VRF_MASK);

#define PLATFORM_NAT64_MAX_TRANSLATION_ENTRIES (30)
#define PLATFORM_DS_LITE_MAX_TRANSLATION_ENTRIES (30)

#define PLATFORM_SET_NAT64_ENABLE_FLAG(uidb_index, nat64_id) \
        { \
              nat64_set_enable_flag(nat64_id, ENABLE); \
        }

#define PLATFORM_CHECK_NAT64_ENABLE_FLAG 1
#define PLATFORM_SET_MAPE_ENABLE_FLAG(uidb_index, mape_id)
#define PLATFORM_CHECK_MAPE_ENABLE_FLAG 1

/* very small number , PD has correct value.
   this is bcoz, if platform doesnt support nat64..shudnt take too much..*/ 
#define PLATFORM_NAT64_MAX_SESSIONS         10 
#define PLATFORM_NAT64_TIMEOUT_HASH_SIZE    10
#define PLATFORM_MAP_ADDR_PER_CORE          1024

#define ENABLE 1
#define DISABLE 0

/* Platform Xlat inline learn function  */
#define PLATFORM_INLINE_LEARN_FUNC(a,b,c)


/* Checksum calculation to be done in software */
#define PLATFORM_XLAT_SW_CHECKSUM_CALC 0


/* Below include overrides all the above null defs and defines platform specific
    define */
#include "platform_common_override.h"

#endif /*  __PLATFORM_COMMON_H__ */
