/*
 *------------------------------------------------------------------
 * cnat_log_common.h
 * Contains macros and definitions that are common to both syslog and nfv9
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

#ifndef __CNAT_LOG_COMMON_H__ 
#define __CNAT_LOG_COMMON_H__

#include <stdio.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "cnat_db.h"
#include "nat64_db.h"
#include "spp_timers.h"
#include "spp_ctx.h"

/*
 * This corresponds to the length of the IMETRO SHIM Header for RODDICK
 * For non-roddick cases, introduce an Ethernet header as well
 */
#if 0
   #if defined(TARGET_RODDICK)
   #define CNAT_NFV9_SHIM_HDR_OFFSET   8
   #define CNAT_NFV9_L2_ENCAPS_OFFSET  0
   #else
   #define CNAT_NFV9_SHIM_HDR_OFFSET   0
   #define CNAT_NFV9_L2_ENCAPS_OFFSET 16
   #endif
#endif

   #define CNAT_NFV9_IP_HDR_OFFSET 0

   #define CNAT_NFV9_UDP_HDR_OFFSET \
        (CNAT_NFV9_IP_HDR_OFFSET + sizeof(ipv4_header))

   #define CNAT_NFV9_HDR_OFFSET \
        (CNAT_NFV9_UDP_HDR_OFFSET + sizeof(udp_hdr_type_t))

u32 cnat_get_sys_up_time_in_ms(void);
u32 cnat_get_unix_time_in_seconds(void);
void cnat_dump_time_change_logs(void);
void cnat_handle_sys_time_change (time_t current_unix_time);
/*
 * Maximum number of time log changes we maintain
 */

#define MAX_TIME_CHANGE_LOGS (8)

typedef struct {
    /*
     * A timer structure to periodically send NFv9 & syslog logging packets
     * that have been waiting to be full for a long time.  This will
     * ensure add/delete events don't get delayed too much before they
     * are sent to the collector.
     */
     spp_timer_t log_timer;
     
     /*
      * Whether we have initialized the NFv9 information
      */
     u8 cnat_log_init_done;
} cnat_log_global_info_t;

#endif /* __CNAT_LOG_COMMON_H__ */
