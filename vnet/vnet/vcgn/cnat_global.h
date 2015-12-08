/* 
 *------------------------------------------------------------------
 * cnat_global.h - global definition and variables
 * to be used by non cnat files
 *
 * Copyright (c) 2007-2012 Cisco and/or its affiliates.
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

#ifndef __CNAT_GLOBAL_H__
#define __CNAT_GLOBAL_H__

/* gloable variables */

extern u8  cnat_db_init_done;
extern u32 cnat_current_time;
extern u64 in2out_drops_port_limit_exceeded;
extern u64 in2out_drops_system_limit_reached;
extern u64 in2out_drops_resource_depletion;
extern u64 no_translation_entry_drops;
extern u8 nfv9_configured;
extern u32 translation_create_count;
extern u32 translation_create_rate;

extern u32 translation_delete_count;
extern u32 translation_delete_rate;

extern u32 in2out_forwarding_count;
extern u32 in2out_forwarding_rate;

extern u32 out2in_forwarding_count;
extern u32 out2in_forwarding_rate;

extern u32 total_address_pool_allocated;

extern u32 nat44_active_translations;

#if 1 //DSLITE_DEF
extern u32 dslite_translation_create_rate;
extern u32 dslite_translation_delete_rate;
extern u32 dslite_translation_create_count;
extern u32 dslite_in2out_forwarding_count;
extern u32 dslite_in2out_forwarding_count;
extern u32 dslite_out2in_forwarding_rate;
#endif
/* sf/ctx allocation error collection declarations */
#define COLLECT_FREQ_FACTOR 100
#define NUM_SECONDS_TO_WAIT 10
#define COUNTER_BUFFER_SIZE 25

extern u32 null_enq_pkt;
extern u32 null_deq_pkt;

extern u32 null_enq_ctx;
extern u32 null_deq_ctx;

extern u32 null_enq_wqe;
extern u32 null_deq_wqe;

extern u32 ctx_alloc_errs;
extern u32 sf_alloc_errs;

extern u32 rcv_pkt_errs;

struct counter_array_t {
        u32     sf_error_counter;
        u32     ctx_error_counter;
        u32     timestamp;
} counter_array_t;

#define COUNTER_BUFFER_SIZE 25
struct counter_array_t err_cnt_arr[COUNTER_BUFFER_SIZE];

//#define DISABLE_ICMP_THROTTLE_FOR_DEBUG_PURPOSE

#endif  /*__CNAT_GLOBAL_H__*/
