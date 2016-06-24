/* 
 *------------------------------------------------------------------
 * cnat_global.c - global variables
 *
 * Copyright (c) 2008-2009, 2012 Cisco and/or its affiliates.
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

/* gloable variables */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/buffer.h>

#include "dslite_defs.h"
#include "tcp_header_definitions.h"
u32 cnat_current_time;
u8 nfv9_configured = 0;
/* ctx/sf alloc error counters */
u32 null_enq_pkt;
u32 null_deq_pkt;

u32 null_enq_ctx;
u32 null_deq_ctx;

u32 null_enq_wqe;
u32 null_deq_wqe;

u32 ctx_alloc_errs;
u32 sf_alloc_errs;

u32 rcv_pkt_errs;

/* TOBE_PORTED : Remove following once we bring DSLite */
u32 dslite_config_debug_level = 1;
u32 dslite_data_path_debug_level = 1;
u32 dslite_defrag_debug_level = 1;
u32 dslite_debug_level = 1;

dslite_table_entry_t *dslite_table_db_ptr;

/*
 * ipv4_decr_ttl_n_calc_csum()
 * - It decrements the TTL and calculates the incremental IPv4 checksum
 */

/* TOBE_PORTED: Following is in cnat_util.c */
always_inline __attribute__((unused))
void ipv4_decr_ttl_n_calc_csum(ipv4_header *ipv4)
{
    u32 checksum;
    u16 old;
    u16 ttl;

    ttl = ipv4->ttl;
    old = clib_net_to_host_u16(ttl);

    /* Decrement TTL */
    ipv4->ttl--;

    /* Calculate incremental checksum */
    checksum = old + (~clib_net_to_host_u16(ttl) & 0xFFFF);
    checksum += clib_net_to_host_u16(ipv4->checksum);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    ipv4->checksum = clib_host_to_net_u32(checksum + (checksum >> 16));
}

