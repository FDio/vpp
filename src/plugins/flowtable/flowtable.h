/*---------------------------------------------------------------------------
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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

#ifndef __flowtable_h__
#define __flowtable_h__

#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>

#include "flowdata.h"

#define foreach_flowtable_error                       \
    _(HIT, "packets with an existing flow")           \
    _(THRU, "packets gone through")                   \
    _(CREATED, "packets which created a new flow")    \
    _(OFFLOADED, "packets which have been offloaded") \
    _(ALLOC_ERROR, "failed to allocate flow")         \
    _(TIMER_EXPIRE, "flows that have expired")        \
    _(COLLISION, "hashtable collisions")

typedef enum {
#define _(sym, str) FLOWTABLE_ERROR_##sym,
    foreach_flowtable_error
#undef _
    FLOWTABLE_N_ERROR
} flowtable_error_t;


typedef enum {
    FT_NEXT_DROP,
    FT_NEXT_ETHERNET_INPUT,
    FT_NEXT_N_NEXT
} flowtable_next_t;

/* signatures */
struct ip6_sig {
    ip6_address_t src, dst;
    u8 proto;
    u16 port_src, port_dst;
} __attribute__ ((packed));
struct ip4_sig {
    ip4_address_t src, dst;
    u8 proto;
    u16 port_src, port_dst;
} __attribute__ ((packed));

typedef union {
    struct ip6_sig ip6;
    struct ip4_sig ip4;
    u8 data[0]; /* gcc will take the max */
} signature;

/* dlist helpers */
#define dlist_is_head(node) ((node)->value == (u32) ~0)
#define dlist_is_empty(pool, head_index)                          \
({                                                                \
    dlist_elt_t *head = pool_elt_at_index ((pool), (head_index)); \
    (head->next == (u32) ~0 || head->next == (head_index));       \
})

/* flow helpers */
#define flow_is_offloaded(f) ((f)->infos.data.offloaded)

typedef struct {
    u32 straight;
    u32 reverse;
} flow_stats_t;

typedef struct flow_entry
{
    /* Required for pool_get_aligned  */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* flow signature */
    u32 sig_len;
    signature sig;
    u64 sig_hash; /* used to delete hashtable entries */

    /* hashtable */
    u32 ht_line_index; /* index of the list head of the line in the hashtable */
    u32 ht_index; /* index in the hashtable line pool */

    /* stats */
    flow_stats_t stats;

    /* timers */
    u32 expire; /* in seconds */
    u32 lifetime; /* in seconds */
    u32 timer_index; /* index in the timer pool */

    /* the following union will be copied to vlib->opaque
     * it MUST be less or equal CLIB_CACHE_LINE_BYTES */
    flow_data_t infos;
} flow_entry_t;

/* TODO improve timer duration (tcp sm state) */

/* Timers (in seconds) */
#define TIMER_DEFAULT_LIFETIME (60)
#define TIMER_MAX_LIFETIME (300)

/* Default max number of flows to expire during one run.
 * 256 is the max number of packets in a vector, so this is a minimum 
 * if all packets create a flow. */
#define TIMER_MAX_EXPIRE (256)

typedef struct {
    /* flow entry pool */
    flow_entry_t * flows;

    /* hashtable */
    BVT(clib_bihash) flows_ht;
    dlist_elt_t * ht_lines;
    u64 flows_cpt;

    /* flowtable node index */
    u32 flowtable_index;

    /* timers */
    dlist_elt_t * timers;
    u32 * timer_wheel;
    u32 time_index;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;

    /* next-node of flowtable node, NOT pm node id */
    u32 next_node_index;

    /* API dynamically registered base ID. */
    u16 msg_id_base;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;

/*
 * As advised in the thread below :
 * https://lists.fd.io/pipermail/vpp-dev/2016-October/002787.html
 * hashtable is configured to alloc (NUM_BUCKETS * CLIB_CACHE_LINE_BYTES) Bytes
 * with (flow_count / (BIHASH_KVP_PER_PAGE / 2)) Buckets
 */
#define FM_POOL_COUNT_LOG2 20
#define FM_POOL_COUNT (1 << FM_POOL_COUNT_LOG2)
#define FM_NUM_BUCKETS (1 << (FM_POOL_COUNT_LOG2 - (BIHASH_KVP_PER_PAGE / 2)))
#define FM_MEMORY_SIZE (FM_NUM_BUCKETS * CLIB_CACHE_LINE_BYTES)


extern vlib_node_registration_t flowtable_node;

/* API functions */
int flowtable_enable_disable(flowtable_main_t * fm, u32 sw_if_index, int enable_disable);

int flowtable_update(u8 is_ip4, u8 ip_src[16], u8 ip_dst[16], u8 ip_upper_proto,
        u16 port_src, u16 port_dst, u16 lifetime, u8 offloaded, u8 infos[27]);

#endif  /* __flowtable_h__ */
