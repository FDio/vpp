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

#include <pthread.h>
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
    _(UNHANDLED, "unhandled (non-ip)  packet")        \
    _(TIMER_EXPIRE, "flows that have expired")        \
    _(COLLISION, "hashtable collisions")              \
    _(RECYCLE, "flow recycled")

typedef enum {
#define _(sym, str) FLOWTABLE_ERROR_ ## sym,
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
}
__attribute__ ((packed));
struct ip4_sig {
    ip4_address_t src, dst;
    u8 proto;
    u16 port_src, port_dst;
}
__attribute__ ((packed));

typedef struct flow_signature {
    union {
        struct ip6_sig ip6;
        struct ip4_sig ip4;
        u8 data[0];  /* gcc will take the max */
    } s;
    u8 len;
} flow_signature_t;
#define flow_signature_is_ip4(s) (s->len == sizeof(struct ip4_sig))

/* dlist helpers */
#define dlist_is_empty(pool, head_index)                              \
    ({                                                                \
        dlist_elt_t * head = pool_elt_at_index((pool), (head_index)); \
        (head->next == (u32) ~0 || head->next == (head_index));       \
    })

/* flow helpers */
#define flow_is_offloaded(f) ((f)->infos.data.offloaded)

typedef struct {
    u32 pkts;
    u64 Bytes;
} flow_stats_t;

typedef struct {
    u32 flags;
    u32 ctx_id;
    u32 clt_pkts;
    u32 srv_pkts;
    u64 clt_Bytes;
    u64 srv_Bytes;
} __attribute__ ((packed)) timeout_msg_t;


typedef struct flow_entry
{
    /* Required for pool_get_aligned  */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

    /* flow signature */
    flow_signature_t sig;
    u16 tcp_state;
    u64 sig_hash;  /* used to delete hashtable entries */

    /* hashtable */
    u32 ht_line_index; /* index of the list head of the line in the hashtable */
    u32 ht_index; /* index in the hashtable line pool */

    /* stats */
    flow_stats_t stats[2];

    /* timers */
    u32 expire;  /* in seconds */
    u16 lifetime;  /* in seconds */
    u32 timer_index;  /* index in the timer pool */

    /* the following union will be copied to vlib->opaque
     * - it MUST be less or equal CLIB_CACHE_LINE_BYTES
     * - it SHOULD be less than 24Bytes so that it can fit into
     * the plugins_data field */
    flow_data_t infos;
} flow_entry_t;

/* Timers (in seconds) */
#define TIMER_DEFAULT_LIFETIME (60)
#define TIMER_MAX_LIFETIME (300)

/* Default max number of flows to expire during one run.
 * 256 is the max number of packets in a vector, so this is a minimum
 * if all packets create a flow. */
#define TIMER_MAX_EXPIRE (1 << 8)

/*
 * Maximum number of queued timeout messages
 * we expire at most (1 << 8) flows/vector, and store at most 4 times that
 * number in a circular buffer, which should be more than enough for another
 * node to get them.
 */
#define TIMEOUT_MSG_QUEUE_SZ (1 << 10)
#define TIMEOUT_MSG_MASK (TIMEOUT_MSG_QUEUE_SZ - 1)

typedef struct {
    /* hashtable */
    BVT(clib_bihash) flows_ht;
    dlist_elt_t * ht_lines;

    /* timers */
    dlist_elt_t * timers;
    u32 * timer_wheel;
    u32 time_index;

    /* flow cache
     * set cache size to 256 so that the worst node run fills the cache at most once */
#define FLOW_CACHE_SZ 256
    u32 * flow_cache;
} flowtable_main_per_cpu_t;

/*
 * As advised in the thread below :
 * https://lists.fd.io/pipermail/vpp-dev/2016-October/002787.html
 * hashtable is configured to alloc (NUM_BUCKETS * CLIB_CACHE_LINE_BYTES) Bytes
 * with (flow_count / (BIHASH_KVP_PER_PAGE / 2)) Buckets
 */
#define FM_POOL_COUNT_LOG2 22
#define FM_POOL_COUNT (1 << FM_POOL_COUNT_LOG2)
#define FM_NUM_BUCKETS (1 << (FM_POOL_COUNT_LOG2 - (BIHASH_KVP_PER_PAGE / 2)))
#define FM_MEMORY_SIZE (FM_NUM_BUCKETS * CLIB_CACHE_LINE_BYTES * 6)

typedef struct {
    /* flow entry pool */
    u32 flows_max;
    flow_entry_t * flows;
    pthread_spinlock_t flows_lock;
    u64 flows_cpt;

    /* timeout messages pool */
    timeout_msg_t * msg_pool;
    pthread_spinlock_t msg_lock;
    u32 first_msg_index;
    u32 last_msg_index;

    /* per cpu */
    flowtable_main_per_cpu_t * per_cpu;

    /* flowtable node index */
    u32 flowtable_index;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;

    /* next-node of flowtable node, NOT pm node id */
    u32 next_node_index;

    /* API dynamically registered base ID. */
    u16 msg_id_base;
} flowtable_main_t;

extern flowtable_main_t flowtable_main;
extern vlib_node_registration_t flowtable_input_node;

/* API functions */
int
flowtable_enable_disable(flowtable_main_t * fm, u32 sw_if_index, u8 enable_disable);

int
flowtable_update(u8 is_ip4, u8 ip_src[16], u8 ip_dst[16], u8 ip_upper_proto,
    u16 port_src, u16 port_dst, u16 lifetime, u8 offloaded, u8 infos[16]);

#endif  /* __flowtable_h__ */
