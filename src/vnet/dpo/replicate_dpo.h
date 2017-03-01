/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */
/**
 * @brief
 *
 */

#ifndef __REPLICATE_DPO_H__
#define __REPLICATE_DPO_H__

#include <vlib/vlib.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_types.h>
#include <vnet/mpls/mpls_types.h>

/**
 * replicate main
 */
typedef struct replicate_main_t_
{
    vlib_combined_counter_main_t repm_counters;

    /* per-cpu vector of cloned packets */
    u32 **clones;
} replicate_main_t;

extern replicate_main_t replicate_main;

/**
 * The number of buckets that a load-balance object can have and still
 * fit in one cache-line
 */
#define REP_NUM_INLINE_BUCKETS 4

/**
 * The FIB DPO provieds;
 *  - load-balancing over the next DPOs in the chain/graph
 *  - per-route counters
 */
typedef struct replicate_t_ {
    /**
     * number of buckets in the load-balance. always a power of 2.
     */
    u16 rep_n_buckets;

   /**
     * The protocol of packets that traverse this REP.
     * need in combination with the flow hash config to determine how to hash.
     * u8.
     */
    dpo_proto_t rep_proto;

    /**
     * The number of locks, which is approximately the number of users,
     * of this load-balance.
     * Load-balance objects of via-entries are heavily shared by recursives,
     * so the lock count is a u32.
     */
    u32 rep_locks;

    /**
     * Vector of buckets containing the next DPOs, sized as repo_num
     */
    dpo_id_t *rep_buckets;

    /**
     * The rest of the cache line is used for buckets. In the common case
     * where there there are less than 4 buckets, then the buckets are
     * on the same cachlie and we save ourselves a pointer dereferance in 
     * the data-path.
     */
    dpo_id_t rep_buckets_inline[REP_NUM_INLINE_BUCKETS];
} replicate_t;

STATIC_ASSERT(sizeof(replicate_t) <= CLIB_CACHE_LINE_BYTES,
	      "A replicate object size exceeds one cachline");

/**
 * Flags controlling load-balance formatting/display
 */
typedef enum replicate_format_flags_t_ {
    REPLICATE_FORMAT_NONE,
    REPLICATE_FORMAT_DETAIL = (1 << 0),
} replicate_format_flags_t;

extern index_t replicate_create(u32 num_buckets,
                                dpo_proto_t rep_proto);
extern void replicate_multipath_update(
    const dpo_id_t *dpo,
    load_balance_path_t *next_hops);

extern void replicate_set_bucket(index_t repi,
				    u32 bucket,
				    const dpo_id_t *next);

extern u8* format_replicate(u8 * s, va_list * args);

extern const dpo_id_t *replicate_get_bucket(index_t repi,
					       u32 bucket);
extern int replicate_is_drop(const dpo_id_t *dpo);

/**
 * The encapsulation breakages are for fast DP access
 */
extern replicate_t *replicate_pool;
static inline replicate_t*
replicate_get (index_t repi)
{
    repi &= ~MPLS_IS_REPLICATE;
    return (pool_elt_at_index(replicate_pool, repi));
}

#define REP_HAS_INLINE_BUCKETS(_rep)		\
    ((_rep)->rep_n_buckets <= REP_NUM_INLINE_BUCKETS)

static inline const dpo_id_t *
replicate_get_bucket_i (const replicate_t *rep,
			   u32 bucket)
{
    ASSERT(bucket < rep->rep_n_buckets);

    if (PREDICT_TRUE(REP_HAS_INLINE_BUCKETS(rep)))
    {
	return (&rep->rep_buckets_inline[bucket]);
    }
    else
    {
	return (&rep->rep_buckets[bucket]);
    }
}

extern void replicate_module_init(void);

#endif
