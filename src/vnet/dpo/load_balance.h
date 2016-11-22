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
 * \brief
 * The load-balance object represents an ECMP choice. The buckets of a load
 * balance object point to the sub-graph after the choice is made.
 * THe load-balance object is also object type returned from a FIB table lookup.
 * As such it needs to represent the case where there is only one coice. It may
 * seem like overkill to use a load-balance object in this case, but the reason
 * is for performance. If the load-balance object were not the result of the FIB
 * lookup, then some other object would be. The case where there was ECMP
 * this other object would need a load-balance as a parent and hence just add
 * an unnecessary indirection.
 *
 * It is also the object in the DP that represents a via-fib-entry in a recursive
 * route.
 *
 */

#ifndef __LOAD_BALANCE_H__
#define __LOAD_BALANCE_H__

#include <vlib/vlib.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_entry.h>

/**
 * Load-balance main
 */
typedef struct load_balance_main_t_
{
    vlib_combined_counter_main_t lbm_to_counters;
    vlib_combined_counter_main_t lbm_via_counters;
} load_balance_main_t;

extern load_balance_main_t load_balance_main;

/**
 * The number of buckets that a load-balance object can have and still
 * fit in one cache-line
 */
#define LB_NUM_INLINE_BUCKETS 4

/**
 * @brief One path from an [EU]CMP set that the client wants to add to a
 * load-balance object
 */
typedef struct load_balance_path_t_ {
    /**
     * ID of the Data-path object.
     */
    dpo_id_t path_dpo;

    /**
     * The index of the FIB path
     */
    fib_node_index_t path_index;

    /**
     * weight for the path.
     */
    u32 path_weight;
} load_balance_path_t;

/**
 * The FIB DPO provieds;
 *  - load-balancing over the next DPOs in the chain/graph
 *  - per-route counters
 */
typedef struct load_balance_t_ {
    /**
     * number of buckets in the load-balance. always a power of 2.
     */
    u16 lb_n_buckets;
    /**
     * number of buckets in the load-balance - 1. used in the switch path
     * as part of the hash calculation.
     */
    u16 lb_n_buckets_minus_1;

   /**
     * The protocol of packets that traverse this LB.
     * need in combination with the flow hash config to determine how to hash.
     * u8.
     */
    dpo_proto_t lb_proto;

    /**
     * Flags from the load-balance's associated fib_entry_t
     */
    fib_entry_flag_t lb_fib_entry_flags;

    /**
     * The number of locks, which is approximately the number of users,
     * of this load-balance.
     * Load-balance objects of via-entries are heavily shared by recursives,
     * so the lock count is a u32.
     */
    u32 lb_locks;

    /**
     * index of the load-balance map, INVALID if this LB does not use one
     */
    index_t lb_map;

    /**
     * This is the index of the uRPF list for this LB
     */
    index_t lb_urpf;

    /**
     * the hash config to use when selecting a bucket. this is a u16
     */
    flow_hash_config_t lb_hash_config;

    /**
     * Vector of buckets containing the next DPOs, sized as lbo_num
     */
    dpo_id_t *lb_buckets;

    /**
     * The rest of the cache line is used for buckets. In the common case
     * where there there are less than 4 buckets, then the buckets are
     * on the same cachlie and we save ourselves a pointer dereferance in 
     * the data-path.
     */
    dpo_id_t lb_buckets_inline[LB_NUM_INLINE_BUCKETS];
} load_balance_t;

STATIC_ASSERT(sizeof(load_balance_t) <= CLIB_CACHE_LINE_BYTES,
	      "A load_balance object size exceeds one cachline");

/**
 * Flags controlling load-balance formatting/display
 */
typedef enum load_balance_format_flags_t_ {
    LOAD_BALANCE_FORMAT_NONE,
    LOAD_BALANCE_FORMAT_DETAIL = (1 << 0),
} load_balance_format_flags_t;

/**
 * Flags controlling load-balance creation and modification
 */
typedef enum load_balance_flags_t_ {
    LOAD_BALANCE_FLAG_NONE = 0,
    LOAD_BALANCE_FLAG_USES_MAP = (1 << 0),
} load_balance_flags_t;

extern index_t load_balance_create(u32 num_buckets,
				   dpo_proto_t lb_proto,
				   flow_hash_config_t fhc);
extern void load_balance_multipath_update(
    const dpo_id_t *dpo,
    const load_balance_path_t * raw_next_hops,
    load_balance_flags_t flags);

extern void load_balance_set_bucket(index_t lbi,
				    u32 bucket,
				    const dpo_id_t *next);
extern void load_balance_set_urpf(index_t lbi,
				  index_t urpf);
extern void load_balance_set_fib_entry_flags(index_t lbi,
                                             fib_entry_flag_t flags);
extern index_t load_balance_get_urpf(index_t lbi);

extern u8* format_load_balance(u8 * s, va_list * args);

extern const dpo_id_t *load_balance_get_bucket(index_t lbi,
					       u32 bucket);
extern int load_balance_is_drop(const dpo_id_t *dpo);

extern f64 load_balance_get_multipath_tolerance(void);

/**
 * The encapsulation breakages are for fast DP access
 */
extern load_balance_t *load_balance_pool;
static inline load_balance_t*
load_balance_get (index_t lbi)
{
    return (pool_elt_at_index(load_balance_pool, lbi));
}

#define LB_HAS_INLINE_BUCKETS(_lb)		\
    ((_lb)->lb_n_buckets <= LB_NUM_INLINE_BUCKETS)

static inline const dpo_id_t *
load_balance_get_bucket_i (const load_balance_t *lb,
			   u32 bucket)
{
    ASSERT(bucket < lb->lb_n_buckets);

    if (PREDICT_TRUE(LB_HAS_INLINE_BUCKETS(lb)))
    {
	return (&lb->lb_buckets_inline[bucket]);
    }
    else
    {
	return (&lb->lb_buckets[bucket]);
    }
}

extern void load_balance_module_init(void);

#endif
