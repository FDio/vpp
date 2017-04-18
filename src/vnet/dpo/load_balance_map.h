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
 */

#ifndef __LOAD_BALANCE_MAP_H__
#define __LOAD_BALANCE_MAP_H__

#include <vlib/vlib.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/load_balance.h>

struct load_balance_map_path_t_;

/**
 */
typedef struct load_balance_map_t_ {
    /**
     * The buckets of the map that provide the index to index translation.
     * In the first cacheline.
     */
    u16 *lbm_buckets;

    /**
     * the vector of paths this MAP represents
     */
    struct load_balance_map_path_t_ *lbm_paths;

    /**
     * the sum of the normalised weights. cache for convenience
     */
    u32 lbm_sum_of_norm_weights;

    /**
     * Number of locks. Maps are shared by a large number of recrusvie fib_entry_ts
     */
    u32 lbm_locks;
} load_balance_map_t;

extern index_t load_balance_map_add_or_lock(u32 n_buckets,
                                            u32 sum_of_weights,
                                            const load_balance_path_t *norm_paths);

extern void load_balance_map_lock(index_t lmbi);
extern void load_balance_map_unlock(index_t lbmi);

extern void load_balance_map_path_state_change(fib_node_index_t path_index);

extern u8* format_load_balance_map(u8 *s, va_list ap);
extern void load_balance_map_show_mem(void);

/**
 * The encapsulation breakages are for fast DP access
 */
extern load_balance_map_t *load_balance_map_pool;

static inline load_balance_map_t*
load_balance_map_get (index_t lbmi)
{
    return (pool_elt_at_index(load_balance_map_pool, lbmi));
}

static inline u16
load_balance_map_translate (index_t lbmi,
                            u16 bucket)
{
    load_balance_map_t*lbm;

    lbm = load_balance_map_get(lbmi);

    return (lbm->lbm_buckets[bucket]);
}

static inline const dpo_id_t *
load_balance_get_fwd_bucket (const load_balance_t *lb,
                             u16 bucket)
{
    ASSERT(bucket < lb->lb_n_buckets);

    if (INDEX_INVALID != lb->lb_map)
    {
        bucket = load_balance_map_translate(lb->lb_map, bucket);
    }

    if (PREDICT_TRUE(LB_HAS_INLINE_BUCKETS(lb)))
    {
	return (&lb->lb_buckets_inline[bucket]);
    }
    else
    {
	return (&lb->lb_buckets[bucket]);
    }
}

extern void load_balance_map_module_init(void);

#endif
