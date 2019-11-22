/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __FILTER_TARGET_RETURN_H__
#define __FILTER_TARGET_RETURN_H__

#include <filter/filter_target.h>

/**
 * Target to return to return from the end of one chain to the next match
 * after the original jump.
 */
typedef struct filter_target_return_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Base class first
   */
  dpo_proto_t ftr_proto;

  /**
   * locks.
   */
  u32 ftr_locks;
} filter_target_return_t;

STATIC_ASSERT (sizeof (filter_target_return_t) <= CLIB_CACHE_LINE_BYTES,
	       "return Target not in a cache line");

extern int filter_target_return_add_and_lock (dpo_proto_t proto,
					      dpo_id_t * fot);
extern void filter_target_return_restack (index_t);

/**
 * Walk/visit each of the return targets
 */
extern void filter_target_return_walk (filter_target_walk_cb_t cb, void *ctx);

/**
 * Exposed DP types and function
 */
extern filter_target_return_t *filter_target_return_pool;

static inline filter_target_return_t *
filter_target_return_get (index_t ftji)
{
  return (pool_elt_at_index (filter_target_return_pool, ftji));
}

/**
 * TEST functions
 */
extern bool filter_target_is_return (const dpo_id_t * dpo);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
