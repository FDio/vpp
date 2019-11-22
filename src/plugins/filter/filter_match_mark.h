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

#ifndef __FILTER_MATCH_MARK_H__
#define __FILTER_MATCH_MARK_H__

#include <filter/filter_match.h>

#include <vnet/ip/ip.h>

/**
 * Match packets based on IP address
 */
typedef struct filter_match_mark_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Base class first
   */
  filter_match_t fmm_base;

  /**
   * mask and bits
   */
  u32 fmm_mask;
  u32 fmm_bits;

  /**
   * locks.
   */
  u32 fmm_locks;
} filter_match_mark_t;

STATIC_ASSERT (sizeof (filter_match_mark_t) <= CLIB_CACHE_LINE_BYTES,
	       "Match mark not in a cache line");

extern int filter_match_mark_add_and_lock (dpo_proto_t proto,
					   u32 bits,
					   u32 mask, dpo_id_t * dpo);

/**
 * Callback function invoked during a walk of all matches
 */
typedef int (*filter_match_mark_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the FILTER policies
 */
extern void filter_match_mark_walk (filter_match_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_match_mark_t *filter_match_mark_pool;

static inline filter_match_mark_t *
filter_match_mark_get (index_t fmmi)
{
  return (pool_elt_at_index (filter_match_mark_pool, fmmi));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
