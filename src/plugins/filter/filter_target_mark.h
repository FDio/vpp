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

#ifndef __FILTER_TARGET_MARK_H__
#define __FILTER_TARGET_MARK_H__

#include <filter/filter_target.h>

/**
 * Target to mark packets
 */
typedef struct filter_target_mark_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  dpo_proto_t ftm_proto;
  bool ftm_xor;
  u32 ftm_bits, ftm_mask;

  dpo_id_t ftm_next;
  index_t ftm_rule;

  /**
   * locks.
   */
  u32 ftm_locks;
} filter_target_mark_t;

STATIC_ASSERT (sizeof (filter_target_mark_t) <= CLIB_CACHE_LINE_BYTES,
	       "mark Target not in a cache line");

extern int filter_target_mark_add_and_lock (dpo_proto_t proto,
					    bool xor,
					    u32 mask,
					    u32 bits, dpo_id_t * fot);

/**
 * Walk/visit each of the mark targets
 */
extern void filter_target_mark_walk (filter_target_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_target_mark_t *filter_target_mark_pool;

static inline filter_target_mark_t *
filter_target_mark_get (index_t ftmi)
{
  return (pool_elt_at_index (filter_target_mark_pool, ftmi));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
