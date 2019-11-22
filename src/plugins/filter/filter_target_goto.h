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

#ifndef __FILTER_TARGET_GOTO_H__
#define __FILTER_TARGET_GOTO_H__

#include <filter/filter_target.h>

/**
 * Target to goto to another chain
 */
typedef struct filter_target_goto_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * filter node graph linkage
   */
  filter_node_t ftg_node;

  /**
   * The index of the rule that this goto target is attached to
   */
  index_t ftg_rule;
  index_t ftg_chain;

  dpo_proto_t ftg_proto;

  /**
   * type
   */
  filter_hook_type_t ftg_hook;

  /**
   * next
   */
  dpo_id_t ftg_next;
} filter_target_goto_t;

STATIC_ASSERT (sizeof (filter_target_goto_t) <= CLIB_CACHE_LINE_BYTES,
	       "goto Target not in a cache line");

extern int filter_target_goto_add_and_lock (dpo_proto_t proto,
					    index_t fci, dpo_id_t * fot);
extern void filter_target_goto_stack (index_t ftgi);

/**
 * Walk/visit each of the goto targets
 */
extern void filter_target_goto_walk (filter_target_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_target_goto_t *filter_target_goto_pool;

static inline filter_target_goto_t *
filter_target_goto_get (index_t ftgi)
{
  return (pool_elt_at_index (filter_target_goto_pool, ftgi));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
