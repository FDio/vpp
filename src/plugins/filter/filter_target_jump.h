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

#ifndef __FILTER_TARGET_JUMP_H__
#define __FILTER_TARGET_JUMP_H__

#include <filter/filter_target.h>

/**
 * Target to jump to another chain
 */
typedef struct filter_target_jump_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * filter node graph linkage
   */
  filter_node_t ftj_node;

  /**
   * The index of the rule that this jump target is attached to
   */
  index_t ftj_rule;
  index_t ftj_chain;

  dpo_proto_t ftj_proto;

  /**
   * type
   */
  filter_hook_type_t ftj_hook;

  /**
   * The dpo that is pushed o nthe stack
   */
  dpo_id_t ftj_push;

  /**
   * next
   */
  dpo_id_t ftj_next;
} filter_target_jump_t;

STATIC_ASSERT (sizeof (filter_target_jump_t) <= CLIB_CACHE_LINE_BYTES,
	       "jump Target not in a cache line");

extern int filter_target_jump_add_and_lock (dpo_proto_t proto,
					    index_t fci, dpo_id_t * fot);
extern void filter_target_jump_stack (index_t ftji);

/**
 * Walk/visit each of the jump targets
 */
extern void filter_target_jump_walk (filter_target_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_target_jump_t *filter_target_jump_pool;

static inline filter_target_jump_t *
filter_target_jump_get (index_t ftji)
{
  return (pool_elt_at_index (filter_target_jump_pool, ftji));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
