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

#ifndef __FILTER_TARGET_ACCEPT_H__
#define __FILTER_TARGET_ACCEPT_H__

#include <filter/filter_target.h>

/**
 * Target to accept packet.
 * This halts all parsing of chains in the current table and move onto
 * chains from the next table. In other words it's a jump to a chain
 * in the next table.
 */
typedef struct filter_target_accept_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Base class first
   */
  filter_target_t fta_base;
  dpo_proto_t fta_proto;

  dpo_id_t fta_next[FILTER_N_BASE_HOOKS];

  filter_node_t fta_node;

  /**
   * The table in which this target has been created
   */
  index_t fta_table;


} filter_target_accept_t;

//STATIC_ASSERT (sizeof (filter_target_accept_t) <= CLIB_CACHE_LINE_BYTES,
//             "accept target not in a cache line");

extern int filter_target_accept_add_and_lock (index_t fti,
					      dpo_proto_t proto,
					      dpo_id_t * fot);

/**
 * Walk/visit each of the accept targets
 */
extern void filter_target_accept_walk (filter_target_walk_cb_t cb, void *ctx);

/**
 * Exposed DP types and function
 */
extern filter_target_accept_t *filter_target_accept_pool;

static inline filter_target_accept_t *
filter_target_accept_get (index_t ftai)
{
  return (pool_elt_at_index (filter_target_accept_pool, ftai));
}

/**
 * TEST functions
 */
extern bool filter_target_is_accept (const dpo_id_t * dpo);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
