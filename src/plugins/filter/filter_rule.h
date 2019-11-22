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

#ifndef __FILTER_RULE_H__
#define __FILTER_RULE_H__

#include <filter/filter_types.h>

/**
 */
typedef struct filter_rule_t_
{
  /**
   * graph linkage
   */
  filter_node_t fr_node;

  /**
   * name of the rule (could be NULL)
   */
  u8 *fr_name;

  /**
   */
  dpo_proto_t fr_proto;

  /**
   * matcher
   */
  dpo_id_t fr_match;

  /**
   * target
   */
  dpo_id_t fr_target;

  /**
   * next DPO is the match is not matched
   */
  dpo_id_t fr_next;
} filter_rule_t;

extern u8 *format_filter_rule (u8 * s, va_list * args);

/**
 * Create or modify a filter Rule
 *
 * @return error code
 */
extern index_t filter_rule_create_and_lock (const u8 * name,
					    const dpo_id_t * match,
					    const dpo_id_t * target,
					    const dpo_id_t * next);
extern void filter_rule_update (index_t fri,
				const dpo_id_t * match,
				const dpo_id_t * target,
				const dpo_id_t * next);

extern void filter_rule_child_add (index_t fci,
				   index_t child_index, filter_node_t * node);
extern void filter_rule_child_remove (index_t fci, filter_node_t * node);

extern void filter_rule_update_next (index_t fri, const dpo_id_t * next);
extern const dpo_id_t *filter_rule_dpo_get (index_t fci);

extern void filter_rule_unlock (index_t fri);

/**
 * Callback function invoked during a walk of all policies
 */
typedef int (*filter_rule_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the filter policies
 */
extern void filter_rule_walk (filter_rule_walk_cb_t cb, void *ctx);


/**
 * Get an filter object from its VPP index
 */
extern filter_rule_t *filter_rule_get (index_t fri);

/**
 * DP coutners
 */
extern vlib_combined_counter_main_t filter_rule_counters;

/*
 * functions for test purposes
 */
extern u32 filter_rule_n_elts (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
