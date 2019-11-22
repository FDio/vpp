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

#ifndef __FILTER_CHAIN_H__
#define __FILTER_CHAIN_H__

#include <filter/filter_types.h>
#include <filter/filter_list.h>

/**
 */
typedef struct filter_chain_t_
{
  /**
   * graph node. jump targets that point at us as dependants
   */
  filter_node_t fc_node;

  /**
   * name of the chain
   */
  u8 *fc_name;

  /**
   */
  dpo_proto_t fc_proto;

  /**
   * sorted vector of rules
   */
  struct filter_list_t_ *fc_rules;

  /**
   * DPO describing hos to forward once the end of the chain is reached
   */
  dpo_id_t fc_terminator;

  dpo_id_t fc_jump;
  /**
   * db of rules
   */
  uword *fc_db;

  /**
   * Precedence w.r.t. other chains at the same hook
   */
  u32 fc_precedence;

  /**
   * The hook the chain is jumpt o from
   */
  filter_hook_type_t fc_hook;

  /**
   * The policy at chain termination
   */
  filter_chain_policy_t fc_policy;

  /**
   * the table the chain is in
   */
  index_t fc_table;

  index_t fc_next;
} filter_chain_t;

/**
 * Create a filter Chain
 *
 * @return error code
 */
extern index_t filter_chain_create_and_lock (index_t fti,
					     const u8 * name,
					     dpo_proto_t dproto,
					     filter_hook_type_t type,
					     filter_chain_policy_t policy,
					     u32 precedence);
extern index_t filter_chain_rule_find (index_t fci, const u8 * rule);

extern filter_hook_type_t filter_chain_get_hook (index_t fci);
extern void filter_chain_update_next_chain (index_t fci, index_t fci_next);

extern index_t filter_chain_rule_append (index_t fci,
					 const u8 * name,
					 const dpo_id_t * match,
					 const dpo_id_t * target);
extern int filter_chain_rule_delete (index_t fci, const u8 * name);
extern void filter_chain_delete (index_t fci);

/**
 * Delete paths from an filter Chain. If no more paths exist, the chain
 * is deleted.
 */
extern void filter_chain_delete (index_t fci);

/**
 * Callback function invoked during a walk of all policies
 */
typedef int (*filter_chain_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the filter policies
 */
extern void filter_chain_walk (filter_chain_walk_cb_t cb, void *ctx);

extern u8 *format_filter_chain (u8 * s, va_list * args);


extern const dpo_id_t *filter_chain_rule_dpo_get (index_t fci);
extern const dpo_id_t *filter_chain_push_dpo_get (index_t fci);
extern const dpo_id_t *filter_chain_jump_dpo_get (index_t fci);
extern void filter_chain_jump_dpo_update (index_t fci);
extern u32 filter_chain_precedence_get (index_t fci);
extern filter_hook_type_t filter_chain_hook_type_get (index_t fci);

extern void filter_chain_child_add (index_t fci,
				    index_t child_index,
				    filter_node_t * node);
extern void filter_chain_child_remove (index_t fci, filter_node_t * node);

extern filter_chain_t *filter_chain_get (index_t fci);

/**
 * chain counters
 */
extern vlib_combined_counter_main_t filter_chain_counters;

/*
 * functions for test purposes
 */
extern u32 filter_chain_n_elts (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
