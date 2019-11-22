/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __FILTER_TABLE_H__
#define __FILTER_TABLE_H__

#include <filter/filter_list.h>

typedef struct filter_table_next_t_
{
  index_t ftn_index;
  u32 ftn_sibling;
} filter_table_next_t;

/**
 */
typedef struct filter_table_t_
{
  /**
   * graph linkage
   */
  filter_node_t ft_node;

  /**
   * name of the table
   */
  u8 *ft_name;

  /**
   */
  u32 ft_precedence;

  dpo_proto_t ft_proto;

  /**
   * vecotrs of chains starting at the given hook
   */
  struct filter_list_t_ *ft_hooks[FILTER_N_BASE_HOOKS];

  /**
   * DB of all chains
   */
  uword *ft_db;

  /**
   * Next table at a given hook
   */
  filter_table_next_t ft_nexts[FILTER_N_BASE_HOOKS];
} filter_table_t;

/**
 * Get an FILTER object from its VPP index
 */
extern filter_table_t *filter_table_get (index_t index);

/**
 * Find a filter object from the client's table ID
 *
 * @param table_id Client's defined table ID
 * @return VPP's object index
 */
extern index_t filter_table_find (const u8 * name, dpo_proto_t dproto);

/**
 * Create or update an filter Table
 *
 * @return error code
 */
extern int filter_table_update (const u8 * name,
				dpo_proto_t dproto,
				u32 precedence, index_t * fti);
extern index_t filter_table_chain_find (index_t fti, const u8 * chain);

extern int filter_table_chain_add (index_t fti,
				   const u8 * chain,
				   filter_hook_type_t type,
				   filter_chain_policy_t policy,
				   u32 precedence, index_t * fci);
extern int filter_table_chain_delete (index_t fti, const u8 * chain);

extern int filter_table_rule_append (index_t fti,
				     const u8 * chain,
				     const u8 * rule,
				     const dpo_id_t * match,
				     const dpo_id_t * target, index_t * fri);
extern int filter_table_rule_delete (index_t fti,
				     const u8 * chain, const u8 * rule);
extern int filter_table_rule_delete_index (index_t fti, index_t fci,
					   index_t fri);
extern void filter_table_update_next (index_t fti,
				      index_t next, filter_hook_type_t fht);

/**
 * Delete paths from an filter Table. If no more paths exist, the table
 * is deleted.
 */
extern int filter_table_delete (const u8 * name, dpo_proto_t dproto);
extern int filter_table_delete_index (index_t fti);

extern const dpo_id_t *filter_table_push_dpo_get (index_t fti,
						  filter_hook_type_t fht);
extern const dpo_id_t *filter_table_jump_dpo_get (index_t fti,
						  filter_hook_type_t fht);
extern u32 filter_table_precedence_get (index_t fti);

extern void filter_table_child_add (index_t fti,
				    index_t child_index,
				    filter_node_t * node);
extern void filter_table_child_remove (index_t fti, filter_node_t * node);

/**
 * Callback function invoked during a walk of all tables
 */
typedef int (*filter_table_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the filter tables
 */
extern void filter_table_walk (filter_table_walk_cb_t cb, void *ctx);

extern u8 *format_filter_table (u8 * s, va_list * args);

/*
 * functions for test purposes
 */
extern u32 filter_table_n_elts (void);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
