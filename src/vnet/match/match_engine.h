/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_ENGINE_H__
#define __MATCH_ENGINE_H__

#include <vnet/match/match_set.h>

/**
 * Match Engine
 *  a match engine is an abstract entity that 'renderers' set/list/rules
 *  into a data-base that can be consulted at switch time.
 *
 * A example of a concreate instance of an engine is the classifier engine.
 * This engine renders the rules the vnet-classifier tables and sessions.
 */


/**
 * A function to apply/render a set
 * @param ms - the match-set to render
 * @param semantic - Match semantics
 * @param flags - The number of VLAN tags the packets will have
 *
 * @return a match-set application ID tha tneeds to be available to the DP
 */
typedef void (*match_engine_apply_t) (match_set_t * mt,
				      match_semantic_t semantic,
				      match_set_tag_flags_t flags,
				      match_set_app_t * msa);
typedef void (*match_engine_unapply_t) (match_set_t * mt,
					const match_set_app_t * msa);

/**
 * Notify the engine to a change to one of the lists the
 * set contains
 */
typedef void (*match_engine_list_notify_t) (match_set_t * mt,
					    index_t msei,
					    const match_set_app_t * msa);

typedef enum match_engine_list_action_t_
{
  MATCH_ENGINE_LIST_ADD,
  MATCH_ENGINE_LIST_REPLACE,
  MATCH_ENGINE_LIST_DELETE,
} match_engine_list_action_t;

#define MATCH_ENGINE_N_ACTIONS (MATCH_ENGINE_LIST_DELETE + 1)

typedef struct match_engine_vft_t_
{
  match_engine_apply_t mev_apply;
  match_engine_unapply_t mev_unapply;
  match_engine_list_notify_t mev_list_actions[MATCH_ENGINE_N_ACTIONS];
  format_function_t *mev_format;
} match_engine_vft_t;


/**
 * A description of the priority assigned to a given engine per-type, per-semantic
 */
typedef struct match_engine_priority_t_
{
  /**
   * priority value, lower is better
   */
  u32 prio;

  /**
   * The set size (in total number of rules) for which the priority
   * applies. the engine infra will round this value up to the nearest power
   * of 2.
   */
  u32 len;
} match_engine_priority_t;

extern void match_engine_register (const char *name,
				   match_type_t type,
				   match_semantic_t semantic,
				   const match_engine_vft_t * vft,
				   const match_engine_priority_t *
				   priorities);

extern const match_engine_vft_t *match_engine_get (match_semantic_t semantic,
						   match_type_t type,
						   u32 set_size);

extern void match_engine_set_priority (const char *engine,
				       match_semantic_t semantic,
				       match_type_t type,
				       u32 set_size, u32 priority);

extern void match_engine_restore_defaults (void);

#define MATCH_ENGINE_LEN_LOG2S 24

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
