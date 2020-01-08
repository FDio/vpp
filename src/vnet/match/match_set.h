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

#ifndef __MATCH_SET_H__
#define __MATCH_SET_H__

#include <vnet/match/match.h>

/**
 * A match-set is a priority ordered set of match-list that will be matched
 * sequentially
 */

typedef u32 match_handle_t;
#define MATCH_HANDLE_INVALID (~0)

typedef index_t match_set_app_t;

#define MATCH_SET_APP_INVALID (~0)

typedef enum match_semantic_t_
{
  /**
   * Given a list of rules return true if any of them match.
   * The order of the search in this case is undefined. (i.e.
   * it is an implmentation choice of the engine). The engine may
   * return which rule it was that matched, FWIW.
   */
  MATCH_SEMANTIC_ANY,

  /**
   * Given a list of rules, search them in order and return the first
   * match
   */
  MATCH_SEMANTIC_FIRST,
} match_semantic_t;

#define MATCH_N_SEMANTICS (MATCH_SEMANTIC_FIRST+1)

extern u8 *format_match_semantic (u8 * s, va_list * arga);

typedef struct match_set_pos_t_
{
  union
  {
    u64 msp_pos;
    struct
    {
      u32 msp_list_index;
      u32 msp_rule_index;
    };
  };
} match_set_pos_t;

extern u8 *format_match_set_pos (u8 * s, va_list * args);

typedef struct match_set_result_t_
{
  /**
   */
  void *msr_user_ctx;
  match_set_pos_t msr_pos;
} match_set_result_t;

extern u8 *format_match_set_result (u8 * s, va_list * args);

static_always_inline bool
match_set_pos_is_better (const match_set_pos_t * msp1,
			 const match_set_pos_t * msp2)
{
  return (msp1->msp_pos <= msp2->msp_pos);
}

#define MATCH_RESULT_MISS (~0)

typedef struct match_set_entry_t_
{
  u16 mse_priority;
  match_list_t mse_list;
  void *mse_usr_ctxt;

} match_set_entry_t;

typedef enum match_set_tag_flags_t_
{
  MATCH_SET_TAG_FLAG_NONE = 0,
  MATCH_SET_TAG_FLAG_0_TAG = (1 << 1),
  MATCH_SET_TAG_FLAG_1_TAG = (1 << 2),
  MATCH_SET_TAG_FLAG_2_TAG = (1 << 3),
} match_set_tag_flags_t;

typedef struct match_set_app_ref_t_
{
  match_set_app_t msar_app;
  u32 msar_locks;
  match_set_tag_flags_t msar_flags;
} match_set_app_ref_t;

typedef struct match_set_t_
{
  u8 *ms_tag;
  u32 ms_locks;

  match_type_t ms_type;

  /* Priority ordered list of entries */
  index_t *ms_entries;

  /* heap to use to allocate any set/engine resources */
  void *ms_heap;

  /* the set's applications */
  match_set_app_ref_t ms_apps[MATCH_N_SEMANTICS][VNET_LINK_NUM];
} match_set_t;

extern u8 *format_match_set (u8 * s, va_list * args);

/**
 * Create and lock a set
 *
 * @param name [vector] to ID the table
 * @param heap - optional heap within which all match infra memory
 *               will be allocated.
 * @return ID of the set
 */
extern index_t match_set_create_and_lock (const u8 * name, void *heap);
extern void match_set_unlock (index_t * ms);
extern void match_set_lock (index_t msi);

/**
 * Add, replace, delete lists.
 *
 * @param msi - ID of the set (from match_set_create_and_lock)
 * @param ml - list of rules to add
 * @param priority - List priority (search order) lower is better.
 * @param data - client data ssociated with the list (probably a vector of actions)
 *
 * @return ID of the list (used to delete or replace).
 */
extern match_handle_t match_set_list_add (index_t msi,
					  const match_list_t * ml,
					  u16 priority, void *dats);
extern void match_set_list_replace (index_t msi,
				    match_handle_t mh,
				    const match_list_t * ml,
				    u16 priority, void *dats);
extern void *match_set_list_del (index_t msi, match_handle_t * mh);

/**
 * Apply
 * instantiate the set for a given match semantic of a given packet type.
 * This will call the match-engine to construct the necessary lookup tables
 * to perform the match.
 *
 * @param msi - Set ID
 * @param sem - Match semantic
 * @param linkt - packet type (where the buffer's 'current' pointer will be in
 *                the data plane).
 * @param flags - Flags describing how many tags VLAN tags the packet may have.
 *                may not be relevant depending on linkt and rule type. i.e.
 *                if the rule only does L3 parameters and link=VNET_LINK_IP4.
 */
extern match_set_app_t match_set_apply (index_t msi,
					match_semantic_t sem,
					vnet_link_t linkt,
					match_set_tag_flags_t flags);
extern void match_set_unapply (index_t msi, match_set_app_t * msb);


/**
 * Walk a set's entries/lists and rules
 */
typedef walk_rc_t (*match_set_rule_walk_t) (const match_rule_t * mr,
					    void *ctx);

extern void match_set_entry_walk_rules (const match_set_entry_t * mse,
					match_set_rule_walk_t fn, void *ctx);

typedef walk_rc_t (*match_set_entry_walk_t) (const match_set_entry_t * mse,
					     u32 index, void *ctx);

extern void match_set_walk_entries (const match_set_t * ms,
				    match_set_entry_walk_t fn, void *ctx);

/**
 * from a interface get the tag flags describing the packets that may ingress
 */
extern match_set_tag_flags_t match_set_get_itf_tag_flags (u32 sw_if_index);
extern i16 match_set_get_l2_offset (vnet_link_t linkt,
				    match_set_tag_flags_t flag);



#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
