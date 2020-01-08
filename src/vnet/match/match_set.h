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

typedef struct match_set_pos_t_
{
  union
  {
    u64 msp_as_u64;
    struct
    {
      u32 msp_list_index;
      u32 msp_rule_index;
    };
  };
} match_set_pos_t;

STATIC_ASSERT_SIZEOF (match_set_pos_t, sizeof (u64));

#define MATCH_SET_POS_MISS_INIT {               \
    .msp_list_index = ~0,                       \
      .msp_rule_index = ~0,                     \
}
const static match_set_pos_t MATCH_SET_POS_MISS = MATCH_SET_POS_MISS_INIT;

extern u8 *format_match_set_pos (u8 * s, va_list * args);

static_always_inline bool
match_set_pos_is_better (const match_set_pos_t * msp1,
			 const match_set_pos_t * msp2)
{
  return (msp1->msp_list_index <= msp2->msp_list_index &&
	  msp1->msp_rule_index < msp2->msp_rule_index);
}

extern void match_set_pos_copy (const match_set_pos_t * msp1,
				match_set_pos_t * msp2);

struct match_set_app_t_;


typedef bool (*match_match_t) (vlib_main_t * vm,
			       vlib_buffer_t * buf,
			       i16 l2_offset,
			       i16 l3_offset,
			       const struct match_set_app_t_ * app,
			       f64 now, match_result_t * result);

typedef struct match_set_app_t_
{
  index_t msa_index;
  match_match_t msa_match;
} match_set_app_t;

const static match_set_app_t MATCH_SET_APP_INVALID = {
  .msa_index = INDEX_INVALID,
};

#define MATCH_SET_APP_INITIALISOR {             \
    .msa_index = INDEX_INVALID                  \
}

extern bool match_set_app_is_valid (const match_set_app_t * msa);
extern bool match_set_app_is_equal (const match_set_app_t * msa1,
				    const match_set_app_t * msa2);

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

#define FOR_EACH_MATCH_SEMANTIC(_sem)           \
  for (_sem = MATCH_SEMANTIC_ANY; _sem < MATCH_N_SEMANTICS; _sem++)

extern u8 *format_match_semantic (u8 * s, va_list * arga);
extern uword unformat_match_semantic (unformat_input_t * input,
				      va_list * args);

typedef struct match_set_entry_t_
{
  u16 mse_priority;
  match_list_t mse_list;
} match_set_entry_t;

typedef enum match_set_tag_flags_t_
{
  MATCH_SET_TAG_FLAG_NONE = 0,
  MATCH_SET_TAG_FLAG_0_TAG = (1 << 1),
  MATCH_SET_TAG_FLAG_1_TAG = (1 << 2),
  MATCH_SET_TAG_FLAG_2_TAG = (1 << 3),
} match_set_tag_flags_t;

extern u8 *format_match_tag_flags (u8 * s, va_list * args);

struct match_engine_vft_t_;

typedef struct match_set_app_ref_t_
{
  match_set_app_t msar_app;
  u32 msar_locks;
  match_set_tag_flags_t msar_flags;
  const struct match_engine_vft_t_ *msar_engine;
} match_set_app_ref_t;

typedef struct match_set_t_
{
  u8 *ms_tag;
  u32 ms_locks;

  match_type_t ms_type;
  match_orientation_t ms_orientation;
  ethernet_type_t ms_eth_type;

  /* Priority ordered list of entries */
  index_t *ms_entries;

  /* heap to use to allocate any set/engine resources */
  void *ms_heap;

  /* the set's applications */
  match_set_app_ref_t ms_apps[MATCH_N_SEMANTICS];
} match_set_t;

extern u8 *format_match_set (u8 * s, va_list * args);

/**
 * Create and lock a set
 *
 * @param name [vector] to ID the table
 * @param rtype - the type of rules that will be added to this set. Each set
 *                is restricted to one rule type to simplify the engine implementation
 *                (it's also the expected use-case). it is thus the clients
 *                responsibility to translate all its rules into one type.
 * @param heap - optional heap within which all match infra memory
 *               will be allocated.
 * @return ID of the set
 */
extern index_t match_set_create_and_lock (const u8 * name,
					  match_type_t rtype,
					  match_orientation_t mo,
					  ethernet_type_t etype, void *heap);
extern void match_set_unlock (index_t * ms);
extern void match_set_lock (index_t msi);
extern bool match_set_index_is_valid (index_t msi);

/**
 * Add, replace, delete lists.
 *
 * @param msi - ID of the set (from match_set_create_and_lock)
 * @param ml - list of rules to add
 * @param priority - List priority (search order) lower is better.
 * @return ID of the list (used to delete or replace).
 */
extern match_handle_t match_set_list_add (index_t msi,
					  const match_list_t * ml,
					  u16 priority);
extern void match_set_list_replace (index_t msi,
				    match_handle_t mh,
				    const match_list_t * ml, u16 priority);
extern void match_set_list_del (index_t msi, match_handle_t * mh);

/**
 * Apply
 * instantiate the set for a given match semantic of a given packet type.
 * This will call the match-engine to construct the necessary lookup tables
 * to perform the match.
 *
 * @param msi - Set ID
 * @param sem - Match semantic
 * @param flags - Flags describing how many tags VLAN tags the packet may have.
 *                may not be relevant depending on rule type. i.e.
 *                if the rule only does L3 parameters.
 */
extern void match_set_apply (index_t msi,
			     match_semantic_t sem,
			     match_set_tag_flags_t flags,
			     match_set_app_t * msa);
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

typedef walk_rc_t (*match_set_walk_cb_t) (index_t msi, void *arg);
extern void match_sets_walk (match_set_walk_cb_t fn, void *arg);

/**
 * from a interface get the tag flags describing the packets that may ingress
 */
extern match_set_tag_flags_t match_set_get_itf_tag_flags (u32 sw_if_index);

extern ip_address_family_t match_set_get_af (index_t msi);
extern u32 match_set_size (const match_set_t * ms);
extern u32 match_set_list_position (const match_set_t * ms, index_t msei);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
