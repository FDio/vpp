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

#ifndef _MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_H__
#define _MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_H__

#include <vnet/match/engines/classifier/match_classifier.h>

/**
 * Engine Context.
 *  Per-set application data that this classifier engine stores
 */
typedef struct match_engine_classifier_app_t_
{
  index_t meca_set;
  vnet_link_t meca_linkt;
  match_set_tag_flags_t meca_tag_flags;
  match_semantic_t meca_semantic;

  /* Address family for the rules contained in the set */
  ip_address_family_t meca_af;

  /** Hash map of all the mask classes */
  uword *meca_masks;

  /**
   * The index of the first vnet-classifier table in the chain
   *  - this is where we start the lookup from in the data-plane
   */
  u32 meca_table_index;

  /** A vector of lists/entries that correspond to those in the set */
  index_t *meca_lists;
} match_engine_classifier_app_t;

extern match_engine_classifier_app_t *match_engine_classifier_app_pool;

/**
 * A session;
 *  derived from the rule, this is the data on which we match
 *  it's what we store in the table
 */
typedef struct match_classifier_session_t_
{
  /** What we return to the user if it's this session that matches */
  match_set_result_t mcs_result;

  /** The mask-class object this session uses */
  index_t mcs_mask;

  /* index of a clash rule, if there is one for this session */
  index_t mcs_clash;

  /** The session data we add to the vnet-classifier table
   *   this is derived from the match rule */
  u8 *mcs_data;
} match_classifier_session_t;

/**
 * When we fetch a session from the pool in the DP, we want to be sure that it doesn't
 * span two cache lines.
 */
#define MATCH_CLASSIFIER_SESSION_ALGIN (CLIB_CACHE_LINE_BYTES / 2)

STATIC_ASSERT_SIZEOF (match_classifier_session_t, CLIB_CACHE_LINE_BYTES / 2);

extern match_classifier_session_t *match_classifier_session_pool;

/**
 * in the movie, when session collide, the protagonist is unsure which
 * they match the best with. or even whether they match at all, so they
 * have to try each one in turn... maybe tey'll swap gum on a bus and smile
 * at one another...
 */
typedef struct match_classifier_clash_t_
{
  /** a reference to the rule that created this clash/session */
  match_mask_n_tuple_t mcc_rule;

  /** What we return to the user if it's this session that matches */
  match_set_result_t mcc_result;

  /** the head the object is present in */
  index_t mcc_head;
} match_classifier_clash_t;

STATIC_ASSERT (__alignof__ (match_classifier_clash_t) == __alignof__ (u64),
	       "");

extern match_classifier_clash_t *match_classifier_clash_pool;


typedef struct match_classifier_clash_head_t_
{
  /**
   * vector of indicies of the clash sessions. sorted in order of best result first
   * so best reulst is the first to be tested for a amtch in the DP
   */
  index_t *mcch_clashes;
} match_classifier_clash_head_t;

extern match_classifier_clash_head_t *match_classifier_clash_head_pool;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
