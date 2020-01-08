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
  /** The mask this session uses */
  index_t mcs_mask;

  /** The session data we add to the classifier table
   *   this is derived from the match rule */
  u8 *mcs_data;

  /** What we return to rhe user if it's this session that matches */
  match_set_result_t mcs_result;
} match_classifier_session_t;

extern match_classifier_session_t *match_classifier_session_pool;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
