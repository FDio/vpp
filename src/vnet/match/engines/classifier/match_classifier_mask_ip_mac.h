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

#ifndef _MATCH_ENGINE_CLASSIFIER_MASK_SRC_IP_MAC_H__
#define _MATCH_ENGINE_CLASSIFIER_MASK_SRC_IP_MAC_H__

#include <vnet/match/engines/classifier/match_classifier.h>

/**
 * Engine Context.
 *  Per-set data that this classifier engine stores
 */
typedef struct match_engine_classifier_t_
{
  match_semantic_t mec_semantic;
  vnet_link_t mec_linkt;
  match_set_tag_flags_t mec_flags;

  /** Hash map of all the mask classes */
  uword *mec_hash;

  /**
   * The index of the first vnet-classifier table in the chain
   *  - this is where we start the lookup from in the data-plane
   */
  u32 mec_table_index;

  // FIXME
  void *mec_usr_ctx;
} match_engine_classifier_t;

extern match_engine_classifier_t *match_engine_classifier_pool;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
