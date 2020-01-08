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

#ifndef _MATCH_ENGINE_CLASSIFIER_H__
#define _MATCH_ENGINE_CLASSIFIER_H__

#include <vnet/match/match_set.h>
#include <vnet/classify/vnet_classify.h>

extern u32 match_classifier_round_up_to_classifier_vector_size (u32 n_bytes);
extern u32 match_classifier_mk_table (void *mask,
				      u32 mask_len,
				      u32 n_sessions,
				      u32 next_table_index,
				      vnet_classify_flags_t flags,
				      i16 offset, uword user_ctx);
extern int match_classifier_mk_session (u32 table_index,
					void *match,
					u32 usr_context, u32 hit_next_index);

extern vnet_classify_entry_t *match_classifier_find_session (u32 table_index,
							     void *match);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
