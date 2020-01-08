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

#ifndef __MATCH_CLASSIFIER_DP_H__
#define __MATCH_CLASSIFIER_DP_H__

#include <vnet/match/engines/classifier/match_classifier_util.h>

static_always_inline match_classifier_session_t *
match_classifier_session_get (index_t mcsi)
{
  return (pool_elt_at_index (match_classifier_session_pool, mcsi));
}

static_always_inline match_classifier_engine_t *
match_classifier_engine_get (index_t mcei)
{
  return (pool_elt_at_index (match_classifier_engine_pool, mcei));
}

static_always_inline void
match_classifier_update_if_better (match_classifier_best_t * mcb,
				   const match_set_pos_t * msr,
				   match_result_t res)
{
  if (match_set_pos_is_better (msr, &mcb->mcb_pos))
    {
      mcb->mcb_pos = *msr;
      mcb->mcb_res = res;
    }
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
