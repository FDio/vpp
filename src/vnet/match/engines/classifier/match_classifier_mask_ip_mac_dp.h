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

#ifndef __MATCH_ENGINE_CLASSIFIER_MASK_IP_MAC_DP_H__
#define __MATCH_ENGINE_CLASSIFIER_MASK_IP_MAC_DP_H__

#include <vnet/match/engines/classifier/match_classifier.h>
#include <vnet/match/engines/classifier/match_classifier_dp.h>

/**
 * Data-plane function to go match
 */
static_always_inline bool
match_classifier_engine_match (vlib_main_t * vm,
			       vlib_buffer_t * b,
			       i16 l2_offset,
			       i16 l3_offset,
			       const match_set_app_t * app,
			       f64 now,
			       match_semantic_t sem, match_result_t * res)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  const vnet_classify_entry_t *e0;
  vnet_classify_table_t *t0;
  u64 hash0;
  u8 *h0;

  match_classifier_engine_t *mtec0;

  mtec0 = pool_elt_at_index (match_classifier_engine_pool, app->msa_index);

  t0 = pool_elt_at_index (vcm->tables, mtec0->mce_table_index);
  h0 = vlib_buffer_get_current (b) + l2_offset;
  hash0 = vnet_classify_hash_packet_inline (t0, h0);

  if (MATCH_SEMANTIC_ANY == sem)
    {
      e0 = vnet_classify_find_entry_inline (t0, h0, hash0, now);
      while (NULL == e0)
	{
	  if (PREDICT_TRUE (t0->next_table_index != ~0))
	    t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	  else
	    break;

	  hash0 = vnet_classify_hash_packet_inline (t0, h0);
	  e0 = vnet_classify_find_entry_inline (t0, h0, hash0, now);
	}

      if (NULL != e0)
	{
	  match_classifier_session_t *mcs0;

	  mcs0 = match_classifier_session_get (e0->opaque_index);

	  *res = mcs0->mcs_result;
	}
      // else - miss
      return (NULL != e0);
    }
  else
    {
      match_classifier_best_t mcb = {
	.mcb_pos = MATCH_SET_POS_MISS_INIT,
      };
      bool matched0;

      matched0 = false;

      /* search each of the tables, saving the lowest, i.e. first, match */
      while (t0)
	{
	  e0 = vnet_classify_find_entry_inline (t0, h0, hash0, now);

	  if (NULL != e0)
	    {
	      match_classifier_session_t *mcs0;

	      mcs0 = match_classifier_session_get (e0->opaque_index);

	      match_classifier_update_if_better (&mcb, &mcs0->mcs_pos,
						 mcs0->mcs_result);
	      matched0 = true;
	    }
	  if (PREDICT_TRUE (t0->next_table_index != ~0))
	    {
	      ASSERT (t0 != pool_elt_at_index (vcm->tables,
					       t0->next_table_index));
	      t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	      hash0 = vnet_classify_hash_packet_inline (t0, h0);
	    }
	  else
	    t0 = NULL;
	}

      *res = mcb.mcb_res;

      return (matched0);
    }
}

static_always_inline bool
match_classifier_engine_match_mask_src_ip_mac_any (vlib_main_t * vm,
						   vlib_buffer_t * b,
						   i16 l2_offset,
						   i16 l3_offset,
						   const match_set_app_t *
						   app, f64 now,
						   match_result_t * res)
{
  return (match_classifier_engine_match
	  (vm, b, l2_offset, l3_offset, app, now, MATCH_SEMANTIC_ANY, res));
}

static_always_inline bool
match_classifier_engine_match_mask_src_ip_mac_first (vlib_main_t * vm,
						     vlib_buffer_t * b,
						     i16 l2_offset,
						     i16 l3_offset,
						     const match_set_app_t *
						     app, f64 now,
						     match_result_t * res)
{
  return (match_classifier_engine_match
	  (vm, b, l2_offset, l3_offset, app, now, MATCH_SEMANTIC_FIRST, res));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
