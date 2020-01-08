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

#include <vnet/match/engines/classifier/match_classifier_mask_ip_mac.h>

/**
 * Data-plane function to go match
 */
static_always_inline void
match_engine_classifier_match (vlib_main_t * vm,
			       vlib_buffer_t * b,
			       const match_set_app_t * app,
			       f64 now,
			       match_semantic_t sem, match_set_result_t * res)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  const vnet_classify_entry_t *e0;
  vnet_classify_table_t *t0;
  u64 hash0;
  u32 mi;
  u8 *h0;

  match_engine_classifier_t *mtec0;

  mtec0 = pool_elt_at_index (match_engine_classifier_pool, app->msa_index);

  t0 = pool_elt_at_index (vcm->tables, mtec0->mec_table_index);
  h0 = vlib_buffer_get_current (b) + t0->current_data_offset;
  hash0 = vnet_classify_hash_packet_inline (t0, h0);

  res->msr_pos.msp_list_index = MATCH_RESULT_MISS;

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
	  // returns the index of the rule in the list.
	  res->msr_pos.msp_rule_index = e0->opaque_index;
	  // FIXME
	  res->msr_pos.msp_list_index = 0;
	  res->msr_user_ctx = mtec0->mec_usr_ctx;
	}
      else
	// miss
	res->msr_pos.msp_rule_index = MATCH_RESULT_MISS;
    }
  else
    {
      mi = MATCH_RESULT_MISS;

      /* search each of the tables, saving the lowest, i.e. first, match */
      while (t0)
	{
	  e0 = vnet_classify_find_entry_inline (t0, h0, hash0, now);

	  if (NULL != e0)
	    {
	      // FIXME
	      res->msr_pos.msp_list_index = 0;
	      mi = clib_min (mi, e0->opaque_index);
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

      res->msr_pos.msp_rule_index = mi;
      res->msr_user_ctx = mtec0->mec_usr_ctx;
    }
}

static_always_inline void
match_engine_classifier_match_mask_src_ip_mac_any (vlib_main_t * vm,
						   vlib_buffer_t * b,
						   const match_set_app_t *
						   app, f64 now,
						   match_set_result_t * res)
{
  return (match_engine_classifier_match
	  (vm, b, app, now, MATCH_SEMANTIC_ANY, res));
}

static_always_inline void
match_engine_classifier_match_mask_src_ip_mac_first (vlib_main_t * vm,
						     vlib_buffer_t * b,
						     const match_set_app_t *
						     app, f64 now,
						     match_set_result_t * res)
{
  return (match_engine_classifier_match
	  (vm, b, app, now, MATCH_SEMANTIC_FIRST, res));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
