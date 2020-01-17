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

#ifndef __MATCH_ENGINE_CLASSIFIER_DP_H__
#define __MATCH_ENGINE_CLASSIFIER_DP_H__

#include <vnet/match/engines/classifier/match_classifier.h>

typedef struct match_engine_classifier_match_pass_1_t_
{
  u32 table_index;
  u64 hash;
  void *usr_ctx;
} match_engine_classifier_match_pass_1_t;

/**
 * Data-plane function to go match
 */
static_always_inline void
match_engine_classifier_match (vlib_main_t * vm,
			       vlib_buffer_t ** bufs,
			       u32 n_bufs,
			       match_set_app_t * apps,
			       match_set_result_t * results)
{
  match_engine_classifier_match_pass_1_t pass[VLIB_FRAME_SIZE], *p;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  match_set_result_t *res;
  match_set_app_t *app;
  vlib_buffer_t **b;
  u32 n_left;

  f64 now = vlib_time_now (vm);

  b = bufs;
  n_left = n_bufs;
  p = pass;
  app = apps;

  /* First pass: compute hashes */
  while (n_left > 0)
    {
      match_engine_classifier_t *mtec0;
      vnet_classify_table_t *t0;
      u8 *h0;

      // FIXME
      mtec0 = pool_elt_at_index (match_engine_classifier_pool, app[0]);
      p[0].table_index = mtec0->mec_table_index;
      p[0].usr_ctx = mtec0->mec_usr_ctx;

      t0 = pool_elt_at_index (vcm->tables, p[0].table_index);
      h0 = vlib_buffer_get_current (b[0]) + t0->current_data_offset;

      p[0].hash = vnet_classify_hash_packet_inline (t0, h0);
      vnet_classify_prefetch_bucket (t0, p[0].hash);

      app++;
      p++;
      n_left--;
      b++;
    }

  n_left = n_bufs;
  b = bufs;
  p = pass;
  res = results;

  while (n_left > 0)
    {
      const vnet_classify_entry_t *e0;
      vnet_classify_table_t *t0;
      u8 *h0;

      /* Stride 3 seems to work best */
      if (PREDICT_TRUE (n_left > 3))
	{
	  vnet_classify_table_t *tp1;

	  tp1 = pool_elt_at_index (vcm->tables, p[2].table_index);
	  vnet_classify_prefetch_entry (tp1, p[2].hash);
	}

      t0 = pool_elt_at_index (vcm->tables, p[0].table_index);
      h0 = vlib_buffer_get_current (b[0]) + t0->current_data_offset;
      e0 = vnet_classify_find_entry_inline (t0, h0, p[0].hash, now);

      while (NULL == e0)
	{
	  if (PREDICT_TRUE (t0->next_table_index != ~0))
	    t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	  else
	    break;

	  p[0].hash = vnet_classify_hash_packet_inline (t0, h0);
	  e0 = vnet_classify_find_entry_inline (t0, h0, p[0].hash, now);
	}
      if (NULL != e0)
	{
	  // returns the index of the rule in the list.
	  res[0].msr_index = e0->opaque_index;
	  res[0].msr_user_ctx = p[0].usr_ctx;
	}
      else
	// miss
	res[0].msr_index = ~0;

      b++;
      p++;
      res++;
      n_left--;
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
