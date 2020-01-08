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

#ifndef __MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_DP_H__
#define __MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLR_DP_H__

#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple.h>

typedef struct match_engine_classifier_match_pass_1_t_
{
  u32 table_index;
  u64 hash;
} match_engine_classifier_match_pass_1_t;

static_always_inline void
match_engine_classifier_match_mask_n_tuple_one (vlib_main_t * vm,
						vlib_buffer_t * b,
						match_set_app_t app,
						f64 now,
						match_set_result_t * res)
{
  const vnet_classify_main_t *vcm = &vnet_classify_main;
  const match_engine_classifier_app_t *meca0;
  const match_classifier_session_t *mcs0;
  vnet_classify_table_t *vct0, *vct1;
  const vnet_classify_entry_t *e0;
  u64 hash0;
  u8 *h0;

  /* set the result to big fat miss */
  res->msr_pos.msp_pos = (~(0ULL));

  meca0 = pool_elt_at_index (match_engine_classifier_app_pool, app);
  vct0 = pool_elt_at_index (vcm->tables, meca0->meca_table_index);

  h0 = vlib_buffer_get_current (b);

  if (vct0->current_data_flag & CLASSIFY_FLAG_USE_L2_LEN)
    h0 += vnet_buffer (b)->l2.l2_len;

  /*
   * we sorted the tables so that those containing the best rules are first.
   * so loop thru the tables until the match we have is better than the best
   * the table has to offer. At that point there ar eno better rules to
   * match and we're done.
   */
  while (vct0 &&
	 match_set_pos_is_better ((match_set_pos_t *) & vct0->user_ctx,
				  &res->msr_pos))
    {
      if (PREDICT_TRUE (vct0->next_table_index != ~0))
	{
	  vct1 = pool_elt_at_index (vcm->tables, vct0->next_table_index);
	  CLIB_PREFETCH (vct1, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      hash0 = vnet_classify_hash_packet_inline (vct0, h0);
      e0 = vnet_classify_find_entry_inline (vct0, h0, hash0, now);

      if (NULL != e0)
	{
	  mcs0 = pool_elt_at_index (match_classifier_session_pool,
				    e0->opaque_index);
	  res[0] = mcs0->mcs_result;
	}

      if (PREDICT_TRUE (vct0->next_table_index != ~0))
	vct0 = vct1;
      else
	vct0 = NULL;
    }
}

/**
 * Data-plane function to go match
 */
static_always_inline void
match_engine_classifier_match_mask_n_tuple (vlib_main_t * vm,
					    vlib_buffer_t ** bufs,
					    u32 n_bufs,
					    match_set_app_t * apps,
					    match_set_result_t * results)
{
  // match_engine_classifier_match_pass_1_t pass[VLIB_FRAME_SIZE], *p;
  match_set_result_t *res;
  match_set_app_t *app;
  vlib_buffer_t **b;
  u32 n_left;

  f64 now = vlib_time_now (vm);

  n_left = n_bufs;
  b = bufs;
  // p = pass;
  res = results;
  app = apps;

  while (n_left > 0)
    {
      match_engine_classifier_match_mask_n_tuple_one (vm, b[0], app[0], now,
						      &res[0]);

      b++;
      // p++;
      res++;
      n_left--;
      app++;
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
