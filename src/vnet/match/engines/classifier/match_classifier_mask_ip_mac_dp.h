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

/* typedef struct match_engine_classifier_match_pass_1_t_ */
/* { */
/*   u32 table_index; */
/*   u64 hash; */
/*   void *usr_ctx; */
/* } match_engine_classifier_match_pass_1_t; */

/* /\** */
/*  * Data-plane function to go match */
/*  *\/ */
/* static_always_inline void */
/* match_engine_classifier_match (vlib_main_t * vm, */
/* 			       vlib_buffer_t ** bufs, */
/* 			       u32 n_bufs, */
/* 			       const match_set_app_t ** apps, */
/* 			       match_set_result_t * results, */
/* 			       match_semantic_t sem) */
/* { */
/*   match_engine_classifier_match_pass_1_t pass[VLIB_FRAME_SIZE], *p; */
/*   vnet_classify_main_t *vcm = &vnet_classify_main; */
/*   const match_set_app_t **app; */
/*   match_set_result_t *res; */
/*   vlib_buffer_t **b; */
/*   u32 n_left; */

/*   f64 now = vlib_time_now (vm); */

/*   b = bufs; */
/*   n_left = n_bufs; */
/*   p = pass; */
/*   app = apps; */

/*   /\* First pass: compute hashes *\/ */
/*   while (n_left > 0) */
/*     { */
/*       match_engine_classifier_t *mtec0; */
/*       vnet_classify_table_t *t0; */
/*       u8 *h0; */

/*       // FIXME */
/*       mtec0 = */
/* 	pool_elt_at_index (match_engine_classifier_pool, app[0]->msa_index); */
/*       p[0].table_index = mtec0->mec_table_index; */
/*       p[0].usr_ctx = mtec0->mec_usr_ctx; */

/*       t0 = pool_elt_at_index (vcm->tables, p[0].table_index); */
/*       h0 = vlib_buffer_get_current (b[0]) + t0->current_data_offset; */

/*       p[0].hash = vnet_classify_hash_packet_inline (t0, h0); */
/*       vnet_classify_prefetch_bucket (t0, p[0].hash); */

/*       app++; */
/*       p++; */
/*       n_left--; */
/*       b++; */
/*     } */

/*   n_left = n_bufs; */
/*   b = bufs; */
/*   p = pass; */
/*   res = results; */

/*   while (n_left > 0) */
/*     { */
/*       const vnet_classify_entry_t *e0; */
/*       vnet_classify_table_t *t0; */
/*       u32 mi; */
/*       u8 *h0; */

/*       /\* Stride 3 seems to work best *\/ */
/*       if (PREDICT_TRUE (n_left > 3)) */
/* 	{ */
/* 	  vnet_classify_table_t *tp1; */

/* 	  tp1 = pool_elt_at_index (vcm->tables, p[2].table_index); */
/* 	  vnet_classify_prefetch_entry (tp1, p[2].hash); */
/* 	} */

/*       t0 = pool_elt_at_index (vcm->tables, p[0].table_index); */
/*       h0 = vlib_buffer_get_current (b[0]) + t0->current_data_offset; */

/*       if (MATCH_SEMANTIC_ANY == sem) */
/* 	{ */
/* 	  e0 = vnet_classify_find_entry_inline (t0, h0, p[0].hash, now); */
/* 	  while (NULL == e0) */
/* 	    { */
/* 	      if (PREDICT_TRUE (t0->next_table_index != ~0)) */
/* 		t0 = pool_elt_at_index (vcm->tables, t0->next_table_index); */
/* 	      else */
/* 		break; */

/* 	      p[0].hash = vnet_classify_hash_packet_inline (t0, h0); */
/* 	      e0 = vnet_classify_find_entry_inline (t0, h0, p[0].hash, now); */
/* 	    } */

/* 	  if (NULL != e0) */
/* 	    { */
/* 	      // returns the index of the rule in the list. */
/* 	      res[0].msr_pos.msp_rule_index = e0->opaque_index; */
/* 	      res[0].msr_user_ctx = p[0].usr_ctx; */
/* 	    } */
/* 	  else */
/* 	    // miss */
/* 	    res[0].msr_pos.msp_rule_index = ~0; */
/* 	} */
/*       else */
/* 	{ */
/* 	  mi = MATCH_RESULT_MISS; */

/* 	  /\* search each of the tables, saving the lowest, i.e. first, match *\/ */
/* 	  while (t0) */
/* 	    { */
/* 	      e0 = vnet_classify_find_entry_inline (t0, h0, p[0].hash, now); */

/* 	      if (NULL != e0) */
/* 		mi = clib_min (mi, e0->opaque_index); */

/* 	      if (PREDICT_TRUE (t0->next_table_index != ~0)) */
/* 		{ */
/* 		  t0 = pool_elt_at_index (vcm->tables, t0->next_table_index); */
/* 		  p[0].hash = vnet_classify_hash_packet_inline (t0, h0); */
/* 		} */
/* 	      else */
/* 		t0 = NULL; */
/* 	    } */

/* 	  res[0].msr_pos.msp_rule_index = mi; */
/* 	  res[0].msr_user_ctx = p[0].usr_ctx; */
/* 	} */
/*       res[0].msr_pos.msp_list_index = 0; */

/*       b++; */
/*       p++; */
/*       res++; */
/*       n_left--; */
/*     } */
/* } */

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
	  res->msr_user_ctx = mtec0->mec_usr_ctx;
	}
      else
	// miss
	res->msr_pos.msp_rule_index = ~0;
    }
  else
    {
      mi = MATCH_RESULT_MISS;

      /* search each of the tables, saving the lowest, i.e. first, match */
      while (t0)
	{
	  e0 = vnet_classify_find_entry_inline (t0, h0, hash0, now);

	  if (NULL != e0)
	    mi = clib_min (mi, e0->opaque_index);

	  if (PREDICT_TRUE (t0->next_table_index != ~0))
	    {
	      t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	      hash0 = vnet_classify_hash_packet_inline (t0, h0);
	    }
	  else
	    t0 = NULL;
	}

      res->msr_pos.msp_rule_index = mi;
      res->msr_user_ctx = mtec0->mec_usr_ctx;
    }
  res->msr_pos.msp_list_index = 0;
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
