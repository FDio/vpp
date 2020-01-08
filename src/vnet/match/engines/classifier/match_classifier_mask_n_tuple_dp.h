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
#define __MATCH_ENGINE_CLASSIFIER_MASK_N_TUPLE_DP_H__

#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple.h>
#include <vnet/match/engines/classifier/match_classifier_dp.h>

#include <vnet/match/match_types_dp.h>

static_always_inline bool
match_classifier_engine_match (vlib_main_t * vm,
			       vlib_buffer_t * b,
			       i16 l3_offset,
			       const match_set_app_t * app,
			       f64 now,
			       ip_address_family_t af, match_result_t * res)
{
  const vnet_classify_main_t *vcm = &vnet_classify_main;
  const match_classifier_engine_t *mce0;
  u8 scratch[VNET_CLASSIFY_VECTOR_SIZE * 5];
  const match_classifier_session_t *mcs0;
  vnet_classify_table_t *vct0, *vct1;
  const vnet_classify_entry_t *e0;
  const u8 *h0;
  u64 hash0;

  match_classifier_best_t mcb = {
    .mcb_pos = MATCH_SET_POS_MISS_INIT,
  };

  e0 = NULL;
  mce0 = pool_elt_at_index (match_classifier_engine_pool, app->msa_index);
  vct0 = pool_elt_at_index (vcm->tables, mce0->mce_table_index);
  vct1 = NULL;

  h0 = vlib_buffer_get_current (b) + l3_offset;

  if (AF_IP6 == af)
    {
      /* The classifer tables are build to expect only IP and UDP headers
       * so if there is a fragment header in packet, they are not going to match,
       * Our options are;
       *  1) throw more memory at the problem. build a parallel set of classifier
       *     tables that would match IP+frag+UDP. the downside, apart from being
       *     a truck load more memory is that it probably won't be quicker (than
       *     option 2) because the parallel structures will cause their own set
       *     of cache misses.
       *  2) build a temporary 'packet' with the frag header removed. We
       *     therefore get to re-use the the same set of classifier tables
       */
      h0 = match_ip6_strip_frag (h0, scratch, sizeof (scratch));
    }

  /*
   * we sorted the tables so that those containing the best rules are first.
   * so loop thru the tables until the match we have is better than the best
   * the table has to offer. At that point there ar eno better rules to
   * match and we're done.
   */
  while (vct0
	 && match_set_pos_is_better ((match_set_pos_t *) & vct0->user_ctx,
				     &mcb.mcb_pos))
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
	  if (PREDICT_TRUE (e0->next_index == ~0))
	    {
	      mcs0 = match_classifier_session_get (e0->opaque_index);
	      match_classifier_update_if_better (&mcb, &mcs0->mcs_pos,
						 mcs0->mcs_result);
	    }
	  else
	    {
	      /* clash rules => linear search
	       */
	      match_classifier_clash_head_t *mcch0;
	      match_classifier_clash_t *mcc0;
	      index_t *mcci0;

	      mcch0 = pool_elt_at_index (match_classifier_clash_head_pool,
					 e0->next_index);

	      vec_foreach (mcci0, mcch0->mcch_clashes)
	      {
		bool match;

		// FIXME - do some rule prefetchin.
		mcc0 =
		  pool_elt_at_index (match_classifier_clash_pool, *mcci0);

		if (AF_IP4 == af)
		  match = match_ip4_mask_n_tuple ((ip4_header_t *) h0,
						  &mcc0->mcc_rule);
		else
		  match = match_ip6_mask_n_tuple ((ip6_header_t *) h0,
						  &mcc0->mcc_rule);

		if (match)
		  {
		    /* the sessions are sorted best first, so once we match one,
		     * we're done */
		    match_classifier_update_if_better (&mcb, &mcc0->mcc_pos,
						       mcc0->mcc_result);
		    break;
		  }
	      }
	      /*
	       * it is possible that we don't match any clashing rules. They
	       * are in the clash list because they cannot be represented as a
	       * exact match mask, i.e. they have some sort of associated range)
	       * So what this packet match was all the fields that could be
	       * represented as a mask. but there's no guarantee that this
	       * packet also matches the fields that are ranges. So if we miss
	       * in this list, we continue to the next table.
	       */
	    }
	}

      if (PREDICT_TRUE (vct0->next_table_index != ~0))
	vct0 = vct1;
      else
	vct0 = NULL;
    }

  *res = mcb.mcb_res;
  return (NULL != e0);
}

/**
 * Data-plane function to go match
 */
static_always_inline bool
match_classifier_engine_match_mask_n_tuple_ip4 (vlib_main_t * vm,
						vlib_buffer_t * b,
						i16 l2_offset,
						i16 l3_offset,
						const match_set_app_t * app,
						f64 now, match_result_t * res)
{
  return (match_classifier_engine_match
	  (vm, b, l3_offset, app, now, AF_IP4, res));
}

static_always_inline bool
match_classifier_engine_match_mask_n_tuple_ip6 (vlib_main_t * vm,
						vlib_buffer_t * b,
						i16 l2_offset,
						i16 l3_offset,
						const match_set_app_t * app,
						f64 now, match_result_t * res)
{
  return (match_classifier_engine_match
	  (vm, b, l3_offset, app, now, AF_IP6, res));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
