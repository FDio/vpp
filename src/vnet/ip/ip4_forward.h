/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/ip4_forward.h: IP v4 forwarding
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __included_ip4_forward_h__
#define __included_ip4_forward_h__

#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/load_balance_map.h>

/**
 * @file
 * @brief IPv4 Forwarding.
 *
 * This file contains the source code for IPv4 forwarding.
 */

always_inline uword
ip4_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame,
		   int lookup_for_responses_to_locally_received_packets)
{
  ip4_main_t *im = &ip4_main;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left_from, n_left_to_next, *from, *to_next;
  ip_lookup_next_t next;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  vlib_buffer_t *p0, *p1, *p2, *p3;
	  ip4_header_t *ip0, *ip1, *ip2, *ip3;
	  ip_lookup_next_t next0, next1, next2, next3;
	  const load_balance_t *lb0, *lb1, *lb2, *lb3;
	  ip4_fib_mtrie_t *mtrie0, *mtrie1, *mtrie2, *mtrie3;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1, leaf2, leaf3;
	  ip4_address_t *dst_addr0, *dst_addr1, *dst_addr2, *dst_addr3;
	  u32 pi0, fib_index0, lb_index0;
	  u32 pi1, fib_index1, lb_index1;
	  u32 pi2, fib_index2, lb_index2;
	  u32 pi3, fib_index3, lb_index3;
	  flow_hash_config_t flow_hash_config0, flow_hash_config1;
	  flow_hash_config_t flow_hash_config2, flow_hash_config3;
	  u32 hash_c0, hash_c1, hash_c2, hash_c3;
	  const dpo_id_t *dpo0, *dpo1, *dpo2, *dpo3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p5->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p6->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p7->data, sizeof (ip0[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  pi2 = to_next[2] = from[2];
	  pi3 = to_next[3] = from[3];

	  from += 4;
	  to_next += 4;
	  n_left_to_next -= 4;
	  n_left_from -= 4;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  p2 = vlib_get_buffer (vm, pi2);
	  p3 = vlib_get_buffer (vm, pi3);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  ip2 = vlib_buffer_get_current (p2);
	  ip3 = vlib_buffer_get_current (p3);

	  dst_addr0 = &ip0->dst_address;
	  dst_addr1 = &ip1->dst_address;
	  dst_addr2 = &ip2->dst_address;
	  dst_addr3 = &ip3->dst_address;

	  fib_index0 =
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  fib_index1 =
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (p1)->sw_if_index[VLIB_RX]);
	  fib_index2 =
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (p2)->sw_if_index[VLIB_RX]);
	  fib_index3 =
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (p3)->sw_if_index[VLIB_RX]);
	  fib_index0 =
	    (vnet_buffer (p0)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index0 : vnet_buffer (p0)->sw_if_index[VLIB_TX];
	  fib_index1 =
	    (vnet_buffer (p1)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index1 : vnet_buffer (p1)->sw_if_index[VLIB_TX];
	  fib_index2 =
	    (vnet_buffer (p2)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index2 : vnet_buffer (p2)->sw_if_index[VLIB_TX];
	  fib_index3 =
	    (vnet_buffer (p3)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index3 : vnet_buffer (p3)->sw_if_index[VLIB_TX];


	  if (!lookup_for_responses_to_locally_received_packets)
	    {
	      mtrie0 = &ip4_fib_get (fib_index0)->mtrie;
	      mtrie1 = &ip4_fib_get (fib_index1)->mtrie;
	      mtrie2 = &ip4_fib_get (fib_index2)->mtrie;
	      mtrie3 = &ip4_fib_get (fib_index3)->mtrie;

	      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, dst_addr0);
	      leaf1 = ip4_fib_mtrie_lookup_step_one (mtrie1, dst_addr1);
	      leaf2 = ip4_fib_mtrie_lookup_step_one (mtrie2, dst_addr2);
	      leaf3 = ip4_fib_mtrie_lookup_step_one (mtrie3, dst_addr3);
	    }

	  if (!lookup_for_responses_to_locally_received_packets)
	    {
	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 2);
	      leaf2 = ip4_fib_mtrie_lookup_step (mtrie2, leaf2, dst_addr2, 2);
	      leaf3 = ip4_fib_mtrie_lookup_step (mtrie3, leaf3, dst_addr3, 2);
	    }

	  if (!lookup_for_responses_to_locally_received_packets)
	    {
	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 3);
	      leaf2 = ip4_fib_mtrie_lookup_step (mtrie2, leaf2, dst_addr2, 3);
	      leaf3 = ip4_fib_mtrie_lookup_step (mtrie3, leaf3, dst_addr3, 3);
	    }

	  if (lookup_for_responses_to_locally_received_packets)
	    {
	      lb_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_RX];
	      lb_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_RX];
	      lb_index2 = vnet_buffer (p2)->ip.adj_index[VLIB_RX];
	      lb_index3 = vnet_buffer (p3)->ip.adj_index[VLIB_RX];
	    }
	  else
	    {
	      lb_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	      lb_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
	      lb_index2 = ip4_fib_mtrie_leaf_get_adj_index (leaf2);
	      lb_index3 = ip4_fib_mtrie_leaf_get_adj_index (leaf3);
	    }

	  ASSERT (lb_index0 && lb_index1 && lb_index2 && lb_index3);
	  lb0 = load_balance_get (lb_index0);
	  lb1 = load_balance_get (lb_index1);
	  lb2 = load_balance_get (lb_index2);
	  lb3 = load_balance_get (lb_index3);

	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));
	  ASSERT (lb1->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb1->lb_n_buckets));
	  ASSERT (lb2->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb2->lb_n_buckets));
	  ASSERT (lb3->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb3->lb_n_buckets));

	  /* Use flow hash to compute multipath adjacency. */
	  hash_c0 = vnet_buffer (p0)->ip.flow_hash = 0;
	  hash_c1 = vnet_buffer (p1)->ip.flow_hash = 0;
	  hash_c2 = vnet_buffer (p2)->ip.flow_hash = 0;
	  hash_c3 = vnet_buffer (p3)->ip.flow_hash = 0;
	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      flow_hash_config0 = lb0->lb_hash_config;
	      hash_c0 = vnet_buffer (p0)->ip.flow_hash =
		ip4_compute_flow_hash (ip0, flow_hash_config0);
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (hash_c0 &
					      (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }
	  if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
	    {
	      flow_hash_config1 = lb1->lb_hash_config;
	      hash_c1 = vnet_buffer (p1)->ip.flow_hash =
		ip4_compute_flow_hash (ip1, flow_hash_config1);
	      dpo1 =
		load_balance_get_fwd_bucket (lb1,
					     (hash_c1 &
					      (lb1->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo1 = load_balance_get_bucket_i (lb1, 0);
	    }
	  if (PREDICT_FALSE (lb2->lb_n_buckets > 1))
	    {
	      flow_hash_config2 = lb2->lb_hash_config;
	      hash_c2 = vnet_buffer (p2)->ip.flow_hash =
		ip4_compute_flow_hash (ip2, flow_hash_config2);
	      dpo2 =
		load_balance_get_fwd_bucket (lb2,
					     (hash_c2 &
					      (lb2->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo2 = load_balance_get_bucket_i (lb2, 0);
	    }
	  if (PREDICT_FALSE (lb3->lb_n_buckets > 1))
	    {
	      flow_hash_config3 = lb3->lb_hash_config;
	      hash_c3 = vnet_buffer (p3)->ip.flow_hash =
		ip4_compute_flow_hash (ip3, flow_hash_config3);
	      dpo3 =
		load_balance_get_fwd_bucket (lb3,
					     (hash_c3 &
					      (lb3->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo3 = load_balance_get_bucket_i (lb3, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
	  next1 = dpo1->dpoi_next_node;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;
	  next2 = dpo2->dpoi_next_node;
	  vnet_buffer (p2)->ip.adj_index[VLIB_TX] = dpo2->dpoi_index;
	  next3 = dpo3->dpoi_next_node;
	  vnet_buffer (p3)->ip.adj_index[VLIB_TX] = dpo3->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lb_index0, 1,
	     vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter
	    (cm, thread_index, lb_index1, 1,
	     vlib_buffer_length_in_chain (vm, p1));
	  vlib_increment_combined_counter
	    (cm, thread_index, lb_index2, 1,
	     vlib_buffer_length_in_chain (vm, p2));
	  vlib_increment_combined_counter
	    (cm, thread_index, lb_index3, 1,
	     vlib_buffer_length_in_chain (vm, p3));

	  vlib_validate_buffer_enqueue_x4 (vm, node, next,
					   to_next, n_left_to_next,
					   pi0, pi1, pi2, pi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  ip_lookup_next_t next0;
	  const load_balance_t *lb0;
	  ip4_fib_mtrie_t *mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  ip4_address_t *dst_addr0;
	  u32 pi0, fib_index0, lbi0;
	  flow_hash_config_t flow_hash_config0;
	  const dpo_id_t *dpo0;
	  u32 hash_c0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  dst_addr0 = &ip0->dst_address;

	  fib_index0 =
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  fib_index0 =
	    (vnet_buffer (p0)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index0 : vnet_buffer (p0)->sw_if_index[VLIB_TX];

	  if (!lookup_for_responses_to_locally_received_packets)
	    {
	      mtrie0 = &ip4_fib_get (fib_index0)->mtrie;

	      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, dst_addr0);
	    }

	  if (!lookup_for_responses_to_locally_received_packets)
	    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);

	  if (!lookup_for_responses_to_locally_received_packets)
	    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);

	  if (lookup_for_responses_to_locally_received_packets)
	    lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_RX];
	  else
	    {
	      /* Handle default route. */
	      lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	    }

	  ASSERT (lbi0);
	  lb0 = load_balance_get (lbi0);

	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));

	  /* Use flow hash to compute multipath adjacency. */
	  hash_c0 = vnet_buffer (p0)->ip.flow_hash = 0;
	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      flow_hash_config0 = lb0->lb_hash_config;

	      hash_c0 = vnet_buffer (p0)->ip.flow_hash =
		ip4_compute_flow_hash (ip0, flow_hash_config0);
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (hash_c0 &
					      (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

	  vlib_increment_combined_counter (cm, thread_index, lbi0, 1,
					   vlib_buffer_length_in_chain (vm,
									p0));

	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  if (PREDICT_FALSE (next0 != next))
	    {
	      n_left_to_next += 1;
	      vlib_put_next_frame (vm, node, next, n_left_to_next);
	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = pi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

#endif /* __included_ip4_forward_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
