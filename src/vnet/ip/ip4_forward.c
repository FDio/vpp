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
 * ip/ip4_forward.c: IP v4 forwarding
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/ethernet/arp_packet.h>	/* for ethernet_arp_header_t */
#include <vnet/ppp/ppp.h>
#include <vnet/srp/srp.h>	/* for srp_hw_interface_class */
#include <vnet/api_errno.h>	/* for API error numbers */
#include <vnet/fib/fib_table.h>	/* for FIB table and entry creation */
#include <vnet/fib/fib_entry.h>	/* for FIB table and entry creation */
#include <vnet/fib/fib_urpf_list.h>	/* for FIB uRPF check */
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/mfib/mfib_table.h>	/* for mFIB table and entry creation */

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

/** @brief IPv4 lookup node.
    @node ip4-lookup

    This is the main IPv4 lookup dispatch node.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.
    - <code>vnet_buffer(b)->sw_if_index[VLIB_TX]</code>
        - When the value is @c ~0 then the node performs a longest prefix
          match (LPM) for the packet destination address in the FIB attached
          to the receive interface.
        - Otherwise perform LPM for the packet destination address in the
          indicated FIB. In this case <code>[VLIB_TX]</code> is a FIB index
          value (0, 1, ...) and not a VRF id.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Index:</em>
    - Dispatches the packet to the node index found in
      ip_adjacency_t @c adj->lookup_next_index
      (where @c adj is the lookup result adjacency).
*/
static uword
ip4_lookup (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_lookup_inline (vm, node, frame,
			    /* lookup_for_responses_to_locally_received_packets */
			    0);

}

static u8 *format_ip4_lookup_trace (u8 * s, va_list * args);

VLIB_REGISTER_NODE (ip4_lookup_node) =
{
.function = ip4_lookup,.name = "ip4-lookup",.vector_size =
    sizeof (u32),.format_trace = format_ip4_lookup_trace,.n_next_nodes =
    IP_LOOKUP_N_NEXT,.next_nodes = IP4_LOOKUP_NEXT_NODES,};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_lookup_node, ip4_lookup);

always_inline uword
ip4_load_balance (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_via_counters;
  u32 n_left_from, n_left_to_next, *from, *to_next;
  ip_lookup_next_t next;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);


      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  ip_lookup_next_t next0, next1;
	  const load_balance_t *lb0, *lb1;
	  vlib_buffer_t *p0, *p1;
	  u32 pi0, lbi0, hc0, pi1, lbi1, hc1;
	  const ip4_header_t *ip0, *ip1;
	  const dpo_id_t *dpo0, *dpo1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), STORE);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  lbi1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

	  lb0 = load_balance_get (lbi0);
	  lb1 = load_balance_get (lbi1);

	  /*
	   * this node is for via FIBs we can re-use the hash value from the
	   * to node if present.
	   * We don't want to use the same hash value at each level in the recursion
	   * graph as that would lead to polarisation
	   */
	  hc0 = hc1 = 0;

	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p0)->ip.flow_hash))
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    vnet_buffer (p0)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    ip4_compute_flow_hash (ip0, lb0->lb_hash_config);
		}
	      dpo0 = load_balance_get_fwd_bucket
		(lb0, (hc0 & (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }
	  if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p1)->ip.flow_hash))
		{
		  hc1 = vnet_buffer (p1)->ip.flow_hash =
		    vnet_buffer (p1)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc1 = vnet_buffer (p1)->ip.flow_hash =
		    ip4_compute_flow_hash (ip1, lb1->lb_hash_config);
		}
	      dpo1 = load_balance_get_fwd_bucket
		(lb1, (hc1 & (lb1->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo1 = load_balance_get_bucket_i (lb1, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  next1 = dpo1->dpoi_next_node;

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter
	    (cm, thread_index, lbi1, 1, vlib_buffer_length_in_chain (vm, p1));

	  vlib_validate_buffer_enqueue_x2 (vm, node, next,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_lookup_next_t next0;
	  const load_balance_t *lb0;
	  vlib_buffer_t *p0;
	  u32 pi0, lbi0, hc0;
	  const ip4_header_t *ip0;
	  const dpo_id_t *dpo0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);
	  lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  lb0 = load_balance_get (lbi0);

	  hc0 = 0;
	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p0)->ip.flow_hash))
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    vnet_buffer (p0)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    ip4_compute_flow_hash (ip0, lb0->lb_hash_config);
		}
	      dpo0 = load_balance_get_fwd_bucket
		(lb0, (hc0 & (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_load_balance_node) =
{
.function = ip4_load_balance,.name = "ip4-load-balance",.vector_size =
    sizeof (u32),.sibling_of = "ip4-lookup",.format_trace =
    format_ip4_lookup_trace,};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_load_balance_node, ip4_load_balance);

/* get first interface address */
ip4_address_t *
ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
			     ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address
    (lm, ia, sw_if_index,
     1 /* honor unnumbered */ ,
     ({
       ip4_address_t * a =
         ip_interface_address_get_address (lm, ia);
       result = a;
       break;
     }));
  /* *INDENT-OFF* */
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

static void
ip4_add_interface_routes (u32 sw_if_index,
			  ip4_main_t * im, u32 fib_index,
			  ip_interface_address_t * a)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip4_address_t *address = ip_interface_address_get_address (lm, a);
  fib_prefix_t pfx = {
    .fp_len = a->address_length,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = *address,
  };

  if (pfx.fp_len <= 30)
    {
      /* a /30 or shorter - add a glean for the network address */
      fib_table_entry_update_one_path (fib_index, &pfx,
                                       FIB_SOURCE_INTERFACE,
                                       (FIB_ENTRY_FLAG_CONNECTED |
                                        FIB_ENTRY_FLAG_ATTACHED),
                                       DPO_PROTO_IP4,
                                       /* No next-hop address */
                                       NULL,
                                       sw_if_index,
                                       // invalid FIB index
                                       ~0,
                                       1,
                                       // no out-label stack
                                       NULL,
                                       FIB_ROUTE_PATH_FLAG_NONE);

      /* Add the two broadcast addresses as drop */
      fib_prefix_t net_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr.ip4.as_u32 = address->as_u32 & im->fib_masks[pfx.fp_len],
      };
      if (net_pfx.fp_addr.ip4.as_u32 != pfx.fp_addr.ip4.as_u32)
        fib_table_entry_special_add(fib_index,
                                    &net_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_DROP |
                                     FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));
      net_pfx.fp_addr.ip4.as_u32 |= ~im->fib_masks[pfx.fp_len];
      if (net_pfx.fp_addr.ip4.as_u32 != pfx.fp_addr.ip4.as_u32)
        fib_table_entry_special_add(fib_index,
                                    &net_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_DROP |
                                     FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));
    }
  else if (pfx.fp_len == 31)
    {
      u32 mask = clib_host_to_net_u32(1);
      fib_prefix_t net_pfx = pfx;

      net_pfx.fp_len = 32;
      net_pfx.fp_addr.ip4.as_u32 ^= mask;

      /* a /31 - add the other end as an attached host */
      fib_table_entry_update_one_path (fib_index, &net_pfx,
                                       FIB_SOURCE_INTERFACE,
                                       (FIB_ENTRY_FLAG_ATTACHED),
                                       DPO_PROTO_IP4,
                                       &net_pfx.fp_addr,
                                       sw_if_index,
                                       // invalid FIB index
                                       ~0,
                                       1,
                                       NULL,
                                       FIB_ROUTE_PATH_FLAG_NONE);
    }
  pfx.fp_len = 32;

  if (sw_if_index < vec_len (lm->classify_table_index_by_sw_if_index))
    {
      u32 classify_table_index =
	lm->classify_table_index_by_sw_if_index[sw_if_index];
      if (classify_table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP4,
		   classify_dpo_create (DPO_PROTO_IP4, classify_table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
    }

  fib_table_entry_update_one_path (fib_index, &pfx,
                                   FIB_SOURCE_INTERFACE,
                                   (FIB_ENTRY_FLAG_CONNECTED |
                                    FIB_ENTRY_FLAG_LOCAL),
                                   DPO_PROTO_IP4,
                                   &pfx.fp_addr,
                                   sw_if_index,
                                   // invalid FIB index
                                   ~0,
				   1, NULL,
				   FIB_ROUTE_PATH_FLAG_NONE);
}

static void
ip4_del_interface_routes (ip4_main_t * im,
			  u32 fib_index,
			  ip4_address_t * address, u32 address_length)
{
  fib_prefix_t pfx = {
    .fp_len = address_length,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = *address,
  };

  if (pfx.fp_len <= 30)
    {
      fib_prefix_t net_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr.ip4.as_u32 = address->as_u32 & im->fib_masks[pfx.fp_len],
      };
      if (net_pfx.fp_addr.ip4.as_u32 != pfx.fp_addr.ip4.as_u32)
        fib_table_entry_special_remove(fib_index,
                                       &net_pfx,
                                       FIB_SOURCE_INTERFACE);
      net_pfx.fp_addr.ip4.as_u32 |= ~im->fib_masks[pfx.fp_len];
      if (net_pfx.fp_addr.ip4.as_u32 != pfx.fp_addr.ip4.as_u32)
        fib_table_entry_special_remove(fib_index,
                                       &net_pfx,
                                       FIB_SOURCE_INTERFACE);
      fib_table_entry_delete (fib_index, &pfx, FIB_SOURCE_INTERFACE);
    }
    else if (pfx.fp_len == 31)
    {
      u32 mask = clib_host_to_net_u32(1);
      fib_prefix_t net_pfx = pfx;

      net_pfx.fp_len = 32;
      net_pfx.fp_addr.ip4.as_u32 ^= mask;

      fib_table_entry_delete (fib_index, &net_pfx, FIB_SOURCE_INTERFACE);
    }

  pfx.fp_len = 32;
  fib_table_entry_delete (fib_index, &pfx, FIB_SOURCE_INTERFACE);
}

void
ip4_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable)
{
  ip4_main_t *im = &ip4_main;

  vec_validate_init_empty (im->ip_enabled_by_sw_if_index, sw_if_index, 0);

  /*
   * enable/disable only on the 1<->0 transition
   */
  if (is_enable)
    {
      if (1 != ++im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }
  else
    {
      ASSERT (im->ip_enabled_by_sw_if_index[sw_if_index] > 0);
      if (0 != --im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }
  vnet_feature_enable_disable ("ip4-unicast", "ip4-drop", sw_if_index,
			       !is_enable, 0, 0);


  vnet_feature_enable_disable ("ip4-multicast", "ip4-drop",
			       sw_if_index, !is_enable, 0, 0);
}

static clib_error_t *
ip4_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip4_address_t * address,
					u32 address_length, u32 is_del)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  clib_error_t *error = 0;
  u32 if_address_index, elts_before;
  ip4_address_fib_t ip4_af, *addr_fib = 0;

  /* local0 interface doesn't support IP addressing  */
  if (sw_if_index == 0)
    {
      return
       clib_error_create ("local0 interface doesn't support IP addressing");
    }

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  ip4_addr_fib_init (&ip4_af, address,
		     vec_elt (im->fib_index_by_sw_if_index, sw_if_index));
  vec_add1 (addr_fib, ip4_af);

  /* FIXME-LATER
   * there is no support for adj-fib handling in the presence of overlapping
   * subnets on interfaces. Easy fix - disallow overlapping subnets, like
   * most routers do.
   */
  /* *INDENT-OFF* */
  if (!is_del)
    {
      /* When adding an address check that it does not conflict
         with an existing address. */
      ip_interface_address_t *ia;
      foreach_ip_interface_address
        (&im->lookup_main, ia, sw_if_index,
         0 /* honor unnumbered */ ,
         ({
           ip4_address_t * x =
             ip_interface_address_get_address
             (&im->lookup_main, ia);
           if (ip4_destination_matches_route
               (im, address, x, ia->address_length) ||
               ip4_destination_matches_route (im,
                                              x,
                                              address,
                                              address_length))
             return
               clib_error_create
               ("failed to add %U which conflicts with %U for interface %U",
                format_ip4_address_and_length, address,
                address_length,
                format_ip4_address_and_length, x,
                ia->address_length,
                format_vnet_sw_if_index_name, vnm,
                sw_if_index);
         }));
    }
  /* *INDENT-ON* */

  elts_before = pool_elts (lm->if_address_pool);

  error = ip_interface_address_add_del
    (lm, sw_if_index, addr_fib, address_length, is_del, &if_address_index);
  if (error)
    goto done;

  ip4_sw_interface_enable_disable (sw_if_index, !is_del);

  if (is_del)
    ip4_del_interface_routes (im, ip4_af.fib_index, address, address_length);
  else
    ip4_add_interface_routes (sw_if_index,
			      im, ip4_af.fib_index,
			      pool_elt_at_index
			      (lm->if_address_pool, if_address_index));

  /* If pool did not grow/shrink: add duplicate address. */
  if (elts_before != pool_elts (lm->if_address_pool))
    {
      ip4_add_del_interface_address_callback_t *cb;
      vec_foreach (cb, im->add_del_interface_address_callbacks)
	cb->function (im, cb->function_opaque, sw_if_index,
		      address, address_length, if_address_index, is_del);
    }

done:
  vec_free (addr_fib);
  return error;
}

clib_error_t *
ip4_add_del_interface_address (vlib_main_t * vm,
			       u32 sw_if_index,
			       ip4_address_t * address,
			       u32 address_length, u32 is_del)
{
  return ip4_add_del_interface_address_internal
    (vm, sw_if_index, address, address_length, is_del);
}

/* Built-in ip4 unicast rx feature path definition */
/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip4_unicast, static) =
{
  .arc_name = "ip4-unicast",
  .start_nodes = VNET_FEATURES ("ip4-input", "ip4-input-no-checksum"),
  .arc_index_ptr = &ip4_main.lookup_main.ucast_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_flow_classify, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-flow-classify",
  .runs_before = VNET_FEATURES ("ip4-inacl"),
};

VNET_FEATURE_INIT (ip4_inacl, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-inacl",
  .runs_before = VNET_FEATURES ("ip4-source-check-via-rx"),
};

VNET_FEATURE_INIT (ip4_source_check_1, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-source-check-via-rx",
  .runs_before = VNET_FEATURES ("ip4-source-check-via-any"),
};

VNET_FEATURE_INIT (ip4_source_check_2, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-source-check-via-any",
  .runs_before = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (ip4_source_and_port_range_check_rx, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-source-and-port-range-check-rx",
  .runs_before = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (ip4_policer_classify, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-policer-classify",
  .runs_before = VNET_FEATURES ("ipsec-input-ip4"),
};

VNET_FEATURE_INIT (ip4_ipsec, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ipsec-input-ip4",
  .runs_before = VNET_FEATURES ("vpath-input-ip4"),
};

VNET_FEATURE_INIT (ip4_vpath, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "vpath-input-ip4",
  .runs_before = VNET_FEATURES ("ip4-vxlan-bypass"),
};

VNET_FEATURE_INIT (ip4_vxlan_bypass, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-vxlan-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip4_drop, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-drop",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip4_lookup, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-lookup",
  .runs_before = 0,	/* not before any other features */
};

/* Built-in ip4 multicast rx feature path definition */
VNET_FEATURE_ARC_INIT (ip4_multicast, static) =
{
  .arc_name = "ip4-multicast",
  .start_nodes = VNET_FEATURES ("ip4-input", "ip4-input-no-checksum"),
  .arc_index_ptr = &ip4_main.lookup_main.mcast_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_vpath_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "vpath-input-ip4",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip4_mc_drop, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "ip4-drop",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip4_lookup_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "ip4-mfib-forward-lookup",
  .runs_before = 0,	/* last feature */
};

/* Source and port-range check ip4 tx feature path definition */
VNET_FEATURE_ARC_INIT (ip4_output, static) =
{
  .arc_name = "ip4-output",
  .start_nodes = VNET_FEATURES ("ip4-rewrite", "ip4-midchain"),
  .arc_index_ptr = &ip4_main.lookup_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_source_and_port_range_check_tx, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-source-and-port-range-check-tx",
  .runs_before = VNET_FEATURES ("ipsec-output-ip4"),
};

VNET_FEATURE_INIT (ip4_ipsec_output, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ipsec-output-ip4",
  .runs_before = VNET_FEATURES ("interface-output"),
};

/* Built-in ip4 tx feature path definition */
VNET_FEATURE_INIT (ip4_interface_output, static) =
{
  .arc_name = "ip4-output",
  .node_name = "interface-output",
  .runs_before = 0,	/* not before any other features */
};
/* *INDENT-ON* */

static clib_error_t *
ip4_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  ip4_main_t *im = &ip4_main;

  /* Fill in lookup tables with default table (0). */
  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  vec_validate (im->mfib_index_by_sw_if_index, sw_if_index);

  if (!is_add)
    {
      ip4_main_t *im4 = &ip4_main;
      ip_lookup_main_t *lm4 = &im4->lookup_main;
      ip_interface_address_t *ia = 0;
      ip4_address_t *address;
      vlib_main_t *vm = vlib_get_main ();

      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* honor unnumbered */,
      ({
        address = ip_interface_address_get_address (lm4, ia);
        ip4_add_del_interface_address(vm, sw_if_index, address, ia->address_length, 1);
      }));
      /* *INDENT-ON* */
    }

  vnet_feature_enable_disable ("ip4-unicast", "ip4-drop", sw_if_index,
			       is_add, 0, 0);

  vnet_feature_enable_disable ("ip4-multicast", "ip4-drop", sw_if_index,
			       is_add, 0, 0);

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip4_sw_interface_add_del);

/* Global IP4 main. */
ip4_main_t ip4_main;

clib_error_t *
ip4_lookup_init (vlib_main_t * vm)
{
  ip4_main_t *im = &ip4_main;
  clib_error_t *error;
  uword i;

  if ((error = vlib_call_init_function (vm, vnet_feature_init)))
    return error;

  for (i = 0; i < ARRAY_LEN (im->fib_masks); i++)
    {
      u32 m;

      if (i < 32)
	m = pow2_mask (i) << (32 - i);
      else
	m = ~0;
      im->fib_masks[i] = clib_host_to_net_u32 (m);
    }

  ip_lookup_init (&im->lookup_main, /* is_ip6 */ 0);

  /* Create FIB with index 0 and table id of 0. */
  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, 0,
				     FIB_SOURCE_DEFAULT_ROUTE);
  mfib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, 0,
				      MFIB_SOURCE_DEFAULT_ROUTE);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip4_lookup_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  {
    ethernet_arp_header_t h;

    memset (&h, 0, sizeof (h));

    /* Set target ethernet address to all zeros. */
    memset (h.ip4_over_ethernet[1].ethernet, 0,
	    sizeof (h.ip4_over_ethernet[1].ethernet));

#define _16(f,v) h.f = clib_host_to_net_u16 (v);
#define _8(f,v) h.f = v;
    _16 (l2_type, ETHERNET_ARP_HARDWARE_TYPE_ethernet);
    _16 (l3_type, ETHERNET_TYPE_IP4);
    _8 (n_l2_address_bytes, 6);
    _8 (n_l3_address_bytes, 4);
    _16 (opcode, ETHERNET_ARP_OPCODE_request);
#undef _16
#undef _8

    vlib_packet_template_init (vm, &im->ip4_arp_request_packet_template,
			       /* data */ &h,
			       sizeof (h),
			       /* alloc chunk size */ 8,
			       "ip4 arp");
  }

  return error;
}

VLIB_INIT_FUNCTION (ip4_lookup_init);

typedef struct
{
  /* Adjacency taken. */
  u32 dpo_index;
  u32 flow_hash;
  u32 fib_index;

  /* Packet data, possibly *after* rewrite. */
  u8 packet_data[64 - 1 * sizeof (u32)];
}
ip4_forward_next_trace_t;

u8 *
format_ip4_forward_next_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "%U%U",
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static u8 *
format_ip4_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "fib %d dpo-idx %d flow hash: 0x%08x",
	      t->fib_index, t->dpo_index, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static u8 *
format_ip4_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "tx_sw_if_index %d dpo-idx %d : %U flow hash: 0x%08x",
	      t->fib_index, t->dpo_index, format_ip_adjacency,
	      t->dpo_index, FORMAT_IP_ADJACENCY_NONE, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip_adjacency_packet_data,
	      t->dpo_index, t->packet_data, sizeof (t->packet_data));
  return s;
}

/* Common trace function for all ip4-forward next nodes. */
void
ip4_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame, vlib_rx_or_tx_t which_adj_index)
{
  u32 *from, n_left;
  ip4_main_t *im = &ip4_main;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ip4_forward_next_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->dpo_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy (t0->packet_data,
		       vlib_buffer_get_current (b0),
		       sizeof (t0->packet_data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->dpo_index = vnet_buffer (b1)->ip.adj_index[which_adj_index];
	  t1->flow_hash = vnet_buffer (b1)->ip.flow_hash;
	  t1->fib_index =
	    (vnet_buffer (b1)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b1)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b1)->sw_if_index[VLIB_RX]);
	  clib_memcpy (t1->packet_data, vlib_buffer_get_current (b1),
		       sizeof (t1->packet_data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ip4_forward_next_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->dpo_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  clib_memcpy (t0->packet_data, vlib_buffer_get_current (b0),
		       sizeof (t0->packet_data));
	}
      from += 1;
      n_left -= 1;
    }
}

/* Compute TCP/UDP/ICMP4 checksum in software. */
u16
ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			      ip4_header_t * ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;
  u32 n_this_buffer, n_bytes_left, n_ip_bytes_this_buffer;
  u16 sum16;
  void *data_this_buffer;

  /* Initialize checksum with ip header. */
  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order =
    clib_net_to_host_u16 (ip0->length) - ip_header_length;
  sum0 =
    clib_host_to_net_u32 (payload_length_host_byte_order +
			  (ip0->protocol << 16));

  if (BITS (uword) == 32)
    {
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->src_address, u32));
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    sum0 =
      ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u64));

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  data_this_buffer = (void *) ip0 + ip_header_length;
  n_ip_bytes_this_buffer =
    p0->current_length - (((u8 *) ip0 - p0->data) - p0->current_data);
  if (n_this_buffer + ip_header_length > n_ip_bytes_this_buffer)
    {
      n_this_buffer = n_ip_bytes_this_buffer > ip_header_length ?
	n_ip_bytes_this_buffer - ip_header_length : 0;
    }
  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      ASSERT (p0->flags & VLIB_BUFFER_NEXT_PRESENT);
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  sum16 = ~ip_csum_fold (sum0);

  return sum16;
}

u32
ip4_tcp_udp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip4_header_t *ip0 = vlib_buffer_get_current (p0);
  udp_header_t *udp0;
  u16 sum16;

  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
	  || ip0->protocol == IP_PROTOCOL_UDP);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		    | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip4_tcp_udp_compute_checksum (vm, p0, ip0);

  p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		| ((sum16 == 0) << VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT));

  return p0->flags;
}

/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip4_local) =
{
  .arc_name  = "ip4-local",
  .start_nodes = VNET_FEATURES ("ip4-local"),
};
/* *INDENT-ON* */

static inline void
ip4_local_validate_l4 (vlib_main_t * vm, vlib_buffer_t * p, ip4_header_t * ip,
		       u8 is_udp, u8 * error, u8 * good_tcp_udp)
{
  u32 flags0;
  flags0 = ip4_tcp_udp_validate_checksum (vm, p);
  *good_tcp_udp = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
  if (is_udp)
    {
      udp_header_t *udp;
      u32 ip_len, udp_len;
      i32 len_diff;
      udp = ip4_next_header (ip);
      /* Verify UDP length. */
      ip_len = clib_net_to_host_u16 (ip->length);
      udp_len = clib_net_to_host_u16 (udp->length);

      len_diff = ip_len - udp_len;
      *good_tcp_udp &= len_diff >= 0;
      *error = len_diff < 0 ? IP4_ERROR_UDP_LENGTH : *error;
    }
}

#define ip4_local_do_l4_check(is_tcp_udp, flags) 			\
    (is_tcp_udp && !(flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED))

static inline uword
ip4_local_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int head_of_feature_arc)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_local_next_t next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  ip4_fib_mtrie_t *mtrie0, *mtrie1;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1;
	  const dpo_id_t *dpo0, *dpo1;
	  const load_balance_t *lb0, *lb1;
	  u32 pi0, next0, fib_index0, lbi0;
	  u32 pi1, next1, fib_index1, lbi1;
	  u8 error0, is_udp0, is_tcp_udp0, good_tcp_udp0, proto0;
	  u8 error1, is_udp1, is_tcp_udp1, good_tcp_udp1, proto1;
	  u32 sw_if_index0, sw_if_index1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = next1 = IP_LOCAL_NEXT_DROP;
	  error0 = error1 = IP4_ERROR_UNKNOWN_PROTOCOL;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
	  vnet_buffer (p1)->l3_hdr_offset = p1->current_data;

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (p1)->sw_if_index[VLIB_RX];

	  /* Treat IP frag packets as "experimental" protocol for now
	     until support of IP frag reassembly is implemented */
	  proto0 = ip4_is_fragment (ip0) ? 0xfe : ip0->protocol;
	  proto1 = ip4_is_fragment (ip1) ? 0xfe : ip1->protocol;

	  if (head_of_feature_arc == 0)
	    goto skip_checks;

	  is_udp0 = proto0 == IP_PROTOCOL_UDP;
	  is_udp1 = proto1 == IP_PROTOCOL_UDP;
	  is_tcp_udp0 = is_udp0 || proto0 == IP_PROTOCOL_TCP;
	  is_tcp_udp1 = is_udp1 || proto1 == IP_PROTOCOL_TCP;

	  good_tcp_udp0 =
	    (p0->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	  good_tcp_udp1 =
	    (p1->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  if (PREDICT_FALSE (ip4_local_do_l4_check (is_tcp_udp0, p0->flags)
			     || ip4_local_do_l4_check (is_tcp_udp1,
						       p1->flags)))
	    {
	      if (is_tcp_udp0)
		ip4_local_validate_l4 (vm, p0, ip0, is_udp0, &error0,
				       &good_tcp_udp0);
	      if (is_tcp_udp1)
		ip4_local_validate_l4 (vm, p1, ip1, is_udp1, &error1,
				       &good_tcp_udp1);
	    }

	  ASSERT (IP4_ERROR_TCP_CHECKSUM + 1 == IP4_ERROR_UDP_CHECKSUM);
	  error0 = (is_tcp_udp0 && !good_tcp_udp0
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp0 : error0);
	  error1 = (is_tcp_udp1 && !good_tcp_udp1
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp1 : error1);

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);
	  fib_index0 =
	    (vnet_buffer (p0)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index0 : vnet_buffer (p0)->sw_if_index[VLIB_TX];

	  fib_index1 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index1);
	  fib_index1 =
	    (vnet_buffer (p1)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index1 : vnet_buffer (p1)->sw_if_index[VLIB_TX];

	  /* TODO maybe move to lookup? */
	  vnet_buffer (p0)->ip.fib_index = fib_index0;
	  vnet_buffer (p1)->ip.fib_index = fib_index1;

	  mtrie0 = &ip4_fib_get (fib_index0)->mtrie;
	  mtrie1 = &ip4_fib_get (fib_index1)->mtrie;

	  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip0->src_address);
	  leaf1 = ip4_fib_mtrie_lookup_step_one (mtrie1, &ip1->src_address);
	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address,
					     2);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address,
					     2);
	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address,
					     3);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address,
					     3);

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = lbi0 =
	    ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = lbi0;

	  vnet_buffer (p1)->ip.adj_index[VLIB_RX] = lbi1 =
	    ip4_fib_mtrie_leaf_get_adj_index (leaf1);
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = lbi1;

	  lb0 = load_balance_get (lbi0);
	  lb1 = load_balance_get (lbi1);
	  dpo0 = load_balance_get_bucket_i (lb0, 0);
	  dpo1 = load_balance_get_bucket_i (lb1, 0);

	  /*
	   * Must have a route to source otherwise we drop the packet.
	   * ip4 broadcasts are accepted, e.g. to make dhcp client work
	   *
	   * The checks are:
	   *  - the source is a recieve => it's from us => bogus, do this
	   *    first since it sets a different error code.
	   *  - uRPF check for any route to source - accept if passes.
	   *  - allow packets destined to the broadcast address from unknown sources
	   */
	  if (p0->flags & VNET_BUFFER_F_IS_NATED)
	    goto skip_check0;

	  error0 = ((error0 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     dpo0->dpoi_type == DPO_RECEIVE) ?
		    IP4_ERROR_SPOOFED_LOCAL_PACKETS : error0);
	  error0 = ((error0 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     !fib_urpf_check_size (lb0->lb_urpf) &&
		     ip0->dst_address.as_u32 != 0xFFFFFFFF)
		    ? IP4_ERROR_SRC_LOOKUP_MISS : error0);

	skip_check0:
	  if (p1->flags & VNET_BUFFER_F_IS_NATED)
	    goto skip_checks;

	  error1 = ((error1 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     dpo1->dpoi_type == DPO_RECEIVE) ?
		    IP4_ERROR_SPOOFED_LOCAL_PACKETS : error1);
	  error1 = ((error1 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     !fib_urpf_check_size (lb1->lb_urpf) &&
		     ip1->dst_address.as_u32 != 0xFFFFFFFF)
		    ? IP4_ERROR_SRC_LOOKUP_MISS : error1);

	skip_checks:

	  next0 = lm->local_next_by_ip_protocol[proto0];
	  next1 = lm->local_next_by_ip_protocol[proto1];

	  next0 =
	    error0 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;
	  next1 =
	    error1 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next1;

	  p0->error = error0 ? error_node->errors[error0] : 0;
	  p1->error = error1 ? error_node->errors[error1] : 0;

	  if (head_of_feature_arc)
	    {
	      if (PREDICT_TRUE (error0 == (u8) IP4_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index, sw_if_index0, &next0, p0);
	      if (PREDICT_TRUE (error1 == (u8) IP4_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index, sw_if_index1, &next1, p1);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1,
					   next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  ip4_fib_mtrie_t *mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  u32 pi0, next0, fib_index0, lbi0;
	  u8 error0, is_udp0, is_tcp_udp0, good_tcp_udp0, proto0;
	  load_balance_t *lb0;
	  const dpo_id_t *dpo0;
	  u32 sw_if_index0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  next0 = IP_LOCAL_NEXT_DROP;
	  error0 = IP4_ERROR_UNKNOWN_PROTOCOL;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);
	  vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* Treat IP frag packets as "experimental" protocol for now
	     until support of IP frag reassembly is implemented */
	  proto0 = ip4_is_fragment (ip0) ? 0xfe : ip0->protocol;

	  if (head_of_feature_arc == 0 || p0->flags & VNET_BUFFER_F_IS_NATED)
	    goto skip_check;

	  is_udp0 = proto0 == IP_PROTOCOL_UDP;
	  is_tcp_udp0 = is_udp0 || proto0 == IP_PROTOCOL_TCP;
	  good_tcp_udp0 =
	    (p0->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  if (PREDICT_FALSE (ip4_local_do_l4_check (is_tcp_udp0, p0->flags)))
	    {
	      ip4_local_validate_l4 (vm, p0, ip0, is_udp0, &error0,
				     &good_tcp_udp0);
	    }

	  ASSERT (IP4_ERROR_TCP_CHECKSUM + 1 == IP4_ERROR_UDP_CHECKSUM);
	  error0 = (is_tcp_udp0 && !good_tcp_udp0
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp0 : error0);

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);
	  fib_index0 =
	    (vnet_buffer (p0)->sw_if_index[VLIB_TX] ==
	     (u32) ~ 0) ? fib_index0 : vnet_buffer (p0)->sw_if_index[VLIB_TX];
	  vnet_buffer (p0)->ip.fib_index = fib_index0;
	  mtrie0 = &ip4_fib_get (fib_index0)->mtrie;
	  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip0->src_address);
	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address,
					     2);
	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address,
					     3);
	  lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = lbi0;
	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = lbi0;

	  lb0 = load_balance_get (lbi0);
	  dpo0 = load_balance_get_bucket_i (lb0, 0);

	  error0 = ((error0 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     dpo0->dpoi_type == DPO_RECEIVE) ?
		    IP4_ERROR_SPOOFED_LOCAL_PACKETS : error0);
	  error0 = ((error0 == IP4_ERROR_UNKNOWN_PROTOCOL &&
		     !fib_urpf_check_size (lb0->lb_urpf) &&
		     ip0->dst_address.as_u32 != 0xFFFFFFFF)
		    ? IP4_ERROR_SRC_LOOKUP_MISS : error0);

	skip_check:
	  next0 = lm->local_next_by_ip_protocol[proto0];
	  next0 =
	    error0 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;

	  p0->error = error0 ? error_node->errors[error0] : 0;

	  if (head_of_feature_arc)
	    {
	      if (PREDICT_TRUE (error0 == (u8) IP4_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index, sw_if_index0, &next0, p0);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip4_local (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_local_inline (vm, node, frame, 1 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_local_node) =
{
  .function = ip4_local,
  .name = "ip4-local",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_next_nodes = IP_LOCAL_N_NEXT,
  .next_nodes =
  {
    [IP_LOCAL_NEXT_DROP] = "ip4-drop",
    [IP_LOCAL_NEXT_PUNT] = "ip4-punt",
    [IP_LOCAL_NEXT_UDP_LOOKUP] = "ip4-udp-lookup",
    [IP_LOCAL_NEXT_ICMP] = "ip4-icmp-input",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_local_node, ip4_local);

static uword
ip4_local_end_of_arc (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_local_inline (vm, node, frame, 0 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_local_end_of_arc_node,static) = {
  .function = ip4_local_end_of_arc,
  .name = "ip4-local-end-of-arc",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,
  .sibling_of = "ip4-local",
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_local_end_of_arc_node, ip4_local_end_of_arc)

VNET_FEATURE_INIT (ip4_local_end_of_arc, static) = {
  .arc_name = "ip4-local",
  .node_name = "ip4-local-end-of-arc",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

void
ip4_register_protocol (u32 protocol, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] =
    vlib_node_add_next (vm, ip4_local_node.index, node_index);
}

static clib_error_t *
show_ip_local_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  int i;

  vlib_cli_output (vm, "Protocols handled by ip4_local");
  for (i = 0; i < ARRAY_LEN (lm->local_next_by_ip_protocol); i++)
    {
      if (lm->local_next_by_ip_protocol[i] != IP_LOCAL_NEXT_PUNT)
	{
	  u32 node_index = vlib_get_node (vm,
					  ip4_local_node.index)->
	    next_nodes[lm->local_next_by_ip_protocol[i]];
	  vlib_cli_output (vm, "%d: %U", i, format_vlib_node_name, vm,
			   node_index);
	}
    }
  return 0;
}



/*?
 * Display the set of protocols handled by the local IPv4 stack.
 *
 * @cliexpar
 * Example of how to display local protocol table:
 * @cliexstart{show ip local}
 * Protocols handled by ip4_local
 * 1
 * 17
 * 47
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_local, static) =
{
  .path = "show ip local",
  .function = show_ip_local_command_fn,
  .short_help = "show ip local",
};
/* *INDENT-ON* */

always_inline uword
ip4_arp_inline (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame, int is_glean)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 *from, *to_next_drop;
  uword n_left_from, n_left_to_next_drop, next_index;
  static f64 time_last_seed_change = -1e100;
  static u32 hash_seeds[3];
  static uword hash_bitmap[256 / BITS (uword)];
  f64 time_now;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  time_now = vlib_time_now (vm);
  if (time_now - time_last_seed_change > 1e-3)
    {
      uword i;
      u32 *r = clib_random_buffer_get_data (&vm->random_buffer,
					    sizeof (hash_seeds));
      for (i = 0; i < ARRAY_LEN (hash_seeds); i++)
	hash_seeds[i] = r[i];

      /* Mark all hash keys as been no-seen before. */
      for (i = 0; i < ARRAY_LEN (hash_bitmap); i++)
	hash_bitmap[i] = 0;

      time_last_seed_change = time_now;
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  if (next_index == IP4_ARP_NEXT_DROP)
    next_index = IP4_ARP_N_NEXT;	/* point to first interface */

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP4_ARP_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 pi0, adj_index0, a0, b0, c0, m0, sw_if_index0, drop0;
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  uword bm0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  adj0 = adj_get (adj_index0);
	  ip0 = vlib_buffer_get_current (p0);

	  a0 = hash_seeds[0];
	  b0 = hash_seeds[1];
	  c0 = hash_seeds[2];

	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  if (is_glean)
	    {
	      /*
	       * this is the Glean case, so we are ARPing for the
	       * packet's destination
	       */
	      a0 ^= ip0->dst_address.data_u32;
	    }
	  else
	    {
	      a0 ^= adj0->sub_type.nbr.next_hop.ip4.data_u32;
	    }
	  b0 ^= sw_if_index0;

	  hash_v3_mix32 (a0, b0, c0);
	  hash_v3_finalize32 (a0, b0, c0);

	  c0 &= BITS (hash_bitmap) - 1;
	  m0 = (uword) 1 << (c0 % BITS (uword));
	  c0 = c0 / BITS (uword);

	  bm0 = hash_bitmap[c0];
	  drop0 = (bm0 & m0) != 0;

	  /* Mark it as seen. */
	  hash_bitmap[c0] = bm0 | m0;

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  p0->error =
	    node->errors[drop0 ? IP4_ARP_ERROR_DROP :
			 IP4_ARP_ERROR_REQUEST_SENT];

	  /*
	   * the adj has been updated to a rewrite but the node the DPO that got
	   * us here hasn't - yet. no big deal. we'll drop while we wait.
	   */
	  if (IP_LOOKUP_NEXT_REWRITE == adj0->lookup_next_index)
	    continue;

	  if (drop0)
	    continue;

	  /*
	   * Can happen if the control-plane is programming tables
	   * with traffic flowing; at least that's today's lame excuse.
	   */
	  if ((is_glean && adj0->lookup_next_index != IP_LOOKUP_NEXT_GLEAN)
	      || (!is_glean && adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP))
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_NON_ARP_ADJ];
	    }
	  else
	    /* Send ARP request. */
	    {
	      u32 bi0 = 0;
	      vlib_buffer_t *b0;
	      ethernet_arp_header_t *h0;
	      vnet_hw_interface_t *hw_if0;

	      h0 =
		vlib_packet_template_get_packet (vm,
						 &im->ip4_arp_request_packet_template,
						 &bi0);

	      /* Seems we're out of buffers */
	      if (PREDICT_FALSE (!h0))
		continue;

	      /* Add rewrite/encap string for ARP packet. */
	      vnet_rewrite_one_header (adj0[0], h0,
				       sizeof (ethernet_header_t));

	      hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	      /* Src ethernet address in ARP header. */
	      clib_memcpy (h0->ip4_over_ethernet[0].ethernet,
			   hw_if0->hw_address,
			   sizeof (h0->ip4_over_ethernet[0].ethernet));

	      if (is_glean)
		{
		  /* The interface's source address is stashed in the Glean Adj */
		  h0->ip4_over_ethernet[0].ip4 =
		    adj0->sub_type.glean.receive_addr.ip4;

		  /* Copy in destination address we are requesting. This is the
		   * glean case, so it's the packet's destination.*/
		  h0->ip4_over_ethernet[1].ip4.data_u32 =
		    ip0->dst_address.data_u32;
		}
	      else
		{
		  /* Src IP address in ARP header. */
		  if (ip4_src_address_for_packet (lm, sw_if_index0,
						  &h0->
						  ip4_over_ethernet[0].ip4))
		    {
		      /* No source address available */
		      p0->error =
			node->errors[IP4_ARP_ERROR_NO_SOURCE_ADDRESS];
		      vlib_buffer_free (vm, &bi0, 1);
		      continue;
		    }

		  /* Copy in destination address we are requesting from the
		     incomplete adj */
		  h0->ip4_over_ethernet[1].ip4.data_u32 =
		    adj0->sub_type.nbr.next_hop.ip4.as_u32;
		}

	      vlib_buffer_copy_trace_flag (vm, p0, bi0);
	      b0 = vlib_get_buffer (vm, bi0);
	      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	      vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

	      vlib_set_next_frame_buffer (vm, node,
					  adj0->rewrite_header.next_index,
					  bi0);
	    }
	}

      vlib_put_next_frame (vm, node, IP4_ARP_NEXT_DROP, n_left_to_next_drop);
    }

  return frame->n_vectors;
}

static uword
ip4_arp (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip4_arp_inline (vm, node, frame, 0));
}

static uword
ip4_glean (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip4_arp_inline (vm, node, frame, 1));
}

static char *ip4_arp_error_strings[] = {
  [IP4_ARP_ERROR_DROP] = "address overflow drops",
  [IP4_ARP_ERROR_REQUEST_SENT] = "ARP requests sent",
  [IP4_ARP_ERROR_NON_ARP_ADJ] = "ARPs to non-ARP adjacencies",
  [IP4_ARP_ERROR_REPLICATE_DROP] = "ARP replication completed",
  [IP4_ARP_ERROR_REPLICATE_FAIL] = "ARP replication failed",
  [IP4_ARP_ERROR_NO_SOURCE_ADDRESS] = "no source address for ARP request",
};

VLIB_REGISTER_NODE (ip4_arp_node) =
{
  .function = ip4_arp,.name = "ip4-arp",.vector_size =
    sizeof (u32),.format_trace = format_ip4_forward_next_trace,.n_errors =
    ARRAY_LEN (ip4_arp_error_strings),.error_strings =
    ip4_arp_error_strings,.n_next_nodes = IP4_ARP_N_NEXT,.next_nodes =
  {
  [IP4_ARP_NEXT_DROP] = "error-drop",}
,};

VLIB_REGISTER_NODE (ip4_glean_node) =
{
  .function = ip4_glean,.name = "ip4-glean",.vector_size =
    sizeof (u32),.format_trace = format_ip4_forward_next_trace,.n_errors =
    ARRAY_LEN (ip4_arp_error_strings),.error_strings =
    ip4_arp_error_strings,.n_next_nodes = IP4_ARP_N_NEXT,.next_nodes =
  {
  [IP4_ARP_NEXT_DROP] = "error-drop",}
,};

#define foreach_notrace_ip4_arp_error           \
_(DROP)                                         \
_(REQUEST_SENT)                                 \
_(REPLICATE_DROP)                               \
_(REPLICATE_FAIL)

clib_error_t *
arp_notrace_init (vlib_main_t * vm)
{
  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, ip4_arp_node.index);

  /* don't trace ARP request packets */
#define _(a)                                    \
    vnet_pcap_drop_trace_filter_add_del         \
        (rt->errors[IP4_ARP_ERROR_##a],         \
         1 /* is_add */);
  foreach_notrace_ip4_arp_error;
#undef _
  return 0;
}

VLIB_INIT_FUNCTION (arp_notrace_init);


/* Send an ARP request to see if given destination is reachable on given interface. */
clib_error_t *
ip4_probe_neighbor (vlib_main_t * vm, ip4_address_t * dst, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  ethernet_arp_header_t *h;
  ip4_address_t *src;
  ip_interface_address_t *ia;
  ip_adjacency_t *adj;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vlib_buffer_t *b;
  adj_index_t ai;
  u32 bi = 0;

  si = vnet_get_sw_interface (vnm, sw_if_index);

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      return clib_error_return (0, "%U: interface %U down",
				format_ip4_address, dst,
				format_vnet_sw_if_index_name, vnm,
				sw_if_index);
    }

  src =
    ip4_interface_address_matching_destination (im, dst, sw_if_index, &ia);
  if (!src)
    {
      vnm->api_errno = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      return clib_error_return
	(0,
	 "no matching interface address for destination %U (interface %U)",
	 format_ip4_address, dst, format_vnet_sw_if_index_name, vnm,
	 sw_if_index);
    }

  h = vlib_packet_template_get_packet (vm,
				       &im->ip4_arp_request_packet_template,
				       &bi);

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (PREDICT_FALSE (!hi->hw_address))
    {
      return clib_error_return (0, "%U: interface %U do not support ip probe",
				format_ip4_address, dst,
				format_vnet_sw_if_index_name, vnm,
				sw_if_index);
    }

  clib_memcpy (h->ip4_over_ethernet[0].ethernet, hi->hw_address,
	       sizeof (h->ip4_over_ethernet[0].ethernet));

  h->ip4_over_ethernet[0].ip4 = src[0];
  h->ip4_over_ethernet[1].ip4 = dst[0];

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] =
    vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  ip46_address_t nh = {
    .ip4 = *dst,
  };

  ai = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4,
			    VNET_LINK_IP4, &nh, sw_if_index);
  adj = adj_get (ai);

  /* Peer has been previously resolved, retrieve glean adj instead */
  if (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE)
    {
      adj_unlock (ai);
      ai = adj_glean_add_or_lock (FIB_PROTOCOL_IP4, sw_if_index, &nh);
      adj = adj_get (ai);
    }

  /* Add encapsulation string for software interface (e.g. ethernet header). */
  vnet_rewrite_one_header (adj[0], h, sizeof (ethernet_header_t));
  vlib_buffer_advance (b, -adj->rewrite_header.data_bytes);

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hi->output_node_index, f);
  }

  adj_unlock (ai);
  return /* no error */ 0;
}

typedef enum
{
  IP4_REWRITE_NEXT_DROP,
  IP4_REWRITE_NEXT_ICMP_ERROR,
} ip4_rewrite_next_t;

always_inline uword
ip4_rewrite_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    int do_counters, int is_midchain, int is_mcast)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  ip_adjacency_t *adj0, *adj1;
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  u32 pi0, rw_len0, next0, error0, checksum0, adj_index0;
	  u32 pi1, rw_len1, next1, error1, checksum1, adj_index1;
	  u32 tx_sw_if_index0, tx_sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), STORE);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  adj_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

	  /*
	   * pre-fetch the per-adjacency counters
	   */
	  if (do_counters)
	    {
	      vlib_prefetch_combined_counter (&adjacency_counters,
					      thread_index, adj_index0);
	      vlib_prefetch_combined_counter (&adjacency_counters,
					      thread_index, adj_index1);
	    }

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  error0 = error1 = IP4_ERROR_NONE;
	  next0 = next1 = IP4_REWRITE_NEXT_DROP;

	  /* Decrement TTL & update checksum.
	     Works either endian, so no need for byte swap. */
	  if (PREDICT_TRUE (!(p0->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED)))
	    {
	      i32 ttl0 = ip0->ttl;

	      /* Input node should have reject packets with ttl 0. */
	      ASSERT (ip0->ttl > 0);

	      checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
	      checksum0 += checksum0 >= 0xffff;

	      ip0->checksum = checksum0;
	      ttl0 -= 1;
	      ip0->ttl = ttl0;

	      /*
	       * If the ttl drops below 1 when forwarding, generate
	       * an ICMP response.
	       */
	      if (PREDICT_FALSE (ttl0 <= 0))
		{
		  error0 = IP4_ERROR_TIME_EXPIRED;
		  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
					       ICMP4_time_exceeded_ttl_exceeded_in_transit,
					       0);
		  next0 = IP4_REWRITE_NEXT_ICMP_ERROR;
		}

	      /* Verify checksum. */
	      ASSERT ((ip0->checksum == ip4_header_checksum (ip0)) ||
		      (p0->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM));
	    }
	  else
	    {
	      p0->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	  if (PREDICT_TRUE (!(p1->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED)))
	    {
	      i32 ttl1 = ip1->ttl;

	      /* Input node should have reject packets with ttl 0. */
	      ASSERT (ip1->ttl > 0);

	      checksum1 = ip1->checksum + clib_host_to_net_u16 (0x0100);
	      checksum1 += checksum1 >= 0xffff;

	      ip1->checksum = checksum1;
	      ttl1 -= 1;
	      ip1->ttl = ttl1;

	      /*
	       * If the ttl drops below 1 when forwarding, generate
	       * an ICMP response.
	       */
	      if (PREDICT_FALSE (ttl1 <= 0))
		{
		  error1 = IP4_ERROR_TIME_EXPIRED;
		  vnet_buffer (p1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (p1, ICMP4_time_exceeded,
					       ICMP4_time_exceeded_ttl_exceeded_in_transit,
					       0);
		  next1 = IP4_REWRITE_NEXT_ICMP_ERROR;
		}

	      /* Verify checksum. */
	      ASSERT ((ip1->checksum == ip4_header_checksum (ip1)) ||
		      (p1->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM));
	    }
	  else
	    {
	      p1->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }

	  /* Rewrite packet header and updates lengths. */
	  adj0 = adj_get (adj_index0);
	  adj1 = adj_get (adj_index1);

	  /* Worth pipelining. No guarantee that adj0,1 are hot... */
	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  rw_len1 = adj1[0].rewrite_header.data_bytes;
	  vnet_buffer (p0)->ip.save_rewrite_length = rw_len0;
	  vnet_buffer (p1)->ip.save_rewrite_length = rw_len1;

	  /* Check MTU of outgoing interface. */
	  error0 =
	    (vlib_buffer_length_in_chain (vm, p0) >
	     adj0[0].
	     rewrite_header.max_l3_packet_bytes ? IP4_ERROR_MTU_EXCEEDED :
	     error0);
	  error1 =
	    (vlib_buffer_length_in_chain (vm, p1) >
	     adj1[0].
	     rewrite_header.max_l3_packet_bytes ? IP4_ERROR_MTU_EXCEEDED :
	     error1);

	  /* Don't adjust the buffer for ttl issue; icmp-error node wants
	   * to see the IP headerr */
	  if (PREDICT_TRUE (error0 == IP4_ERROR_NONE))
	    {
	      next0 = adj0[0].rewrite_header.next_index;
	      p0->current_data -= rw_len0;
	      p0->current_length += rw_len0;
	      tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;

	      if (PREDICT_FALSE
		  (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index0, &next0, p0);
	    }
	  if (PREDICT_TRUE (error1 == IP4_ERROR_NONE))
	    {
	      next1 = adj1[0].rewrite_header.next_index;
	      p1->current_data -= rw_len1;
	      p1->current_length += rw_len1;

	      tx_sw_if_index1 = adj1[0].rewrite_header.sw_if_index;
	      vnet_buffer (p1)->sw_if_index[VLIB_TX] = tx_sw_if_index1;

	      if (PREDICT_FALSE
		  (adj1[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index1, &next1, p1);
	    }

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_two_headers (adj0[0], adj1[0],
				    ip0, ip1, sizeof (ethernet_header_t));

	  /*
	   * Bump the per-adjacency counters
	   */
	  if (do_counters)
	    {
	      vlib_increment_combined_counter
		(&adjacency_counters,
		 thread_index,
		 adj_index0, 1,
		 vlib_buffer_length_in_chain (vm, p0) + rw_len0);

	      vlib_increment_combined_counter
		(&adjacency_counters,
		 thread_index,
		 adj_index1, 1,
		 vlib_buffer_length_in_chain (vm, p1) + rw_len1);
	    }

	  if (is_midchain)
	    {
	      adj0->sub_type.midchain.fixup_func (vm, adj0, p0);
	      adj1->sub_type.midchain.fixup_func (vm, adj1, p1);
	    }
	  if (is_mcast)
	    {
	      /*
	       * copy bytes from the IP address into the MAC rewrite
	       */
	      vnet_fixup_one_header (adj0[0], &ip0->dst_address, ip0);
	      vnet_fixup_one_header (adj1[0], &ip1->dst_address, ip1);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  u32 pi0, rw_len0, adj_index0, next0, error0, checksum0;
	  u32 tx_sw_if_index0;

	  pi0 = to_next[0] = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  adj0 = adj_get (adj_index0);

	  ip0 = vlib_buffer_get_current (p0);

	  error0 = IP4_ERROR_NONE;
	  next0 = IP4_REWRITE_NEXT_DROP;	/* drop on error */

	  /* Decrement TTL & update checksum. */
	  if (PREDICT_TRUE (!(p0->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED)))
	    {
	      i32 ttl0 = ip0->ttl;

	      checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);

	      checksum0 += checksum0 >= 0xffff;

	      ip0->checksum = checksum0;

	      ASSERT (ip0->ttl > 0);

	      ttl0 -= 1;

	      ip0->ttl = ttl0;

	      ASSERT ((ip0->checksum == ip4_header_checksum (ip0)) ||
		      (p0->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM));

	      if (PREDICT_FALSE (ttl0 <= 0))
		{
		  /*
		   * If the ttl drops below 1 when forwarding, generate
		   * an ICMP response.
		   */
		  error0 = IP4_ERROR_TIME_EXPIRED;
		  next0 = IP4_REWRITE_NEXT_ICMP_ERROR;
		  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
					       ICMP4_time_exceeded_ttl_exceeded_in_transit,
					       0);
		}
	    }
	  else
	    {
	      p0->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }

	  if (do_counters)
	    vlib_prefetch_combined_counter (&adjacency_counters,
					    thread_index, adj_index0);

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_one_header (adj0[0], ip0, sizeof (ethernet_header_t));
	  if (is_mcast)
	    {
	      /*
	       * copy bytes from the IP address into the MAC rewrite
	       */
	      vnet_fixup_one_header (adj0[0], &ip0->dst_address, ip0);
	    }

	  /* Update packet buffer attributes/set output interface. */
	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  vnet_buffer (p0)->ip.save_rewrite_length = rw_len0;

	  if (do_counters)
	    vlib_increment_combined_counter
	      (&adjacency_counters,
	       thread_index, adj_index0, 1,
	       vlib_buffer_length_in_chain (vm, p0) + rw_len0);

	  /* Check MTU of outgoing interface. */
	  error0 = (vlib_buffer_length_in_chain (vm, p0)
		    > adj0[0].rewrite_header.max_l3_packet_bytes
		    ? IP4_ERROR_MTU_EXCEEDED : error0);

	  p0->error = error_node->errors[error0];

	  /* Don't adjust the buffer for ttl issue; icmp-error node wants
	   * to see the IP headerr */
	  if (PREDICT_TRUE (error0 == IP4_ERROR_NONE))
	    {
	      p0->current_data -= rw_len0;
	      p0->current_length += rw_len0;
	      tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;

	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
	      next0 = adj0[0].rewrite_header.next_index;

	      if (is_midchain)
		{
		  adj0->sub_type.midchain.fixup_func (vm, adj0, p0);
		}

	      if (PREDICT_FALSE
		  (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index0, &next0, p0);

	    }

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Need to do trace after rewrites to pick up new packet data. */
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}


/** @brief IPv4 rewrite node.
    @node ip4-rewrite

    This is the IPv4 transit-rewrite node: decrement TTL, fix the ipv4
    header checksum, fetch the ip adjacency, check the outbound mtu,
    apply the adjacency rewrite, and send pkts to the adjacency
    rewrite header's rewrite_next_index.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - the rewrite adjacency index
    - <code>adj->lookup_next_index</code>
        - Must be IP_LOOKUP_NEXT_REWRITE or IP_LOOKUP_NEXT_ARP, otherwise
          the packet will be dropped.
    - <code>adj->rewrite_header</code>
        - Rewrite string length, rewrite string, next_index

    @em Sets:
    - <code>b->current_data, b->current_length</code>
        - Updated net of applying the rewrite string

    <em>Next Indices:</em>
    - <code> adj->rewrite_header.next_index </code>
      or @c error-drop
*/
static uword
ip4_rewrite (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 0, 0);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 0, 0);
}

static uword
ip4_midchain (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 1, 0);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 1, 0);
}

static uword
ip4_rewrite_mcast (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 0, 1);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 0, 1);
}

static uword
ip4_mcast_midchain (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 1, 1);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 1, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_rewrite_node) = {
  .function = ip4_rewrite,
  .name = "ip4-rewrite",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,

  .n_next_nodes = 2,
  .next_nodes = {
    [IP4_REWRITE_NEXT_DROP] = "error-drop",
    [IP4_REWRITE_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_rewrite_node, ip4_rewrite)

VLIB_REGISTER_NODE (ip4_rewrite_mcast_node) = {
  .function = ip4_rewrite_mcast,
  .name = "ip4-rewrite-mcast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_rewrite_mcast_node, ip4_rewrite_mcast)

VLIB_REGISTER_NODE (ip4_mcast_midchain_node, static) = {
  .function = ip4_mcast_midchain,
  .name = "ip4-mcast-midchain",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_mcast_midchain_node, ip4_mcast_midchain)

VLIB_REGISTER_NODE (ip4_midchain_node) = {
  .function = ip4_midchain,
  .name = "ip4-midchain",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .sibling_of =  "ip4-rewrite",
};
VLIB_NODE_FUNCTION_MULTIARCH (ip4_midchain_node, ip4_midchain);
/* *INDENT-ON */

int
ip4_lookup_validate (ip4_address_t * a, u32 fib_index0)
{
  ip4_fib_mtrie_t *mtrie0;
  ip4_fib_mtrie_leaf_t leaf0;
  u32 lbi0;

  mtrie0 = &ip4_fib_get (fib_index0)->mtrie;

  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, a);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 2);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 3);

  lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

  return lbi0 == ip4_fib_table_lookup_lb (ip4_fib_get (fib_index0), a);
}

static clib_error_t *
test_lookup_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_fib_t *fib;
  u32 table_id = 0;
  f64 count = 1;
  u32 n;
  int i;
  ip4_address_t ip4_base_address;
  u64 errors = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_id))
	{
	  /* Make sure the entry exists. */
	  fib = ip4_fib_get (table_id);
	  if ((fib) && (fib->index != table_id))
	    return clib_error_return (0, "<fib-index> %d does not exist",
				      table_id);
	}
      else if (unformat (input, "count %f", &count))
	;

      else if (unformat (input, "%U",
			 unformat_ip4_address, &ip4_base_address))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  n = count;

  for (i = 0; i < n; i++)
    {
      if (!ip4_lookup_validate (&ip4_base_address, table_id))
	errors++;

      ip4_base_address.as_u32 =
	clib_host_to_net_u32 (1 +
			      clib_net_to_host_u32 (ip4_base_address.as_u32));
    }

  if (errors)
    vlib_cli_output (vm, "%llu errors out of %d lookups\n", errors, n);
  else
    vlib_cli_output (vm, "No errors in %d lookups\n", n);

  return 0;
}

/*?
 * Perform a lookup of an IPv4 Address (or range of addresses) in the
 * given FIB table to determine if there is a conflict with the
 * adjacency table. The fib-id can be determined by using the
 * '<em>show ip fib</em>' command. If fib-id is not entered, default value
 * of 0 is used.
 *
 * @todo This command uses fib-id, other commands use table-id (not
 * just a name, they are different indexes). Would like to change this
 * to table-id for consistency.
 *
 * @cliexpar
 * Example of how to run the test lookup command:
 * @cliexstart{test lookup 172.16.1.1 table 1 count 2}
 * No errors in 2 lookups
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lookup_test_command, static) =
{
  .path = "test lookup",
  .short_help = "test lookup <ipv4-addr> [table <fib-id>] [count <nn>]",
  .function = test_lookup_command_fn,
};
/* *INDENT-ON* */

int
vnet_set_ip4_flow_hash (u32 table_id, u32 flow_hash_config)
{
  u32 fib_index;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_table_set_flow_hash_config (fib_index, FIB_PROTOCOL_IP4,
				  flow_hash_config);

  return 0;
}

static clib_error_t *
set_ip_flow_hash_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  int matched = 0;
  u32 table_id = 0;
  u32 flow_hash_config = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_id))
	matched = 1;
#define _(a,v) \
    else if (unformat (input, #a)) { flow_hash_config |= v; matched=1;}
      foreach_flow_hash_bit
#undef _
	else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  rv = vnet_set_ip4_flow_hash (table_id, flow_hash_config);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such FIB table %d", table_id);

    default:
      clib_warning ("BUG: illegal flow hash config 0x%x", flow_hash_config);
      break;
    }

  return 0;
}

/*?
 * Configure the set of IPv4 fields used by the flow hash.
 *
 * @cliexpar
 * Example of how to set the flow hash on a given table:
 * @cliexcmd{set ip flow-hash table 7 dst sport dport proto}
 * Example of display the configured flow hash:
 * @cliexstart{show ip fib}
 * ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:0 buckets:1 uRPF:0 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:1 buckets:1 uRPF:1 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:3 buckets:1 uRPF:3 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 6.0.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:30 buckets:1 uRPF:29 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 7.0.0.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:31 buckets:4 uRPF:30 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [1] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [2] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [3] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:2 buckets:1 uRPF:2 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:4 buckets:1 uRPF:4 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * ipv4-VRF:7, fib_index 1, flow hash: dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 172.16.1.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet0
 * 172.16.1.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
 *     [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
 * 172.16.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -> 26:a5:f6:9c:3a:36
 * 172.16.2.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet1
 * 172.16.2.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
 *     [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip_flow_hash_command, static) =
{
  .path = "set ip flow-hash",
  .short_help =
  "set ip flow-hash table <table-id> [src] [dst] [sport] [dport] [proto] [reverse]",
  .function = set_ip_flow_hash_command_fn,
};
/* *INDENT-ON* */

int
vnet_set_ip4_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
			     u32 table_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip4_main_t *ipm = &ip4_main;
  ip_lookup_main_t *lm = &ipm->lookup_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  ip4_address_t *if_addr;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_validate (lm->classify_table_index_by_sw_if_index, sw_if_index);
  lm->classify_table_index_by_sw_if_index[sw_if_index] = table_index;

  if_addr = ip4_interface_first_address (ipm, sw_if_index, NULL);

  if (NULL != if_addr)
    {
      fib_prefix_t pfx = {
	.fp_len = 32,
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_addr.ip4 = *if_addr,
      };
      u32 fib_index;

      fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);


      if (table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP4,
		   classify_dpo_create (DPO_PROTO_IP4, table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
      else
	{
	  fib_table_entry_special_remove (fib_index,
					  &pfx, FIB_SOURCE_CLASSIFY);
	}
    }

  return 0;
}

static clib_error_t *
set_ip_classify_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  u32 table_index = ~0;
  int table_index_set = 0;
  u32 sw_if_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table-index %d", &table_index))
	table_index_set = 1;
      else if (unformat (input, "intfc %U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (table_index_set == 0)
    return clib_error_return (0, "classify table-index must be specified");

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface / subif must be specified");

  rv = vnet_set_ip4_classify_intfc (vm, sw_if_index, table_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_MATCHING_INTERFACE:
      return clib_error_return (0, "No such interface");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No such classifier table");
    }
  return 0;
}

/*?
 * Assign a classification table to an interface. The classification
 * table is created using the '<em>classify table</em>' and '<em>classify session</em>'
 * commands. Once the table is create, use this command to filter packets
 * on an interface.
 *
 * @cliexpar
 * Example of how to assign a classification table to an interface:
 * @cliexcmd{set ip classify intfc GigabitEthernet2/0/0 table-index 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip_classify_command, static) =
{
    .path = "set ip classify",
    .short_help =
    "set ip classify intfc <interface> table-index <classify-idx>",
    .function = set_ip_classify_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
