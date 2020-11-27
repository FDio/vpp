/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * ip/ip6_forward.h: IP v6 forwarding
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

#ifndef __included_ip6_forward_h__
#define __included_ip6_forward_h__

#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/ip/ip6_inlines.h>

/**
 * @file
 * @brief IPv6 Forwarding.
 *
 * This file contains the source code for IPv6 forwarding.
 */


always_inline uword
ip6_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_main_t *im = &ip6_main;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left_from, n_left_to_next, *from, *to_next;
  ip_lookup_next_t next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  u32 pi0, pi1, lbi0, lbi1, wrong_next;
	  ip_lookup_next_t next0, next1;
	  ip6_header_t *ip0, *ip1;
	  ip6_address_t *dst_addr0, *dst_addr1;
	  u32 flow_hash_config0, flow_hash_config1;
	  const dpo_id_t *dpo0, *dpo1;
	  const load_balance_t *lb0, *lb1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  dst_addr0 = &ip0->dst_address;
	  dst_addr1 = &ip1->dst_address;

	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p0);
	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p1);

	  lbi0 = ip6_fib_table_fwding_lookup (vnet_buffer (p0)->ip.fib_index,
					      dst_addr0);
	  lbi1 = ip6_fib_table_fwding_lookup (vnet_buffer (p1)->ip.fib_index,
					      dst_addr1);

	  lb0 = load_balance_get (lbi0);
	  lb1 = load_balance_get (lbi1);
	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (lb1->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));
	  ASSERT (is_pow2 (lb1->lb_n_buckets));

	  vnet_buffer (p0)->ip.flow_hash = vnet_buffer (p1)->ip.flow_hash = 0;

	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      flow_hash_config0 = lb0->lb_hash_config;
	      vnet_buffer (p0)->ip.flow_hash =
		ip6_compute_flow_hash (ip0, flow_hash_config0);
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (vnet_buffer (p0)->ip.flow_hash &
					      (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }
	  if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
	    {
	      flow_hash_config1 = lb1->lb_hash_config;
	      vnet_buffer (p1)->ip.flow_hash =
		ip6_compute_flow_hash (ip1, flow_hash_config1);
	      dpo1 =
		load_balance_get_fwd_bucket (lb1,
					     (vnet_buffer (p1)->ip.flow_hash &
					      (lb1->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo1 = load_balance_get_bucket_i (lb1, 0);
	    }
	  next0 = dpo0->dpoi_next_node;
	  next1 = dpo1->dpoi_next_node;

	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
	    }
	  if (PREDICT_FALSE
	      (ip1->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next1 = (dpo_is_adj (dpo1) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next1;
	    }
	  vnet_buffer (p0)->ip.adj_index = dpo0->dpoi_index;
	  vnet_buffer (p1)->ip.adj_index = dpo1->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter
	    (cm, thread_index, lbi1, 1, vlib_buffer_length_in_chain (vm, p1));

	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  wrong_next = (next0 != next) + 2 * (next1 != next);
	  if (PREDICT_FALSE (wrong_next != 0))
	    {
	      switch (wrong_next)
		{
		case 1:
		  /* A B A */
		  to_next[-2] = pi1;
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  break;

		case 2:
		  /* A A B */
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  break;

		case 3:
		  /* A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  if (next0 == next1)
		    {
		      /* A B B */
		      vlib_put_next_frame (vm, node, next, n_left_to_next);
		      next = next1;
		      vlib_get_next_frame (vm, node, next, to_next,
					   n_left_to_next);
		    }
		}
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  u32 pi0, lbi0;
	  ip_lookup_next_t next0;
	  load_balance_t *lb0;
	  ip6_address_t *dst_addr0;
	  u32 flow_hash_config0;
	  const dpo_id_t *dpo0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);
	  dst_addr0 = &ip0->dst_address;
	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p0);
	  lbi0 = ip6_fib_table_fwding_lookup (vnet_buffer (p0)->ip.fib_index,
					      dst_addr0);

	  lb0 = load_balance_get (lbi0);
	  flow_hash_config0 = lb0->lb_hash_config;

	  vnet_buffer (p0)->ip.flow_hash = 0;
	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));

	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      flow_hash_config0 = lb0->lb_hash_config;
	      vnet_buffer (p0)->ip.flow_hash =
		ip6_compute_flow_hash (ip0, flow_hash_config0);
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (vnet_buffer (p0)->ip.flow_hash &
					      (lb0->lb_n_buckets_minus_1)));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }

	  dpo0 = load_balance_get_bucket_i (lb0,
					    (vnet_buffer (p0)->ip.flow_hash &
					     lb0->lb_n_buckets_minus_1));
	  next0 = dpo0->dpoi_next_node;

	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
	    }
	  vnet_buffer (p0)->ip.adj_index = dpo0->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));

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
    ip6_forward_next_trace (vm, node, frame);

  return frame->n_vectors;
}

#endif /*__included_ip6_forward_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
