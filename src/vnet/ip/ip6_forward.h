/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip6_forward.h: IP v6 forwarding */

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
  clib_thread_index_t thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0, p1;
	  ip6_header_t *ip0;
	  u32 pi0, lbi0;
	  ip_lookup_next_t next0;
	  load_balance_t *lb0;
	  ip6_address_t *dst_addr0;
	  u32 flow_hash_config0;
	  const dpo_id_t *dpo0;

	  /* Prefetch next iteration. */
	  if (n_left_from > 1 && n_left_to_next > 1)
	    {
	      p1 = vlib_get_buffer (vm, from[1]);
	      vlib_prefetch_buffer_header (p1, LOAD);
	      CLIB_PREFETCH (p1->data, sizeof (ip0[0]), LOAD);
	    }

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

	  next0 = dpo0->dpoi_next_node;

	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
	    }
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

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
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

#endif /*__included_ip6_forward_h__ */
