/*
 * decap.c - decapsulate VXLAN GPE
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
/**
 *  @file
 *  @brief Functions for decapsulating VXLAN GPE tunnels
 *
*/

#include <vlib/vlib.h>
#include <vnet/udp/udp_local.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>

/**
 * @brief Struct for VXLAN GPE decap packet tracing
 *
 */
typedef struct
{
  u32 next_index;
  u32 tunnel_index;
  u32 error;
} vxlan_gpe_rx_trace_t;

/**
 * @brief Tracing function for VXLAN GPE packet decapsulation
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 *
format_vxlan_gpe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_rx_trace_t *t = va_arg (*args, vxlan_gpe_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "VXLAN-GPE: tunnel %d next %d error %d", t->tunnel_index,
		  t->next_index, t->error);
    }
  else
    {
      s = format (s, "VXLAN-GPE: no tunnel next %d error %d\n", t->next_index,
		  t->error);
    }
  return s;
}

/**
 * @brief Tracing function for VXLAN GPE packet decapsulation including length
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 *
format_vxlan_gpe_with_length (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);


  return s;
}

/**
 * @brief Common processing for IPv4 and IPv6 VXLAN GPE decap dispatch functions
 *
 * It is worth noting that other than trivial UDP forwarding (transit), VXLAN GPE
 * tunnels are "terminate local". This means that there is no "TX" interface for this
 * decap case, so that field in the buffer_metadata can be "used for something else".
 * The something else in this case is, for the IPv4/IPv6 inner-packet type case, the
 * FIB index used to look up the inner-packet's adjacency.
 *
 *      vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;
 *
 * @param *vm
 * @param *node
 * @param *from_frame
 * @param is_ip4
 *
 * @return from_frame->n_vectors
 *
 */
always_inline uword
vxlan_gpe_input (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  vxlan_gpe_main_t *nngm = &vxlan_gpe_main;
  vnet_main_t *vnm = nngm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 last_tunnel_index = ~0;
  vxlan4_gpe_tunnel_key_t last_key4;
  vxlan6_gpe_tunnel_key_t last_key6;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vm->thread_index;
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  if (is_ip4)
    clib_memset (&last_key4, 0xff, sizeof (last_key4));
  else
    clib_memset (&last_key6, 0xff, sizeof (last_key6));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  ip4_vxlan_gpe_header_t *iuvn4_0, *iuvn4_1;
	  ip6_vxlan_gpe_header_t *iuvn6_0, *iuvn6_1;
	  uword *p0, *p1;
	  u32 tunnel_index0, tunnel_index1;
	  vxlan_gpe_tunnel_t *t0, *t1;
	  vxlan4_gpe_tunnel_key_t key4_0, key4_1;
	  vxlan6_gpe_tunnel_key_t key6_0, key6_1;
	  u32 error0, error1;
	  u32 sw_if_index0, sw_if_index1, len0, len1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  if (is_ip4)
	    {
	      /* udp leaves current_data pointing at the vxlan-gpe header */
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));
	      vlib_buffer_advance (b1,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));

	      iuvn4_0 = vlib_buffer_get_current (b0);
	      iuvn4_1 = vlib_buffer_get_current (b1);

	      /* pop (ip, udp, vxlan) */
	      vlib_buffer_advance (b0, sizeof (*iuvn4_0));
	      vlib_buffer_advance (b1, sizeof (*iuvn4_1));
	    }
	  else
	    {
	      /* udp leaves current_data pointing at the vxlan-gpe header */
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));
	      vlib_buffer_advance (b1,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));

	      iuvn6_0 = vlib_buffer_get_current (b0);
	      iuvn6_1 = vlib_buffer_get_current (b1);

	      /* pop (ip, udp, vxlan) */
	      vlib_buffer_advance (b0, sizeof (*iuvn6_0));
	      vlib_buffer_advance (b1, sizeof (*iuvn6_1));
	    }

	  tunnel_index0 = ~0;
	  tunnel_index1 = ~0;
	  error0 = 0;
	  error1 = 0;

	  if (is_ip4)
	    {
	      next0 =
		(iuvn4_0->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn4_0->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;
	      next1 =
		(iuvn4_1->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn4_1->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;

	      key4_0.local = iuvn4_0->ip4.dst_address.as_u32;
	      key4_1.local = iuvn4_1->ip4.dst_address.as_u32;

	      key4_0.remote = iuvn4_0->ip4.src_address.as_u32;
	      key4_1.remote = iuvn4_1->ip4.src_address.as_u32;

	      key4_0.vni = iuvn4_0->vxlan.vni_res;
	      key4_1.vni = iuvn4_1->vxlan.vni_res;

	      key4_0.pad = 0;
	      key4_1.pad = 0;
	    }
	  else			/* is_ip6 */
	    {
	      next0 = (iuvn6_0->vxlan.protocol < node->n_next_nodes) ?
		iuvn6_0->vxlan.protocol : VXLAN_GPE_INPUT_NEXT_DROP;
	      next1 = (iuvn6_1->vxlan.protocol < node->n_next_nodes) ?
		iuvn6_1->vxlan.protocol : VXLAN_GPE_INPUT_NEXT_DROP;

	      key6_0.local.as_u64[0] = iuvn6_0->ip6.dst_address.as_u64[0];
	      key6_0.local.as_u64[1] = iuvn6_0->ip6.dst_address.as_u64[1];
	      key6_1.local.as_u64[0] = iuvn6_1->ip6.dst_address.as_u64[0];
	      key6_1.local.as_u64[1] = iuvn6_1->ip6.dst_address.as_u64[1];

	      key6_0.remote.as_u64[0] = iuvn6_0->ip6.src_address.as_u64[0];
	      key6_0.remote.as_u64[1] = iuvn6_0->ip6.src_address.as_u64[1];
	      key6_1.remote.as_u64[0] = iuvn6_1->ip6.src_address.as_u64[0];
	      key6_1.remote.as_u64[1] = iuvn6_1->ip6.src_address.as_u64[1];

	      key6_0.vni = iuvn6_0->vxlan.vni_res;
	      key6_1.vni = iuvn6_1->vxlan.vni_res;
	    }

	  /* Processing packet 0 */
	  if (is_ip4)
	    {
	      /* Processing for key4_0 */
	      if (PREDICT_FALSE ((key4_0.as_u64[0] != last_key4.as_u64[0])
				 || (key4_0.as_u64[1] !=
				     last_key4.as_u64[1])))
		{
		  p0 = hash_get_mem (nngm->vxlan4_gpe_tunnel_by_key, &key4_0);

		  if (p0 == 0)
		    {
		      error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace0;
		    }

		  last_key4.as_u64[0] = key4_0.as_u64[0];
		  last_key4.as_u64[1] = key4_0.as_u64[1];
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	    }
	  else			/* is_ip6 */
	    {
	      next0 =
		(iuvn6_0->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn6_0->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;
	      next1 =
		(iuvn6_1->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn6_1->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;

	      key6_0.local.as_u64[0] = iuvn6_0->ip6.dst_address.as_u64[0];
	      key6_0.local.as_u64[1] = iuvn6_0->ip6.dst_address.as_u64[1];
	      key6_1.local.as_u64[0] = iuvn6_1->ip6.dst_address.as_u64[0];
	      key6_1.local.as_u64[1] = iuvn6_1->ip6.dst_address.as_u64[1];

	      key6_0.remote.as_u64[0] = iuvn6_0->ip6.src_address.as_u64[0];
	      key6_0.remote.as_u64[1] = iuvn6_0->ip6.src_address.as_u64[1];
	      key6_1.remote.as_u64[0] = iuvn6_1->ip6.src_address.as_u64[0];
	      key6_1.remote.as_u64[1] = iuvn6_1->ip6.src_address.as_u64[1];

	      key6_0.vni = iuvn6_0->vxlan.vni_res;
	      key6_1.vni = iuvn6_1->vxlan.vni_res;

	      /* Processing for key6_0 */
	      if (PREDICT_FALSE
		  (memcmp (&key6_0, &last_key6, sizeof (last_key6)) != 0))
		{
		  p0 = hash_get_mem (nngm->vxlan6_gpe_tunnel_by_key, &key6_0);

		  if (p0 == 0)
		    {
		      error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace0;
		    }

		  memcpy (&last_key6, &key6_0, sizeof (key6_0));
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	    }

	  t0 = pool_elt_at_index (nngm->tunnels, tunnel_index0);


	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b0);

	  /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = t0->sw_if_index;

      /**
       * ip[46] lookup in the configured FIB
       */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (im->combined_sw_if_counters +
						 VNET_INTERFACE_COUNTER_RX,
						 thread_index,
						 stats_sw_if_index,
						 stats_n_packets,
						 stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

	trace0:b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_rx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->tunnel_index = tunnel_index0;
	    }

	  /* Process packet 1 */
	  if (is_ip4)
	    {
	      /* Processing for key4_1 */
	      if (PREDICT_FALSE ((key4_1.as_u64[0] != last_key4.as_u64[0])
				 || (key4_1.as_u64[1] !=
				     last_key4.as_u64[1])))
		{
		  p1 = hash_get_mem (nngm->vxlan4_gpe_tunnel_by_key, &key4_1);

		  if (p1 == 0)
		    {
		      error1 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace1;
		    }

		  last_key4.as_u64[0] = key4_1.as_u64[0];
		  last_key4.as_u64[1] = key4_1.as_u64[1];
		  tunnel_index1 = last_tunnel_index = p1[0];
		}
	      else
		tunnel_index1 = last_tunnel_index;
	    }
	  else			/* is_ip6 */
	    {
	      /* Processing for key6_1 */
	      if (PREDICT_FALSE
		  (memcmp (&key6_1, &last_key6, sizeof (last_key6)) != 0))
		{
		  p1 = hash_get_mem (nngm->vxlan6_gpe_tunnel_by_key, &key6_1);

		  if (p1 == 0)
		    {
		      error1 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace1;
		    }

		  memcpy (&last_key6, &key6_1, sizeof (key6_1));
		  tunnel_index1 = last_tunnel_index = p1[0];
		}
	      else
		tunnel_index1 = last_tunnel_index;
	    }

	  t1 = pool_elt_at_index (nngm->tunnels, tunnel_index1);

	  sw_if_index1 = t1->sw_if_index;
	  len1 = vlib_buffer_length_in_chain (vm, b1);

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b1);

	  /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = t1->sw_if_index;

	  /*
	   * ip[46] lookup in the configured FIB
	   */
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len1;

	  /* Batch stats increment on the same vxlan tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index1 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len1;
	      if (stats_n_packets)
		vlib_increment_combined_counter (im->combined_sw_if_counters +
						 VNET_INTERFACE_COUNTER_RX,
						 thread_index,
						 stats_sw_if_index,
						 stats_n_packets,
						 stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len1;
	      stats_sw_if_index = sw_if_index1;
	    }
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;

	trace1:b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_rx_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->next_index = next1;
	      tr->error = error1;
	      tr->tunnel_index = tunnel_index1;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip4_vxlan_gpe_header_t *iuvn4_0;
	  ip6_vxlan_gpe_header_t *iuvn6_0;
	  uword *p0;
	  u32 tunnel_index0;
	  vxlan_gpe_tunnel_t *t0;
	  vxlan4_gpe_tunnel_key_t key4_0;
	  vxlan6_gpe_tunnel_key_t key6_0;
	  u32 error0;
	  u32 sw_if_index0, len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_ip4)
	    {
	      /* udp leaves current_data pointing at the vxlan-gpe header */
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip4_header_t)));

	      iuvn4_0 = vlib_buffer_get_current (b0);

	      /* pop (ip, udp, vxlan) */
	      vlib_buffer_advance (b0, sizeof (*iuvn4_0));
	    }
	  else
	    {
	      /* udp leaves current_data pointing at the vxlan-gpe header */
	      vlib_buffer_advance (b0,
				   -(word) (sizeof (udp_header_t) +
					    sizeof (ip6_header_t)));

	      iuvn6_0 = vlib_buffer_get_current (b0);

	      /* pop (ip, udp, vxlan) */
	      vlib_buffer_advance (b0, sizeof (*iuvn6_0));
	    }

	  tunnel_index0 = ~0;
	  error0 = 0;

	  if (is_ip4)
	    {
	      next0 =
		(iuvn4_0->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn4_0->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;

	      key4_0.local = iuvn4_0->ip4.dst_address.as_u32;
	      key4_0.remote = iuvn4_0->ip4.src_address.as_u32;
	      key4_0.vni = iuvn4_0->vxlan.vni_res;
	      key4_0.pad = 0;

	      /* Processing for key4_0 */
	      if (PREDICT_FALSE ((key4_0.as_u64[0] != last_key4.as_u64[0])
				 || (key4_0.as_u64[1] !=
				     last_key4.as_u64[1])))
		{
		  p0 = hash_get_mem (nngm->vxlan4_gpe_tunnel_by_key, &key4_0);

		  if (p0 == 0)
		    {
		      error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace00;
		    }

		  last_key4.as_u64[0] = key4_0.as_u64[0];
		  last_key4.as_u64[1] = key4_0.as_u64[1];
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	    }
	  else			/* is_ip6 */
	    {
	      next0 =
		(iuvn6_0->vxlan.protocol < VXLAN_GPE_PROTOCOL_MAX) ?
		nngm->decap_next_node_list[iuvn6_0->vxlan.protocol] :
		VXLAN_GPE_INPUT_NEXT_DROP;

	      key6_0.local.as_u64[0] = iuvn6_0->ip6.dst_address.as_u64[0];
	      key6_0.local.as_u64[1] = iuvn6_0->ip6.dst_address.as_u64[1];
	      key6_0.remote.as_u64[0] = iuvn6_0->ip6.src_address.as_u64[0];
	      key6_0.remote.as_u64[1] = iuvn6_0->ip6.src_address.as_u64[1];
	      key6_0.vni = iuvn6_0->vxlan.vni_res;

	      /* Processing for key6_0 */
	      if (PREDICT_FALSE
		  (memcmp (&key6_0, &last_key6, sizeof (last_key6)) != 0))
		{
		  p0 = hash_get_mem (nngm->vxlan6_gpe_tunnel_by_key, &key6_0);

		  if (p0 == 0)
		    {
		      error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
		      goto trace00;
		    }

		  memcpy (&last_key6, &key6_0, sizeof (key6_0));
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	    }

	  t0 = pool_elt_at_index (nngm->tunnels, tunnel_index0);


	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b0);

	  /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = t0->sw_if_index;

	  /*
	   * ip[46] lookup in the configured FIB
	   */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same vxlan-gpe tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (im->combined_sw_if_counters +
						 VNET_INTERFACE_COUNTER_RX,
						 thread_index,
						 stats_sw_if_index,
						 stats_n_packets,
						 stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

	trace00:b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_rx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->tunnel_index = tunnel_index0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm,
			       is_ip4 ? vxlan4_gpe_input_node.index :
			       vxlan6_gpe_input_node.index,
			       VXLAN_GPE_ERROR_DECAPSULATED,
			       pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_RX,
				       thread_index, stats_sw_if_index,
				       stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }
  return from_frame->n_vectors;
}

/**
 * @brief Graph processing dispatch function for IPv4 VXLAN GPE
 *
 * @node vxlan4-gpe-input
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
VLIB_NODE_FN (vxlan4_gpe_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return vxlan_gpe_input (vm, node, from_frame, /* is_ip4 */ 1);
}

#ifndef CLIB_MARCH_VARIANT
void
vxlan_gpe_register_decap_protocol (u8 protocol_id, uword next_node_index)
{
  vxlan_gpe_main_t *hm = &vxlan_gpe_main;
  hm->decap_next_node_list[protocol_id] = next_node_index;
  return;
}

void
vxlan_gpe_unregister_decap_protocol (u8 protocol_id, uword next_node_index)
{
  vxlan_gpe_main_t *hm = &vxlan_gpe_main;
  hm->decap_next_node_list[protocol_id] = VXLAN_GPE_INPUT_NEXT_DROP;
  return;
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief Graph processing dispatch function for IPv6 VXLAN GPE
 *
 * @node vxlan6-gpe-input
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors - uword
 *
 */
VLIB_NODE_FN (vxlan6_gpe_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return vxlan_gpe_input (vm, node, from_frame, /* is_ip4 */ 0);
}

/**
 * @brief VXLAN GPE error strings
 */
static char *vxlan_gpe_error_strings[] = {
#define vxlan_gpe_error(n,s) s,
#include <vnet/vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan4_gpe_input_node) = {
  .name = "vxlan4-gpe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vxlan_gpe_error_strings),
  .error_strings = vxlan_gpe_error_strings,

  .n_next_nodes = VXLAN_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_GPE_INPUT_NEXT_##s] = n,
    foreach_vxlan_gpe_input_next
#undef _
  },

  .format_buffer = format_vxlan_gpe_with_length,
  .format_trace = format_vxlan_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_vxlan_gpe_header,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan6_gpe_input_node) = {
  .name = "vxlan6-gpe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vxlan_gpe_error_strings),
  .error_strings = vxlan_gpe_error_strings,

  .n_next_nodes = VXLAN_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_GPE_INPUT_NEXT_##s] = n,
    foreach_vxlan_gpe_input_next
#undef _
  },

  .format_buffer = format_vxlan_gpe_with_length,
  .format_trace = format_vxlan_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_vxlan_gpe_header,
};
/* *INDENT-ON* */

typedef enum
{
  IP_VXLAN_BYPASS_NEXT_DROP,
  IP_VXLAN_BYPASS_NEXT_VXLAN,
  IP_VXLAN_BYPASS_N_NEXT,
} ip_vxlan_bypass_next_t;

always_inline uword
ip_vxlan_gpe_bypass_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame, u32 is_ip4)
{
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  vtep4_key_t last_vtep4;	/* last IPv4 address / fib index
				   matching a local VTEP address */
  vtep6_key_t last_vtep6;	/* last IPv6 address / fib index
				   matching a local VTEP address */
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  if (is_ip4)
    vtep4_key_init (&last_vtep4);
  else
    vtep6_key_init (&last_vtep6);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  udp_header_t *udp0, *udp1;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  u32 bi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, good_udp0, proto0;
	  u8 error1, good_udp1, proto1;

	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = b[0];
	  b1 = b[1];
	  b += 2;
	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      ip41 = vlib_buffer_get_current (b1);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      ip61 = vlib_buffer_get_current (b1);
	    }

	  /* Setup packet for next IP feature */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  if (is_ip4)
	    {
	      proto0 = ip40->protocol;
	      proto1 = ip41->protocol;
	    }
	  else
	    {
	      proto0 = ip60->protocol;
	      proto1 = ip61->protocol;
	    }

	  /* Process packet 0 */
	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit0;		/* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE))
	    goto exit0;		/* not VXLAN packet */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&ngm->vtep_table, b0, ip40, &last_vtep4,
				       &ngm->vtep4_u512))
#else
	      if (!vtep4_check (&ngm->vtep_table, b0, ip40, &last_vtep4))
#endif
		goto exit0;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&ngm->vtep_table, b0, ip60, &last_vtep6))
		goto exit0;	/* no local VTEP for VXLAN packet */
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan_gpe-input node expect current at VXLAN header */
	  if (is_ip4)
	    vlib_buffer_advance (b0,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b0,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit0:
	  /* Process packet 1 */
	  if (proto1 != IP_PROTOCOL_UDP)
	    goto exit1;		/* not UDP packet */

	  if (is_ip4)
	    udp1 = ip4_next_header (ip41);
	  else
	    udp1 = ip6_next_header (ip61);

	  if (udp1->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE))
	    goto exit1;		/* not VXLAN packet */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&ngm->vtep_table, b1, ip41, &last_vtep4,
				       &ngm->vtep4_u512))
#else
	      if (!vtep4_check (&ngm->vtep_table, b1, ip41, &last_vtep4))
#endif
		goto exit1;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&ngm->vtep_table, b1, ip61, &last_vtep6))
		goto exit1;	/* no local VTEP for VXLAN packet */
	    }

	  flags1 = b1->flags;
	  good_udp1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp1 |= udp1->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len1 = clib_net_to_host_u16 (ip41->length);
	  else
	    ip_len1 = clib_net_to_host_u16 (ip61->payload_length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);
	  len_diff1 = ip_len1 - udp_len1;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp1))
	    {
	      if ((flags1 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
		  else
		    flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);
		  good_udp1 =
		    (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error1 = good_udp1 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error1 = good_udp1 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP6_ERROR_UDP_LENGTH;
	    }

	  next1 = error1 ?
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b1->error = error1 ? error_node->errors[error1] : 0;

	  /* vxlan_gpe-input node expect current at VXLAN header */
	  if (is_ip4)
	    vlib_buffer_advance (b1,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b1,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit1:
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  udp_header_t *udp0;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, good_udp0, proto0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = b[0];
	  b++;
	  if (is_ip4)
	    ip40 = vlib_buffer_get_current (b0);
	  else
	    ip60 = vlib_buffer_get_current (b0);

	  /* Setup packet for next IP feature */
	  vnet_feature_next (&next0, b0);

	  if (is_ip4)
	    proto0 = ip40->protocol;
	  else
	    proto0 = ip60->protocol;

	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit;		/* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE))
	    goto exit;		/* not VXLAN packet */

	  /* Validate DIP against VTEPs */

	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&ngm->vtep_table, b0, ip40, &last_vtep4,
				       &ngm->vtep4_u512))
#else
	      if (!vtep4_check (&ngm->vtep_table, b0, ip40, &last_vtep4))
#endif
		goto exit;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&ngm->vtep_table, b0, ip60, &last_vtep6))
		goto exit;	/* no local VTEP for VXLAN packet */
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan_gpe-input node expect current at VXLAN header */
	  if (is_ip4)
	    vlib_buffer_advance (b0,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b0,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_vxlan_gpe_bypass_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return ip_vxlan_gpe_bypass_inline (vm, node, frame, /* is_ip4 */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_vxlan_gpe_bypass_node) = {
  .name = "ip4-vxlan-gpe-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_VXLAN_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_VXLAN_BYPASS_NEXT_DROP] = "error-drop",
    [IP_VXLAN_BYPASS_NEXT_VXLAN] = "vxlan4-gpe-input",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t *
ip4_vxlan_gpe_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip4_vxlan_gpe_bypass_init);
#endif /* CLIB_MARCH_VARIANT */

VLIB_NODE_FN (ip6_vxlan_gpe_bypass_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return ip_vxlan_gpe_bypass_inline (vm, node, frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_vxlan_gpe_bypass_node) = {
  .name = "ip6-vxlan-gpe-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_VXLAN_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_VXLAN_BYPASS_NEXT_DROP] = "error-drop",
    [IP_VXLAN_BYPASS_NEXT_VXLAN] = "vxlan6-gpe-input",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t *
ip6_vxlan_gpe_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip6_vxlan_gpe_bypass_init);
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
