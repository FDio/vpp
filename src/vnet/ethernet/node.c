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
 * ethernet_node.c: ethernet packet processing
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/p2p_ethernet.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/l2/l2_bvi.h>


#define foreach_ethernet_input_next		\
  _ (PUNT, "error-punt")			\
  _ (DROP, "error-drop")			\
  _ (LLC, "llc-input")

typedef enum
{
#define _(s,n) ETHERNET_INPUT_NEXT_##s,
  foreach_ethernet_input_next
#undef _
    ETHERNET_INPUT_N_NEXT,
} ethernet_input_next_t;

typedef struct
{
  u8 packet_data[32];
} ethernet_input_trace_t;

static u8 *
format_ethernet_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_input_trace_t *t = va_arg (*va, ethernet_input_trace_t *);

  s = format (s, "%U", format_ethernet_header, t->packet_data);

  return s;
}

vlib_node_registration_t ethernet_input_node;

typedef enum
{
  ETHERNET_INPUT_VARIANT_ETHERNET,
  ETHERNET_INPUT_VARIANT_ETHERNET_TYPE,
  ETHERNET_INPUT_VARIANT_NOT_L2,
} ethernet_input_variant_t;


// Parse the ethernet header to extract vlan tags and innermost ethertype
static_always_inline void
parse_header (ethernet_input_variant_t variant,
	      vlib_buffer_t * b0,
	      u16 * type,
	      u16 * orig_type,
	      u16 * outer_id, u16 * inner_id, u32 * match_flags)
{
  u8 vlan_count;

  if (variant == ETHERNET_INPUT_VARIANT_ETHERNET
      || variant == ETHERNET_INPUT_VARIANT_NOT_L2)
    {
      ethernet_header_t *e0;

      e0 = (void *) (b0->data + b0->current_data);

      vnet_buffer (b0)->l2_hdr_offset = b0->current_data;

      vlib_buffer_advance (b0, sizeof (e0[0]));

      *type = clib_net_to_host_u16 (e0->type);
    }
  else if (variant == ETHERNET_INPUT_VARIANT_ETHERNET_TYPE)
    {
      // here when prior node was LLC/SNAP processing
      u16 *e0;

      e0 = (void *) (b0->data + b0->current_data);

      vlib_buffer_advance (b0, sizeof (e0[0]));

      *type = clib_net_to_host_u16 (e0[0]);
    }

  // save for distinguishing between dot1q and dot1ad later
  *orig_type = *type;

  // default the tags to 0 (used if there is no corresponding tag)
  *outer_id = 0;
  *inner_id = 0;

  *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_0_TAG;
  vlan_count = 0;

  // check for vlan encaps
  if (ethernet_frame_is_tagged (*type))
    {
      ethernet_vlan_header_t *h0;
      u16 tag;

      *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_1_TAG;

      h0 = (void *) (b0->data + b0->current_data);

      tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);

      *outer_id = tag & 0xfff;
      if (0 == *outer_id)
	*match_flags &= ~SUBINT_CONFIG_MATCH_1_TAG;

      *type = clib_net_to_host_u16 (h0->type);

      vlib_buffer_advance (b0, sizeof (h0[0]));
      vlan_count = 1;

      if (*type == ETHERNET_TYPE_VLAN)
	{
	  // Double tagged packet
	  *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_2_TAG;

	  h0 = (void *) (b0->data + b0->current_data);

	  tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);

	  *inner_id = tag & 0xfff;

	  *type = clib_net_to_host_u16 (h0->type);

	  vlib_buffer_advance (b0, sizeof (h0[0]));
	  vlan_count = 2;
	  if (*type == ETHERNET_TYPE_VLAN)
	    {
	      // More than double tagged packet
	      *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_3_TAG;

	      vlib_buffer_advance (b0, sizeof (h0[0]));
	      vlan_count = 3;	// "unknown" number, aka, 3-or-more
	    }
	}
    }
  ethernet_buffer_set_vlan_count (b0, vlan_count);
}

// Determine the subinterface for this packet, given the result of the
// vlan table lookups and vlan header parsing. Check the most specific
// matches first.
static_always_inline void
identify_subint (vnet_hw_interface_t * hi,
		 vlib_buffer_t * b0,
		 u32 match_flags,
		 main_intf_t * main_intf,
		 vlan_intf_t * vlan_intf,
		 qinq_intf_t * qinq_intf,
		 u32 * new_sw_if_index, u8 * error0, u32 * is_l2)
{
  u32 matched;

  matched = eth_identify_subint (hi, b0, match_flags,
				 main_intf, vlan_intf, qinq_intf,
				 new_sw_if_index, error0, is_l2);

  if (matched)
    {

      // Perform L3 my-mac filter
      // A unicast packet arriving on an L3 interface must have a dmac matching the interface mac.
      // This is required for promiscuous mode, else we will forward packets we aren't supposed to.
      if (!(*is_l2))
	{
	  ethernet_header_t *e0;
	  e0 = (void *) (b0->data + vnet_buffer (b0)->l2_hdr_offset);

	  if (!(ethernet_address_cast (e0->dst_address)))
	    {
	      if (!eth_mac_equal ((u8 *) e0, hi->hw_address))
		{
		  *error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		}
	    }
	}

      // Check for down subinterface
      *error0 = (*new_sw_if_index) != ~0 ? (*error0) : ETHERNET_ERROR_DOWN;
    }
}

static_always_inline void
determine_next_node (ethernet_main_t * em,
		     ethernet_input_variant_t variant,
		     u32 is_l20,
		     u32 type0, vlib_buffer_t * b0, u8 * error0, u8 * next0)
{
  if (PREDICT_FALSE (*error0 != ETHERNET_ERROR_NONE))
    {
      // some error occurred
      *next0 = ETHERNET_INPUT_NEXT_DROP;
    }
  else if (is_l20)
    {
      *next0 = em->l2_next;
      // record the L2 len and reset the buffer so the L2 header is preserved
      u32 eth_start = vnet_buffer (b0)->l2_hdr_offset;
      vnet_buffer (b0)->l2.l2_len = b0->current_data - eth_start;
      ASSERT (vnet_buffer (b0)->l2.l2_len ==
	      ethernet_buffer_header_size (b0));
      vlib_buffer_advance (b0, -ethernet_buffer_header_size (b0));

      // check for common IP/MPLS ethertypes
    }
  else if (type0 == ETHERNET_TYPE_IP4)
    {
      *next0 = em->l3_next.input_next_ip4;
    }
  else if (type0 == ETHERNET_TYPE_IP6)
    {
      *next0 = em->l3_next.input_next_ip6;
    }
  else if (type0 == ETHERNET_TYPE_MPLS)
    {
      *next0 = em->l3_next.input_next_mpls;

    }
  else if (em->redirect_l3)
    {
      // L3 Redirect is on, the cached common next nodes will be
      // pointing to the redirect node, catch the uncommon types here
      *next0 = em->redirect_l3_next;
    }
  else
    {
      // uncommon ethertype, check table
      u32 i0;
      i0 = sparse_vec_index (em->l3_next.input_next_by_type, type0);
      *next0 = vec_elt (em->l3_next.input_next_by_type, i0);
      *error0 =
	i0 ==
	SPARSE_VEC_INVALID_INDEX ? ETHERNET_ERROR_UNKNOWN_TYPE : *error0;

      // The table is not populated with LLC values, so check that now.
      // If variant is variant_ethernet then we came from LLC processing. Don't
      // go back there; drop instead using by keeping the drop/bad table result.
      if ((type0 < 0x600) && (variant == ETHERNET_INPUT_VARIANT_ETHERNET))
	{
	  *next0 = ETHERNET_INPUT_NEXT_LLC;
	}
    }
}

static_always_inline int
ethernet_frame_is_any_tagged (u16 type0, u16 type1)
{
#if __SSE4_2__
  const __m128i ethertype_mask = _mm_set_epi16 (ETHERNET_TYPE_VLAN,
						ETHERNET_TYPE_DOT1AD,
						ETHERNET_TYPE_VLAN_9100,
						ETHERNET_TYPE_VLAN_9200,
						/* duplicate for type1 */
						ETHERNET_TYPE_VLAN,
						ETHERNET_TYPE_DOT1AD,
						ETHERNET_TYPE_VLAN_9100,
						ETHERNET_TYPE_VLAN_9200);

  __m128i r =
    _mm_set_epi16 (type0, type0, type0, type0, type1, type1, type1, type1);
  r = _mm_cmpeq_epi16 (ethertype_mask, r);
  return !_mm_test_all_zeros (r, r);
#else
  return ethernet_frame_is_tagged (type0) || ethernet_frame_is_tagged (type1);
#endif
}

static_always_inline uword
ethernet_input_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame,
		       ethernet_input_variant_t variant)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_main_t *em = &ethernet_main;
  vlib_node_runtime_t *error_node;
  u32 n_left_from, next_index, *from, *to_next;
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 thread_index = vlib_get_thread_index ();
  u32 cached_sw_if_index = ~0;
  u32 cached_is_l2 = 0;		/* shut up gcc */
  vnet_hw_interface_t *hi = NULL;	/* used for main interface only */

  if (variant != ETHERNET_INPUT_VARIANT_ETHERNET)
    error_node = vlib_node_get_runtime (vm, ethernet_input_node.index);
  else
    error_node = node;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (ethernet_input_trace_t));

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
	  u8 next0, next1, error0, error1;
	  u16 type0, orig_type0, type1, orig_type1;
	  u16 outer_id0, inner_id0, outer_id1, inner_id1;
	  u32 match_flags0, match_flags1;
	  u32 old_sw_if_index0, new_sw_if_index0, len0, old_sw_if_index1,
	    new_sw_if_index1, len1;
	  vnet_hw_interface_t *hi0, *hi1;
	  main_intf_t *main_intf0, *main_intf1;
	  vlan_intf_t *vlan_intf0, *vlan_intf1;
	  qinq_intf_t *qinq_intf0, *qinq_intf1;
	  u32 is_l20, is_l21;
	  ethernet_header_t *e0, *e1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, STORE);
	    vlib_prefetch_buffer_header (b3, STORE);

	    CLIB_PREFETCH (b2->data, sizeof (ethernet_header_t), LOAD);
	    CLIB_PREFETCH (b3->data, sizeof (ethernet_header_t), LOAD);
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

	  error0 = error1 = ETHERNET_ERROR_NONE;
	  e0 = vlib_buffer_get_current (b0);
	  type0 = clib_net_to_host_u16 (e0->type);
	  e1 = vlib_buffer_get_current (b1);
	  type1 = clib_net_to_host_u16 (e1->type);

	  /* Speed-path for the untagged case */
	  if (PREDICT_TRUE (variant == ETHERNET_INPUT_VARIANT_ETHERNET
			    && !ethernet_frame_is_any_tagged (type0, type1)))
	    {
	      main_intf_t *intf0;
	      subint_config_t *subint0;
	      u32 sw_if_index0, sw_if_index1;

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      is_l20 = cached_is_l2;

	      /* This is probably wholly unnecessary */
	      if (PREDICT_FALSE (sw_if_index0 != sw_if_index1))
		goto slowpath;

	      /* Now sw_if_index0 == sw_if_index1  */
	      if (PREDICT_FALSE (cached_sw_if_index != sw_if_index0))
		{
		  cached_sw_if_index = sw_if_index0;
		  hi = vnet_get_sup_hw_interface (vnm, sw_if_index0);
		  intf0 = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
		  subint0 = &intf0->untagged_subint;
		  cached_is_l2 = is_l20 = subint0->flags & SUBINT_CONFIG_L2;
		}

	      vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
	      vnet_buffer (b1)->l2_hdr_offset = b1->current_data;

	      if (PREDICT_TRUE (is_l20 != 0))
		{
		  next0 = em->l2_next;
		  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
		  next1 = em->l2_next;
		  vnet_buffer (b1)->l2.l2_len = sizeof (ethernet_header_t);
		}
	      else
		{
		  if (!ethernet_address_cast (e0->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e0, hi->hw_address))
		    error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  if (!ethernet_address_cast (e1->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e1, hi->hw_address))
		    error1 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  determine_next_node (em, variant, 0, type0, b0,
				       &error0, &next0);
		  vlib_buffer_advance (b0, sizeof (ethernet_header_t));
		  determine_next_node (em, variant, 0, type1, b1,
				       &error1, &next1);
		  vlib_buffer_advance (b1, sizeof (ethernet_header_t));
		}
	      goto ship_it01;
	    }

	  /* Slow-path for the tagged case */
	slowpath:
	  parse_header (variant,
			b0,
			&type0,
			&orig_type0, &outer_id0, &inner_id0, &match_flags0);

	  parse_header (variant,
			b1,
			&type1,
			&orig_type1, &outer_id1, &inner_id1, &match_flags1);

	  old_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  old_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index0,
				  orig_type0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index1,
				  orig_type1,
				  outer_id1,
				  inner_id1,
				  &hi1,
				  &main_intf1, &vlan_intf1, &qinq_intf1);

	  identify_subint (hi0,
			   b0,
			   match_flags0,
			   main_intf0,
			   vlan_intf0,
			   qinq_intf0, &new_sw_if_index0, &error0, &is_l20);

	  identify_subint (hi1,
			   b1,
			   match_flags1,
			   main_intf1,
			   vlan_intf1,
			   qinq_intf1, &new_sw_if_index1, &error1, &is_l21);

	  // Save RX sw_if_index for later nodes
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    error0 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index0 : new_sw_if_index0;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] =
	    error1 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index1 : new_sw_if_index1;

	  // Check if there is a stat to take (valid and non-main sw_if_index for pkt 0 or pkt 1)
	  if (((new_sw_if_index0 != ~0)
	       && (new_sw_if_index0 != old_sw_if_index0))
	      || ((new_sw_if_index1 != ~0)
		  && (new_sw_if_index1 != old_sw_if_index1)))
	    {

	      len0 = vlib_buffer_length_in_chain (vm, b0) + b0->current_data
		- vnet_buffer (b0)->l2_hdr_offset;
	      len1 = vlib_buffer_length_in_chain (vm, b1) + b1->current_data
		- vnet_buffer (b1)->l2_hdr_offset;

	      stats_n_packets += 2;
	      stats_n_bytes += len0 + len1;

	      if (PREDICT_FALSE
		  (!(new_sw_if_index0 == stats_sw_if_index
		     && new_sw_if_index1 == stats_sw_if_index)))
		{
		  stats_n_packets -= 2;
		  stats_n_bytes -= len0 + len1;

		  if (new_sw_if_index0 != old_sw_if_index0
		      && new_sw_if_index0 != ~0)
		    vlib_increment_combined_counter (vnm->
						     interface_main.combined_sw_if_counters
						     +
						     VNET_INTERFACE_COUNTER_RX,
						     thread_index,
						     new_sw_if_index0, 1,
						     len0);
		  if (new_sw_if_index1 != old_sw_if_index1
		      && new_sw_if_index1 != ~0)
		    vlib_increment_combined_counter (vnm->
						     interface_main.combined_sw_if_counters
						     +
						     VNET_INTERFACE_COUNTER_RX,
						     thread_index,
						     new_sw_if_index1, 1,
						     len1);

		  if (new_sw_if_index0 == new_sw_if_index1)
		    {
		      if (stats_n_packets > 0)
			{
			  vlib_increment_combined_counter
			    (vnm->interface_main.combined_sw_if_counters
			     + VNET_INTERFACE_COUNTER_RX,
			     thread_index,
			     stats_sw_if_index,
			     stats_n_packets, stats_n_bytes);
			  stats_n_packets = stats_n_bytes = 0;
			}
		      stats_sw_if_index = new_sw_if_index0;
		    }
		}
	    }

	  if (variant == ETHERNET_INPUT_VARIANT_NOT_L2)
	    is_l20 = is_l21 = 0;

	  determine_next_node (em, variant, is_l20, type0, b0, &error0,
			       &next0);
	  determine_next_node (em, variant, is_l21, type1, b1, &error1,
			       &next1);

	ship_it01:
	  b0->error = error_node->errors[error0];
	  b1->error = error_node->errors[error1];

	  // verify speculative enqueue
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u8 error0, next0;
	  u16 type0, orig_type0;
	  u16 outer_id0, inner_id0;
	  u32 match_flags0;
	  u32 old_sw_if_index0, new_sw_if_index0, len0;
	  vnet_hw_interface_t *hi0;
	  main_intf_t *main_intf0;
	  vlan_intf_t *vlan_intf0;
	  qinq_intf_t *qinq_intf0;
	  ethernet_header_t *e0;
	  u32 is_l20;

	  // Prefetch next iteration
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *p2;

	      p2 = vlib_get_buffer (vm, from[1]);
	      vlib_prefetch_buffer_header (p2, STORE);
	      CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  error0 = ETHERNET_ERROR_NONE;
	  e0 = vlib_buffer_get_current (b0);
	  type0 = clib_net_to_host_u16 (e0->type);

	  /* Speed-path for the untagged case */
	  if (PREDICT_TRUE (variant == ETHERNET_INPUT_VARIANT_ETHERNET
			    && !ethernet_frame_is_tagged (type0)))
	    {
	      main_intf_t *intf0;
	      subint_config_t *subint0;
	      u32 sw_if_index0;

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      is_l20 = cached_is_l2;

	      if (PREDICT_FALSE (cached_sw_if_index != sw_if_index0))
		{
		  cached_sw_if_index = sw_if_index0;
		  hi = vnet_get_sup_hw_interface (vnm, sw_if_index0);
		  intf0 = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
		  subint0 = &intf0->untagged_subint;
		  cached_is_l2 = is_l20 = subint0->flags & SUBINT_CONFIG_L2;
		}

	      vnet_buffer (b0)->l2_hdr_offset = b0->current_data;

	      if (PREDICT_TRUE (is_l20 != 0))
		{
		  next0 = em->l2_next;
		  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
		}
	      else
		{
		  if (!ethernet_address_cast (e0->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e0, hi->hw_address))
		    error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  determine_next_node (em, variant, 0, type0, b0,
				       &error0, &next0);
		  vlib_buffer_advance (b0, sizeof (ethernet_header_t));
		}
	      goto ship_it0;
	    }

	  /* Slow-path for the tagged case */
	  parse_header (variant,
			b0,
			&type0,
			&orig_type0, &outer_id0, &inner_id0, &match_flags0);

	  old_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index0,
				  orig_type0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  identify_subint (hi0,
			   b0,
			   match_flags0,
			   main_intf0,
			   vlan_intf0,
			   qinq_intf0, &new_sw_if_index0, &error0, &is_l20);

	  // Save RX sw_if_index for later nodes
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    error0 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index0 : new_sw_if_index0;

	  // Increment subinterface stats
	  // Note that interface-level counters have already been incremented
	  // prior to calling this function. Thus only subinterface counters
	  // are incremented here.
	  //
	  // Interface level counters include packets received on the main
	  // interface and all subinterfaces. Subinterface level counters
	  // include only those packets received on that subinterface
	  // Increment stats if the subint is valid and it is not the main intf
	  if ((new_sw_if_index0 != ~0)
	      && (new_sw_if_index0 != old_sw_if_index0))
	    {

	      len0 = vlib_buffer_length_in_chain (vm, b0) + b0->current_data
		- vnet_buffer (b0)->l2_hdr_offset;

	      stats_n_packets += 1;
	      stats_n_bytes += len0;

	      // Batch stat increments from the same subinterface so counters
	      // don't need to be incremented for every packet.
	      if (PREDICT_FALSE (new_sw_if_index0 != stats_sw_if_index))
		{
		  stats_n_packets -= 1;
		  stats_n_bytes -= len0;

		  if (new_sw_if_index0 != ~0)
		    vlib_increment_combined_counter
		      (vnm->interface_main.combined_sw_if_counters
		       + VNET_INTERFACE_COUNTER_RX,
		       thread_index, new_sw_if_index0, 1, len0);
		  if (stats_n_packets > 0)
		    {
		      vlib_increment_combined_counter
			(vnm->interface_main.combined_sw_if_counters
			 + VNET_INTERFACE_COUNTER_RX,
			 thread_index,
			 stats_sw_if_index, stats_n_packets, stats_n_bytes);
		      stats_n_packets = stats_n_bytes = 0;
		    }
		  stats_sw_if_index = new_sw_if_index0;
		}
	    }

	  if (variant == ETHERNET_INPUT_VARIANT_NOT_L2)
	    is_l20 = 0;

	  determine_next_node (em, variant, is_l20, type0, b0, &error0,
			       &next0);

	ship_it0:
	  b0->error = error_node->errors[error0];

	  // verify speculative enqueue
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  // Increment any remaining batched stats
  if (stats_n_packets > 0)
    {
      vlib_increment_combined_counter
	(vnm->interface_main.combined_sw_if_counters
	 + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

static uword
ethernet_input (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return ethernet_input_inline (vm, node, from_frame,
				ETHERNET_INPUT_VARIANT_ETHERNET);
}

static uword
ethernet_input_type (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return ethernet_input_inline (vm, node, from_frame,
				ETHERNET_INPUT_VARIANT_ETHERNET_TYPE);
}

static uword
ethernet_input_not_l2 (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return ethernet_input_inline (vm, node, from_frame,
				ETHERNET_INPUT_VARIANT_NOT_L2);
}


// Return the subinterface config struct for the given sw_if_index
// Also return via parameter the appropriate match flags for the
// configured number of tags.
// On error (unsupported or not ethernet) return 0.
static subint_config_t *
ethernet_sw_interface_get_config (vnet_main_t * vnm,
				  u32 sw_if_index,
				  u32 * flags, u32 * unsupported)
{
  ethernet_main_t *em = &ethernet_main;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  main_intf_t *main_intf;
  vlan_table_t *vlan_table;
  qinq_table_t *qinq_table;
  subint_config_t *subint = 0;

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  if (!hi || (hi->hw_class_index != ethernet_hw_interface_class.index))
    {
      *unsupported = 0;
      goto done;		// non-ethernet interface
    }

  // ensure there's an entry for the main intf (shouldn't really be necessary)
  vec_validate (em->main_intfs, hi->hw_if_index);
  main_intf = vec_elt_at_index (em->main_intfs, hi->hw_if_index);

  // Locate the subint for the given ethernet config
  si = vnet_get_sw_interface (vnm, sw_if_index);

  if (si->type == VNET_SW_INTERFACE_TYPE_P2P)
    {
      p2p_ethernet_main_t *p2pm = &p2p_main;
      u32 p2pe_sw_if_index =
	p2p_ethernet_lookup (hi->hw_if_index, si->p2p.client_mac);
      if (p2pe_sw_if_index == ~0)
	{
	  pool_get (p2pm->p2p_subif_pool, subint);
	  si->p2p.pool_index = subint - p2pm->p2p_subif_pool;
	}
      else
	subint = vec_elt_at_index (p2pm->p2p_subif_pool, si->p2p.pool_index);
      *flags = SUBINT_CONFIG_P2P;
    }
  else if (si->sub.eth.flags.default_sub)
    {
      subint = &main_intf->default_subint;
      *flags = SUBINT_CONFIG_MATCH_0_TAG |
	SUBINT_CONFIG_MATCH_1_TAG |
	SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG;
    }
  else if ((si->sub.eth.flags.no_tags) || (si->sub.eth.raw_flags == 0))
    {
      // if no flags are set then this is a main interface
      // so treat as untagged
      subint = &main_intf->untagged_subint;
      *flags = SUBINT_CONFIG_MATCH_0_TAG;
    }
  else
    {
      // one or two tags
      // first get the vlan table
      if (si->sub.eth.flags.dot1ad)
	{
	  if (main_intf->dot1ad_vlans == 0)
	    {
	      // Allocate a vlan table from the pool
	      pool_get (em->vlan_pool, vlan_table);
	      main_intf->dot1ad_vlans = vlan_table - em->vlan_pool;
	    }
	  else
	    {
	      // Get ptr to existing vlan table
	      vlan_table =
		vec_elt_at_index (em->vlan_pool, main_intf->dot1ad_vlans);
	    }
	}
      else
	{			// dot1q
	  if (main_intf->dot1q_vlans == 0)
	    {
	      // Allocate a vlan table from the pool
	      pool_get (em->vlan_pool, vlan_table);
	      main_intf->dot1q_vlans = vlan_table - em->vlan_pool;
	    }
	  else
	    {
	      // Get ptr to existing vlan table
	      vlan_table =
		vec_elt_at_index (em->vlan_pool, main_intf->dot1q_vlans);
	    }
	}

      if (si->sub.eth.flags.one_tag)
	{
	  *flags = si->sub.eth.flags.exact_match ?
	    SUBINT_CONFIG_MATCH_1_TAG :
	    (SUBINT_CONFIG_MATCH_1_TAG |
	     SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG);

	  if (si->sub.eth.flags.outer_vlan_id_any)
	    {
	      // not implemented yet
	      *unsupported = 1;
	      goto done;
	    }
	  else
	    {
	      // a single vlan, a common case
	      subint =
		&vlan_table->vlans[si->sub.eth.
				   outer_vlan_id].single_tag_subint;
	    }

	}
      else
	{
	  // Two tags
	  *flags = si->sub.eth.flags.exact_match ?
	    SUBINT_CONFIG_MATCH_2_TAG :
	    (SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG);

	  if (si->sub.eth.flags.outer_vlan_id_any
	      && si->sub.eth.flags.inner_vlan_id_any)
	    {
	      // not implemented yet
	      *unsupported = 1;
	      goto done;
	    }

	  if (si->sub.eth.flags.inner_vlan_id_any)
	    {
	      // a specific outer and "any" inner
	      // don't need a qinq table for this
	      subint =
		&vlan_table->vlans[si->sub.eth.
				   outer_vlan_id].inner_any_subint;
	      if (si->sub.eth.flags.exact_match)
		{
		  *flags = SUBINT_CONFIG_MATCH_2_TAG;
		}
	      else
		{
		  *flags = SUBINT_CONFIG_MATCH_2_TAG |
		    SUBINT_CONFIG_MATCH_3_TAG;
		}
	    }
	  else
	    {
	      // a specific outer + specifc innner vlan id, a common case

	      // get the qinq table
	      if (vlan_table->vlans[si->sub.eth.outer_vlan_id].qinqs == 0)
		{
		  // Allocate a qinq table from the pool
		  pool_get (em->qinq_pool, qinq_table);
		  vlan_table->vlans[si->sub.eth.outer_vlan_id].qinqs =
		    qinq_table - em->qinq_pool;
		}
	      else
		{
		  // Get ptr to existing qinq table
		  qinq_table =
		    vec_elt_at_index (em->qinq_pool,
				      vlan_table->vlans[si->sub.
							eth.outer_vlan_id].
				      qinqs);
		}
	      subint = &qinq_table->vlans[si->sub.eth.inner_vlan_id].subint;
	    }
	}
    }

done:
  return subint;
}

clib_error_t *
ethernet_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;
  clib_error_t *error = 0;

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      // not implemented yet or not ethernet
      goto done;
    }

  subint->sw_if_index =
    ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? sw_if_index : ~0);

done:
  return error;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ethernet_sw_interface_up_down);


// Set the L2/L3 mode for the subinterface
void
ethernet_sw_interface_set_l2_mode (vnet_main_t * vnm, u32 sw_if_index, u32 l2)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;
  int is_port;
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  is_port = !(sw->type == VNET_SW_INTERFACE_TYPE_SUB);

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      // unimplemented or not ethernet
      goto done;
    }

  // Double check that the config we found is for our interface (or the interface is down)
  ASSERT ((subint->sw_if_index == sw_if_index) | (subint->sw_if_index == ~0));

  if (l2)
    {
      subint->flags |= SUBINT_CONFIG_L2;
      if (is_port)
	subint->flags |=
	  SUBINT_CONFIG_MATCH_0_TAG | SUBINT_CONFIG_MATCH_1_TAG
	  | SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG;
    }
  else
    {
      subint->flags &= ~SUBINT_CONFIG_L2;
      if (is_port)
	subint->flags &=
	  ~(SUBINT_CONFIG_MATCH_1_TAG | SUBINT_CONFIG_MATCH_2_TAG
	    | SUBINT_CONFIG_MATCH_3_TAG);
    }

done:
  return;
}

/*
 * Set the L2/L3 mode for the subinterface regardless of port
 */
void
ethernet_sw_interface_set_l2_mode_noport (vnet_main_t * vnm,
					  u32 sw_if_index, u32 l2)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;

  /* Find the config for this subinterface */
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      /* unimplemented or not ethernet */
      goto done;
    }

  /*
   * Double check that the config we found is for our interface (or the
   * interface is down)
   */
  ASSERT ((subint->sw_if_index == sw_if_index) | (subint->sw_if_index == ~0));

  if (l2)
    {
      subint->flags |= SUBINT_CONFIG_L2;
    }
  else
    {
      subint->flags &= ~SUBINT_CONFIG_L2;
    }

done:
  return;
}

static clib_error_t *
ethernet_sw_interface_add_del (vnet_main_t * vnm,
			       u32 sw_if_index, u32 is_create)
{
  clib_error_t *error = 0;
  subint_config_t *subint;
  u32 match_flags;
  u32 unsupported = 0;

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &match_flags,
				      &unsupported);

  if (subint == 0)
    {
      // not implemented yet or not ethernet
      if (unsupported)
	{
	  // this is the NYI case
	  error = clib_error_return (0, "not implemented yet");
	}
      goto done;
    }

  if (!is_create)
    {
      subint->flags = 0;
      return error;
    }

  // Initialize the subint
  if (subint->flags & SUBINT_CONFIG_VALID)
    {
      // Error vlan already in use
      error = clib_error_return (0, "vlan is already in use");
    }
  else
    {
      // Note that config is L3 by defaulty
      subint->flags = SUBINT_CONFIG_VALID | match_flags;
      subint->sw_if_index = ~0;	// because interfaces are initially down
    }

done:
  return error;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ethernet_sw_interface_add_del);

static char *ethernet_error_strings[] = {
#define ethernet_error(n,c,s) s,
#include "error.def"
#undef ethernet_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ethernet_input_node) = {
  .function = ethernet_input,
  .name = "ethernet-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_N_ERROR,
  .error_strings = ethernet_error_strings,
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_ethernet_input_trace,
  .unformat_buffer = unformat_ethernet_header,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FUNCTION_MULTIARCH (ethernet_input_node, ethernet_input)
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ethernet_input_type_node, static) = {
  .function = ethernet_input_type,
  .name = "ethernet-input-type",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FUNCTION_MULTIARCH (ethernet_input_type_node, ethernet_input_type)
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ethernet_input_not_l2_node, static) = {
  .function = ethernet_input_not_l2,
  .name = "ethernet-input-not-l2",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_NODE_FUNCTION_MULTIARCH (ethernet_input_not_l2_node,
			      ethernet_input_not_l2)
/* *INDENT-ON* */


void
ethernet_set_rx_redirect (vnet_main_t * vnm,
			  vnet_hw_interface_t * hi, u32 enable)
{
  // Insure all packets go to ethernet-input (i.e. untagged ipv4 packets
  // don't go directly to ip4-input)
  vnet_hw_interface_rx_redirect_to_node
    (vnm, hi->hw_if_index, enable ? ethernet_input_node.index : ~0);
}


/*
 * Initialization and registration for the next_by_ethernet structure
 */

clib_error_t *
next_by_ethertype_init (next_by_ethertype_t * l3_next)
{
  l3_next->input_next_by_type = sparse_vec_new
    ( /* elt bytes */ sizeof (l3_next->input_next_by_type[0]),
     /* bits in index */ BITS (((ethernet_header_t *) 0)->type));

  vec_validate (l3_next->sparse_index_by_input_next_index,
		ETHERNET_INPUT_NEXT_DROP);
  vec_validate (l3_next->sparse_index_by_input_next_index,
		ETHERNET_INPUT_NEXT_PUNT);
  l3_next->sparse_index_by_input_next_index[ETHERNET_INPUT_NEXT_DROP] =
    SPARSE_VEC_INVALID_INDEX;
  l3_next->sparse_index_by_input_next_index[ETHERNET_INPUT_NEXT_PUNT] =
    SPARSE_VEC_INVALID_INDEX;

  /*
   * Make sure we don't wipe out an ethernet registration by mistake
   * Can happen if init function ordering constraints are missing.
   */
  if (CLIB_DEBUG > 0)
    {
      ethernet_main_t *em = &ethernet_main;
      ASSERT (em->next_by_ethertype_register_called == 0);
    }

  return 0;
}

// Add an ethertype -> next index mapping to the structure
clib_error_t *
next_by_ethertype_register (next_by_ethertype_t * l3_next,
			    u32 ethertype, u32 next_index)
{
  u32 i;
  u16 *n;
  ethernet_main_t *em = &ethernet_main;

  if (CLIB_DEBUG > 0)
    {
      ethernet_main_t *em = &ethernet_main;
      em->next_by_ethertype_register_called = 1;
    }

  /* Setup ethernet type -> next index sparse vector mapping. */
  n = sparse_vec_validate (l3_next->input_next_by_type, ethertype);
  n[0] = next_index;

  /* Rebuild next index -> sparse index inverse mapping when sparse vector
     is updated. */
  vec_validate (l3_next->sparse_index_by_input_next_index, next_index);
  for (i = 1; i < vec_len (l3_next->input_next_by_type); i++)
    l3_next->
      sparse_index_by_input_next_index[l3_next->input_next_by_type[i]] = i;

  // do not allow the cached next index's to be updated if L3
  // redirect is enabled, as it will have overwritten them
  if (!em->redirect_l3)
    {
      // Cache common ethertypes directly
      if (ethertype == ETHERNET_TYPE_IP4)
	{
	  l3_next->input_next_ip4 = next_index;
	}
      else if (ethertype == ETHERNET_TYPE_IP6)
	{
	  l3_next->input_next_ip6 = next_index;
	}
      else if (ethertype == ETHERNET_TYPE_MPLS)
	{
	  l3_next->input_next_mpls = next_index;
	}
    }
  return 0;
}


static clib_error_t *
ethernet_input_init (vlib_main_t * vm)
{
  ethernet_main_t *em = &ethernet_main;
  __attribute__ ((unused)) vlan_table_t *invalid_vlan_table;
  __attribute__ ((unused)) qinq_table_t *invalid_qinq_table;

  ethernet_setup_node (vm, ethernet_input_node.index);
  ethernet_setup_node (vm, ethernet_input_type_node.index);
  ethernet_setup_node (vm, ethernet_input_not_l2_node.index);

  next_by_ethertype_init (&em->l3_next);

  // Initialize pools and vector for vlan parsing
  vec_validate (em->main_intfs, 10);	// 10 main interfaces
  pool_alloc (em->vlan_pool, 10);
  pool_alloc (em->qinq_pool, 1);

  // The first vlan pool will always be reserved for an invalid table
  pool_get (em->vlan_pool, invalid_vlan_table);	// first id = 0
  // The first qinq pool will always be reserved for an invalid table
  pool_get (em->qinq_pool, invalid_qinq_table);	// first id = 0

  return 0;
}

VLIB_INIT_FUNCTION (ethernet_input_init);

void
ethernet_register_input_type (vlib_main_t * vm,
			      ethernet_type_t type, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_type_info_t *ti;
  u32 i;

  {
    clib_error_t *error = vlib_call_init_function (vm, ethernet_init);
    if (error)
      clib_error_report (error);
  }

  ti = ethernet_get_type_info (em, type);
  ti->node_index = node_index;
  ti->next_index = vlib_node_add_next (vm,
				       ethernet_input_node.index, node_index);
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);
  ASSERT (i == ti->next_index);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);
  ASSERT (i == ti->next_index);

  // Add the L3 node for this ethertype to the next nodes structure
  next_by_ethertype_register (&em->l3_next, type, ti->next_index);

  // Call the registration functions for other nodes that want a mapping
  l2bvi_register_input_type (vm, type, node_index);
}

void
ethernet_register_l2_input (vlib_main_t * vm, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  u32 i;

  em->l2_next =
    vlib_node_add_next (vm, ethernet_input_node.index, node_index);

  /*
   * Even if we never use these arcs, we have to align the next indices...
   */
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);

  ASSERT (i == em->l2_next);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);
  ASSERT (i == em->l2_next);
}

// Register a next node for L3 redirect, and enable L3 redirect
void
ethernet_register_l3_redirect (vlib_main_t * vm, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  u32 i;

  em->redirect_l3 = 1;
  em->redirect_l3_next = vlib_node_add_next (vm,
					     ethernet_input_node.index,
					     node_index);
  /*
   * Change the cached next nodes to the redirect node
   */
  em->l3_next.input_next_ip4 = em->redirect_l3_next;
  em->l3_next.input_next_ip6 = em->redirect_l3_next;
  em->l3_next.input_next_mpls = em->redirect_l3_next;

  /*
   * Even if we never use these arcs, we have to align the next indices...
   */
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);

  ASSERT (i == em->redirect_l3_next);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);

  ASSERT (i == em->redirect_l3_next);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
