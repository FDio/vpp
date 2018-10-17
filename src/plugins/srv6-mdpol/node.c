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

#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <srv6-mdpol/srv6_mdpol.h>


/******************************* Packet tracing *******************************/

typedef struct
{
  ip6_address_t src, dst;
  u8 dscp;
} srv6_mdpol_rewrite_trace_t;

static u8 *
format_srv6_mdpol_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_mdpol_rewrite_trace_t *t =
    va_arg (*args, srv6_mdpol_rewrite_trace_t *);

  s = format
    (s, "SRv6-mdpol-rewrite: src %U dst %U dscp %u",
     format_ip6_address, &t->src, format_ip6_address, &t->dst, t->dscp);

  return s;
}


/***************************** Nodes registration *****************************/

vlib_node_registration_t srv6_mdpol_rewrite_encaps_node;
vlib_node_registration_t srv6_mdpol_rewrite_encaps_v4_node;


/******************************* Error counters *******************************/

#define foreach_srv6_mdpol_rewrite_error                     \
_(INTERNAL_ERROR, "Segment Routing undefined error")        \
_(BSID_ZERO, "BSID with SL = 0")                            \
_(COUNTER_TOTAL, "SR steered IPv6 packets")                 \
_(COUNTER_ENCAP, "SR: Encaps packets")                      \
_(COUNTER_INSERT, "SR: SRH inserted packets")               \
_(COUNTER_BSID, "SR: BindingSID steered packets")

typedef enum
{
#define _(sym,str) SR_POLICY_REWRITE_ERROR_##sym,
  foreach_srv6_mdpol_rewrite_error
#undef _
    SR_POLICY_REWRITE_N_ERROR,
} srv6_mdpol_rewrite_error_t;

static char *srv6_mdpol_rewrite_error_strings[] = {
#define _(sym,string) string,
  foreach_srv6_mdpol_rewrite_error
#undef _
};


/********************************* Next nodes *********************************/

#define foreach_srv6_mdpol_rewrite_next     \
_(IP6_LOOKUP, "ip6-lookup")         \
_(ERROR, "error-drop")

typedef enum
{
#define _(s,n) SR_POLICY_REWRITE_NEXT_##s,
  foreach_srv6_mdpol_rewrite_next
#undef _
    SR_POLICY_REWRITE_N_NEXT,
} srv6_mdpol_rewrite_next_t;


/******************************** Graph nodes *********************************/

/**
 * @brief Graph node for applying a SR policy into an IPv6 packet. Encapsulation
 */
static uword
srv6_mdpol_rewrite_encaps (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0, *ip0_encap = 0;
	  ip6_sr_sl_t *sl0;
	  ip6_sr_header_t *sr0;
	  ip6_srh_tlv_opaque_t *md0;
	  u32 new_l0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 = pool_elt_at_index (sm->sid_lists,
				   vnet_buffer (b0)->ip.adj_index[VLIB_TX]);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);

	  clib_memcpy (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
		       sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  /* Inner IPv6: Decrement hop limit */
	  ip0_encap->hop_limit -= 1;

	  /* Outer IPv6: Update length and flow label */
	  new_l0 = ip0->payload_length + sizeof (ip6_header_t) +
	    clib_net_to_host_u16 (ip0_encap->payload_length);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip0->ip_version_traffic_class_and_flow_label =
	    ip0_encap->ip_version_traffic_class_and_flow_label;

	  /* Outer SRH: Set TLV */
	  sr0 = (void *) (ip0 + 1);
	  md0 = (void *) (sr0->segments + sr0->first_segment + 1);
	  md0->value[0] = ip6_traffic_class_network_order (ip0_encap);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_mdpol_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
			   sizeof (tr->src.as_u8));
	      clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
			   sizeof (tr->dst.as_u8));
	      tr->dscp = md0->value[0];
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_mdpol_rewrite_encaps_node) = {
  .function = srv6_mdpol_rewrite_encaps,
  .name = "srv6-mdpol-rewrite-encaps",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_mdpol_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_POLICY_REWRITE_N_ERROR,
  .error_strings = srv6_mdpol_rewrite_error_strings,
  .n_next_nodes = SR_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_POLICY_REWRITE_NEXT_##s] = n,
    foreach_srv6_mdpol_rewrite_next
#undef _
  },
};
/* *INDENT-ON* */

/**
 * @brief Graph node for encapsulating IPv4 packets and setting metadata
 */
static uword
srv6_mdpol_rewrite_encaps_v4 (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip4_header_t *ip0_encap = 0;
	  ip6_sr_sl_t *sl0;
	  ip6_sr_header_t *sr0;
	  ip6_srh_tlv_opaque_t *md0;
	  u32 new_l0;
	  u32 checksum0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm->sid_lists,
			       vnet_buffer (b0)->ip.adj_index[VLIB_TX]);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);

	  clib_memcpy (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
		       sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  /* Inner IPv4: Decrement TTL & update checksum */
	  ip0_encap->ttl -= 1;
	  checksum0 = ip0_encap->checksum + clib_host_to_net_u16 (0x0100);
	  checksum0 += checksum0 >= 0xffff;
	  ip0_encap->checksum = checksum0;

	  /* Outer IPv6: Update length, flow label and next header */
	  new_l0 =
	    ip0->payload_length + clib_net_to_host_u16 (ip0_encap->length);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip0->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28) |
				  ((ip0_encap->tos & 0xFF) << 20));
	  sr0 = (void *) (ip0 + 1);
	  sr0->protocol = IP_PROTOCOL_IP_IN_IP;

	  /* Outer SRH: Set TLV */
	  md0 = (void *) (sr0->segments + sr0->first_segment + 1);
	  md0->value[0] = ip0_encap->tos;

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_mdpol_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
			   sizeof (tr->src.as_u8));
	      clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
			   sizeof (tr->dst.as_u8));
	      tr->dscp = md0->value[0];
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_mdpol_rewrite_encaps_v4_node) = {
  .function = srv6_mdpol_rewrite_encaps_v4,
  .name = "srv6-mdpol-rewrite-encaps-v4",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_mdpol_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_POLICY_REWRITE_N_ERROR,
  .error_strings = srv6_mdpol_rewrite_error_strings,
  .n_next_nodes = SR_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_POLICY_REWRITE_NEXT_##s] = n,
    foreach_srv6_mdpol_rewrite_next
#undef _
  },
};
/* *INDENT-ON* */

static uword
srv6_mdpol_rewrite_b_encaps (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0, *ip0_encap = 0;
	  ip6_ext_header_t *prev0;
	  ip6_sr_header_t *sr0 = 0, *sr0_encap = 0;
	  ip6_sr_sl_t *sl0;
	  ip6_srh_tlv_opaque_t *md0;
	  u32 new_l0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm->sid_lists,
			       vnet_buffer (b0)->ip.adj_index[VLIB_TX]);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);
	  ip6_ext_header_find_t (ip0_encap, prev0, sr0_encap,
				 IP_PROTOCOL_IPV6_ROUTE);

	  if (PREDICT_TRUE
	      (sr0_encap && sr0_encap->type == ROUTING_HEADER_TYPE_SR
	       && sr0_encap->segments_left != 0))
	    {
	      sr0_encap->segments_left -= 1;
	      ip0_encap->dst_address =
		sr0_encap->segments[sr0_encap->segments_left];
	    }
	  else
	    {
	      next0 = SR_POLICY_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SR_POLICY_REWRITE_ERROR_BSID_ZERO];
	    }

	  clib_memcpy (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
		       sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  /* Inner IPv6: Decrement hop limit */
	  ip0_encap->hop_limit -= 1;

	  /* Outer IPv6: Update length and flow label */
	  new_l0 = ip0->payload_length + sizeof (ip6_header_t) +
	    clib_net_to_host_u16 (ip0_encap->payload_length);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip0->ip_version_traffic_class_and_flow_label =
	    ip0_encap->ip_version_traffic_class_and_flow_label;

	  /* Outer SRH: Set TLV */
	  sr0 = (ip6_sr_header_t *) (ip0 + 1);
	  md0 =
	    (ip6_srh_tlv_opaque_t *) (sr0->segments + sr0->first_segment + 1);
	  md0->value[0] = ip6_traffic_class_network_order (ip0_encap);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_mdpol_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
			   sizeof (tr->src.as_u8));
	      clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
			   sizeof (tr->dst.as_u8));
	      tr->dscp = md0->value[0];
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, srv6_mdpol_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_mdpol_rewrite_b_encaps_node) = {
  .function = srv6_mdpol_rewrite_b_encaps,
  .name = "srv6-mdpol-rewrite-b-encaps",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_mdpol_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_POLICY_REWRITE_N_ERROR,
  .error_strings = srv6_mdpol_rewrite_error_strings,
  .n_next_nodes = SR_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_POLICY_REWRITE_NEXT_##s] = n,
    foreach_srv6_mdpol_rewrite_next
#undef _
  },
};
/* *INDENT-ON* */


/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
