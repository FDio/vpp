/*
 * ip/ip6_neighbor.c: IP6 neighbor handling
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ethernet/ethernet.h>

typedef enum
{
  IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
  IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX,
  IP6_DISCOVER_NEIGHBOR_N_NEXT,
} ip6_discover_neighbor_next_t;

typedef enum
{
  IP6_DISCOVER_NEIGHBOR_ERROR_DROP,
  IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT,
  IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS,
} ip6_discover_neighbor_error_t;

static uword
ip6_discover_neighbor_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame, int is_glean)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  u32 *from, *to_next_drop;
  uword n_left_from, n_left_to_next_drop;
  u64 seed;
  u32 thread_index = vm->thread_index;
  int bogus_length;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  seed = throttle_seed (&im->nd_throttle, thread_index, vlib_time_now (vm));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 pi0, adj_index0, sw_if_index0, drop0, r0, next0;
	  vnet_hw_interface_t *hw_if0;
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  ip0 = vlib_buffer_get_current (p0);

	  adj0 = adj_get (adj_index0);

	  if (!is_glean)
	    {
	      ip0->dst_address.as_u64[0] =
		adj0->sub_type.nbr.next_hop.ip6.as_u64[0];
	      ip0->dst_address.as_u64[1] =
		adj0->sub_type.nbr.next_hop.ip6.as_u64[1];
	    }

	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  /* combine the address and interface for a hash */
	  r0 = ip6_address_hash_to_u64 (&ip0->dst_address) ^ sw_if_index0;

	  drop0 = throttle_check (&im->nd_throttle, thread_index, r0, seed);

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  /* If the interface is link-down, drop the pkt */
	  if (!(hw_if0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	    drop0 = 1;

	  /* if (vec_len (nm->if_radv_pool_index_by_sw_if_index) > sw_if_index0) */
	  /*   { */
	  /*     u32 ri = nm->if_radv_pool_index_by_sw_if_index[sw_if_index0]; */

	  /*     if (ri != ~0) */
	  /*       radv_info = pool_elt_at_index (nm->if_radv_pool, ri); */
	  /*     else */
	  /*       drop0 = 1; */
	  /*   } */
	  /* else */
	  /*   drop0 = 1; */

	  /*
	   * the adj has been updated to a rewrite but the node the DPO that got
	   * us here hasn't - yet. no big deal. we'll drop while we wait.
	   */
	  if (IP_LOOKUP_NEXT_REWRITE == adj0->lookup_next_index)
	    drop0 = 1;

	  p0->error =
	    node->errors[drop0 ? IP6_DISCOVER_NEIGHBOR_ERROR_DROP
			 : IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT];

	  if (drop0)
	    continue;

	  {
	    u32 bi0 = 0;
	    icmp6_neighbor_solicitation_header_t *h0;
	    vlib_buffer_t *b0;

	    h0 = vlib_packet_template_get_packet
	      (vm, &im->discover_neighbor_packet_template, &bi0);
	    if (!h0)
	      continue;

	    /* copy the persistent fields from the original */
	    b0 = vlib_get_buffer (vm, bi0);
	    clib_memcpy_fast (b0->opaque2, p0->opaque2, sizeof (p0->opaque2));

	    /*
	     * Build ethernet header.
	     * Choose source address based on destination lookup
	     * adjacency.
	     */
	    if (!ip6_src_address_for_packet (sw_if_index0,
					     &ip0->dst_address,
					     &h0->ip.src_address))
	      {
		/* There is no address on the interface */
		p0->error =
		  node->errors[IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS];
		vlib_buffer_free (vm, &bi0, 1);
		continue;
	      }

	    /*
	     * Destination address is a solicited node multicast address.
	     * We need to fill in
	     * the low 24 bits with low 24 bits of target's address.
	     */
	    h0->ip.dst_address.as_u8[13] = ip0->dst_address.as_u8[13];
	    h0->ip.dst_address.as_u8[14] = ip0->dst_address.as_u8[14];
	    h0->ip.dst_address.as_u8[15] = ip0->dst_address.as_u8[15];

	    h0->neighbor.target_address = ip0->dst_address;

	    clib_memcpy (h0->link_layer_option.ethernet_address,
			 hw_if0->hw_address, vec_len (hw_if0->hw_address));

	    /* $$$$ appears we need this; why is the checksum non-zero? */
	    h0->neighbor.icmp.checksum = 0;
	    h0->neighbor.icmp.checksum =
	      ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip,
						 &bogus_length);

	    ASSERT (bogus_length == 0);

	    vlib_buffer_copy_trace_flag (vm, p0, bi0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX]
	      = vnet_buffer (p0)->sw_if_index[VLIB_TX];

	    vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	      ip6_link_get_mcast_adj (sw_if_index0);

	    b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    next0 = IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX;

	    vlib_set_next_frame_buffer (vm, node, next0, bi0);
	  }
	}

      vlib_put_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
			   n_left_to_next_drop);
    }

  return frame->n_vectors;
}

static uword
ip6_discover_neighbor (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip6_discover_neighbor_inline (vm, node, frame, 0));
}

static uword
ip6_glean (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip6_discover_neighbor_inline (vm, node, frame, 1));
}

static char *ip6_discover_neighbor_error_strings[] = {
  [IP6_DISCOVER_NEIGHBOR_ERROR_DROP] = "address overflow drops",
  [IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT] = "neighbor solicitations sent",
  [IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS]
    = "no source address for ND solicitation",
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_glean_node) =
{
  .function = ip6_glean,
  .name = "ip6-glean",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_errors = ARRAY_LEN (ip6_discover_neighbor_error_strings),
  .error_strings = ip6_discover_neighbor_error_strings,
  .n_next_nodes = IP6_DISCOVER_NEIGHBOR_N_NEXT,
  .next_nodes =
  {
    [IP6_DISCOVER_NEIGHBOR_NEXT_DROP] = "ip6-drop",
    [IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
  },
};
VLIB_REGISTER_NODE (ip6_discover_neighbor_node) =
{
  .function = ip6_discover_neighbor,
  .name = "ip6-discover-neighbor",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_errors = ARRAY_LEN (ip6_discover_neighbor_error_strings),
  .error_strings = ip6_discover_neighbor_error_strings,
  .n_next_nodes = IP6_DISCOVER_NEIGHBOR_N_NEXT,
  .next_nodes =
  {
    [IP6_DISCOVER_NEIGHBOR_NEXT_DROP] = "ip6-drop",
    [IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
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
