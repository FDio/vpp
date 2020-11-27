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

#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <vnet/util/throttle.h>

/** ND throttling */
static throttle_t nd_throttle;

void
ip6_neighbor_probe_dst (const ip_adjacency_t * adj, const ip6_address_t * dst)
{
  ip_interface_address_t *ia;
  ip6_address_t *src;

  src = ip6_interface_address_matching_destination
    (&ip6_main, dst, adj->rewrite_header.sw_if_index, &ia);

  if (!src)
    return;

  ip6_neighbor_probe (vlib_get_main (), vnet_get_main (), adj, src, dst);
}

void
ip6_neighbor_advertise (vlib_main_t * vm,
			vnet_main_t * vnm,
			u32 sw_if_index, const ip6_address_t * addr)
{
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ip6_main_t *i6m = &ip6_main;
  u8 *rewrite, rewrite_len;
  u8 dst_address[6];

  if (NULL == addr)
    addr = ip6_interface_first_address (i6m, sw_if_index);

  if (addr)
    {
      clib_warning
	("Sending unsolicitated NA IP6 address %U on sw_if_idex %d",
	 format_ip6_address, addr, sw_if_index);

      /* Form unsolicited neighbor advertisement packet from NS pkt template */
      int bogus_length;
      u32 bi = 0;
      icmp6_neighbor_solicitation_header_t *h =
	vlib_packet_template_get_packet (vm,
					 &ip6_neighbor_packet_template,
					 &bi);
      if (!h)
	return;

      ip6_set_reserved_multicast_address (&h->ip.dst_address,
					  IP6_MULTICAST_SCOPE_link_local,
					  IP6_MULTICAST_GROUP_ID_all_hosts);
      h->ip.src_address = addr[0];
      h->neighbor.icmp.type = ICMP6_neighbor_advertisement;
      h->neighbor.target_address = addr[0];
      h->neighbor.advertisement_flags = clib_host_to_net_u32
	(ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);
      h->link_layer_option.header.type =
	ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
      clib_memcpy (h->link_layer_option.ethernet_address,
		   hi->hw_address, vec_len (hi->hw_address));
      h->neighbor.icmp.checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h->ip, &bogus_length);
      ASSERT (bogus_length == 0);

      /* Setup MAC header with IP6 Etype and mcast DMAC */
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      ip6_multicast_ethernet_address (dst_address,
				      IP6_MULTICAST_GROUP_ID_all_hosts);
      rewrite =
	ethernet_build_rewrite (vnm, sw_if_index, VNET_LINK_IP6, dst_address);
      rewrite_len = vec_len (rewrite);
      vlib_buffer_advance (b, -rewrite_len);
      ethernet_header_t *e = vlib_buffer_get_current (b);
      clib_memcpy (e->dst_address, rewrite, rewrite_len);
      vec_free (rewrite);

      /* Send unsolicited ND advertisement packet out the specified interface */
      vnet_buffer (b)->sw_if_index[VLIB_RX] =
	vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
      u32 *to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
      vlib_put_frame_to_node (vm, hi->output_node_index, f);
    }
}

typedef enum
{
  IP6_NBR_NEXT_DROP,
  IP6_NBR_NEXT_REPLY_TX,
  IP6_NBR_N_NEXT,
} ip6_discover_neighbor_next_t;

typedef enum
{
  IP6_NBR_ERROR_DROP,
  IP6_NBR_ERROR_REQUEST_SENT,
  IP6_NBR_ERROR_NO_SOURCE_ADDRESS,
  IP6_NBR_ERROR_NO_BUFFERS,
} ip6_discover_neighbor_error_t;

static uword
ip6_discover_neighbor_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame, int is_glean)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 *from, *to_next_drop;
  uword n_left_from, n_left_to_next_drop;
  u64 seed;
  u32 thread_index = vm->thread_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame);

  seed = throttle_seed (&nd_throttle, thread_index, vlib_time_now (vm));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP6_NBR_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 pi0, adj_index0, sw_if_index0, drop0, r0;
	  vnet_hw_interface_t *hw_if0;
	  vlib_buffer_t *p0, *b0;
	  ip_adjacency_t *adj0;
	  ip6_address_t src;
	  ip6_header_t *ip0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index;

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

	  drop0 = throttle_check (&nd_throttle, thread_index, r0, seed);

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  /* If the interface is link-down, drop the pkt */
	  if (!(hw_if0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	    drop0 = 1;

	  if (!ip6_link_is_enabled (sw_if_index0))
	    drop0 = 1;

	  /*
	   * the adj has been updated to a rewrite but the node the DPO that got
	   * us here hasn't - yet. no big deal. we'll drop while we wait.
	   */
	  if (IP_LOOKUP_NEXT_REWRITE == adj0->lookup_next_index)
	    drop0 = 1;

	  if (drop0)
	    {
	      p0->error = node->errors[IP6_NBR_ERROR_DROP];
	      continue;
	    }

	  /*
	   * Choose source address based on destination lookup
	   * adjacency.
	   */
	  if (!ip6_src_address_for_packet (sw_if_index0,
					   &ip0->dst_address, &src))
	    {
	      /* There is no address on the interface */
	      p0->error = node->errors[IP6_NBR_ERROR_NO_SOURCE_ADDRESS];
	      continue;
	    }

	  b0 = ip6_neighbor_probe (vm, vnm, adj0, &src, &ip0->dst_address);

	  if (PREDICT_TRUE (NULL != b0))
	    {
	      clib_memcpy_fast (b0->opaque2, p0->opaque2,
				sizeof (p0->opaque2));
	      b0->flags |= p0->flags & VLIB_BUFFER_IS_TRACED;
	      b0->trace_handle = p0->trace_handle;
	      p0->error = node->errors[IP6_NBR_ERROR_REQUEST_SENT];
	    }
	  else
	    {
	      /* There is no address on the interface */
	      p0->error = node->errors[IP6_NBR_ERROR_NO_BUFFERS];
	      continue;
	    }
	}

      vlib_put_next_frame (vm, node, IP6_NBR_NEXT_DROP, n_left_to_next_drop);
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
  [IP6_NBR_ERROR_DROP] = "address overflow drops",
  [IP6_NBR_ERROR_REQUEST_SENT] = "neighbor solicitations sent",
  [IP6_NBR_ERROR_NO_SOURCE_ADDRESS] = "no source address for ND solicitation",
  [IP6_NBR_ERROR_NO_BUFFERS] = "no buffers",
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
  .n_next_nodes = IP6_NBR_N_NEXT,
  .next_nodes =
  {
    [IP6_NBR_NEXT_DROP] = "ip6-drop",
    [IP6_NBR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
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
  .n_next_nodes = IP6_NBR_N_NEXT,
  .next_nodes =
  {
    [IP6_NBR_NEXT_DROP] = "ip6-drop",
    [IP6_NBR_NEXT_REPLY_TX] = "ip6-rewrite-mcast",
  },
};
/* *INDENT-ON* */

/* Template used to generate IP6 neighbor solicitation packets. */
vlib_packet_template_t ip6_neighbor_packet_template;

static clib_error_t *
ip6_neighbor_init (vlib_main_t * vm)
{
  icmp6_neighbor_solicitation_header_t p;

  clib_memset (&p, 0, sizeof (p));

  p.ip.ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  p.ip.payload_length =
    clib_host_to_net_u16 (sizeof (p) -
			  STRUCT_OFFSET_OF
			  (icmp6_neighbor_solicitation_header_t, neighbor));
  p.ip.protocol = IP_PROTOCOL_ICMP6;
  p.ip.hop_limit = 255;
  ip6_set_solicited_node_multicast_address (&p.ip.dst_address, 0);

  p.neighbor.icmp.type = ICMP6_neighbor_solicitation;

  p.link_layer_option.header.type =
    ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
  p.link_layer_option.header.n_data_u64s =
    sizeof (p.link_layer_option) / sizeof (u64);

  vlib_packet_template_init (vm,
			     &ip6_neighbor_packet_template, &p, sizeof (p),
			     /* alloc chunk size */ 8,
			     "ip6 neighbor discovery");

  return NULL;
}

VLIB_INIT_FUNCTION (ip6_neighbor_init);

static clib_error_t *
ip6_nd_main_loop_enter (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;

  throttle_init (&nd_throttle, tm->n_vlib_mains, 1e-3);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (ip6_nd_main_loop_enter);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
