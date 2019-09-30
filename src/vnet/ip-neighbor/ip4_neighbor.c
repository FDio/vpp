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
#include <vnet/ethernet/arp_packet.h>

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
  u32 thread_index = vm->thread_index;
  u64 seed;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  seed = throttle_seed (&im->arp_throttle, thread_index, vlib_time_now (vm));

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
	  u32 pi0, bi0, adj_index0, sw_if_index0;
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0, *b0;
	  ip4_address_t resolve0;
	  ethernet_arp_header_t *h0;
	  vnet_hw_interface_t *hw_if0;
	  u64 r0;

	  pi0 = from[0];
	  p0 = vlib_get_buffer (vm, pi0);

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  adj0 = adj_get (adj_index0);

	  if (is_glean)
	    {
	      /* resolve the packet's destination */
	      ip4_header_t *ip0 = vlib_buffer_get_current (p0);
	      resolve0 = ip0->dst_address;
	    }
	  else
	    {
	      /* resolve the incomplete adj */
	      resolve0 = adj0->sub_type.nbr.next_hop.ip4;
	    }

	  /* combine the address and interface for the hash key */
	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  r0 = (u64) resolve0.data_u32 << 32;
	  r0 |= sw_if_index0;

	  if (throttle_check (&im->arp_throttle, thread_index, r0, seed))
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_THROTTLED];
	      continue;
	    }

	  /*
	   * the adj has been updated to a rewrite but the node the DPO that got
	   * us here hasn't - yet. no big deal. we'll drop while we wait.
	   */
	  if (IP_LOOKUP_NEXT_REWRITE == adj0->lookup_next_index)
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_RESOLVED];
	      continue;
	    }

	  /*
	   * Can happen if the control-plane is programming tables
	   * with traffic flowing; at least that's today's lame excuse.
	   */
	  if ((is_glean && adj0->lookup_next_index != IP_LOOKUP_NEXT_GLEAN)
	      || (!is_glean && adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP))
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_NON_ARP_ADJ];
	      continue;
	    }
	  /* Send ARP request. */
	  h0 =
	    vlib_packet_template_get_packet (vm,
					     &im->ip4_arp_request_packet_template,
					     &bi0);
	  /* Seems we're out of buffers */
	  if (PREDICT_FALSE (!h0))
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_NO_BUFFERS];
	      continue;
	    }

	  b0 = vlib_get_buffer (vm, bi0);

	  /* copy the persistent fields from the original */
	  clib_memcpy_fast (b0->opaque2, p0->opaque2, sizeof (p0->opaque2));

	  /* Add rewrite/encap string for ARP packet. */
	  vnet_rewrite_one_header (adj0[0], h0, sizeof (ethernet_header_t));

	  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  /* Src ethernet address in ARP header. */
	  mac_address_from_bytes (&h0->ip4_over_ethernet[0].mac,
				  hw_if0->hw_address);
	  if (is_glean)
	    {
	      /* The interface's source address is stashed in the Glean Adj */
	      h0->ip4_over_ethernet[0].ip4 =
		adj0->sub_type.glean.receive_addr.ip4;
	    }
	  else
	    {
	      /* Src IP address in ARP header. */
	      if (ip4_src_address_for_packet (lm, sw_if_index0,
					      &h0->ip4_over_ethernet[0].ip4))
		{
		  /* No source address available */
		  p0->error = node->errors[IP4_ARP_ERROR_NO_SOURCE_ADDRESS];
		  vlib_buffer_free (vm, &bi0, 1);
		  continue;
		}
	    }
	  h0->ip4_over_ethernet[1].ip4 = resolve0;

	  p0->error = node->errors[IP4_ARP_ERROR_REQUEST_SENT];

	  vlib_buffer_copy_trace_flag (vm, p0, bi0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

	  vlib_set_next_frame_buffer (vm, node,
				      adj0->rewrite_header.next_index, bi0);
	}

      vlib_put_next_frame (vm, node, IP4_ARP_NEXT_DROP, n_left_to_next_drop);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_arp_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
{
  return (ip4_arp_inline (vm, node, frame, 0));
}

VLIB_NODE_FN (ip4_glean_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return (ip4_arp_inline (vm, node, frame, 1));
}

static char *ip4_arp_error_strings[] = {
  [IP4_ARP_ERROR_THROTTLED] = "ARP requests throttled",
  [IP4_ARP_ERROR_RESOLVED] = "ARP requests resolved",
  [IP4_ARP_ERROR_NO_BUFFERS] = "ARP requests out of buffer",
  [IP4_ARP_ERROR_REQUEST_SENT] = "ARP requests sent",
  [IP4_ARP_ERROR_NON_ARP_ADJ] = "ARPs to non-ARP adjacencies",
  [IP4_ARP_ERROR_NO_SOURCE_ADDRESS] = "no source address for ARP request",
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_arp_node) =
{
  .name = "ip4-arp",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_errors = ARRAY_LEN (ip4_arp_error_strings),
  .error_strings = ip4_arp_error_strings,
  .n_next_nodes = IP4_ARP_N_NEXT,
  .next_nodes = {
    [IP4_ARP_NEXT_DROP] = "ip4-drop",
  },
};

VLIB_REGISTER_NODE (ip4_glean_node) =
{
  .name = "ip4-glean",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_errors = ARRAY_LEN (ip4_arp_error_strings),
  .error_strings = ip4_arp_error_strings,
  .n_next_nodes = IP4_ARP_N_NEXT,
  .next_nodes = {
    [IP4_ARP_NEXT_DROP] = "ip4-drop",
  },
};
/* *INDENT-ON* */

#define foreach_notrace_ip4_arp_error           \
_(THROTTLED)                                    \
_(RESOLVED)                                     \
_(NO_BUFFERS)                                   \
_(REQUEST_SENT)                                 \
_(NON_ARP_ADJ)                                  \
_(NO_SOURCE_ADDRESS)

static clib_error_t *
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
