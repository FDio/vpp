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

#include <vnet/ip-neighbor/ip4_neighbor.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/util/throttle.h>
#include <vnet/fib/fib_sas.h>

/** ARP throttling */
static throttle_t arp_throttle;

void
ip4_neighbor_probe_dst (u32 sw_if_index, const ip4_address_t * dst)
{
  ip4_address_t src;
  adj_index_t ai;

  /* any glean will do, it's just for the rewrite */
  ai = adj_glean_get (FIB_PROTOCOL_IP4, sw_if_index, NULL);

  if (ADJ_INDEX_INVALID != ai && fib_sas4_get (sw_if_index, dst, &src))
    ip4_neighbor_probe (vlib_get_main (),
			vnet_get_main (), adj_get (ai), &src, dst);
}

void
ip4_neighbor_advertise (vlib_main_t * vm,
			vnet_main_t * vnm,
			u32 sw_if_index, const ip4_address_t * addr)
{
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ip4_main_t *i4m = &ip4_main;
  u8 *rewrite, rewrite_len;
  ip4_address_t tmp;

  if (NULL == addr)
    {
      fib_sas4_get (sw_if_index, NULL, &tmp);
      addr = &tmp;
    }

  if (addr)
    {
      clib_warning ("Sending GARP for IP4 address %U on sw_if_idex %d",
		    format_ip4_address, addr, sw_if_index);

      /* Form GARP packet for output - Gratuitous ARP is an ARP request packet
         where the interface IP/MAC pair is used for both source and request
         MAC/IP pairs in the request */
      u32 bi = 0;
      ethernet_arp_header_t *h = vlib_packet_template_get_packet
	(vm, &i4m->ip4_arp_request_packet_template, &bi);

      if (!h)
	return;

      mac_address_from_bytes (&h->ip4_over_ethernet[0].mac, hi->hw_address);
      mac_address_from_bytes (&h->ip4_over_ethernet[1].mac, hi->hw_address);
      h->ip4_over_ethernet[0].ip4 = addr[0];
      h->ip4_over_ethernet[1].ip4 = addr[0];

      /* Setup MAC header with ARP Etype and broadcast DMAC */
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      rewrite =
	ethernet_build_rewrite (vnm, sw_if_index, VNET_LINK_ARP,
				VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST);
      rewrite_len = vec_len (rewrite);
      vlib_buffer_advance (b, -rewrite_len);
      ethernet_header_t *e = vlib_buffer_get_current (b);
      clib_memcpy_fast (e->dst_address, rewrite, rewrite_len);
      vec_free (rewrite);

      /* Send GARP packet out the specified interface */
      vnet_buffer (b)->sw_if_index[VLIB_RX] =
	vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
      u32 *to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
      vlib_put_frame_to_node (vm, hi->output_node_index, f);
    }
}

always_inline uword
ip4_arp_inline (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame, int is_glean)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 *from, *to_next_drop;
  uword n_left_from, n_left_to_next_drop, next_index;
  u32 thread_index = vm->thread_index;
  u64 seed;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  seed = throttle_seed (&arp_throttle, thread_index, vlib_time_now (vm));

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
	  u32 pi0, adj_index0, sw_if_index0;
	  ip4_address_t resolve0, src0;
	  vlib_buffer_t *p0, *b0;
	  ip_adjacency_t *adj0;
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
	  sw_if_index0 = adj0->rewrite_header.sw_if_index;

	  if (is_glean)
	    {
	      /* resolve the packet's destination */
	      ip4_header_t *ip0 = vlib_buffer_get_current (p0);
	      resolve0 = ip0->dst_address;
	      src0 = adj0->sub_type.glean.rx_pfx.fp_addr.ip4;
	    }
	  else
	    {
	      /* resolve the incomplete adj */
	      resolve0 = adj0->sub_type.nbr.next_hop.ip4;
	      /* Src IP address in ARP header. */
	      if (!fib_sas4_get (sw_if_index0, &resolve0, &src0))
		{
		  /* No source address available */
		  p0->error = node->errors[IP4_ARP_ERROR_NO_SOURCE_ADDRESS];
		  continue;
		}
	    }

	  /* combine the address and interface for the hash key */
	  r0 = (u64) resolve0.data_u32 << 32;
	  r0 |= sw_if_index0;

	  if (throttle_check (&arp_throttle, thread_index, r0, seed))
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
	  b0 = ip4_neighbor_probe (vm, vnm, adj0, &src0, &resolve0);

	  if (PREDICT_TRUE (NULL != b0))
	    {
	      /* copy the persistent fields from the original */
	      clib_memcpy_fast (b0->opaque2, p0->opaque2,
				sizeof (p0->opaque2));
	      p0->error = node->errors[IP4_ARP_ERROR_REQUEST_SENT];
	    }
	  else
	    {
	      p0->error = node->errors[IP4_ARP_ERROR_NO_BUFFERS];
	      continue;
	    }
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

static clib_error_t *
ip4_neighbor_main_loop_enter (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;

  throttle_init (&arp_throttle, n_vlib_mains, 1e-3);

  return (NULL);
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (ip4_neighbor_main_loop_enter);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
