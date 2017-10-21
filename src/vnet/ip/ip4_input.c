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
 * ip/ip4_input.c: IP v4 input node
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

#include <vnet/ip/ip4_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>

typedef struct
{
  u8 packet_data[64];
} ip4_input_trace_t;

static u8 *
format_ip4_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_input_trace_t *t = va_arg (*va, ip4_input_trace_t *);

  s = format (s, "%U",
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

/* Validate IP v4 packets and pass them either to forwarding code
   or drop/punt exception packets. */
always_inline uword
ip4_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int verify_checksum)
{
  ip4_main_t *im = &ip4_main;
  vnet_main_t *vnm = vnet_get_main ();
  ip_lookup_main_t *lm = &im->lookup_main;
  u32 n_left_from, *from, *to_next;
  ip4_input_next_t next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  vlib_simple_counter_main_t *cm;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip4_input_trace_t));

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			 VNET_INTERFACE_COUNTER_IP4);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  u32 sw_if_index0, pi0, next0;
	  u32 sw_if_index1, pi1, next1;
	  u8 arc0, arc1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
	  }

	  to_next[0] = pi0 = from[0];
	  to_next[1] = pi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (p1)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (ip4_address_is_multicast (&ip0->dst_address)))
	    {
	      arc0 = lm->mcast_feature_arc_index;
	      next0 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
	    }
	  else
	    {
	      arc0 = lm->ucast_feature_arc_index;
	      next0 = IP4_INPUT_NEXT_LOOKUP;
	    }

	  if (PREDICT_FALSE (ip4_address_is_multicast (&ip1->dst_address)))
	    {
	      arc1 = lm->mcast_feature_arc_index;
	      next1 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
	    }
	  else
	    {
	      arc1 = lm->ucast_feature_arc_index;
	      next1 = IP4_INPUT_NEXT_LOOKUP;
	    }

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_RX] = ~0;

	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);
	  vnet_feature_arc_start (arc1, sw_if_index1, &next1, p1);

	  vlib_increment_simple_counter (cm, thread_index, sw_if_index0, 1);
	  vlib_increment_simple_counter (cm, thread_index, sw_if_index1, 1);
	  ip4_input_check_x2 (vm, error_node,
			      p0, p1, ip0, ip1,
			      &next0, &next1, verify_checksum);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  u32 sw_if_index0, pi0, next0;
	  u8 arc0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (ip4_address_is_multicast (&ip0->dst_address)))
	    {
	      arc0 = lm->mcast_feature_arc_index;
	      next0 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
	    }
	  else
	    {
	      arc0 = lm->ucast_feature_arc_index;
	      next0 = IP4_INPUT_NEXT_LOOKUP;
	    }

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);

	  vlib_increment_simple_counter (cm, thread_index, sw_if_index0, 1);
	  ip4_input_check_x1 (vm, error_node, p0, ip0, &next0,
			      verify_checksum);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/** \brief IPv4 input node.
    @node ip4-input

    This is the IPv4 input node: validates ip4 header checksums,
    verifies ip header lengths, discards pkts with expired TTLs,
    and sends pkts to the set of ip feature nodes configured on
    the rx interface.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - vnet_feature_config_main_t cm corresponding to each pkt's dst address unicast /
      multicast status.
    - <code>b->current_config_index</code> corresponding to each pkt's
      rx sw_if_index.
         - This sets the per-packet graph trajectory, ensuring that
           each packet visits the per-interface features in order.

    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Indices:</em>
    - Dispatches pkts to the (first) feature node:
      <code> vnet_get_config_data (... &next0 ...); </code>
      or @c error-drop
*/
static uword
ip4_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 1);
}

static uword
ip4_input_no_checksum (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 0);
}

char *ip4_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_input_node) = {
  .function = ip4_input,
  .name = "ip4-input",
  .vector_size = sizeof (u32),

  .n_errors = IP4_N_ERROR,
  .error_strings = ip4_error_strings,

  .n_next_nodes = IP4_INPUT_N_NEXT,
  .next_nodes = {
    [IP4_INPUT_NEXT_DROP] = "error-drop",
    [IP4_INPUT_NEXT_PUNT] = "error-punt",
    [IP4_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP4_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-mfib-forward-lookup",
    [IP4_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_input_node, ip4_input);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_input_no_checksum_node,static) = {
  .function = ip4_input_no_checksum,
  .name = "ip4-input-no-checksum",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_INPUT_N_NEXT,
  .next_nodes = {
    [IP4_INPUT_NEXT_DROP] = "error-drop",
    [IP4_INPUT_NEXT_PUNT] = "error-punt",
    [IP4_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP4_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-mfib-forward-lookup",
    [IP4_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_input_no_checksum_node,
			      ip4_input_no_checksum);

static clib_error_t *
ip4_init (vlib_main_t * vm)
{
  clib_error_t *error;

  ethernet_register_input_type (vm, ETHERNET_TYPE_IP4, ip4_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip4, ip4_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip4, ip4_input_node.index);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip4_input_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
    pn = pg_get_node (ip4_input_no_checksum_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  if ((error = vlib_call_init_function (vm, ip4_cli_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_source_check_init)))
    return error;

  if ((error = vlib_call_init_function
       (vm, ip4_source_and_port_range_check_init)))
    return error;

  /* Set flow hash to something non-zero. */
  ip4_main.flow_hash_seed = 0xdeadbeef;

  /* Default TTL for packets we generate. */
  ip4_main.host_config.ttl = 64;

  return error;
}

VLIB_INIT_FUNCTION (ip4_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
