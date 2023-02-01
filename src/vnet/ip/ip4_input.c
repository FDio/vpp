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

#include <vnet/ip/ip_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/pg/pg.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/util/throttle.h>

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
VLIB_NODE_FN (ip4_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip_input_inline (vm, node, frame, node, VNET_INTERFACE_COUNTER_IP4,
			  AF_IP4, sizeof (ip4_input_trace_t),
			  IP_INPUT_FLAGS_VERIFY_CHECKSUM);
}

VLIB_NODE_FN (ip4_input_no_checksum_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  return ip_input_inline (vm, node, frame,
			  vlib_node_get_runtime (vm, ip4_input_node.index),
			  VNET_INTERFACE_COUNTER_IP4, AF_IP4,
			  sizeof (ip4_input_trace_t), IP_INPUT_FLAGS_NONE);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_input_node) = {
  .name = "ip4-input",
  .vector_size = sizeof (u32),
  .protocol_hint = VLIB_NODE_PROTO_HINT_IP4,

  .n_errors = IP4_N_ERROR,
  .error_counters = ip4_error_counters,

  .n_next_nodes = IP_INPUT_N_NEXT,
  .next_nodes = {
    [IP_INPUT_NEXT_DROP] = "error-drop",
    [IP_INPUT_NEXT_PUNT] = "error-punt",
    [IP_INPUT_NEXT_OPTIONS] = "ip4-options",
    [IP_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-mfib-forward-lookup",
    [IP_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};

VLIB_REGISTER_NODE (ip4_input_no_checksum_node) = {
  .name = "ip4-input-no-checksum",
  .vector_size = sizeof (u32),

  .sibling_of = "ip4-input",
  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};
/* *INDENT-ON* */

static clib_error_t *
ip4_init (vlib_main_t * vm)
{
  clib_error_t *error;

  ethernet_register_input_type (vm, ETHERNET_TYPE_IP4, ip4_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip4, ip4_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip4, ip4_input_node.index);

  {
    extern vlib_node_registration_t ip4_input_no_checksum_node;
    pg_node_t *pn;
    pn = pg_get_node (ip4_input_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
    pn = pg_get_node (ip4_input_no_checksum_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  if ((error = vlib_call_init_function (vm, ip4_cli_init)))
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
