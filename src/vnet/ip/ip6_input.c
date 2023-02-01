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
 * ip/ip6_input.c: IP v6 input node
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
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/pg/pg.h>

typedef struct
{
  u8 packet_data[64];
} ip6_input_trace_t;

static u8 *
format_ip6_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip6_input_trace_t *t = va_arg (*va, ip6_input_trace_t *);

  s = format (s, "%U",
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

VLIB_NODE_FN (ip6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip_input_inline (vm, node, frame,
			  vlib_node_get_runtime (vm, ip6_input_node.index),
			  VNET_INTERFACE_COUNTER_IP6, AF_IP6,
			  sizeof (ip6_input_trace_t), IP_INPUT_FLAGS_NONE);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_input_node) = {
  .name = "ip6-input",
  .vector_size = sizeof (u32),

  .n_errors = IP6_N_ERROR,
  .error_counters = ip6_error_counters,

  .n_next_nodes = IP_INPUT_N_NEXT,
  .next_nodes = {
    [IP_INPUT_NEXT_DROP] = "ip6-drop",
    [IP_INPUT_NEXT_PUNT] = "error-punt",
    [IP_INPUT_NEXT_OPTIONS] = "error-drop",
    [IP_INPUT_NEXT_LOOKUP] = "ip6-lookup",
    [IP_INPUT_NEXT_ICMP_ERROR] = "ip6-icmp-error",
    [IP_INPUT_NEXT_LOOKUP_MULTICAST] = "ip6-mfib-forward-lookup",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_input_trace,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_init (vlib_main_t * vm)
{
  ethernet_register_input_type (vm, ETHERNET_TYPE_IP6, ip6_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip6, ip6_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip6, ip6_input_node.index);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip6_input_node.index);
    pn->unformat_edit = unformat_pg_ip6_header;
  }

  /* Set flow hash to something non-zero. */
  ip6_main.flow_hash_seed = 0xdeadbeef;

  /* Default hop limit for packets we generate. */
  ip6_main.host_config.ttl = 64;


  uword *u = hash_get (ip_main.protocol_info_by_name, "IPV6_FRAGMENTATION");
  if (u)
    {
      ip_protocol_info_t *info =
	vec_elt_at_index (ip_main.protocol_infos, *u);
      ASSERT (NULL == info->format_header);
      info->format_header = format_ip6_frag_hdr;
    }
  return /* no error */ 0;
}

VLIB_INIT_FUNCTION (ip6_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
