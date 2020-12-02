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
 * ip/ip4_source_check.c: IP v4 check source address (unicast RPF check)
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

#include <urpf/urpf.h>
#include <urpf/urpf_dp.h>

static char *ip4_urpf_error_strings[] = {
#define _(a,b) "ip4-" # b,
  foreach_urpf_error
#undef _
};

VLIB_NODE_FN (ip4_rx_urpf_loose) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP4, VLIB_RX, URPF_MODE_LOOSE));
}

VLIB_NODE_FN (ip4_rx_urpf_strict) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP4, VLIB_RX, URPF_MODE_STRICT));
}

VLIB_NODE_FN (ip4_tx_urpf_loose) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP4, VLIB_TX, URPF_MODE_LOOSE));
}

VLIB_NODE_FN (ip4_tx_urpf_strict) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (urpf_inline (vm, node, frame, AF_IP4, VLIB_TX, URPF_MODE_STRICT));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_rx_urpf_loose) = {
  .name = "ip4-rx-urpf-loose",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip4-drop",
  },
  .n_errors = ARRAY_LEN (ip4_urpf_error_strings),
  .error_strings = ip4_urpf_error_strings,

  .format_buffer = format_ip4_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip4_rx_urpf_strict) = {
  .name = "ip4-rx-urpf-strict",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip4-drop",
  },
  .n_errors = ARRAY_LEN (ip4_urpf_error_strings),
  .error_strings = ip4_urpf_error_strings,

  .format_buffer = format_ip4_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip4_tx_urpf_loose) = {
  .name = "ip4-tx-urpf-loose",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip4-drop",
  },
  .n_errors = ARRAY_LEN (ip4_urpf_error_strings),
  .error_strings = ip4_urpf_error_strings,

  .format_buffer = format_ip4_header,
  .format_trace = format_urpf_trace,
};

VLIB_REGISTER_NODE (ip4_tx_urpf_strict) = {
  .name = "ip4-tx-urpf-strict",
  .vector_size = sizeof (u32),

  .n_next_nodes = URPF_N_NEXT,
  .next_nodes = {
    [URPF_NEXT_DROP] = "ip4-drop",
  },
  .n_errors = ARRAY_LEN (ip4_urpf_error_strings),
  .error_strings = ip4_urpf_error_strings,

  .format_buffer = format_ip4_header,
  .format_trace = format_urpf_trace,
};

VNET_FEATURE_INIT (ip4_rx_urpf_loose_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-rx-urpf-loose",
  .runs_before = VNET_FEATURES ("ip4-rx-urpf-strict"),
};

VNET_FEATURE_INIT (ip4_rx_urpf_strict_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-rx-urpf-strict",
  .runs_before = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (ip4_tx_urpf_loose_feat, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-tx-urpf-loose",
};

VNET_FEATURE_INIT (ip4_tx_urpf_strict_feat, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-tx-urpf-strict",
};

VNET_FEATURE_INIT (ip4_local_urpf_loose_feat, static) =
{
  .arc_name = "ip4-local",
  .node_name = "ip4-rx-urpf-loose",
};

VNET_FEATURE_INIT (ip4_local_urpf_strict_feat, static) =
{
  .arc_name = "ip4-local",
  .node_name = "ip4-rx-urpf-strict",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
