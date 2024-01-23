/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#include <pvti/output.h>

/* packet trace format function */
static u8 *
format_pvti_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_output_trace_t *t = va_arg (*args, pvti_output_trace_t *);

  u32 indent = format_get_indent (s);
  s =
    format (s, "PVTI-OUT(%d): sw_if_index %d, next index %d, underlay_mtu %d,",
	    t->trace_type, t->sw_if_index, t->next_index, t->underlay_mtu);
  s = format (s, "\n%U stream_index %d, bi0_max_current_length %d, tx_seq %d",
	      format_white_space, indent, t->stream_index,
	      t->bi0_max_current_length, t->tx_seq);
  s = format (s, "\n%U%U", format_white_space, indent,
	      format_ip_adjacency_packet_data, t->packet_data,
	      sizeof (t->packet_data));

  return s;
}

vlib_node_registration_t pvti_output_node;

static char *pvti_output_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_output_error
#undef _
};

VLIB_REGISTER_NODE (pvti4_output_node) =
{
  .name = "pvti4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(pvti_output_error_strings),
  .error_strings = pvti_output_error_strings,

  .n_next_nodes = PVTI_OUTPUT_N_NEXT,

  .next_nodes = {
        [PVTI_OUTPUT_NEXT_DROP] = "error-drop",
        [PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [PVTI_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [PVTI_OUTPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },

};
VLIB_REGISTER_NODE (pvti6_output_node) =
{
  .name = "pvti6-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(pvti_output_error_strings),
  .error_strings = pvti_output_error_strings,

  .n_next_nodes = PVTI_OUTPUT_N_NEXT,

  .next_nodes = {
        [PVTI_OUTPUT_NEXT_DROP] = "error-drop",
        [PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [PVTI_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [PVTI_OUTPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },

};
