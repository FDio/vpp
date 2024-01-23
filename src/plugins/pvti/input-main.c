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

#include <pvti/input.h>

static char *pvti_input_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_input_error
#undef _
};

#define _(f, s) s,
static char *pvti_input_trace_type_names[] = { foreach_pvti_input_trace_type };
#undef _

static char *
get_pvti_trace_type_name (u8 ptype)
{
  if (ptype < PVTI_INPUT_TRACE_N_TYPES)
    {
      return pvti_input_trace_type_names[ptype];
    }
  else
    {
      return "unknown";
    }
}

/* packet trace format function */
static u8 *
format_pvti_input_trace (u8 *s, va_list *args)
{
  int i;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_input_trace_t *t = va_arg (*args, pvti_input_trace_t *);

  u32 indent = format_get_indent (s);

  s = format (s,
	      "PVTI-IN: sw_if_index %d, next index %d, trace_type: %s(%d), "
	      "chunkcnt: %d\n",
	      t->sw_if_index, t->next_index,
	      get_pvti_trace_type_name (t->trace_type), t->trace_type,
	      t->chunk_count);
  s = format (s, "  src %U sport %d dport %d\n", format_ip_address,
	      &t->remote_ip, t->remote_port, t->local_port);
  s = format (s, "  seq: %d, chunk_count: %d\n", t->seq, t->chunk_count);
  u16 max = t->chunk_count > MAX_CHUNKS ? MAX_CHUNKS : t->chunk_count;
  for (i = 0; i < max; i++)
    {
      s = format (s, "    %02d: sz %d\n", i, t->chunks[i].total_chunk_length);
    }
  s = format (s, "\n%U%U", format_white_space, indent,
	      format_ip_adjacency_packet_data, t->packet_data,
	      sizeof (t->packet_data));

  return s;
}

vlib_node_registration_t pvti4_input_node;
vlib_node_registration_t pvti6_input_node;

VLIB_REGISTER_NODE (pvti4_input_node) =
{
  .name = "pvti4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pvti_input_error_strings),
  .error_strings = pvti_input_error_strings,

  .n_next_nodes = PVTI_INPUT_N_NEXT,

  .next_nodes = {
        [PVTI_INPUT_NEXT_DROP] = "error-drop",
        [PVTI_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [PVTI_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [PVTI_INPUT_NEXT_PUNT] = "error-punt",
  },

};
VLIB_REGISTER_NODE (pvti6_input_node) =
{
  .name = "pvti6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pvti_input_error_strings),
  .error_strings = pvti_input_error_strings,

  .n_next_nodes = PVTI_INPUT_N_NEXT,

  .next_nodes = {
        [PVTI_INPUT_NEXT_DROP] = "error-drop",
        [PVTI_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [PVTI_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [PVTI_INPUT_NEXT_PUNT] = "error-punt",
  },

};
