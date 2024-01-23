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

#include <pvti/bypass.h>

/* packet trace format function */
static u8 *
format_pvti_bypass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_bypass_trace_t *t = va_arg (*args, pvti_bypass_trace_t *);

  s = format (s, "PVTI-BYPASS: sw_if_index %d, next index %d\n",
	      t->sw_if_index, t->next_index);
  s = format (s, "  src %U sport %d dport %d\n", format_ip_address,
	      &t->remote_ip, t->remote_port, t->local_port);
  s = format (s, "  seq: %d", t->seq);
  return s;
}

vlib_node_registration_t pvti4_bypass_node;
vlib_node_registration_t pvti6_bypass_node;

static char *pvti_bypass_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_bypass_error
#undef _
};

VLIB_REGISTER_NODE (pvti4_bypass_node) =
{
  .name = "ip4-pvti-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pvti_bypass_error_strings),
  .error_strings = pvti_bypass_error_strings,

  .n_next_nodes = PVTI_BYPASS_N_NEXT,

  .next_nodes = {
        [PVTI_BYPASS_NEXT_DROP] = "error-drop",
        [PVTI_BYPASS_NEXT_PVTI_INPUT] = "pvti4-input",
  },

};

VLIB_REGISTER_NODE (pvti6_bypass_node) =
{
  .name = "ip6-pvti-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pvti_bypass_error_strings),
  .error_strings = pvti_bypass_error_strings,

  .n_next_nodes = PVTI_BYPASS_N_NEXT,

  .next_nodes = {
        [PVTI_BYPASS_NEXT_DROP] = "error-drop",
        [PVTI_BYPASS_NEXT_PVTI_INPUT] = "pvti6-input",
  },

};
