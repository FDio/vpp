/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <filter/filter_target_drop.h>

typedef struct filter_target_drop_trace_t_
{
} filter_target_drop_trace_t;

/* packet trace format function */
static u8 *
format_filter_target_drop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  // filter_target_drop_trace_t *t = va_arg (*args, filter_target_drop_trace_t *);

  // s = format (s, "sclass:%d", t->sclass);

  return s;
}

VLIB_NODE_FN (filter_target_drop_ip4_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return (0);
}

VLIB_NODE_FN (filter_target_drop_ip6_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return (0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (filter_target_drop_ip4_node) = {
  .name = "filter-target-drop-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_drop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (filter_target_drop_ip6_node) = {
  .name = "filter-target-drop-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_filter_target_drop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
