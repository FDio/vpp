/*
 * mpls_features.c: MPLS input and output features
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/mpls/mpls.h>

static u8 *
format_mpls_drop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  return s;
}

static void
mpls_drop_trace (vlib_main_t * vm,
                 vlib_node_runtime_t * node,
                 vlib_frame_t * frame)
{
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 1)
    {
      vlib_buffer_t *b0;
      u32 bi0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          vlib_add_trace (vm, node, b0, 0);
      }
      from += 1;
      n_left -= 1;
    }
}

always_inline uword
mpls_terminate (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * frame,
                int error_code)
{
  u32 * buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
      mpls_drop_trace (vm, node, frame);

  vlib_error_drop_buffers (vm, node,
                           buffers,
                           /* stride */ 1,
                           n_packets,
                           /* next */ 0,
                           mpls_input_node.index,
                           error_code);

  return n_packets;
}

VLIB_NODE_FN (mpls_punt_node) (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_PUNT));
}

VLIB_REGISTER_NODE (mpls_punt_node) = {
  .name = "mpls-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_mpls_drop_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VLIB_NODE_FN (mpls_drop_node) (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_DROP));
}

VLIB_REGISTER_NODE (mpls_drop_node) = {
  .name = "mpls-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_mpls_drop_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (mpls_not_enabled_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_NOT_ENABLED));
}

VLIB_REGISTER_NODE (mpls_not_enabled_node) = {
  .name = "mpls-not-enabled",
  .vector_size = sizeof (u32),
  .format_trace = format_mpls_drop_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VNET_FEATURE_ARC_INIT (mpls_input, static) =
{
  .arc_name  = "mpls-input",
  .start_nodes = VNET_FEATURES ("mpls-input"),
  .last_in_arc = "mpls-lookup",
  .arc_index_ptr = &mpls_main.input_feature_arc_index,
};

VNET_FEATURE_INIT (mpls_not_enabled, static) = {
  .arc_name = "mpls-input",
  .node_name = "mpls-not-enabled",
  .runs_before = VNET_FEATURES ("mpls-lookup"),
};

VNET_FEATURE_INIT (mpls_lookup, static) = {
  .arc_name = "mpls-input",
  .node_name = "mpls-lookup",
  .runs_before = VNET_FEATURES (0), /* not before any other features */
};

VNET_FEATURE_ARC_INIT (mpls_output, static) =
{
  .arc_name  = "mpls-output",
  .start_nodes = VNET_FEATURES ("mpls-output", "mpls-midchain"),
  .last_in_arc = "interface-output",
  .arc_index_ptr = &mpls_main.output_feature_arc_index,
};

/* Built-in ip4 tx feature path definition */
VNET_FEATURE_INIT (mpls_interface_output, static) = {
  .arc_name = "mpls-output",
  .node_name = "interface-output",
  .runs_before = 0, /* not before any other features */
};

static clib_error_t *
mpls_sw_interface_add_del (vnet_main_t * vnm,
                           u32 sw_if_index,
                           u32 is_add)
{
  mpls_main_t * mm = &mpls_main;

  vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);
  vec_validate_init_empty (mm->fib_index_by_sw_if_index, sw_if_index, 0);

  vnet_feature_enable_disable ("mpls-input", "mpls-not-enabled", sw_if_index,
			       is_add, 0, 0);

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (mpls_sw_interface_add_del);


