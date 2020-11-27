/*
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

#include <vnet/buffer.h>
#include <vlib/vlib.h>
#include <vnet/dpo/dpo.h>

#include <vnet/bier/bier_hdr_inlines.h>

typedef struct bier_drop_trace_t_
{
    index_t dpi;
} bier_drop_trace_t;

static void
bier_drop_trace (vlib_main_t * vm,
                 vlib_node_runtime_t * node,
                 vlib_frame_t * frame)
{
  u32 *from, n_left;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      bier_drop_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          t0 = vlib_add_trace (vm, node, b0, sizeof(*t0));

          t0->dpi = vnet_buffer (b0)->ip.adj_index;
      }
      from += 1;
      n_left -= 1;
    }
}

static uword
bier_drop (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
    u32 *buffers = vlib_frame_vector_args (frame);
    uword n_packets = frame->n_vectors;

    if (node->flags & VLIB_NODE_FLAG_TRACE)
        bier_drop_trace (vm, node, frame);

    vlib_error_drop_buffers (vm, node, buffers,
                             /* stride */ 1,
                             n_packets,
                             /* next */ 0,
                             0, // bier_input_node.index,
                             0);

    return n_packets;
}

static u8 *
format_bier_drop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bier_drop_trace_t *t = va_arg (*args, bier_drop_trace_t *);

  s = format (s, "dpo-idx %d", t->dpi);

  return s;
}

VLIB_REGISTER_NODE (bier_drop_node, static) =
{
    .function = bier_drop,
    .name = "bier-drop",
    .vector_size = sizeof (u32),
    .format_trace = format_bier_drop_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    },
};
