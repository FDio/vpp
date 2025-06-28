// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/service.h>
#include <vcdp/vcdp.api_enum.h>

#define foreach_vcdp_drop_next _(DROP, "error-drop")
typedef enum {
#define _(n, x) VCDP_DROP_NEXT_##n,
  foreach_vcdp_drop_next
#undef _
    VCDP_DROP_N_NEXT
} vcdp_drop_next_t;

typedef struct {
  u32 flow_id;
} vcdp_drop_trace_t;

static u8 *
format_vcdp_drop_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_drop_trace_t *t = va_arg(*args, vcdp_drop_trace_t *);

  s = format(s, "vcdp-drop: flow-id %u (session %u, %s)", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

VLIB_NODE_FN(vcdp_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers(vm, from, bufs, n_left);

  for (int i=0; i<n_left; i++) {
    vlib_buffer_t *b = bufs[i];
    if (b->error)
      continue;
    b->error = node->errors[VCDP_DROP_ERROR_UNKNOWN];
  }

  vlib_buffer_enqueue_to_single_next(vm, node, from, VCDP_DROP_NEXT_DROP, n_left);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_drop_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_drop_node) = {
  .name = "vcdp-drop",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_drop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = VCDP_DROP_N_NEXT,
  .next_nodes = {
#define _(n, x) [VCDP_DROP_NEXT_##n] = x,
  foreach_vcdp_drop_next
#undef _
  },
  .error_counters = vcdp_drop_error_counters,
  .n_errors = VCDP_DROP_N_ERROR,

};

VCDP_SERVICE_DEFINE(drop) = {
  .node_name = "vcdp-drop",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 1
};