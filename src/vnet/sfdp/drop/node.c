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

#include <vlib/vlib.h>
#include <vnet/sfdp/service.h>
#define foreach_sfdp_drop_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SFDP_DROP_ERROR_##sym,
  foreach_sfdp_drop_error
#undef _
    SFDP_DROP_N_ERROR,
} sfdp_drop_error_t;

static char *sfdp_drop_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_drop_error
#undef _
};

#define foreach_sfdp_drop_next _ (DROP, "error-drop")

typedef enum
{
#define _(n, x) SFDP_DROP_NEXT_##n,
  foreach_sfdp_drop_next
#undef _
    SFDP_DROP_N_NEXT
} sfdp_drop_next_t;

typedef struct
{
  u32 flow_id;
} sfdp_drop_trace_t;

static u8 *
format_sfdp_drop_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_drop_trace_t *t = va_arg (*args, sfdp_drop_trace_t *);

  s = format (s, "sfdp-drop: flow-id %u (session %u, %s)", t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

VLIB_NODE_FN (sfdp_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_buffer_enqueue_to_single_next (vm, node, from, SFDP_DROP_NEXT_DROP,
				      n_left);
  vlib_node_increment_counter (vm, node->node_index, SFDP_DROP_ERROR_DROP,
			       n_left);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      vlib_get_buffers (vm, from, bufs, n_left);
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_drop_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_drop_node) = {
  .name = "sfdp-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_drop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_drop_error_strings),
  .error_strings = sfdp_drop_error_strings,

  .n_next_nodes = SFDP_DROP_N_NEXT,
  .next_nodes = {
#define _(n, x) [SFDP_DROP_NEXT_##n] = x,
          foreach_sfdp_drop_next
#undef _
  }

};

SFDP_SERVICE_DEFINE (drop) = { .node_name = "sfdp-drop",
			       .runs_before = SFDP_SERVICES (0),
			       .runs_after = SFDP_SERVICES (0),
			       .is_terminal = 1 };