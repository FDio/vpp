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
#include <vnet/vnet.h>
#include <ikev2/ikev2_priv.h>

extern ikev2_main_t ikev2_main;

#define foreach_ikev2_handoff_error _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) IKEV2_HANDOFF_ERROR_##sym,
  foreach_ikev2_handoff_error
#undef _
    IKEV2_HANDOFF_N_ERROR,
} ikev2_handoff_error_t;

static char *ikev2_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ikev2_handoff_error
#undef _
};

typedef struct ikev2_handoff_trace_t_
{
  u32 current_worker_index;
  u32 next_worker_index;
} ikev2_handoff_trace_t;

u8 *
format_ikev2_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ikev2_handoff_trace_t *t = va_arg (*args, ikev2_handoff_trace_t *);
  s = format (s, "ikev2 handoff  %d to %d", t->current_worker_index,
	      t->next_worker_index);
  return s;
}

static_always_inline uword
ikev2_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u32 fq_index)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  u32 this_thread;

  this_thread = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      ti[0] = km->handoff_thread;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ikev2_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->current_worker_index = this_thread;
	  t->next_worker_index = ti[0];
	}
      n_left_from--;
      ti++;
      b++;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 IKEV2_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return n_enq;
}

/* Do worker handoff based on the ikev2's thread_index */
VLIB_NODE_FN (ikev2_ip4_handoff)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ikev2_main_t *km = &ikev2_main;

  return ikev2_handoff_inline (vm, node, from_frame, km->handoff_ip4_fq_index);
}

VLIB_NODE_FN (ikev2_ip4_natt_handoff)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ikev2_main_t *km = &ikev2_main;

  return ikev2_handoff_inline (vm, node, from_frame,
			       km->handoff_ip4_natt_fq_index);
}

VLIB_NODE_FN (ikev2_ip6_handoff)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ikev2_main_t *km = &ikev2_main;

  return ikev2_handoff_inline (vm, node, from_frame, km->handoff_ip6_fq_index);
}

VLIB_REGISTER_NODE (ikev2_ip4_handoff) = {
  .name = "ikev2-ip4-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ikev2_handoff_error_strings),
  .error_strings = ikev2_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ikev2_ip4_natt_handoff) = {
  .name = "ikev2-ip4-natt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ikev2_handoff_error_strings),
  .error_strings = ikev2_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ikev2_ip6_handoff) = {
  .name = "ikev2-ip6-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ikev2_handoff_error_strings),
  .error_strings = ikev2_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
