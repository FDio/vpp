/*
 * handoff_trace.c - used to generate handoff trace records
 *
 * Copyright (c) 2019 Cisco Systems and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

typedef struct
{
  u32 prev_thread;
  u32 prev_trace_index;
} handoff_trace_t;

/* packet trace format function */
static u8 *
format_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  handoff_trace_t *t = va_arg (*args, handoff_trace_t *);

  s = format (s, "HANDED-OFF: from thread %d trace index %d",
	      t->prev_thread, t->prev_trace_index);
  return s;
}

static vlib_node_registration_t handoff_trace_node;

#define foreach_handoff_trace_error \
_(BUGS, "Warning: packets sent to the handoff trace node!")

typedef enum
{
#define _(sym,str) HANDOFF_TRACE_ERROR_##sym,
  foreach_handoff_trace_error
#undef _
    HANDOFF_TRACE_N_ERROR,
} handoff_trace_error_t;

static char *handoff_trace_error_strings[] = {
#define _(sym,string) string,
  foreach_handoff_trace_error
#undef _
};

static uword
handoff_trace_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       HANDOFF_TRACE_ERROR_BUGS, frame->n_vectors);

  return frame->n_vectors;
}

typedef enum
{
  HANDOFF_TRACE_NEXT_DROP,
  HANDOFF_TRACE_N_NEXT,
} tplaceholder_next_t;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (handoff_trace_node, static) =
{
  .name = "handoff_trace",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .function = handoff_trace_node_fn,
  .vector_size = sizeof (u32),
  .format_trace = format_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = HANDOFF_TRACE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [HANDOFF_TRACE_NEXT_DROP] = "error-drop",
  },

  .n_errors = ARRAY_LEN(handoff_trace_error_strings),
  .error_strings = handoff_trace_error_strings,
};
/* *INDENT-ON* */

void
vlib_add_handoff_trace (vlib_main_t * vm, vlib_buffer_t * b)
{
  u32 prev_thread = vlib_buffer_get_trace_thread (b);
  u32 prev_trace_index = vlib_buffer_get_trace_index (b);
  handoff_trace_t *t;
  vlib_node_runtime_t *node
    = vlib_node_get_runtime (vm, handoff_trace_node.index);

  vlib_trace_buffer (vm, node, 0 /* fake next frame index */ ,
		     b, 1 /* folllow chain */ );

  t = vlib_add_trace (vm, node, b, sizeof (*t));

  t->prev_thread = prev_thread;
  t->prev_trace_index = prev_trace_index;
}

void
vlib_add_extra_trace_meta (vlib_main_t * vm, vlib_buffer_t * b,
			   vlib_trace_header_t * h)
{
  h->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
}




/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
