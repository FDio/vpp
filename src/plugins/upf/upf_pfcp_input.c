/*
 * Copyright (c) 2018 Travelping GmbH
 *
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
#include <vnet/ip/ip.h>

#include <vnet/udp/udp.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vlibmemory/api.h>
#include "upf_pfcp_server.h"

vlib_node_registration_t sx4_input_node;
vlib_node_registration_t sx6_input_node;

typedef enum
{
#define sx_error(n,s) SX_ERROR_##n,
#include "sx_input_error.def"
#undef sx_error
  SX_N_ERROR,
} sx_error_t;

static char *sx_error_strings[] = {
#define sx_error(n,s) s,
#include "sx_input_error.def"
#undef sx_error
};

typedef struct
{
  u32 connection;
  u32 disposition;
  u32 thread_index;
} sx_input_trace_t;

/* packet trace format function */
static u8 *
format_sx_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sx_input_trace_t *t = va_arg (*args, sx_input_trace_t *);

  s = format (s, "Sx Input: connection %d, disposition %d, thread %d",
	      t->connection, t->disposition, t->thread_index);
  return s;
}

#define foreach_sx_input_next			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) SX_INPUT_NEXT_##s,
  foreach_sx_input_next
#undef _
    SX_INPUT_N_NEXT,
} sx_input_next_t;

always_inline void
sx_input_inc_counter (vlib_main_t * vm, u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, sx4_input_node.index, evt, val);
  else
    vlib_node_increment_counter (vm, sx6_input_node.index, evt, val);
}

always_inline uword
sx46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame, u8 is_ip4)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 my_thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SX_INPUT_NEXT_DROP;
	  u32 error0 = SX_ERROR_ENQUEUED;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  upf_pfcp_handle_input(vm, b0, is_ip4);

	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      sx_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));

	      t->connection = ~0;
	      t->disposition = error0;
	      t->thread_index = my_thread_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

vlib_node_registration_t sx4_input_node;
vlib_node_registration_t sx6_input_node;

static uword
sx4_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return sx46_input_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sx4_input_node) =
{
  .function = sx4_input,
  .name = "upf-sx4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sx_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sx_error_strings),
  .error_strings = sx_error_strings,
  .n_next_nodes = SX_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [SX_INPUT_NEXT_##s] = n,
      foreach_sx_input_next
#undef _
  },
};
/* *INDENT-ON* */

static uword
sx6_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return sx46_input_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sx6_input_node) =
{
  .function = sx6_input,
  .name = "upf-sx6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sx_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (sx_error_strings),
  .error_strings = sx_error_strings,
  .n_next_nodes = SX_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [SX_INPUT_NEXT_##s] = n,
      foreach_sx_input_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
