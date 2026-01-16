/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <hdrskip/hdrskip.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 skip_bytes;
} hdrskip_input_trace_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 restore_bytes;
} hdrskip_output_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_hdrskip_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  hdrskip_input_trace_t *t = va_arg (*args, hdrskip_input_trace_t *);

  s = format (s, "HDRSKIP input: sw_if_index %u, next %u, skip_bytes %u\n",
	      t->sw_if_index, t->next_index, t->skip_bytes);
  return s;
}

static u8 *
format_hdrskip_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  hdrskip_output_trace_t *t = va_arg (*args, hdrskip_output_trace_t *);

  s = format (s, "HDRSKIP output: sw_if_index %u, next %u, restore_bytes %u\n",
	      t->sw_if_index, t->next_index, t->restore_bytes);
  return s;
}

vlib_node_registration_t hdrskip_input_node;
vlib_node_registration_t hdrskip_output_node;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_hdrskip_input_error \
  _(TOO_SHORT, "skip exceeds buffer length")

typedef enum
{
#define _(sym, str) HDRSKIP_INPUT_ERROR_##sym,
  foreach_hdrskip_input_error
#undef _
    HDRSKIP_INPUT_N_ERROR,
} hdrskip_input_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *hdrskip_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hdrskip_input_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  HDRSKIP_INPUT_NEXT_DROP,
  HDRSKIP_INPUT_N_NEXT,
} hdrskip_input_next_t;

#define foreach_hdrskip_output_error \
  _(NO_HEADROOM, "restore exceeds buffer headroom")

typedef enum
{
#define _(sym, str) HDRSKIP_OUTPUT_ERROR_##sym,
  foreach_hdrskip_output_error
#undef _
    HDRSKIP_OUTPUT_N_ERROR,
} hdrskip_output_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *hdrskip_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hdrskip_output_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  HDRSKIP_OUTPUT_NEXT_DROP,
  HDRSKIP_OUTPUT_N_NEXT,
} hdrskip_output_next_t;

always_inline uword
hdrskip_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, int is_trace)
{
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      u32 skip_bytes =
	(sw_if_index < vec_len (hsm->input_skip_by_sw_if_index)) ?
	  hsm->input_skip_by_sw_if_index[sw_if_index] : 0;
      u32 next0;

      vnet_feature_next (&next0, b0);

      if (PREDICT_FALSE (skip_bytes > b0->current_length))
	{
	  b0->error = node->errors[HDRSKIP_INPUT_ERROR_TOO_SHORT];
	  next0 = HDRSKIP_INPUT_NEXT_DROP;
	}
      else if (skip_bytes)
	{
	  vlib_buffer_advance (b0, (i16) skip_bytes);
	}

      if (is_trace && (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hdrskip_input_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_index = next0;
	  t->sw_if_index = sw_if_index;
	  t->skip_bytes = skip_bytes;
	}

      next[0] = next0;
      b++;
      next++;
      n_left_from--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (hdrskip_input_node) (vlib_main_t *vm,
			       vlib_node_runtime_t *node,
			       vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return hdrskip_input_inline (vm, node, frame, 1 /* is_trace */);
  return hdrskip_input_inline (vm, node, frame, 0 /* is_trace */);
}

always_inline uword
hdrskip_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_trace)
{
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      u32 restore_bytes =
	(sw_if_index < vec_len (hsm->output_restore_by_sw_if_index)) ?
	  hsm->output_restore_by_sw_if_index[sw_if_index] : 0;
      u32 next0;

      vnet_feature_next (&next0, b0);

      if (PREDICT_FALSE (restore_bytes > b0->current_data))
	{
	  b0->error = node->errors[HDRSKIP_OUTPUT_ERROR_NO_HEADROOM];
	  next0 = HDRSKIP_OUTPUT_NEXT_DROP;
	}
      else if (restore_bytes)
	{
	  vlib_buffer_advance (b0, (i16) -restore_bytes);
	}

      if (is_trace && (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hdrskip_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_index = next0;
	  t->sw_if_index = sw_if_index;
	  t->restore_bytes = restore_bytes;
	}

      next[0] = next0;
      b++;
      next++;
      n_left_from--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (hdrskip_output_node) (vlib_main_t *vm,
				vlib_node_runtime_t *node,
				vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return hdrskip_output_inline (vm, node, frame, 1 /* is_trace */);
  return hdrskip_output_inline (vm, node, frame, 0 /* is_trace */);
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (hdrskip_input_node) = {
  .name = "hdrskip-input",
  .vector_size = sizeof (u32),
  .format_trace = format_hdrskip_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (hdrskip_input_error_strings),
  .error_strings = hdrskip_input_error_strings,

  .n_next_nodes = HDRSKIP_INPUT_N_NEXT,

  .next_nodes = {
    [HDRSKIP_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (hdrskip_output_node) = {
  .name = "hdrskip-output",
  .vector_size = sizeof (u32),
  .format_trace = format_hdrskip_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (hdrskip_output_error_strings),
  .error_strings = hdrskip_output_error_strings,

  .n_next_nodes = HDRSKIP_OUTPUT_N_NEXT,

  .next_nodes = {
    [HDRSKIP_OUTPUT_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
