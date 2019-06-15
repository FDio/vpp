/*
 * drop.c - Punt and drop nodes
 *
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

typedef enum
{
  ERROR_DISPOSITION_DROP,
  ERROR_DISPOSITION_PUNT,
  ERROR_N_DISPOSITION,
} error_disposition_t;

static u8 *
validate_error (vlib_main_t * vm, vlib_error_t * e, u32 index)
{
  uword node_index = vlib_error_get_node (e[0]);
  uword code = vlib_error_get_code (e[0]);
  vlib_node_t *n;

  if (node_index >= vec_len (vm->node_main.nodes))
    return format (0, "[%d], node index out of range 0x%x, error 0x%x",
		   index, node_index, e[0]);

  n = vlib_get_node (vm, node_index);
  if (code >= n->n_errors)
    return format (0, "[%d], code %d out of range for node %v",
		   index, code, n->name);

  return 0;
}

static u8 *
validate_error_frame (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * f)
{
  u32 *buffers = vlib_frame_vector_args (f);
  vlib_buffer_t *b;
  u8 *msg = 0;
  uword i;

  for (i = 0; i < f->n_vectors; i++)
    {
      b = vlib_get_buffer (vm, buffers[i]);
      msg = validate_error (vm, &b->error, i);
      if (msg)
	return msg;
    }

  return msg;
}

always_inline u32
counter_index (vlib_main_t * vm, vlib_error_t e)
{
  vlib_node_t *n;
  u32 ci, ni;

  ni = vlib_error_get_node (e);
  n = vlib_get_node (vm, ni);

  ci = vlib_error_get_code (e);
  ASSERT (ci < n->n_errors);

  ci += n->error_heap_index;

  return ci;
}

static u8 *
format_error_trace (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vlib_error_t *e = va_arg (*va, vlib_error_t *);
  vlib_node_t *error_node;
  vlib_error_main_t *em = &vm->error_main;
  u32 i;

  error_node = vlib_get_node (vm, vlib_error_get_node (e[0]));
  i = counter_index (vm, e[0]);
  s = format (s, "%v: %s", error_node->name, em->error_strings_heap[i]);

  return s;
}

static void
trace_errors (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left, *buffers;

  buffers = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      vlib_error_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, buffers[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[3], LOAD);

      bi0 = buffers[0];
      bi1 = buffers[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0[0] = b0->error;
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1[0] = b1->error;
	}
      buffers += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      vlib_error_t *t0;

      bi0 = buffers[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0[0] = b0->error;
	}
      buffers += 1;
      n_left -= 1;
    }
}

static_always_inline uword
process_drop_punt (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, error_disposition_t disposition)
{
  u32 errors[VLIB_FRAME_SIZE], *error, *from, n_left;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_error_main_t *em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  error = errors;

  vlib_get_buffers (vm, from, bufs, n_left);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    trace_errors (vm, node, frame);

  /* collect the array of error first ... */
  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  /* Prefetch 8 ahead - there's not much going on in each iteration */
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	}
      error[0] = b[0]->error;
      error[1] = b[1]->error;
      error[2] = b[2]->error;
      error[3] = b[3]->error;

      error += 4;
      n_left -= 4;
      b += 4;
    }
  while (n_left)
    {
      error[0] = b[0]->error;

      error += 1;
      n_left -= 1;
      b += 1;
    }

  /* ... then count against them in blocks */
  n_left = frame->n_vectors;

  while (n_left)
    {
      u16 off, count;
      u32 c_index;

      off = frame->n_vectors - n_left;

      error = errors + off;

      count = clib_count_equal_u32 (error, n_left);
      n_left -= count;

      c_index = counter_index (vm, error[0]);
      em->counters[c_index] += count;

      vlib_error_elog_count (vm, c_index, count);
    }

  if (disposition == ERROR_DISPOSITION_DROP || !vm->os_punt_frame)
    {
      vlib_buffer_free (vm, from, frame->n_vectors);

      /* If there is no punt function, free the frame as well. */
      if (disposition == ERROR_DISPOSITION_PUNT && !vm->os_punt_frame)
	vlib_frame_free (vm, node, frame);
    }
  else
    vm->os_punt_frame (vm, node, frame);

  return frame->n_vectors;
}

VLIB_NODE_FN (error_drop_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return process_drop_punt (vm, node, frame, ERROR_DISPOSITION_DROP);
}

VLIB_NODE_FN (error_punt_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return process_drop_punt (vm, node, frame, ERROR_DISPOSITION_PUNT);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (error_drop_node) = {
  .name = "drop",
  .flags = VLIB_NODE_FLAG_IS_DROP,
  .vector_size = sizeof (u32),
  .format_trace = format_error_trace,
  .validate_frame = validate_error_frame,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (error_punt_node) = {
  .name = "punt",
  .flags = (VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH
	    | VLIB_NODE_FLAG_IS_PUNT),
  .vector_size = sizeof (u32),
  .format_trace = format_error_trace,
  .validate_frame = validate_error_frame,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
