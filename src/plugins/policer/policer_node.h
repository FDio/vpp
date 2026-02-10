/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __POLICER_NODE_H__
#define __POLICER_NODE_H__

#include <stdbool.h>

#include <vlib/vlib.h>

#include <policer/policer.h>

typedef enum
{
  VNET_POLICER_NEXT_DROP,
  VNET_POLICER_NEXT_HANDOFF,
  VNET_POLICER_N_NEXT,
} policer_next_t;

typedef enum
{
  POLICER_HANDOFF_ERROR_CONGESTION_DROP,
} policer_handoff_error_t;

typedef struct policer_handoff_trace_t_
{
  u32 policer_index;
  u32 current_worker_index;
  u32 next_worker_index;
} policer_handoff_trace_t;

extern u8 *format_policer_handoff_trace (u8 *s, va_list *args);

extern vlib_node_registration_t policer_input_node;
extern vlib_node_registration_t policer_output_node;

/* Do worker handoff based on the policer's thread_index */
always_inline uword
policer_handoff (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u32 fq_index,
		 u32 policer_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  policer_main_t *pm;
  policer_t *policer;
  u32 this_thread, policer_thread = 0;
  bool single_policer_node = (policer_index != ~0);

  pm = &policer_main;
  if (single_policer_node)
    {
      policer = &pm->policers[policer_index];
      policer_thread = policer->thread_index;
    }

  this_thread = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      if (!single_policer_node)
	{
	  policer_index = vnet_buffer (b[0])->policer.index;
	  policer = &pm->policers[policer_index];
	  ti[0] = policer->thread_index;
	}
      else
	{
	  ti[0] = policer_thread;
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  policer_handoff_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->current_worker_index = this_thread;
	  t->next_worker_index = ti[0];
	  t->policer_index = policer_index;
	}

      n_left_from--;
      ti++;
      b++;
    }

  n_enq =
    vlib_buffer_enqueue_to_thread (vm, node, fq_index, from, thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index, POLICER_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}

#endif // !__POLICER_NODE_H__
