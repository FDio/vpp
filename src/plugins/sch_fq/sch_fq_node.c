/* Copyright (c) 2023 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include "sch_fq.h"

static u8 *
format_sch_fq_enqueue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  trace_en_t *tr = va_arg (*args, trace_en_t *);
  s = format (s,
	      "packet enqueued, queue: %d, queue position: %d, start time: "
	      "%d, finish time: %d",
	      tr->queue_i, tr->pos, tr->start_time, tr->finish_time);
  return s;
}

static u8 *
format_sch_fq_dequeue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  trace_de_t *tr = va_arg (*args, trace_de_t *);
  s = format (s,
	      "packet dequeued, queue: %d, frame position: %d, packets left "
	      "in this queue: %d, real finish time: %d",
	      tr->queue_i, tr->pos, tr->rem_pkt, tr->num_round);
  return s;
}

static void
enqueue_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
	       sch_fq_buffer_t *fq_b, vlib_buffer_t **b, u32 *from, int n_pkt)
{
  for (u32 i = 0; i < n_pkt; i++)
    {
      u8 class = vnet_buffer2 (b[0])->qos.bits;
      unsigned long long finish_time, start_time;
      if (clib_bitmap_get (fq_b->class_bitmap, class))
	start_time =
	  ring_buffer_back (&fq_b->queue_map[class]).pkt_data.finish_time;
      else
	{
	  start_time = fq_b->num_round;
	  fq_b->class_bitmap = clib_bitmap_set (fq_b->class_bitmap, class, 1);
	}
      finish_time = start_time + b[0]->current_length;
      ring_buffer_push (&(fq_b->queue_map[class]),
			(buffer_t){ .pkt_data.pkt_index = from[i],
				    .pkt_data.finish_time = finish_time });
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  trace_en_t *tr;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->queue_i = class;
	  tr->pos = fq_b->queue_map[class].count - 1;
	  tr->start_time = start_time;
	  tr->finish_time = finish_time;
	}
      b++;
    }
}

static int
select_next_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
		   sch_fq_buffer_t *fq_b, u32 *i_arr, u32 n_pkt)
{

  int i = 0;
  while (!clib_bitmap_is_zero (fq_b->class_bitmap) && i < n_pkt)
    {
      int j = 0, next_pkt_class = 0;
      unsigned long long next_pkt_finish_time = ~0;
      do
	{
	  if (ring_buffer_front (&fq_b->queue_map[j]).pkt_data.finish_time <
	      next_pkt_finish_time)
	    {
	      next_pkt_class = j;
	      next_pkt_finish_time =
		ring_buffer_front (&fq_b->queue_map[j]).pkt_data.finish_time;
	    }
	  j = clib_bitmap_next_set (fq_b->class_bitmap, j + 1);
	}
      while (j != ~0);

      i_arr[i++] =
	ring_buffer_pop (&fq_b->queue_map[next_pkt_class]).pkt_data.pkt_index;

      int pkt_length = vlib_get_buffer (vm, i_arr[i - 1])->current_length;
      fq_b->num_round += (pkt_length + fq_b->num_bit_excess) /
			 clib_bitmap_count_set_bits (fq_b->class_bitmap);
      fq_b->num_bit_excess = (pkt_length + fq_b->num_bit_excess) %
			     clib_bitmap_count_set_bits (fq_b->class_bitmap);

      if (PREDICT_FALSE (vlib_get_buffer (vm, i_arr[i - 1])->flags &
			 VLIB_BUFFER_IS_TRACED))
	{
	  trace_de_t *tr;
	  tr = vlib_add_trace (vm, node, vlib_get_buffer (vm, i_arr[i - 1]),
			       sizeof (*tr));
	  tr->queue_i = next_pkt_class;
	  tr->pos = i - 1;
	  tr->rem_pkt = fq_b->queue_map[next_pkt_class].count;
	  tr->num_round = fq_b->num_round;
	}

      if (ring_buffer_empty (&fq_b->queue_map[next_pkt_class]))
	clib_bitmap_set (fq_b->class_bitmap, next_pkt_class, 0);
    }

  return i;
}

static uword
sch_fq_enqueue_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame)
{

  sch_fq_buffer_t *fq_b = vec_elt_at_index (fq_buffer, vm->thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_pkt, *from;

  from = vlib_frame_vector_args (frame);
  n_pkt = frame->n_vectors;
  b = bufs;

  vlib_get_buffers (vm, from, bufs, n_pkt);
  enqueue_frame (vm, node, fq_b, b, from, n_pkt);

  return n_pkt;
}

static uword
sch_fq_dequeue_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame)
{

  sch_fq_buffer_t *fq_b = vec_elt_at_index (fq_buffer, vm->thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 i_arr[VLIB_FRAME_SIZE];
  u16 next[VLIB_FRAME_SIZE];

  int n_pkt = select_next_frame (vm, node, fq_b, i_arr, VLIB_FRAME_SIZE);
  vlib_get_buffers (vm, i_arr, bufs, n_pkt);

  for (int i = 0; i < n_pkt; i++)
    vnet_feature_next_u16 (&next[i], bufs[i]);

  vlib_buffer_enqueue_to_next (vm, node, i_arr, next, n_pkt);

  return n_pkt;
}

VLIB_REGISTER_NODE (sch_fq_enqueue_node) = {
  .function = sch_fq_enqueue_node_fn,
  .name = "sch_fq_enqueue_node",
  .vector_size = sizeof (32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "sch_fq_dequeue_node",
  .format_trace = format_sch_fq_enqueue_trace,
};

VLIB_REGISTER_NODE (sch_fq_dequeue_node) = {
  .function = sch_fq_dequeue_node_fn,
  .name = "sch_fq_dequeue_node",
  .vector_size = sizeof (32),
  .type = VLIB_NODE_TYPE_INPUT,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_sch_fq_dequeue_trace,
};

VNET_FEATURE_INIT (sch_fq_enqueue_feat, static) = {
  .arc_name = "interface-output",
  .node_name = "sch_fq_enqueue_node",
};