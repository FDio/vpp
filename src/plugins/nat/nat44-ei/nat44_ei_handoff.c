/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/handoff.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>

#include <nat/nat44-ei/nat44_ei.h>

typedef struct
{
  u32 next_worker_index;
  u32 trace_index;
  u8 in2out;
  u8 output;
} nat44_ei_handoff_trace_t;

#define foreach_nat44_ei_handoff_error                                        \
  _ (CONGESTION_DROP, "congestion drop")                                      \
  _ (SAME_WORKER, "same worker")                                              \
  _ (DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym, str) NAT44_EI_HANDOFF_ERROR_##sym,
  foreach_nat44_ei_handoff_error
#undef _
    NAT44_EI_HANDOFF_N_ERROR,
} nat44_ei_handoff_error_t;

static char *nat44_ei_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_nat44_ei_handoff_error
#undef _
};

static u8 *
format_nat44_ei_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_handoff_trace_t *t = va_arg (*args, nat44_ei_handoff_trace_t *);
  char *tag, *output;

  tag = t->in2out ? "IN2OUT" : "OUT2IN";
  output = t->output ? "OUTPUT-FEATURE" : "";
  s =
    format (s, "NAT44_EI_%s_WORKER_HANDOFF %s: next-worker %d trace index %d",
	    tag, output, t->next_worker_index, t->trace_index);

  return s;
}

static inline uword
nat44_ei_worker_handoff_fn_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				   vlib_frame_t *frame, u8 is_output,
				   u8 is_in2out)
{
  u32 n_enq, n_left_from, *from, do_handoff = 0, same_worker = 0;

  u16 thread_indices[VLIB_FRAME_SIZE], *ti = thread_indices;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  nat44_ei_main_t *nm = &nat44_ei_main;

  u32 fq_index, thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left_from);

  // TODO: move to nm
  // TODO: remove callbacks and use inlines that should be moved here
  if (is_in2out)
    {
      fq_index = is_output ? nm->fq_in2out_output_index : nm->fq_in2out_index;
    }
  else
    {
      fq_index = nm->fq_out2in_index;
    }

  while (n_left_from >= 4)
    {
      u32 arc_next0, arc_next1, arc_next2, arc_next3;
      u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
      u32 rx_fib_index0, rx_fib_index1, rx_fib_index2, rx_fib_index3;
      u32 iph_offset0 = 0, iph_offset1 = 0, iph_offset2 = 0, iph_offset3 = 0;
      ip4_header_t *ip0, *ip1, *ip2, *ip3;

      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	  CLIB_PREFETCH (&b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&b[6]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&b[7]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (is_output)
	{
	  iph_offset0 = vnet_buffer (b[0])->ip.save_rewrite_length;
	  iph_offset1 = vnet_buffer (b[1])->ip.save_rewrite_length;
	  iph_offset2 = vnet_buffer (b[2])->ip.save_rewrite_length;
	  iph_offset3 = vnet_buffer (b[3])->ip.save_rewrite_length;
	}

      ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset0);
      ip1 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[1]) + iph_offset1);
      ip2 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[2]) + iph_offset2);
      ip3 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[3]) + iph_offset3);

      vnet_feature_next (&arc_next0, b[0]);
      vnet_feature_next (&arc_next1, b[1]);
      vnet_feature_next (&arc_next2, b[2]);
      vnet_feature_next (&arc_next3, b[3]);

      vnet_buffer2 (b[0])->nat.arc_next = arc_next0;
      vnet_buffer2 (b[1])->nat.arc_next = arc_next1;
      vnet_buffer2 (b[2])->nat.arc_next = arc_next2;
      vnet_buffer2 (b[3])->nat.arc_next = arc_next3;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index2 = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index3 = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
      rx_fib_index1 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index1);
      rx_fib_index2 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index2);
      rx_fib_index3 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index3);

      if (is_in2out)
	{
	  ti[0] =
	    nat44_ei_get_in2out_worker_index (ip0, rx_fib_index0, is_output);
	  ti[1] =
	    nat44_ei_get_in2out_worker_index (ip1, rx_fib_index1, is_output);
	  ti[2] =
	    nat44_ei_get_in2out_worker_index (ip2, rx_fib_index2, is_output);
	  ti[3] =
	    nat44_ei_get_in2out_worker_index (ip3, rx_fib_index3, is_output);
	}
      else
	{
	  ti[0] = nat44_ei_get_out2in_worker_index (b[0], ip0, rx_fib_index0,
						    is_output);
	  ti[1] = nat44_ei_get_out2in_worker_index (b[1], ip1, rx_fib_index1,
						    is_output);
	  ti[2] = nat44_ei_get_out2in_worker_index (b[2], ip2, rx_fib_index2,
						    is_output);
	  ti[3] = nat44_ei_get_out2in_worker_index (b[3], ip3, rx_fib_index3,
						    is_output);
	}

      if (ti[0] == thread_index)
	same_worker++;
      else
	do_handoff++;

      if (ti[1] == thread_index)
	same_worker++;
      else
	do_handoff++;

      if (ti[2] == thread_index)
	same_worker++;
      else
	do_handoff++;

      if (ti[3] == thread_index)
	same_worker++;
      else
	do_handoff++;

      b += 4;
      ti += 4;
      n_left_from -= 4;
    }

  while (n_left_from > 0)
    {
      u32 arc_next0;
      u32 sw_if_index0;
      u32 rx_fib_index0;
      u32 iph_offset0 = 0;
      ip4_header_t *ip0;

      if (is_output)
	iph_offset0 = vnet_buffer (b[0])->ip.save_rewrite_length;

      ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset0);

      vnet_feature_next (&arc_next0, b[0]);
      vnet_buffer2 (b[0])->nat.arc_next = arc_next0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

      if (is_in2out)
	{
	  ti[0] =
	    nat44_ei_get_in2out_worker_index (ip0, rx_fib_index0, is_output);
	}
      else
	{
	  ti[0] = nat44_ei_get_out2in_worker_index (b[0], ip0, rx_fib_index0,
						    is_output);
	}

      if (ti[0] == thread_index)
	same_worker++;
      else
	do_handoff++;

      b += 1;
      ti += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      u32 i;
      b = bufs;
      ti = thread_indices;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nat44_ei_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_worker_index = ti[0];
	      t->trace_index = vlib_buffer_get_trace_index (b[0]);
	      t->in2out = is_in2out;
	      t->output = is_output;

	      b += 1;
	      ti += 1;
	    }
	  else
	    break;
	}
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, fq_index, from, thread_indices,
					 frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    {
      vlib_node_increment_counter (vm, node->node_index,
				   NAT44_EI_HANDOFF_ERROR_CONGESTION_DROP,
				   frame->n_vectors - n_enq);
    }

  vlib_node_increment_counter (
    vm, node->node_index, NAT44_EI_HANDOFF_ERROR_SAME_WORKER, same_worker);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_EI_HANDOFF_ERROR_DO_HANDOFF, do_handoff);
  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ei_in2out_worker_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_worker_handoff_fn_inline (vm, node, frame, 0, 1);
}

VLIB_NODE_FN (nat44_ei_in2out_output_worker_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_worker_handoff_fn_inline (vm, node, frame, 1, 1);
}

VLIB_NODE_FN (nat44_ei_out2in_worker_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_worker_handoff_fn_inline (vm, node, frame, 0, 0);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_output_worker_handoff_node) = {
  .name = "nat44-ei-in2out-output-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat44_ei_handoff_error_strings),
  .error_strings = nat44_ei_handoff_error_strings,
};

VLIB_REGISTER_NODE (nat44_ei_in2out_worker_handoff_node) = {
  .name = "nat44-ei-in2out-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat44_ei_handoff_error_strings),
  .error_strings = nat44_ei_handoff_error_strings,
};

VLIB_REGISTER_NODE (nat44_ei_out2in_worker_handoff_node) = {
  .name = "nat44-ei-out2in-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat44_ei_handoff_error_strings),
  .error_strings = nat44_ei_handoff_error_strings,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
