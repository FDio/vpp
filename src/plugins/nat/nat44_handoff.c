/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT44 worker handoff
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/handoff.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>
#include <nat/nat.h>

typedef struct
{
  u32 next_worker_index;
  u8 in2out;
} nat44_handoff_trace_t;

#define foreach_nat44_handoff_error                       \
_(CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym,str) NAT44_HANDOFF_ERROR_##sym,
  foreach_nat44_handoff_error
#undef _
    NAT44_HANDOFF_N_ERROR,
} nat44_handoff_error_t;

static char *nat44_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_nat44_handoff_error
#undef _
};


vlib_node_registration_t snat_in2out_worker_handoff_node;
vlib_node_registration_t snat_in2out_output_worker_handoff_node;
vlib_node_registration_t snat_out2in_worker_handoff_node;

static u8 *
format_nat44_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_handoff_trace_t *t = va_arg (*args, nat44_handoff_trace_t *);
  char *tag;

  tag = t->in2out ? "IN2OUT" : "OUT2IN";
  s =
    format (s, "NAT44_%s_WORKER_HANDOFF: next-worker %d", tag,
	    t->next_worker_index);

  return s;
}

static inline uword
nat44_worker_handoff_fn_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame, u8 is_output,
				u8 is_in2out)
{
  snat_main_t *sm = &snat_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 fq_index;
  snat_get_worker_function_t *get_worker;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  ASSERT (vec_len (sm->workers));

  if (is_in2out)
    {
      get_worker = sm->worker_in2out_cb;
      if (is_output)
	fq_index = sm->fq_in2out_output_index;
      else
	fq_index = sm->fq_in2out_index;
    }
  else
    {
      fq_index = sm->fq_out2in_index;
      get_worker = sm->worker_out2in_cb;
    }

  while (n_left_from > 0)
    {
      u32 sw_if_index0;
      u32 rx_fib_index0;
      ip4_header_t *ip0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
      ip0 = vlib_buffer_get_current (b[0]);
      ti[0] = get_worker (ip0, rx_fib_index0);

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	  t->in2out = is_in2out;
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq =
    vlib_buffer_enqueue_to_thread (vm, fq_index, from, thread_indices,
				   frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 NAT44_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return frame->n_vectors;
}

static uword
snat_in2out_worker_handoff_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return nat44_worker_handoff_fn_inline (vm, node, frame, 0, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_in2out_worker_handoff_node) = {
  .function = snat_in2out_worker_handoff_fn,
  .name = "nat44-in2out-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_handoff_error_strings),
  .error_strings = nat44_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_worker_handoff_node,
			      snat_in2out_worker_handoff_fn);

static uword
snat_in2out_output_worker_handoff_fn (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return nat44_worker_handoff_fn_inline (vm, node, frame, 1, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_in2out_output_worker_handoff_node) = {
  .function = snat_in2out_output_worker_handoff_fn,
  .name = "nat44-in2out-output-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_handoff_error_strings),
  .error_strings = nat44_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_worker_handoff_node,
			      snat_in2out_output_worker_handoff_fn);

static uword
snat_out2in_worker_handoff_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return nat44_worker_handoff_fn_inline (vm, node, frame, 0, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_out2in_worker_handoff_node) = {
  .function = snat_out2in_worker_handoff_fn,
  .name = "nat44-out2in-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_handoff_error_strings),
  .error_strings = nat44_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_worker_handoff_node,
			      snat_out2in_worker_handoff_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
