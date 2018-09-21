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
  u8 do_handoff;
  u8 in2out;
} nat44_handoff_trace_t;

#define foreach_nat44_handoff_error                       \
_(FQ_CONGESTED, "Handoff frame queue congested")

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
  char *m, *tag;

  m = t->do_handoff ? "next worker" : "same worker";
  tag = t->in2out ? "IN2OUT" : "OUT2IN";
  s =
    format (s, "NAT44_%s_WORKER_HANDOFF: %s %d", tag, m,
	    t->next_worker_index);

  return s;
}

static inline uword
nat44_worker_handoff_fn_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame, u8 is_output,
				u8 is_in2out)
{
  snat_main_t *sm = &snat_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_left_from, *from, *to_next = 0, *to_next_drop = 0;
  static __thread vlib_frame_queue_elt_t **handoff_queue_elt_by_worker_index;
  static __thread vlib_frame_queue_t **congested_handoff_queue_by_worker_index
    = 0;
  vlib_frame_queue_elt_t *hf = 0;
  vlib_frame_queue_t *fq;
  vlib_frame_t *f = 0;
  int i;
  u32 n_left_to_next_worker = 0, *to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  u32 thread_index = vm->thread_index;
  u32 fq_index;
  u32 to_node_index;
  vlib_frame_t *d = 0;

  ASSERT (vec_len (sm->workers));

  if (is_in2out)
    {
      if (is_output)
	{
	  fq_index = sm->fq_in2out_output_index;
	  to_node_index = sm->in2out_output_node_index;
	}
      else
	{
	  fq_index = sm->fq_in2out_index;
	  to_node_index = sm->in2out_node_index;
	}
    }
  else
    {
      fq_index = sm->fq_out2in_index;
      to_node_index = sm->out2in_node_index;
    }

  if (PREDICT_FALSE (handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);

      vec_validate_init_empty (congested_handoff_queue_by_worker_index,
			       tm->n_vlib_mains - 1,
			       (vlib_frame_queue_t *) (~0));
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;
      u32 rx_fib_index0;
      ip4_header_t *ip0;
      u8 do_handoff;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

      ip0 = vlib_buffer_get_current (b0);

      next_worker_index = sm->worker_in2out_cb (ip0, rx_fib_index0);

      if (PREDICT_FALSE (next_worker_index != thread_index))
	{
	  do_handoff = 1;

	  if (next_worker_index != current_worker_index)
	    {
	      fq =
		is_vlib_frame_queue_congested (fq_index, next_worker_index,
					       NAT_FQ_NELTS - 2,
					       congested_handoff_queue_by_worker_index);

	      if (fq)
		{
		  /* if this is 1st frame */
		  if (!d)
		    {
		      d = vlib_get_frame_to_node (vm, sm->error_node_index);
		      to_next_drop = vlib_frame_vector_args (d);
		    }

		  to_next_drop[0] = bi0;
		  to_next_drop += 1;
		  d->n_vectors++;
		  b0->error = node->errors[NAT44_HANDOFF_ERROR_FQ_CONGESTED];
		  goto trace0;
		}

	      if (hf)
		hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

	      hf = vlib_get_worker_handoff_queue_elt (fq_index,
						      next_worker_index,
						      handoff_queue_elt_by_worker_index);

	      n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
	      to_next_worker = &hf->buffer_index[hf->n_vectors];
	      current_worker_index = next_worker_index;
	    }

	  /* enqueue to correct worker thread */
	  to_next_worker[0] = bi0;
	  to_next_worker++;
	  n_left_to_next_worker--;

	  if (n_left_to_next_worker == 0)
	    {
	      hf->n_vectors = VLIB_FRAME_SIZE;
	      vlib_put_frame_queue_elt (hf);
	      current_worker_index = ~0;
	      handoff_queue_elt_by_worker_index[next_worker_index] = 0;
	      hf = 0;
	    }
	}
      else
	{
	  do_handoff = 0;
	  /* if this is 1st frame */
	  if (!f)
	    {
	      f = vlib_get_frame_to_node (vm, to_node_index);
	      to_next = vlib_frame_vector_args (f);
	    }

	  to_next[0] = bi0;
	  to_next += 1;
	  f->n_vectors++;
	}

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_worker_index = next_worker_index;
	  t->do_handoff = do_handoff;
	  t->in2out = is_in2out;
	}
    }

  if (f)
    vlib_put_frame_to_node (vm, to_node_index, f);

  if (d)
    vlib_put_frame_to_node (vm, sm->error_node_index, d);

  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

  /* Ship frames to the worker nodes */
  for (i = 0; i < vec_len (handoff_queue_elt_by_worker_index); i++)
    {
      if (handoff_queue_elt_by_worker_index[i])
	{
	  hf = handoff_queue_elt_by_worker_index[i];
	  /*
	   * It works better to let the handoff node
	   * rate-adapt, always ship the handoff queue element.
	   */
	  if (1 || hf->n_vectors == hf->last_n_vectors)
	    {
	      vlib_put_frame_queue_elt (hf);
	      handoff_queue_elt_by_worker_index[i] = 0;
	    }
	  else
	    hf->last_n_vectors = hf->n_vectors;
	}
      congested_handoff_queue_by_worker_index[i] =
	(vlib_frame_queue_t *) (~0);
    }
  hf = 0;
  current_worker_index = ~0;
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
