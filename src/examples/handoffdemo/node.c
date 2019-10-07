/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <handoffdemo/handoffdemo.h>

typedef struct
{
  int current_thread;
} handoffdemo_trace_t;

/* packet trace format function */
static u8 *
format_handoffdemo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  handoffdemo_trace_t *t = va_arg (*args, handoffdemo_trace_t *);

  s = format (s, "HANDOFFDEMO: current thread %d", t->current_thread);

  return s;
}

vlib_node_registration_t handoffdemo_node;

#define foreach_handoffdemo_error                       \
_(HANDED_OFF, "packets handed off processed")           \
_(CONGESTION_DROP, "handoff queue congestion drops")    \
_(COMPLETE, "completed packets")

typedef enum
{
#define _(sym,str) HANDOFFDEMO_ERROR_##sym,
  foreach_handoffdemo_error
#undef _
    HANDOFFDEMO_N_ERROR,
} handoffdemo_error_t;

static char *handoffdemo_error_strings[] = {
#define _(sym,string) string,
  foreach_handoffdemo_error
#undef _
};

typedef enum
{
  HANDOFFDEMO_NEXT_DROP,
  HANDOFFDEMO_N_NEXT,
} handoffdemo_next_t;

always_inline uword
handoffdemo_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame,
		    int which, int is_trace)
{
  handoffdemo_main_t *hmp = &handoffdemo_main;
  u32 n_left_from, *from;
  u32 error0 = node->errors[HANDOFFDEMO_ERROR_COMPLETE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_enq;
  int i;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  next = nexts;
  b = bufs;

  /* First thread */
  if (which == 1)
    {
      for (i = 0; i < frame->n_vectors; i++)
	{
	  /* Pick a thread to handle this packet */
	  thread_indices[i] = 2;

	  if (is_trace && (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      handoffdemo_trace_t *t = vlib_add_trace (vm, node, b[0],
						       sizeof (*t));
	      t->current_thread = vm->thread_index;
	    }

	  b += 1;
	  next += 1;
	  n_left_from -= 1;
	}

      /* Enqueue buffers to threads */
      n_enq =
	vlib_buffer_enqueue_to_thread (vm, hmp->frame_queue_index,
				       from, thread_indices, frame->n_vectors,
				       1 /* drop on congestion */ );
      if (n_enq < frame->n_vectors)
	vlib_node_increment_counter (vm, node->node_index,
				     HANDOFFDEMO_ERROR_CONGESTION_DROP,
				     frame->n_vectors - n_enq);
      vlib_node_increment_counter (vm, node->node_index,
				   HANDOFFDEMO_ERROR_HANDED_OFF, n_enq);
      return frame->n_vectors;
    }
  else				/* Second thread */
    {
      u32 *from;

      from = vlib_frame_vector_args (frame);
      n_left_from = frame->n_vectors;

      vlib_get_buffers (vm, from, bufs, n_left_from);
      next = nexts;
      b = bufs;

      while (n_left_from > 0)
	{
	  if (is_trace && (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      handoffdemo_trace_t *t = vlib_add_trace (vm, node, b[0],
						       sizeof (*t));
	      t->current_thread = vm->thread_index;
	    }

	  next[0] = HANDOFFDEMO_NEXT_DROP;
	  b[0]->error = error0;
	  next++;
	  b++;
	  n_left_from--;
	}

      vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
				   frame->n_vectors);
    }

  return frame->n_vectors;
}

static uword
handoffdemo_node_1_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return handoffdemo_inline (vm, node, frame, 1 /* which */ ,
			       1 /* is_trace */ );
  else
    return handoffdemo_inline (vm, node, frame, 1 /* which */ ,
			       0 /* is_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (handoffdemo_node_1) =
{
  .name = "handoffdemo-1",
  .function = handoffdemo_node_1_fn,
  .vector_size = sizeof (u32),
  .format_trace = format_handoffdemo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(handoffdemo_error_strings),
  .error_strings = handoffdemo_error_strings,

  .n_next_nodes = HANDOFFDEMO_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [HANDOFFDEMO_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

uword
handoffdemo_node_2_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return handoffdemo_inline (vm, node, frame, 2 /* which */ ,
			       1 /* is_trace */ );
  else
    return handoffdemo_inline (vm, node, frame, 2 /* which */ ,
			       0 /* is_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (handoffdemo_node_2) =
{
  .name = "handoffdemo-2",
  .function = handoffdemo_node_2_fn,
  .vector_size = sizeof (u32),
  .format_trace = format_handoffdemo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(handoffdemo_error_strings),
  .error_strings = handoffdemo_error_strings,

  .n_next_nodes = HANDOFFDEMO_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [HANDOFFDEMO_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

static clib_error_t *
handoffdemo_node_init (vlib_main_t * vm)
{
  handoffdemo_main_t *hmp = &handoffdemo_main;

  hmp->frame_queue_index = vlib_frame_queue_main_init
    (handoffdemo_node_2.index, 16);

  return 0;
}

VLIB_INIT_FUNCTION (handoffdemo_node_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
