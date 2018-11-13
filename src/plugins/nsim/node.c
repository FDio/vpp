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
#include <nsim/nsim.h>

typedef struct
{
  f64 expires;
  u32 tx_sw_if_index;
  int is_drop;
} nsim_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_nsim_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsim_trace_t *t = va_arg (*args, nsim_trace_t *);

  if (t->is_drop)
    s = format (s, "NSIM: ring drop");
  else
    s = format (s, "NSIM: tx time %.6f sw_if_index %d",
		t->expires, t->tx_sw_if_index);

  return s;
}

vlib_node_registration_t nsim_node;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_nsim_error                              \
_(BUFFERED, "Packets buffered")                         \
_(DROPPED, "Packets dropped due to lack of space")

typedef enum
{
#define _(sym,str) NSIM_ERROR_##sym,
  foreach_nsim_error
#undef _
    NSIM_N_ERROR,
} nsim_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *nsim_error_strings[] = {
#define _(sym,string) string,
  foreach_nsim_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  NSIM_NEXT_DROP,
  NSIM_N_NEXT,
} nsim_next_t;

always_inline uword
nsim_inline (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame, int is_trace)
{
  nsim_main_t *nsm = &nsim_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 my_thread_index = vm->thread_index;
  nsim_wheel_t *wp = nsm->wheel_by_thread[my_thread_index];
  f64 now = vlib_time_now (vm);
  f64 expires = now + nsm->delay;
  int is_drop0;
  u32 no_error = node->errors[NSIM_ERROR_BUFFERED];
  u32 no_buffer_error = node->errors[NSIM_ERROR_DROPPED];
  nsim_wheel_entry_t *ep = 0;

  ASSERT (wp);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  /* There is no point in trying to do more than 1 pkt here */
  while (n_left_from > 0)
    {
      b[0]->error = no_error;
      next[0] = NSIM_NEXT_DROP;
      is_drop0 = 0;
      if (PREDICT_TRUE (wp->cursize < wp->wheel_size))
	{
	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->tx_sw_if_index =
	    (vnet_buffer (b[0])->sw_if_index[VLIB_RX] == nsm->sw_if_index0)
	    ? nsm->sw_if_index1 : nsm->sw_if_index0;
	  ep->current_length = vlib_buffer_length_in_chain (vm, b[0]);
	  ASSERT (ep->current_length <= WHEEL_ENTRY_DATA_SIZE);
	  _clib_memcpy (ep->data, vlib_buffer_get_current (b[0]),
			ep->current_length);
	}
      else			/* out of wheel space, drop pkt */
	{
	  b[0]->error = no_buffer_error;
	  is_drop0 = 1;
	}

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop0;
	      t->tx_sw_if_index = (is_drop0 == 0) ? ep->tx_sw_if_index : 0;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (nsim_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return nsim_inline (vm, node, frame, 0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (nsim_node) =
{
  .name = "nsim",
  .vector_size = sizeof (u32),
  .format_trace = format_nsim_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nsim_error_strings),
  .error_strings = nsim_error_strings,

  .n_next_nodes = NSIM_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [NSIM_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
