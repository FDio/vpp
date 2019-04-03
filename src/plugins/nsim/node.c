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
  int is_lost;
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
    s = format (s, "NSIM: dropped, %s", t->is_lost ?
		"simulated network loss" : "no space in ring");
  else
    s = format (s, "NSIM: tx time %.6f sw_if_index %d",
		t->expires, t->tx_sw_if_index);

  return s;
}

vlib_node_registration_t nsim_node;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_nsim_error                              \
_(BUFFERED, "Packets buffered")                         \
_(DROPPED, "Packets dropped due to lack of space")	\
_(LOSS, "Network loss simulation drop packets")

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
	     vlib_node_runtime_t * node, vlib_frame_t * frame, int is_trace,
	     int is_cross_connect)
{
  nsim_main_t *nsm = &nsim_main;
  u32 n_left_from, *from;
  u32 *to_next, n_left_to_next;
  u32 drops[VLIB_FRAME_SIZE], *drop;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u8 is_drop[4];
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 my_thread_index = vm->thread_index;
  nsim_wheel_t *wp = nsm->wheel_by_thread[my_thread_index];
  f64 now = vlib_time_now (vm);
  f64 expires = now + nsm->delay;
  f64 rnd[4];
  u32 no_buffer_error = node->errors[NSIM_ERROR_DROPPED];
  u32 loss_error = node->errors[NSIM_ERROR_LOSS];
  u32 buffered = 0;
  nsim_wheel_entry_t *ep = 0;

  ASSERT (wp);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;
  drop = drops;

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      memset (&is_drop, 0, sizeof (is_drop));
      next[0] = next[1] = next[2] = next[3] = NSIM_NEXT_DROP;
      if (PREDICT_FALSE (wp->cursize + 4 >= wp->wheel_size))
	goto slow_path;
      if (PREDICT_FALSE (nsm->drop_fraction != 0.0))
	{
	  rnd[0] = random_f64 (&nsm->seed);
	  rnd[1] = random_f64 (&nsm->seed);
	  rnd[2] = random_f64 (&nsm->seed);
	  rnd[3] = random_f64 (&nsm->seed);

	  if (rnd[0] <= nsm->drop_fraction)
	    {
	      b[0]->error = loss_error;
	      is_drop[0] = 1;
	    }
	  if (rnd[1] <= nsm->drop_fraction)
	    {
	      b[1]->error = loss_error;
	      is_drop[1] = 1;
	    }
	  if (rnd[2] <= nsm->drop_fraction)
	    {
	      b[2]->error = loss_error;
	      is_drop[2] = 1;
	    }
	  if (rnd[3] <= nsm->drop_fraction)
	    {
	      b[3]->error = loss_error;
	      is_drop[3] = 1;
	    }
	}

      if (PREDICT_TRUE (is_drop[0] == 0))
	{
	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  if (is_cross_connect)
	    {
	      ep->tx_sw_if_index =
		(vnet_buffer (b[0])->sw_if_index[VLIB_RX] ==
		 nsm->sw_if_index0) ? nsm->sw_if_index1 : nsm->sw_if_index0;
	      ep->output_next_index =
		(ep->tx_sw_if_index ==
		 nsm->sw_if_index0) ? nsm->
		output_next_index0 : nsm->output_next_index1;
	    }
	  else			/* output feature, even easier... */
	    {
	      ep->tx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      ep->output_next_index =
		nsm->output_next_index_by_sw_if_index[ep->tx_sw_if_index];
	    }
	  ep->buffer_index = from[0];
	  buffered++;
	}

      if (is_trace)
	{
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop[1];
	      t->is_lost = b[1]->error == loss_error;
	      t->tx_sw_if_index = (is_drop[1] == 0) ? ep->tx_sw_if_index : 0;
	    }
	}

      if (PREDICT_TRUE (is_drop[1] == 0))
	{
	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->rx_sw_if_index = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
	  if (is_cross_connect)
	    {
	      ep->tx_sw_if_index =
		(vnet_buffer (b[1])->sw_if_index[VLIB_RX] ==
		 nsm->sw_if_index0) ? nsm->sw_if_index1 : nsm->sw_if_index0;
	      ep->output_next_index =
		(ep->tx_sw_if_index ==
		 nsm->sw_if_index0) ? nsm->
		output_next_index0 : nsm->output_next_index1;
	    }
	  else			/* output feature, even easier... */
	    {
	      ep->tx_sw_if_index = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	      ep->output_next_index =
		nsm->output_next_index_by_sw_if_index[ep->tx_sw_if_index];
	    }
	  ep->buffer_index = from[1];
	  buffered++;
	}

      if (is_trace)
	{
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop[2];
	      t->is_lost = b[2]->error == loss_error;
	      t->tx_sw_if_index = (is_drop[2] == 0) ? ep->tx_sw_if_index : 0;
	    }
	}
      if (PREDICT_TRUE (is_drop[2] == 0))
	{
	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->rx_sw_if_index = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
	  if (is_cross_connect)
	    {
	      ep->tx_sw_if_index =
		(vnet_buffer (b[2])->sw_if_index[VLIB_RX] ==
		 nsm->sw_if_index0) ? nsm->sw_if_index1 : nsm->sw_if_index0;
	      ep->output_next_index =
		(ep->tx_sw_if_index ==
		 nsm->sw_if_index0) ? nsm->
		output_next_index0 : nsm->output_next_index1;
	    }
	  else			/* output feature, even easier... */
	    {
	      ep->tx_sw_if_index = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
	      ep->output_next_index =
		nsm->output_next_index_by_sw_if_index[ep->tx_sw_if_index];
	    }
	  ep->buffer_index = from[2];
	  buffered++;
	}

      if (is_trace)
	{
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop[2];
	      t->is_lost = b[2]->error == loss_error;
	      t->tx_sw_if_index = (is_drop[2] == 0) ? ep->tx_sw_if_index : 0;
	    }
	}
      if (PREDICT_TRUE (is_drop[3] == 0))
	{
	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->rx_sw_if_index = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
	  if (is_cross_connect)
	    {
	      ep->tx_sw_if_index =
		(vnet_buffer (b[3])->sw_if_index[VLIB_RX] ==
		 nsm->sw_if_index0) ? nsm->sw_if_index1 : nsm->sw_if_index0;
	      ep->output_next_index =
		(ep->tx_sw_if_index ==
		 nsm->sw_if_index0) ? nsm->
		output_next_index0 : nsm->output_next_index1;
	    }
	  else			/* output feature, even easier... */
	    {
	      ep->tx_sw_if_index = vnet_buffer (b[3])->sw_if_index[VLIB_TX];
	      ep->output_next_index =
		nsm->output_next_index_by_sw_if_index[ep->tx_sw_if_index];
	    }
	  ep->buffer_index = from[3];
	  buffered++;
	}

      if (is_trace)
	{
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop[3];
	      t->is_lost = b[3]->error == loss_error;
	      t->tx_sw_if_index = (is_drop[3] == 0) ? ep->tx_sw_if_index : 0;
	    }
	}

      if (PREDICT_FALSE (is_drop[0]))
	*drop++ = from[0];
      if (PREDICT_FALSE (is_drop[1]))
	*drop++ = from[1];
      if (PREDICT_FALSE (is_drop[2]))
	*drop++ = from[2];
      if (PREDICT_FALSE (is_drop[3]))
	*drop++ = from[3];

      b += 4;
      next += 4;
      from += 4;
      n_left_from -= 4;
    }

slow_path:

  while (n_left_from > 0)
    {
      next[0] = NSIM_NEXT_DROP;
      is_drop[0] = 0;
      if (PREDICT_TRUE (wp->cursize < wp->wheel_size))
	{
	  if (PREDICT_FALSE (nsm->drop_fraction != 0.0))
	    {
	      /* Get a random number on the closed interval [0,1] */
	      rnd[0] = random_f64 (&nsm->seed);
	      /* Drop the pkt? */
	      if (rnd[0] <= nsm->drop_fraction)
		{
		  b[0]->error = loss_error;
		  is_drop[0] = 1;
		  goto do_trace;
		}
	    }

	  ep = wp->entries + wp->tail;
	  wp->tail++;
	  if (wp->tail == wp->wheel_size)
	    wp->tail = 0;
	  wp->cursize++;

	  ep->tx_time = expires;
	  ep->rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  if (is_cross_connect)
	    {
	      ep->tx_sw_if_index =
		(vnet_buffer (b[0])->sw_if_index[VLIB_RX] ==
		 nsm->sw_if_index0) ? nsm->sw_if_index1 : nsm->sw_if_index0;
	      ep->output_next_index =
		(ep->tx_sw_if_index ==
		 nsm->sw_if_index0) ? nsm->
		output_next_index0 : nsm->output_next_index1;
	    }
	  else			/* output feature, even easier... */
	    {
	      ep->tx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      ep->output_next_index =
		nsm->output_next_index_by_sw_if_index[ep->tx_sw_if_index];
	    }
	  ep->buffer_index = from[0];
	  buffered++;
	}
      else			/* out of wheel space, drop pkt */
	{
	  b[0]->error = no_buffer_error;
	  is_drop[0] = 1;
	}

    do_trace:
      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nsim_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->expires = expires;
	      t->is_drop = is_drop[0];
	      t->is_lost = b[0]->error == loss_error;
	      t->tx_sw_if_index = (is_drop[0] == 0) ? ep->tx_sw_if_index : 0;
	    }
	}

      b += 1;
      next += 1;
      if (PREDICT_FALSE (is_drop[0]))
	{
	  drop[0] = from[0];
	  drop++;
	}
      from++;
      n_left_from -= 1;
    }
  if (PREDICT_FALSE (drop > drops))
    {
      u32 n_left_to_drop = drop - drops;
      drop = drops;

      while (n_left_to_drop > 0)
	{
	  u32 this_copy_size;
	  vlib_get_next_frame (vm, node, NSIM_NEXT_DROP, to_next,
			       n_left_to_next);
	  this_copy_size = clib_min (n_left_to_drop, n_left_to_next);
	  clib_memcpy_fast (to_next, drop, this_copy_size * sizeof (u32));
	  n_left_to_next -= this_copy_size;
	  vlib_put_next_frame (vm, node, NSIM_NEXT_DROP, n_left_to_next);
	  drop += this_copy_size;
	  n_left_to_drop -= this_copy_size;
	}
    }
  vlib_node_increment_counter (vm, node->node_index,
			       NSIM_ERROR_BUFFERED, buffered);
  return frame->n_vectors;
}

VLIB_NODE_FN (nsim_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_inline (vm, node, frame,
			1 /* is_trace */ , 1 /* is_cross_connect */ );
  else
    return nsim_inline (vm, node, frame,
			0 /* is_trace */ , 1 /* is_cross_connect */ );
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

VLIB_NODE_FN (nsim_feature_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_inline (vm, node, frame,
			1 /* is_trace */ , 0 /* is_cross_connect */ );
  else
    return nsim_inline (vm, node, frame,
			0 /* is_trace */ , 0 /* is_cross_connect */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (nsim_feature_node) =
{
  .name = "nsim-output-feature",
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
