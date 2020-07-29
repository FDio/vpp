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
_(LOSS, "Network loss simulation drop packets")		\
_(REORDERED, "Packets reordered")

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

static void
nsim_set_actions (nsim_main_t * nsm, vlib_buffer_t ** b,
		  nsim_node_ctx_t * ctx, u32 n_actions)
{
  int i;

  memset (ctx->action, 0, n_actions * sizeof (ctx->action[0]));

  if (PREDICT_FALSE (nsm->drop_fraction != 0.0))
    {
      for (i = 0; i < n_actions; i++)
	if (random_f64 (&nsm->seed) <= nsm->drop_fraction)
	  ctx->action[i] |= NSIM_ACTION_DROP;
    }

  if (PREDICT_FALSE (nsm->reorder_fraction != 0.0))
    {
      for (i = 0; i < n_actions; i++)
	if (random_f64 (&nsm->seed) <= nsm->reorder_fraction)
	  ctx->action[i] |= NSIM_ACTION_REORDER;
    }
}

static void
nsim_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_buffer_t * b, nsim_node_ctx_t * ctx, u32 is_drop)
{
  if (b->flags & VLIB_BUFFER_IS_TRACED)
    {
      nsim_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->expires = ctx->expires;
      t->is_drop = is_drop;
      t->is_lost = ctx->action[0] & NSIM_ACTION_DROP;
      t->tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
    }
}

always_inline void
nsim_buffer_fwd_lookup (nsim_main_t * nsm, vlib_buffer_t * b,
			u32 * next, u8 is_cross_connect)
{
  if (is_cross_connect)
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] =
	(vnet_buffer (b)->sw_if_index[VLIB_RX] == nsm->sw_if_index0) ?
	nsm->sw_if_index1 : nsm->sw_if_index0;
      *next =
	(vnet_buffer (b)->sw_if_index[VLIB_TX] == nsm->sw_if_index0) ?
	nsm->output_next_index0 : nsm->output_next_index1;
    }
  else				/* output feature, even easier... */
    {
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      *next = nsm->output_next_index_by_sw_if_index[sw_if_index];
    }
}

always_inline void
nsim_dispatch_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		      nsim_main_t * nsm, nsim_wheel_t * wp, vlib_buffer_t * b,
		      u32 bi, nsim_node_ctx_t * ctx, u8 is_cross_connect,
		      u8 is_trace)
{
  if (PREDICT_TRUE (!(ctx->action[0] & NSIM_ACTION_DROP)))
    {
      if (PREDICT_FALSE (ctx->action[0] & NSIM_ACTION_REORDER))
	{
	  u32 next;
	  ctx->reord[0] = bi;
	  vnet_get_config_data (&ctx->fcm->config_main,
				&b->current_config_index, &next, 0);
	  ctx->reord_nexts[0] = next;
	  ctx->reord += 1;
	  ctx->reord_nexts += 1;
	  goto trace;
	}

      nsim_wheel_entry_t *ep = wp->entries + wp->tail;
      wp->tail++;
      if (wp->tail == wp->wheel_size)
	wp->tail = 0;
      wp->cursize++;

      ep->tx_time = ctx->expires;
      ep->rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      nsim_buffer_fwd_lookup (nsm, b, &ep->output_next_index,
			      is_cross_connect);
      ep->tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      ep->buffer_index = bi;
      ctx->n_buffered += 1;
    }
  else
    {
      ctx->n_loss += 1;
      ctx->drop[0] = bi;
      ctx->drop += 1;
    }

trace:

  if (PREDICT_FALSE (is_trace))
    nsim_trace_buffer (vm, node, b, ctx, 0);

  ctx->action += 1;
}

always_inline uword
nsim_inline (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame, int is_trace,
	     int is_cross_connect)
{
  nsim_main_t *nsm = &nsim_main;
  u32 n_left_from, *from, drops[VLIB_FRAME_SIZE], reorders[VLIB_FRAME_SIZE];
  nsim_wheel_t *wp = nsm->wheel_by_thread[vm->thread_index];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 reorders_nexts[VLIB_FRAME_SIZE];
  u8 actions[VLIB_FRAME_SIZE];
  nsim_node_ctx_t ctx;

  ASSERT (wp);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;

  ctx.fcm = vnet_feature_get_config_main (nsm->arc_index);
  ctx.n_loss = 0;
  ctx.n_buffered = 0;
  ctx.drop = drops;
  ctx.reord = reorders;
  ctx.reord_nexts = reorders_nexts;
  ctx.action = actions;
  ctx.expires = vlib_time_now (vm) + nsm->delay;

  nsim_set_actions (nsm, b, &ctx, n_left_from);

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      if (PREDICT_FALSE (wp->cursize + 4 >= wp->wheel_size))
	goto slow_path;

      nsim_dispatch_buffer (vm, node, nsm, wp, b[0], from[0], &ctx,
			    is_cross_connect, is_trace);
      nsim_dispatch_buffer (vm, node, nsm, wp, b[1], from[1], &ctx,
			    is_cross_connect, is_trace);
      nsim_dispatch_buffer (vm, node, nsm, wp, b[2], from[2], &ctx,
			    is_cross_connect, is_trace);
      nsim_dispatch_buffer (vm, node, nsm, wp, b[3], from[3], &ctx,
			    is_cross_connect, is_trace);

      b += 4;
      from += 4;
      n_left_from -= 4;
    }

slow_path:

  while (n_left_from > 0)
    {
      /* Drop if out of wheel space and not drop or reorder */
      if (PREDICT_TRUE (wp->cursize < wp->wheel_size
			|| (ctx.action[0] & NSIM_ACTION_DROP)
			|| (ctx.action[0] & NSIM_ACTION_REORDER)))
	{
	  nsim_dispatch_buffer (vm, node, nsm, wp, b[0], from[0], &ctx,
				is_cross_connect, is_trace);
	}
      else
	{
	  ctx.drop[0] = from[0];
	  ctx.drop += 1;
	  if (PREDICT_FALSE (is_trace))
	    nsim_trace_buffer (vm, node, b[0], &ctx, 1);
	  ctx.action += 1;
	}

      b += 1;
      from += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (ctx.drop > drops))
    {
      u32 n_left_to_drop = ctx.drop - drops;
      vlib_buffer_free (vm, drops, n_left_to_drop);
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_LOSS,
				   ctx.n_loss);
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_DROPPED,
				   n_left_to_drop - ctx.n_loss);
    }
  if (PREDICT_FALSE (ctx.reord > reorders))
    {
      u32 n_reordered = ctx.reord - reorders;
      vlib_buffer_enqueue_to_next (vm, node, reorders, reorders_nexts,
				   n_reordered);
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_REORDERED,
				   n_reordered);
    }
  vlib_node_increment_counter (vm, node->node_index,
			       NSIM_ERROR_BUFFERED, ctx.n_buffered);
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
