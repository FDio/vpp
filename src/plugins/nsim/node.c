/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* node.c - skeleton vpp engine plug-in dual-loop node skeleton */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
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
    s = format (s, "NSIM: dropped, %s",
		t->is_lost ? "simulated network loss" : "scheduler storage full");
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
nsim_set_actions (nsim_main_t *nsm, nsim_worker_t *nsw, vlib_buffer_t **b, nsim_node_ctx_t *ctx,
		  u32 n_actions, int is_reordering)
{
  int i;

  memset (ctx->action, 0, n_actions * sizeof (ctx->action[0]));

  if (PREDICT_FALSE (nsw->loss.type != NSIM_LOSS_NONE))
    nsim_loss_apply (&nsw->loss, &nsw->loss_seed, ctx->now, b, ctx->action, n_actions);

  if (is_reordering)
    {
      for (i = 0; i < n_actions; i++)
	if (random_f64 (&nsw->reorder_seed) <= nsm->reorder_fraction)
	  ctx->action[i] |= NSIM_ACTION_REORDER;
    }
}

static void
nsim_trace_buffer (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, f64 tx_time,
		   u8 is_drop, u8 is_lost)
{
  if (b->flags & VLIB_BUFFER_IS_TRACED)
    {
      nsim_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->expires = tx_time;
      t->is_drop = is_drop;
      t->is_lost = is_lost;
      t->tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
    }
}

always_inline u32
nsim_worker_storage_size (const nsim_worker_t *nsw, int is_reordering)
{
  return is_reordering ? nsw->storage_cursize : nsw->wheel->cursize;
}

always_inline void
nsim_service_queue_drain (nsim_worker_t *nsw, f64 now)
{
  u32 size = vec_len (nsw->service_departures), low = 0, high = nsw->service_cursize;

  ASSERT (size != 0);
  if (PREDICT_TRUE (!high || nsw->service_departures[nsw->service_head] > now))
    return;

  /* Completion times are monotonic. Find the first future completion without
   * linearly walking a large queue after an idle period. */
  while (low < high)
    {
      u32 middle = low + (high - low) / 2;
      u32 index = nsw->service_head + middle;

      if (index >= size)
	index -= size;
      if (nsw->service_departures[index] <= now)
	low = middle + 1;
      else
	high = middle;
    }

  nsw->service_head += low;
  if (nsw->service_head >= size)
    nsw->service_head -= size;
  nsw->service_cursize -= low;
}

always_inline void
nsim_service_queue_enqueue (nsim_worker_t *nsw, f64 departure)
{
  ASSERT (nsw->service_cursize < vec_len (nsw->service_departures));
  nsw->service_departures[nsw->service_tail] = departure;
  if (++nsw->service_tail == vec_len (nsw->service_departures))
    nsw->service_tail = 0;
  nsw->service_cursize++;
}

always_inline void
nsim_buffer_fwd_lookup (nsim_main_t *nsm, vlib_buffer_t *b, u32 *next, u8 is_cross_connect)
{
  if (is_cross_connect)
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] =
	(vnet_buffer (b)->sw_if_index[VLIB_RX] == nsm->sw_if_index0) ? nsm->sw_if_index1 :
								       nsm->sw_if_index0;
      *next = (vnet_buffer (b)->sw_if_index[VLIB_TX] == nsm->sw_if_index0) ?
		nsm->output_next_index0 :
		nsm->output_next_index1;
    }
  else /* output feature, even easier... */
    {
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      *next = nsm->output_next_index_by_sw_if_index[sw_if_index];
    }
}

/* Enqueue a buffer onto a wheel with the given departure time, filling the
 * entry's forwarding info. Caller guarantees space. */
always_inline void
nsim_wheel_enqueue (nsim_main_t *nsm, nsim_worker_t *nsw, nsim_wheel_t *wp, vlib_buffer_t *b,
		    u32 bi, f64 tx_time, u8 is_cross_connect, int is_reordering)
{
  nsim_wheel_entry_t *ep = wp->entries + wp->tail;
  wp->tail++;
  if (wp->tail == wp->wheel_size)
    wp->tail = 0;
  wp->cursize++;
  if (is_reordering)
    nsw->storage_cursize++;

  ep->tx_time = tx_time;
  ep->rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  ep->tx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  nsim_buffer_fwd_lookup (nsm, b, &ep->output_next_index, is_cross_connect);
  ep->buffer_index = bi;
}

always_inline f64
nsim_schedule_buffer (nsim_main_t *nsm, nsim_worker_t *nsw, nsim_wheel_t *wp, vlib_buffer_t *b,
		      u32 bi, f64 tx_time, u8 is_cross_connect, int is_batching, int is_reordering)
{
  if (is_batching)
    tx_time = nsim_batch_release_time (&nsm->model.batch, &nsw->model.batch, &nsw->model.batch_seed,
				       tx_time);

  nsim_wheel_enqueue (nsm, nsw, wp, b, bi, tx_time, is_cross_connect, is_reordering);
  return tx_time;
}

always_inline void
nsim_dispatch_buffer (vlib_main_t *vm, vlib_node_runtime_t *node, nsim_main_t *nsm,
		      nsim_worker_t *nsw, nsim_wheel_t *wp, vlib_buffer_t *b, u32 bi,
		      nsim_node_ctx_t *ctx, u8 is_cross_connect, u8 is_trace, int is_queued,
		      int is_batching, int is_reordering)
{
  f64 tx_time = ctx->expires;
  u8 is_drop = 0, is_lost = 0;

  if (PREDICT_TRUE (!(ctx->action[0] & NSIM_ACTION_DROP)))
    {
      /* Base departure time: fixed-delay line, or queued (bufferbloat) model
       * serializing at the bottleneck rate then adding propagation delay. */
      if (is_queued)
	{
	  f64 service_start = clib_max (ctx->now, wp->last_tx_time);
	  f64 depart;

	  if (PREDICT_FALSE (nsm->model.rate.type != NSIM_RATE_NONE))
	    depart = nsim_rate_departure_time (&nsm->model.rate, &nsw->model.rate,
					       &nsw->model.rate_seed, service_start);
	  else
	    depart = service_start + nsm->model.serialization_time;
	  wp->last_tx_time = depart;
	  nsim_service_queue_enqueue (nsw, depart);
	  tx_time = depart + nsm->delay;
	}

      if (PREDICT_FALSE (ctx->action[0] & NSIM_ACTION_REORDER))
	{
	  /* Late reorder: push onto the side wheel with an extra delay drawn
	   * uniformly in [0, reorder_delay], so the packet departs behind the
	   * ones that followed it here. Clamp to the reorder wheel's last
	   * departure to keep that wheel's ring monotonic (as the queued model
	   * does for the main wheel). */
	  nsim_wheel_t *rwp = nsw->reorder_wheel;
	  f64 extra = random_f64 (&nsw->reorder_delay_seed) * nsm->reorder_delay;

	  tx_time = clib_max (tx_time + extra, rwp->last_tx_time);
	  rwp->last_tx_time = tx_time;
	  tx_time = nsim_schedule_buffer (nsm, nsw, rwp, b, bi, tx_time, is_cross_connect,
					  is_batching, is_reordering);
	  ctx->n_reordered += 1;
	  goto trace;
	}

      tx_time = nsim_schedule_buffer (nsm, nsw, wp, b, bi, tx_time, is_cross_connect, is_batching,
				      is_reordering);
      ctx->n_buffered += 1;
    }
  else
    {
      ctx->n_loss += 1;
      ctx->drop[0] = bi;
      ctx->drop += 1;
      is_drop = is_lost = 1;
    }

trace:

  if (PREDICT_FALSE (is_trace))
    nsim_trace_buffer (vm, node, b, tx_time, is_drop, is_lost);

  ctx->action += 1;
}

always_inline uword
nsim_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, int is_trace,
	     int is_cross_connect, int is_queued, int is_batching, int is_reordering)
{
  nsim_main_t *nsm = &nsim_main;
  nsim_worker_t *nsw = vec_elt_at_index (nsm->workers, vm->thread_index);
  u32 n_left_from, *from, drops[VLIB_FRAME_SIZE];
  nsim_wheel_t *wp = nsw->wheel;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u8 actions[VLIB_FRAME_SIZE];
  nsim_node_ctx_t ctx;

  ASSERT (wp);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;

  ctx.n_loss = 0;
  ctx.n_buffered = 0;
  ctx.n_reordered = 0;
  ctx.drop = drops;
  ctx.action = actions;
  ctx.now = vlib_time_now (vm);
  ctx.expires = ctx.now + nsm->delay;

  if (is_queued)
    nsim_service_queue_drain (nsw, ctx.now);

  nsim_set_actions (nsm, nsw, b, &ctx, n_left_from, is_reordering);

  while (n_left_from >= 8)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      if (PREDICT_FALSE (wp->wheel_size - nsim_worker_storage_size (nsw, is_reordering) < 4 ||
			 (is_queued && nsm->queue_slots_per_wrk - nsw->service_cursize < 4)))
	goto slow_path;

      nsim_dispatch_buffer (vm, node, nsm, nsw, wp, b[0], from[0], &ctx, is_cross_connect, is_trace,
			    is_queued, is_batching, is_reordering);
      nsim_dispatch_buffer (vm, node, nsm, nsw, wp, b[1], from[1], &ctx, is_cross_connect, is_trace,
			    is_queued, is_batching, is_reordering);
      nsim_dispatch_buffer (vm, node, nsm, nsw, wp, b[2], from[2], &ctx, is_cross_connect, is_trace,
			    is_queued, is_batching, is_reordering);
      nsim_dispatch_buffer (vm, node, nsm, nsw, wp, b[3], from[3], &ctx, is_cross_connect, is_trace,
			    is_queued, is_batching, is_reordering);

      b += 4;
      from += 4;
      n_left_from -= 4;
    }

slow_path:

  while (n_left_from > 0)
    {
      /* Simulated loss does not need storage. All other packets share physical
	 storage, and queued mode additionally enforces bottleneck admission. */
      if (PREDICT_TRUE ((ctx.action[0] & NSIM_ACTION_DROP) ||
			(nsim_worker_storage_size (nsw, is_reordering) < wp->wheel_size &&
			 (!is_queued || nsw->service_cursize < nsm->queue_slots_per_wrk))))
	{
	  nsim_dispatch_buffer (vm, node, nsm, nsw, wp, b[0], from[0], &ctx, is_cross_connect,
				is_trace, is_queued, is_batching, is_reordering);
	}
      else
	{
	  ctx.drop[0] = from[0];
	  ctx.drop += 1;
	  if (PREDICT_FALSE (is_trace))
	    nsim_trace_buffer (vm, node, b[0], ctx.expires, 1, 0);
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
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_LOSS, ctx.n_loss);
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_DROPPED,
				   n_left_to_drop - ctx.n_loss);
      nsw->drops += ctx.n_loss;
      nsw->queue_drops += n_left_to_drop - ctx.n_loss;
    }
  if (PREDICT_FALSE (ctx.n_reordered))
    {
      vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_REORDERED, ctx.n_reordered);
      nsw->reordered += ctx.n_reordered;
    }
  if (is_queued)
    {
      nsw->max_service_cursize = clib_max (nsw->max_service_cursize, nsw->service_cursize);
      nsw->max_service_backlog = clib_max (nsw->max_service_backlog, wp->last_tx_time - ctx.now);
    }
  nsw->max_storage_cursize =
    clib_max (nsw->max_storage_cursize, nsim_worker_storage_size (nsw, is_reordering));
  nsw->packets += frame->n_vectors;
  vlib_node_increment_counter (vm, node->node_index, NSIM_ERROR_BUFFERED, ctx.n_buffered);
  return frame->n_vectors;
}

always_inline uword
nsim_inline_select (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, int is_trace,
		    int is_cross_connect)
{
  nsim_main_t *nsm = &nsim_main;
  int is_queued = nsm->model.buffer_time > 0.0;
  int is_batching = nsm->model.batch.interval > 0.0;
  int is_reordering = nsm->reorder_fraction != 0.0;

  /* Preserve a fully specialized default path, but keep one generic modeled
   * path instead of generating every combination into both graph nodes. */
  if (PREDICT_TRUE (!is_queued && !is_batching && !is_reordering))
    return nsim_inline (vm, node, frame, is_trace, is_cross_connect, 0, 0, 0);
  return nsim_inline (vm, node, frame, is_trace, is_cross_connect, is_queued, is_batching,
		      is_reordering);
}

VLIB_NODE_FN (nsim_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_inline_select (vm, node, frame, 1 /* is_trace */, 1 /* is_cross_connect */);
  else
    return nsim_inline_select (vm, node, frame, 0 /* is_trace */, 1 /* is_cross_connect */);
}

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

VLIB_NODE_FN (nsim_feature_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_inline_select (vm, node, frame, 1 /* is_trace */, 0 /* is_cross_connect */);
  else
    return nsim_inline_select (vm, node, frame, 0 /* is_trace */, 0 /* is_cross_connect */);
}

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
