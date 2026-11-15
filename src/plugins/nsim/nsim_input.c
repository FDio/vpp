/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* nsim.c - skeleton vpp engine plug-in */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <nsim/nsim.h>

typedef struct
{
  f64 expired;
  u32 next_index;
} nsim_tx_trace_t;

#ifndef CLIB_MARCH_VARIANT
/* packet trace format function */
static u8 *
format_nsim_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsim_tx_trace_t *t = va_arg (*args, nsim_tx_trace_t *);

  s = format (s, "NSIM: tx at %.6f next_index %d", t->expired, t->next_index);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_nsim_tx_error                   \
_(TRANSMITTED, "Packets transmitted")

typedef enum
{
#define _(sym,str) NSIM_TX_ERROR_##sym,
  foreach_nsim_tx_error
#undef _
    NSIM_TX_N_ERROR,
} nsim_tx_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *nsim_tx_error_strings[] = {
#define _(sym,string) string,
  foreach_nsim_tx_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  NSIM_NEXT_DROP,
  NSIM_N_NEXT,
} nsim_next_t;

/* Release up to max_tx packets of one wheel, those due by until */
always_inline uword
nsim_drain_wheel (vlib_main_t *vm, vlib_node_runtime_t *node, nsim_worker_t *nsw, nsim_wheel_t *wp,
		  f64 now, f64 until, u32 max_tx, int is_trace)
{
  nsim_wheel_entry_t *ep;

  ASSERT (max_tx <= NSIM_MAX_TX_BURST);

  if (wp->cursize == 0)
    return 0;

  ep = wp->entries + wp->head;
  if (ep->tx_time > until)
    return 0;

  u32 n_burst = clib_min (wp->cursize, max_tx), n_tx_packets = 0;
  u32 froms[NSIM_MAX_TX_BURST], *from;
  u16 nexts[NSIM_MAX_TX_BURST], *next;

  from = froms;
  next = nexts;
  while (n_tx_packets < n_burst)
    {
      ep = wp->entries + wp->head;
      if (ep->tx_time > until)
	break;

      /* Prefetch the next cache line while draining a due backlog. */
      if ((((uword) ep) & (CLIB_CACHE_LINE_BYTES - 1)) == 0)
	clib_prefetch_load ((u8 *) ep + CLIB_CACHE_LINE_BYTES);

      from[0] = ep->buffer_index;
      next[0] = ep->output_next_index;

      if (PREDICT_FALSE (is_trace))
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsim_tx_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	      t->expired = now;
	      t->next_index = next[0];

	      /* Claim the frame before marking it: enqueue may otherwise
	       * swap it with a frame owned by another producer. */
	      vlib_get_next_frame_internal (vm, node, next[0], 0);
	      vlib_trace_next_frame (vm, node, next[0]);
	    }
	}

      wp->head++;
      if (wp->head == wp->wheel_size)
	wp->head = 0;

      from += 1;
      next += 1;
      n_tx_packets++;
    }

  wp->cursize -= n_tx_packets;
  if (nsw->reorder_wheel)
    {
      ASSERT (nsw->storage_cursize >= n_tx_packets);
      nsw->storage_cursize -= n_tx_packets;
    }
  vlib_buffer_enqueue_to_next (vm, node, froms, nexts, n_tx_packets);
  vlib_node_increment_counter (vm, node->node_index, NSIM_TX_ERROR_TRANSMITTED, n_tx_packets);
  nsw->transmitted += n_tx_packets;
  return n_tx_packets;
}

always_inline uword
nsim_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f, int is_trace)
{
  nsim_main_t *nsm = &nsim_main;
  nsim_worker_t *nsw = vec_elt_at_index (nsm->workers, vm->thread_index);
  nsim_wheel_t *wp = nsw->wheel, *rwp = nsw->reorder_wheel, *w;
  f64 now = vlib_time_now (vm), until;
  uword n_tx = 0, n;

  /* Release all that is due, up to a frame per poll, so the wheels never fall behind their
   * departure times. Both share the link: drain the one with the earlier head, up to the other's */
  do
    {
      w = wp;
      until = now;
      if (PREDICT_FALSE (rwp != 0) && rwp->cursize)
	{
	  f64 reorder_head = rwp->entries[rwp->head].tx_time;

	  if (!wp->cursize || reorder_head < wp->entries[wp->head].tx_time)
	    {
	      if (wp->cursize)
		until = clib_min (now, wp->entries[wp->head].tx_time);
	      w = rwp;
	    }
	  else
	    until = clib_min (now, reorder_head);
	}
      n = nsim_drain_wheel (vm, node, nsw, w, now, until,
			    clib_min (NSIM_MAX_TX_PER_POLL - n_tx, NSIM_MAX_TX_BURST), is_trace);
      n_tx += n;
    }
  while (n && n_tx < NSIM_MAX_TX_PER_POLL);

  return n_tx;
}

VLIB_NODE_FN (nsim_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  if (PREDICT_FALSE (vm->trace_main.trace_enable))
    return nsim_input_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return nsim_input_inline (vm, node, frame, 0 /* is_trace */ );

}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (nsim_input_node) =
{
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "nsim-wheel",

  /* Will be enabled if/when the feature is configured */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_trace = format_nsim_tx_trace,

  .n_errors = NSIM_TX_N_ERROR,
  .error_strings = nsim_tx_error_strings,
};
#endif /* CLIB_MARCH_VARIANT */
