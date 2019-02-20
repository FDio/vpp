/*
 * nsim.c - skeleton vpp engine plug-in
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
  f64 expired;
  u32 tx_sw_if_index;
} nsim_tx_trace_t;

#ifndef CLIB_MARCH_VARIANT
/* packet trace format function */
static u8 *
format_nsim_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsim_tx_trace_t *t = va_arg (*args, nsim_tx_trace_t *);

  s = format (s, "NSIM: tx at %.6f sw_if_index %d",
	      t->expired, t->tx_sw_if_index);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_nsim_tx_error                      \
_(TX, "Packets transmitted")                    \
_(DROPPED, "No buffer drops")

typedef enum
{
#define _(sym,str) NSIM_TX_ERROR_##sym,
  foreach_nsim_tx_error
#undef _
    NSIM_N_ERROR,
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

always_inline uword
nsim_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * f, int is_trace)
{
  nsim_main_t *nsm = &nsim_main;
  u32 my_thread_index = vm->thread_index;
  u32 *my_buffer_cache = nsm->buffer_indices_by_thread[my_thread_index];
  nsim_wheel_t *wp = nsm->wheel_by_thread[my_thread_index];
  u32 n_trace = vlib_get_trace_count (vm, node);
  f64 now = vlib_time_now (vm);
  uword n_rx_packets = 0;
  vlib_buffer_t *b0;
  u32 bi0, next0;
  u32 *to_next;
  u32 next_index;
  u32 n_left_to_next;
  nsim_wheel_entry_t *ep;

  /* Nothing on the scheduler wheel? */
  if (wp->cursize == 0)
    return 0;

  /* First entry on the wheel isn't expired? */
  ep = wp->entries + wp->head;
  if (ep->tx_time > now)
    return n_rx_packets;

  /*
   * We use per-thread buffer caches, so we need the freelist to
   * initialize them...
   */
  next_index = node->cached_next_index;

  while (wp->cursize)
    {
      /* Be aware: this is not the usual coding pattern */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_to_next > 0 && ep->tx_time <= now)
	{
	  /* Out of local buffer cache? */
	  if (PREDICT_FALSE (_vec_len (my_buffer_cache) == 0))
	    {
	      u32 n =
		vlib_buffer_alloc (vm, my_buffer_cache, VLIB_FRAME_SIZE);
	      _vec_len (my_buffer_cache) = n;

	      /* Ugh, drop the rest of the expired entries */
	      if (n == 0)
		{
		  u32 drops = 0;
		  while (ep->tx_time <= now && wp->cursize)
		    {
		      wp->head++;
		      if (wp->head == wp->wheel_size)
			wp->head = 0;
		      ep = wp->entries + wp->head;
		      wp->cursize--;
		      drops++;
		    }
		  /* Count the drops */
		  vlib_node_increment_counter (vm, node->node_index,
					       NSIM_TX_ERROR_DROPPED, drops);
		  /* Ship any pkts we already processed */
		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  return n_rx_packets + drops;
		}
	    }

	  /* Allocate a buffer */
	  bi0 = my_buffer_cache[_vec_len (my_buffer_cache) - 1];
	  _vec_len (my_buffer_cache) -= 1;

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /* Initialize the buffer */

	  b0->current_data = 0;
	  b0->current_length = ep->current_length;

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace))
	    {
	      nsim_tx_trace_t *t0;
	      vlib_trace_buffer (vm, node, next_index, b0,
				 0 /* follow_chain */ );
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      t0->expired = ep->tx_time;
	      t0->tx_sw_if_index = ep->tx_sw_if_index;
	    }

	  /* Copy data from the ring */
	  clib_memcpy_fast (b0->data, ep->data, ep->current_length);
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ep->tx_sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    (ep->tx_sw_if_index == nsm->sw_if_index0) ? nsm->sw_if_index1 :
	    nsm->sw_if_index0;
	  next0 = (ep->tx_sw_if_index == nsm->sw_if_index0) ?
	    nsm->output_next_index0 : nsm->output_next_index1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	  /* Advance to the next ring entry */
	  wp->head++;
	  if (wp->head == wp->wheel_size)
	    wp->head = 0;
	  wp->cursize--;
	  ep = wp->entries + wp->head;
	  n_rx_packets++;

	  /* Out of ring entries? */
	  if (PREDICT_FALSE (wp->cursize == 0))
	    break;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

      /* If the current entry hasn't expired, we're done */
      if (ep->tx_time > now)
	break;
    }
  return n_rx_packets;
}

VLIB_NODE_FN (nsim_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return nsim_input_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return nsim_input_inline (vm, node, frame, 0 /* is_trace */ );

}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (nsim_input_node) =
{
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "nsim-wheel",

  /* Will be enabled if/when the feature is configured */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_trace = format_nsim_tx_trace,

  .n_errors = NSIM_N_ERROR,
  .error_strings = nsim_tx_error_strings,
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
