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

always_inline uword
nsim_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * f, int is_trace)
{
  nsim_main_t *nsm = &nsim_main;
  nsim_wheel_t *wp = nsm->wheel_by_thread[vm->thread_index];
  nsim_wheel_entry_t *ep;
  f64 now;

  /* Nothing on the scheduler wheel? */
  if (wp->cursize == 0)
    return 0;

  /* First entry on the wheel isn't expired? */
  ep = wp->entries + wp->head;
  now = vlib_time_now (vm);
  if (ep->tx_time > now)
    return 0;

  u32 n_burst = clib_min (wp->cursize, NSIM_MAX_TX_BURST), n_tx_packets = 0;
  u32 froms[NSIM_MAX_TX_BURST], *from;
  u16 nexts[NSIM_MAX_TX_BURST], *next;

  from = froms;
  next = nexts;
  while (n_tx_packets < n_burst && ep->tx_time <= now)
    {
      /* prefetch one line / 2 entries ahead */
      if ((((uword) ep) & (CLIB_CACHE_LINE_BYTES - 1)) == 0)
	CLIB_PREFETCH ((ep + 2), CLIB_CACHE_LINE_BYTES, LOAD);

      ep = wp->entries + wp->head;
      from[0] = ep->buffer_index;
      next[0] = ep->output_next_index;

      wp->head++;
      if (wp->head == wp->wheel_size)
	wp->head = 0;

      from += 1;
      next += 1;
      n_tx_packets++;
    }

  wp->cursize -= n_tx_packets;
  vlib_buffer_enqueue_to_next (vm, node, froms, nexts, n_tx_packets);
  vlib_node_increment_counter (vm, node->node_index,
			       NSIM_TX_ERROR_TRANSMITTED, n_tx_packets);
  return n_tx_packets;
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

  .n_errors = NSIM_TX_N_ERROR,
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
