/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <vnet/bonding/node.h>
#include <vnet/ethernet/packet.h>
#include <lacp/node.h>

lacp_state_struct lacp_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
  foreach_lacp_state_flag
#undef _
  {.str = NULL}
};

static vlib_node_registration_t lacp_process_node;

/** \file

    2 x LACP graph nodes: an "interior" node to process
    incoming announcements, and a "process" node to periodically
    send announcements.

    The interior node is neither pipelined nor dual-looped, because
    it would be very unusual to see more than one LACP packet in
    a given input frame. So, it's a very simple / straighforward
    example.
*/

/*
 * packet counter strings
 * Dump these counters via the "show error" CLI command
 */
static char *lacp_error_strings[] = {
#define _(sym,string) string,
  foreach_lacp_error
#undef _
};

/*
 * We actually send all lacp pkts to the "error" node after scanning
 * them, so the graph node has only one next-index. The "error-drop"
 * node automatically bumps our per-node packet counters for us.
 */
typedef enum
{
  LACP_INPUT_NEXT_NORMAL,
  LACP_INPUT_N_NEXT,
} lacp_next_t;

/*
 * Process a frame of lacp packets
 * Expect 1 packet / frame
 */
static uword
lacp_node_fn (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  lacp_input_trace_t *t0;
  uword n_trace = vlib_get_trace_count (vm, node);

  from = vlib_frame_vector_args (frame);	/* array of buffer indices */
  n_left_from = frame->n_vectors;	/* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, error0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      next0 = LACP_INPUT_NEXT_NORMAL;

      /* scan this lacp pkt. error0 is the counter index to bump */
      error0 = lacp_input (vm, b0, bi0);
      b0->error = node->errors[error0];

      /* If this pkt is traced, snapshoot the data */
      if (PREDICT_FALSE (n_trace > 0))
	{
	  int len;
	  vlib_trace_buffer (vm, node, next0, b0,
			     /* follow_chain */ 0);
	  vlib_set_trace_count (vm, node, --n_trace);
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  len = (b0->current_length < sizeof (t0->pkt))
	    ? b0->current_length : sizeof (t0->pkt);
	  t0->len = len;
	  t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  clib_memcpy_fast (&t0->pkt, vlib_buffer_get_current (b0), len);
	}
      /* push this pkt to the next graph node, always error-drop */
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

/*
 * lacp input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lacp_input_node, static) = {
  .function = lacp_node_fn,
  .name = "lacp-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LACP_N_ERROR,
  .error_strings = lacp_error_strings,

  .format_trace = lacp_input_format_trace,

  .n_next_nodes = LACP_INPUT_N_NEXT,
  .next_nodes = {
    [LACP_INPUT_NEXT_NORMAL] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * lacp periodic function
 */
static uword
lacp_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  lacp_main_t *lm = &lacp_main;
  f64 poll_time_remaining;
  uword event_type, *event_data = 0;
  u8 enabled = 0;

  /* So we can send events to the lacp process */
  lm->lacp_process_node_index = lacp_process_node.index;

  ethernet_register_input_type (vm, ETHERNET_TYPE_SLOW_PROTOCOLS /* LACP */ ,
				lacp_input_node.index);

  poll_time_remaining = 0.2;
  while (1)
    {
      if (enabled)
	poll_time_remaining =
	  vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  break;
	case LACP_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case LACP_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      if (event_data)
	_vec_len (event_data) = 0;

      if (vlib_process_suspend_time_is_zero (poll_time_remaining))
	{
	  lacp_periodic (vm);
	  poll_time_remaining = 0.2;
	}
    }

  return 0;
}

/*
 * lacp periodic node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lacp_process_node, static) = {
  .function = lacp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lacp-process",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
