/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
#include <vnet/cdp/cdp_node.h>
#include <vnet/ethernet/packet.h>

static vlib_node_registration_t cdp_process_node;

/** \file

    2 x CDP graph nodes: an "interior" node to process
    incoming announcements, and a "process" node to periodically
    send announcements.

    The interior node is neither pipelined nor dual-looped, because
    it would be very unusual to see more than one CDP packet in
    a given input frame. So, it's a very simple / straighforward
    example.
*/

/*
 * packet counter strings
 * Dump these counters via the "show error" CLI command
 */
static char *cdp_error_strings[] = {
#define _(sym,string) string,
  foreach_cdp_error
#undef _
};

/*
 * We actually send all cdp pkts to the "error" node after scanning
 * them, so the graph node has only one next-index. The "error-drop"
 * node automatically bumps our per-node packet counters for us.
 */
typedef enum
{
  CDP_INPUT_NEXT_NORMAL,
  CDP_INPUT_N_NEXT,
} cdp_next_t;

/*
 * Process a frame of cdp packets
 * Expect 1 packet / frame
 */
static uword
cdp_node_fn (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  cdp_input_trace_t *t0;

  from = vlib_frame_vector_args (frame);	/* array of buffer indices */
  n_left_from = frame->n_vectors;	/* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, error0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      next0 = CDP_INPUT_NEXT_NORMAL;

      /* scan this cdp pkt. error0 is the counter index to bump */
      error0 = cdp_input (vm, b0, bi0);
      b0->error = node->errors[error0];

      /* If this pkt is traced, snapshoot the data */
      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  int len;
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  len = (b0->current_length < sizeof (t0->data))
	    ? b0->current_length : sizeof (t0->data);
	  t0->len = len;
	  clib_memcpy (t0->data, vlib_buffer_get_current (b0), len);
	}
      /* push this pkt to the next graph node, always error-drop */
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

/*
 * cdp input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cdp_input_node, static) = {
  .function = cdp_node_fn,
  .name = "cdp-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = CDP_N_ERROR,
  .error_strings = cdp_error_strings,

  .format_trace = cdp_input_format_trace,

  .n_next_nodes = CDP_INPUT_N_NEXT,
  .next_nodes = {
    [CDP_INPUT_NEXT_NORMAL] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * cdp periodic function
 */
static uword
cdp_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  cdp_main_t *cm = &cdp_main;
  f64 poll_time_remaining;
  uword event_type, *event_data = 0;

  /* So we can send events to the cdp process */
  cm->cdp_process_node_index = cdp_process_node.index;

  /* Dynamically register the cdp input node with the snap classifier */
  snap_register_input_protocol (vm, "cdp-input", 0xC /* ieee_oui, Cisco */ ,
				0x2000 /* protocol CDP */ ,
				cdp_input_node.index);

  snap_register_input_protocol (vm, "cdp-input", 0xC /* ieee_oui, Cisco */ ,
				0x2004 /* protocol CDP */ ,
				cdp_input_node.index);

#if 0				/* retain for reference */
  /* with the hdlc classifier */
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_cdp, cdp_input_node.index);
#endif

  /* with ethernet input (for SRP) */
  ethernet_register_input_type (vm, ETHERNET_TYPE_CDP /* CDP */ ,
				cdp_input_node.index);

  poll_time_remaining = 10.0 /* seconds */ ;
  while (1)
    {
      /* sleep until next poll time, or msg serialize event occurs */
      poll_time_remaining =
	vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);

      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  break;

	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      if (event_data)
	_vec_len (event_data) = 0;

      /* peer timeout scan, send announcements */
      if (vlib_process_suspend_time_is_zero (poll_time_remaining))
	{
	  cdp_periodic (vm);
	  poll_time_remaining = 10.0;
	}
    }

  return 0;
}

/*
 * cdp periodic node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cdp_process_node, static) = {
  .function = cdp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cdp-process",
};
/* *INDENT-ON* */

void
vnet_cdp_node_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
