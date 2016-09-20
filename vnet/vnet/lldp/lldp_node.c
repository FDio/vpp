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
/**
 * @file
 * @brief LLDP nodes implementation
 */
#include <vnet/lldp/lldp_node.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>

/* set this to 1 to turn on debug prints via clib_warning() */
#define LLDP_DEBUG (0)

static vlib_node_registration_t lldp_process_node;

#define F(sym, string) static char LLDP_ERR_##sym##_STR[] = string;
foreach_lldp_error (F);
#undef F

/*
 * packet counter strings
 * Dump these counters via the "show error" CLI command
 */
static char *lldp_error_strings[] = {
#define F(sym, string) LLDP_ERR_##sym##_STR,
  foreach_lldp_error (F)
#undef F
};

/*
 * We actually send all lldp pkts to the "error" node after scanning
 * them, so the graph node has only one next-index. The "error-drop"
 * node automatically bumps our per-node packet counters for us.
 */
typedef enum
{
  LLDP_INPUT_NEXT_NORMAL,
  LLDP_INPUT_N_NEXT,
} lldp_next_t;

/*
 * Process a frame of lldp packets
 * Expect 1 packet / frame
 */
static uword
lldp_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  lldp_input_trace_t *t0;

  from = vlib_frame_vector_args (frame);	/* array of buffer indices */
  n_left_from = frame->n_vectors;	/* number of buffer indices */

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, error0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      next0 = LLDP_INPUT_NEXT_NORMAL;

      /* scan this lldp pkt. error0 is the counter index to bump */
      error0 = lldp_input (vm, b0, bi0);
      b0->error = node->errors[error0];

      /* If this pkt is traced, snapshot the data */
      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  int len;
	  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	  len = (b0->current_length < sizeof (t0->data)) ? b0->current_length
	    : sizeof (t0->data);
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
 * lldp input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(lldp_input_node, static) = {
  .function = lldp_node_fn,
  .name = "lldp-input",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LLDP_N_ERROR,
  .error_strings = lldp_error_strings,

  .format_trace = lldp_input_format_trace,

  .n_next_nodes = LLDP_INPUT_N_NEXT,
  .next_nodes =
      {
              [LLDP_INPUT_NEXT_NORMAL] = "error-drop",
      },
};
/* *INDENT-ON* */

/*
 * lldp process node function
 */
static uword
lldp_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  lldp_main_t *lm = &lldp_main;
  f64 timeout = 0;
  uword event_type, *event_data = 0;

  /* So we can send events to the lldp process */
  lm->lldp_process_node_index = lldp_process_node.index;

  /* with ethernet input */
  ethernet_register_input_type (vm, ETHERNET_TYPE_802_1_LLDP /* LLDP */ ,
				lldp_input_node.index);

  while (1)
    {
      if (vec_len (lm->intfs_timeouts))
	{
#if LLDP_DEBUG
	  clib_warning ("DEBUG: wait for event with timeout %f", timeout);
#endif
	  (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	}
      else
	{
#if LLDP_DEBUG
	  clib_warning ("DEBUG: wait for event without timeout");
#endif
	  (void) vlib_process_wait_for_event (vm);
	}
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  /* nothing to do here */
	  break;
	case LLDP_EVENT_RESCHEDULE:
	  /* nothing to do here - reschedule is done automatically after
	   * each event or timeout */
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      if (!vec_len (lm->intfs_timeouts))
	{
	  continue;
	}
      /* send packet(s) and schedule another timeut */
      const f64 now = vlib_time_now (lm->vlib_main);
      while (1)
	{
	  lldp_intf_t *n = pool_elt_at_index (lm->intfs,
					      lm->intfs_timeouts
					      [lm->intfs_timeouts_idx]);
	  if (n->last_sent < 0.01 || now > n->last_sent + lm->msg_tx_interval)
	    {
#if LLDP_DEBUG
	      clib_warning ("send packet to lldp %p, if idx %d", n,
			    n->hw_if_index);
#endif
	      lldp_send_ethernet (lm, n, 0);
	      ++lm->intfs_timeouts_idx;
	      if (lm->intfs_timeouts_idx >= vec_len (lm->intfs_timeouts))
		{
		  lm->intfs_timeouts_idx = 0;
		}
	      continue;
	    }
	  else
	    {
	      timeout = n->last_sent + lm->msg_tx_interval - now;
	      break;
	    }
	}
#if LLDP_DEBUG
      clib_warning ("DEBUG: timeout set to %f", timeout);
      u8 *s = NULL;
      u32 i;
      vec_foreach_index (i, lm->intfs_timeouts)
      {
	if (i == lm->intfs_timeouts_idx)
	  {
	    s = format (s, " [%d]", lm->intfs_timeouts[i]);
	  }
	else
	  {
	    s = format (s, " %d", lm->intfs_timeouts[i]);
	  }
      }
      clib_warning ("DEBUG: timeout schedule: %s", s);
      vec_free (s);
#endif
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

/*
 * lldp process node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(lldp_process_node, static) = {
  .function = lldp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lldp-process",
};
/* *INDENT-ON* */

void
lldp_schedule_intf (lldp_main_t * lm, lldp_intf_t * n)
{
  const int idx = n - lm->intfs;
  u32 v;
  vec_foreach_index (v, lm->intfs_timeouts)
  {
    if (lm->intfs_timeouts[v] == idx)
      {
	/* already scheduled */
	return;
      }
  }
  n->last_sent = 0;		/* ensure that a packet is sent out immediately */
  /* put the interface at the current position in the timeouts - it
   * will timeout immediately */
  vec_insert (lm->intfs_timeouts, 1, lm->intfs_timeouts_idx);
  lm->intfs_timeouts[lm->intfs_timeouts_idx] = n - lm->intfs;
  vlib_process_signal_event (lm->vlib_main, lm->lldp_process_node_index,
			     LLDP_EVENT_RESCHEDULE, 0);
#if LLDP_DEBUG
  clib_warning ("DEBUG: schedule interface %p, if idx %d", n, n->hw_if_index);
#endif
}

void
lldp_unschedule_intf (lldp_main_t * lm, lldp_intf_t * n)
{
  if (!n)
    {
      return;
    }
#if LLDP_DEBUG
  clib_warning ("DEBUG: unschedule interface %p, if idx %d", n,
		n->hw_if_index);
#endif
  const int idx = n - lm->intfs;
  u32 v;
  /* remove intf index from timeouts vector */
  vec_foreach_index (v, lm->intfs_timeouts)
  {
    if (lm->intfs_timeouts[v] == idx)
      {
	vec_delete (lm->intfs_timeouts, 1, v);
	break;
      }
  }
  /* wrap current timeout index to first element if needed */
  if (lm->intfs_timeouts_idx >= vec_len (lm->intfs_timeouts))
    {
      lm->intfs_timeouts_idx = 0;
    }
  vlib_process_signal_event (lm->vlib_main, lm->lldp_process_node_index,
			     LLDP_EVENT_RESCHEDULE, 0);
}

static clib_error_t *
lldp_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  lldp_main_t *lm = &lldp_main;
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  lldp_intf_t *n = lldp_get_intf (lm, hi->hw_if_index);
  if (n)
    {
      if (!(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
	{
	  /* FIXME - the packet sent here isn't send properly - need to find a
	   * way to send the packet before interface goes down */
	  lldp_send_ethernet (lm, n, 1);
	  lldp_unschedule_intf (lm, n);
	}
    }
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (lldp_sw_interface_up_down);

static clib_error_t *
lldp_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  lldp_main_t *lm = &lldp_main;
  lldp_intf_t *n = lldp_get_intf (lm, hw_if_index);
  if (n)
    {
      if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
	{
	  lldp_schedule_intf (lm, n);
	}
    }
  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (lldp_hw_interface_up_down);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
