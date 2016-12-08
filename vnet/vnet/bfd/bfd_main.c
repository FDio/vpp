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
 * @brief BFD nodes implementation
 */

#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/bfd/bfd_debug.h>
#include <vnet/bfd/bfd_protocol.h>
#include <vnet/bfd/bfd_main.h>

static u64
bfd_us_to_clocks (bfd_main_t * bm, u64 us)
{
  return bm->cpu_cps * ((f64) us / USEC_PER_SECOND);
}

static vlib_node_registration_t bfd_process_node;

typedef enum
{
#define F(t, n) BFD_OUTPUT_##t,
  foreach_bfd_transport (F)
#undef F
    BFD_OUTPUT_N_NEXT,
} bfd_output_next_t;

static u32 bfd_next_index_by_transport[] = {
#define F(t, n) [BFD_TRANSPORT_##t] = BFD_OUTPUT_##t,
  foreach_bfd_transport (F)
#undef F
};

/*
 * We actually send all bfd pkts to the "error" node after scanning
 * them, so the graph node has only one next-index. The "error-drop"
 * node automatically bumps our per-node packet counters for us.
 */
typedef enum
{
  BFD_INPUT_NEXT_NORMAL,
  BFD_INPUT_N_NEXT,
} bfd_input_next_t;

static void bfd_on_state_change (bfd_main_t * bm, bfd_session_t * bs, u64 now,
				 int handling_wakeup);

static void
bfd_set_defaults (bfd_main_t * bm, bfd_session_t * bs)
{
  bs->local_state = BFD_STATE_down;
  bs->local_diag = BFD_DIAG_CODE_no_diag;
  bs->remote_state = BFD_STATE_down;
  bs->local_demand = 0;
  bs->remote_discr = 0;
  bs->desired_min_tx_us = BFD_DEFAULT_DESIRED_MIN_TX_US;
  bs->desired_min_tx_clocks = bfd_us_to_clocks (bm, bs->desired_min_tx_us);
  bs->remote_min_rx_us = 1;
  bs->remote_demand = 0;
}

static void
bfd_set_diag (bfd_session_t * bs, bfd_diag_code_e code)
{
  if (bs->local_diag != code)
    {
      BFD_DBG ("set local_diag, bs_idx=%d: '%d:%s'", bs->bs_idx, code,
	       bfd_diag_code_string (code));
      bs->local_diag = code;
    }
}

static void
bfd_set_state (bfd_main_t * bm, bfd_session_t * bs,
	       bfd_state_e new_state, int handling_wakeup)
{
  if (bs->local_state != new_state)
    {
      BFD_DBG ("Change state, bs_idx=%d: %s->%s", bs->bs_idx,
	       bfd_state_string (bs->local_state),
	       bfd_state_string (new_state));
      bs->local_state = new_state;
      bfd_on_state_change (bm, bs, clib_cpu_time_now (), handling_wakeup);
    }
}

static void
bfd_recalc_tx_interval (bfd_main_t * bm, bfd_session_t * bs)
{
  if (!bs->local_demand)
    {
      bs->transmit_interval_clocks =
	clib_max (bs->desired_min_tx_clocks, bs->remote_min_rx_clocks);
    }
  else
    {
      /* TODO */
    }
  BFD_DBG ("Recalculated transmit interval %lu clocks/%.2fs",
	   bs->transmit_interval_clocks,
	   bs->transmit_interval_clocks / bm->cpu_cps);
}

static void
bfd_calc_next_tx (bfd_main_t * bm, bfd_session_t * bs, u64 now)
{
  if (!bs->local_demand)
    {
      if (bs->local_detect_mult > 1)
	{
	  /* common case - 75-100% of transmit interval */
	  bs->tx_timeout_clocks = now +
	    (1 - .25 * (random_f64 (&bm->random_seed))) *
	    bs->transmit_interval_clocks;
	}
      else
	{
	  /* special case - 75-90% of transmit interval */
	  bs->tx_timeout_clocks =
	    now +
	    (.9 - .15 * (random_f64 (&bm->random_seed))) *
	    bs->transmit_interval_clocks;
	}
    }
  else
    {
      /* TODO */
    }
  if (bs->tx_timeout_clocks)
    {
      BFD_DBG ("Next transmit in %lu clocks/%.02fs@%lu",
	       bs->tx_timeout_clocks - now,
	       (bs->tx_timeout_clocks - now) / bm->cpu_cps,
	       bs->tx_timeout_clocks);
    }
}

static void
bfd_recalc_detection_time (bfd_main_t * bm, bfd_session_t * bs)
{
  if (!bs->local_demand)
    {
      bs->detection_time_clocks =
	bs->remote_detect_mult *
	bfd_us_to_clocks (bm, clib_max (bs->required_min_rx_us,
					bs->remote_desired_min_tx_us));
    }
  else
    {
      bs->detection_time_clocks =
	bs->local_detect_mult *
	bfd_us_to_clocks (bm,
			  clib_max (bs->desired_min_tx_us,
				    bs->remote_min_rx_us));
    }
  BFD_DBG ("Recalculated detection time %lu clocks/%.2fs",
	   bs->detection_time_clocks,
	   bs->detection_time_clocks / bm->cpu_cps);
}

static void
bfd_set_timer (bfd_main_t * bm, bfd_session_t * bs, u64 now,
	       int handling_wakeup)
{
  u64 next = 0;
  u64 rx_timeout = 0;
  if (BFD_STATE_up == bs->local_state)
    {
      rx_timeout = bs->last_rx_clocks + bs->detection_time_clocks;
    }
  if (bs->tx_timeout_clocks && rx_timeout)
    {
      next = clib_min (bs->tx_timeout_clocks, rx_timeout);
    }
  else if (bs->tx_timeout_clocks)
    {
      next = bs->tx_timeout_clocks;
    }
  else if (rx_timeout)
    {
      next = rx_timeout;
    }
  BFD_DBG ("bs_idx=%u, tx_timeout=%lu, rx_timeout=%lu, next=%s", bs->bs_idx,
	   bs->tx_timeout_clocks, rx_timeout,
	   next == bs->tx_timeout_clocks ? "tx" : "rx");
  if (next && (next < bs->wheel_time_clocks || !bs->wheel_time_clocks))
    {
      if (bs->wheel_time_clocks)
	{
	  timing_wheel_delete (&bm->wheel, bs->bs_idx);
	}
      bs->wheel_time_clocks = next;
      BFD_DBG ("timing_wheel_insert(%p, %lu (%ld clocks/%.2fs in the "
	       "future), %u);",
	       &bm->wheel, bs->wheel_time_clocks,
	       (i64) bs->wheel_time_clocks - clib_cpu_time_now (),
	       (i64) (bs->wheel_time_clocks - clib_cpu_time_now ()) /
	       bm->cpu_cps, bs->bs_idx);
      timing_wheel_insert (&bm->wheel, bs->wheel_time_clocks, bs->bs_idx);
      if (!handling_wakeup)
	{
	  vlib_process_signal_event (bm->vlib_main,
				     bm->bfd_process_node_index,
				     BFD_EVENT_RESCHEDULE, bs->bs_idx);
	}
    }
}

static void
bfd_set_desired_min_tx (bfd_main_t * bm, bfd_session_t * bs, u64 now,
			u32 desired_min_tx_us, int handling_wakeup)
{
  bs->desired_min_tx_us = desired_min_tx_us;
  bs->desired_min_tx_clocks = bfd_us_to_clocks (bm, bs->desired_min_tx_us);
  BFD_DBG ("Set desired min tx to %uus/%lu clocks/%.2fs",
	   bs->desired_min_tx_us, bs->desired_min_tx_clocks,
	   bs->desired_min_tx_clocks / bm->cpu_cps);
  bfd_recalc_detection_time (bm, bs);
  bfd_recalc_tx_interval (bm, bs);
  bfd_calc_next_tx (bm, bs, now);
  bfd_set_timer (bm, bs, now, handling_wakeup);
}

void
bfd_session_start (bfd_main_t * bm, bfd_session_t * bs)
{
  BFD_DBG ("%U", format_bfd_session, bs);
  bfd_recalc_tx_interval (bm, bs);
  vlib_process_signal_event (bm->vlib_main, bm->bfd_process_node_index,
			     BFD_EVENT_NEW_SESSION, bs->bs_idx);
}

vnet_api_error_t
bfd_del_session (uword bs_idx)
{
  const bfd_main_t *bm = &bfd_main;
  if (!pool_is_free_index (bm->sessions, bs_idx))
    {
      bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
      pool_put (bm->sessions, bs);
      return 0;
    }
  else
    {
      BFD_ERR ("no such session");
      return VNET_API_ERROR_BFD_NOENT;
    }
  return 0;
}

const char *
bfd_diag_code_string (bfd_diag_code_e diag)
{
#define F(n, t, s)             \
  case BFD_DIAG_CODE_NAME (t): \
    return s;
  switch (diag)
    {
    foreach_bfd_diag_code (F)}
  return "UNKNOWN";
#undef F
}

const char *
bfd_state_string (bfd_state_e state)
{
#define F(n, t, s)         \
  case BFD_STATE_NAME (t): \
    return s;
  switch (state)
    {
    foreach_bfd_state (F)}
  return "UNKNOWN";
#undef F
}

vnet_api_error_t
bfd_session_set_flags (u32 bs_idx, u8 admin_up_down)
{
  bfd_main_t *bm = &bfd_main;
  if (pool_is_free_index (bm->sessions, bs_idx))
    {
      BFD_ERR ("invalid bs_idx=%u", bs_idx);
      return VNET_API_ERROR_BFD_NOENT;
    }
  bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
  if (admin_up_down)
    {
      bfd_set_state (bm, bs, BFD_STATE_down, 0);
    }
  else
    {
      bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
      bfd_set_state (bm, bs, BFD_STATE_admin_down, 0);
    }
  return 0;
}

u8 *
bfd_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  const bfd_input_trace_t *t = va_arg (*args, bfd_input_trace_t *);
  const bfd_pkt_t *pkt = (bfd_pkt_t *) t->data;
  if (t->len > STRUCT_SIZE_OF (bfd_pkt_t, head))
    {
      s = format (s, "BFD v%u, diag=%u(%s), state=%u(%s),\n"
		  "    flags=(P:%u, F:%u, C:%u, A:%u, D:%u, M:%u), detect_mult=%u, "
		  "length=%u\n",
		  bfd_pkt_get_version (pkt), bfd_pkt_get_diag_code (pkt),
		  bfd_diag_code_string (bfd_pkt_get_diag_code (pkt)),
		  bfd_pkt_get_state (pkt),
		  bfd_state_string (bfd_pkt_get_state (pkt)),
		  bfd_pkt_get_poll (pkt), bfd_pkt_get_final (pkt),
		  bfd_pkt_get_control_plane_independent (pkt),
		  bfd_pkt_get_auth_present (pkt), bfd_pkt_get_demand (pkt),
		  bfd_pkt_get_multipoint (pkt), pkt->head.detect_mult,
		  pkt->head.length);
      if (t->len >= sizeof (bfd_pkt_t)
	  && pkt->head.length >= sizeof (bfd_pkt_t))
	{
	  s = format (s, "    my discriminator: %u\n", pkt->my_disc);
	  s = format (s, "    your discriminator: %u\n", pkt->your_disc);
	  s = format (s, "    desired min tx interval: %u\n",
		      clib_net_to_host_u32 (pkt->des_min_tx));
	  s = format (s, "    required min rx interval: %u\n",
		      clib_net_to_host_u32 (pkt->req_min_rx));
	  s = format (s, "    required min echo rx interval: %u\n",
		      clib_net_to_host_u32 (pkt->req_min_echo_rx));
	}
    }

  return s;
}

static void
bfd_on_state_change (bfd_main_t * bm, bfd_session_t * bs, u64 now,
		     int handling_wakeup)
{
  BFD_DBG ("State changed: %U", format_bfd_session, bs);
  bfd_event (bm, bs);
  switch (bs->local_state)
    {
    case BFD_STATE_admin_down:
      bfd_set_desired_min_tx (bm, bs, now,
			      clib_max (bs->config_desired_min_tx_us,
					BFD_DEFAULT_DESIRED_MIN_TX_US),
			      handling_wakeup);
      break;
    case BFD_STATE_down:
      bfd_set_desired_min_tx (bm, bs, now,
			      clib_max (bs->config_desired_min_tx_us,
					BFD_DEFAULT_DESIRED_MIN_TX_US),
			      handling_wakeup);
      break;
    case BFD_STATE_init:
      bfd_set_desired_min_tx (bm, bs, now,
			      clib_max (bs->config_desired_min_tx_us,
					BFD_DEFAULT_DESIRED_MIN_TX_US),
			      handling_wakeup);
      break;
    case BFD_STATE_up:
      bfd_set_desired_min_tx (bm, bs, now, bs->config_desired_min_tx_us,
			      handling_wakeup);
      break;
    }
}

static void
bfd_add_transport_layer (vlib_main_t * vm, vlib_buffer_t * b,
			 bfd_session_t * bs)
{
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      /* fallthrough */
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd via udp, bs_idx=%u", bs->bs_idx);
      bfd_add_udp_transport (vm, b, &bs->udp);
      break;
    }
}

static vlib_buffer_t *
bfd_create_frame (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  bfd_session_t * bs)
{
  u32 bi;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return NULL;
    }

  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  ASSERT (b->current_data == 0);

  u32 *to_next;
  u32 n_left_to_next;

  vlib_get_next_frame (vm, rt, bfd_next_index_by_transport[bs->transport],
		       to_next, n_left_to_next);

  to_next[0] = bi;
  n_left_to_next -= 1;

  vlib_put_next_frame (vm, rt, bfd_next_index_by_transport[bs->transport],
		       n_left_to_next);
  return b;
}

static void
bfd_init_control_frame (vlib_buffer_t * b, bfd_session_t * bs)
{
  bfd_pkt_t *pkt = vlib_buffer_get_current (b);
  const u32 bfd_length = 24;
  memset (pkt, 0, sizeof (*pkt));

  bfd_pkt_set_version (pkt, 1);
  bfd_pkt_set_diag_code (pkt, bs->local_diag);
  bfd_pkt_set_state (pkt, bs->local_state);
  if (bs->local_demand && BFD_STATE_up == bs->local_state &&
      BFD_STATE_up == bs->remote_state)
    {
      bfd_pkt_set_demand (pkt);
    }
  pkt->head.detect_mult = bs->local_detect_mult;
  pkt->head.length = clib_host_to_net_u32 (bfd_length);
  pkt->my_disc = bs->local_discr;
  pkt->your_disc = bs->remote_discr;
  pkt->des_min_tx = clib_host_to_net_u32 (bs->desired_min_tx_us);
  pkt->req_min_rx = clib_host_to_net_u32 (bs->required_min_rx_us);
  pkt->req_min_echo_rx = clib_host_to_net_u32 (0);	/* FIXME */
  b->current_length = bfd_length;
}

static void
bfd_send_periodic (vlib_main_t * vm, vlib_node_runtime_t * rt,
		   bfd_main_t * bm, bfd_session_t * bs, u64 now,
		   int handling_wakeup)
{
  if (!bs->remote_min_rx_us)
    {
      BFD_DBG
	("bfd.RemoteMinRxInterval is zero, not sending periodic control "
	 "frame");
      return;
    }
  /* FIXME
     A system MUST NOT periodically transmit BFD Control packets if Demand
     mode is active on the remote system (bfd.RemoteDemandMode is 1,
     bfd.SessionState is Up, and bfd.RemoteSessionState is Up) and a Poll
     Sequence is not being transmitted.
   */
  if (now >= bs->tx_timeout_clocks)
    {
      BFD_DBG ("Send periodic control frame for bs_idx=%lu", bs->bs_idx);
      vlib_buffer_t *b = bfd_create_frame (vm, rt, bs);
      if (!b)
	{
	  return;
	}
      bfd_init_control_frame (b, bs);
      bfd_add_transport_layer (vm, b, bs);
      bfd_calc_next_tx (bm, bs, now);
    }
  else
    {
      BFD_DBG ("No need to send control frame now");
    }
  bfd_set_timer (bm, bs, now, handling_wakeup);
}

void
bfd_send_final (vlib_main_t * vm, vlib_buffer_t * b, bfd_session_t * bs)
{
  BFD_DBG ("Send final control frame for bs_idx=%lu", bs->bs_idx);
  bfd_init_control_frame (b, bs);
  bfd_pkt_set_final (vlib_buffer_get_current (b));
  bfd_add_transport_layer (vm, b, bs);
}

static void
bfd_check_rx_timeout (bfd_main_t * bm, bfd_session_t * bs, u64 now,
		      int handling_wakeup)
{
  if (bs->last_rx_clocks + bs->detection_time_clocks < now)
    {
      BFD_DBG ("Rx timeout, session goes down");
      bfd_set_diag (bs, BFD_DIAG_CODE_det_time_exp);
      bfd_set_state (bm, bs, BFD_STATE_down, handling_wakeup);
    }
}

void
bfd_on_timeout (vlib_main_t * vm, vlib_node_runtime_t * rt, bfd_main_t * bm,
		bfd_session_t * bs, u64 now)
{
  BFD_DBG ("Timeout for bs_idx=%lu", bs->bs_idx);
  switch (bs->local_state)
    {
    case BFD_STATE_admin_down:
      BFD_ERR ("Unexpected timeout when in %s state",
	       bfd_state_string (bs->local_state));
      abort ();
      break;
    case BFD_STATE_down:
      bfd_send_periodic (vm, rt, bm, bs, now, 1);
      break;
    case BFD_STATE_init:
      BFD_ERR ("Unexpected timeout when in %s state",
	       bfd_state_string (bs->local_state));
      abort ();
      break;
    case BFD_STATE_up:
      bfd_check_rx_timeout (bm, bs, now, 1);
      bfd_send_periodic (vm, rt, bm, bs, now, 1);
      break;
    }
}

/*
 * bfd input routine
 */
bfd_error_t
bfd_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0)
{
  // bfd_main_t *bm = &bfd_main;
  bfd_error_t e;

  /* find our interface */
  bfd_session_t *s = NULL;
  // bfd_get_intf (lm, vnet_buffer (b0)->sw_if_index[VLIB_RX]);

  if (!s)
    {
      /* bfd disabled on this interface, we're done */
      return BFD_ERROR_DISABLED;
    }

  /* Actually scan the packet */
  e = BFD_ERROR_NONE;		// bfd_packet_scan (lm, n, vlib_buffer_get_current (b0));

  return e;
}

/*
 * bfd process node function
 */
static uword
bfd_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  bfd_main_t *bm = &bfd_main;
  u32 *expired = 0;
  uword event_type, *event_data = 0;

  /* So we can send events to the bfd process */
  bm->bfd_process_node_index = bfd_process_node.index;

  while (1)
    {
      u64 now = clib_cpu_time_now ();
      u64 next_expire = timing_wheel_next_expiring_elt_time (&bm->wheel);
      BFD_DBG ("timing_wheel_next_expiring_elt_time(%p) returns %lu",
	       &bm->wheel, next_expire);
      if ((i64) next_expire < 0)
	{
	  BFD_DBG ("wait for event without timeout");
	  (void) vlib_process_wait_for_event (vm);
	  event_type = vlib_process_get_events (vm, &event_data);
	}
      else
	{
	  f64 timeout = ((i64) next_expire - (i64) now) / bm->cpu_cps;
	  BFD_DBG ("wait for event with timeout %.02f", timeout);
	  if (timeout < 0)
	    {
	      BFD_DBG ("negative timeout, already expired, skipping wait");
	      event_type = ~0;
	    }
	  else
	    {
	      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	      event_type = vlib_process_get_events (vm, &event_data);
	    }
	}
      now = clib_cpu_time_now ();
      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  /* nothing to do here */
	  break;
	case BFD_EVENT_RESCHEDULE:
	  /* nothing to do here - reschedule is done automatically after
	   * each event or timeout */
	  break;
	case BFD_EVENT_NEW_SESSION:
	  do
	    {
	      bfd_session_t *bs =
		pool_elt_at_index (bm->sessions, *event_data);
	      bfd_send_periodic (vm, rt, bm, bs, now, 1);
	    }
	  while (0);
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      BFD_DBG ("advancing wheel, now is %lu", now);
      BFD_DBG ("timing_wheel_advance (%p, %lu, %p, 0);", &bm->wheel, now,
	       expired);
      expired = timing_wheel_advance (&bm->wheel, now, expired, 0);
      BFD_DBG ("Expired %d elements", vec_len (expired));
      u32 *p = NULL;
      vec_foreach (p, expired)
      {
	const u32 bs_idx = *p;
	if (!pool_is_free_index (bm->sessions, bs_idx))
	  {
	    bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
	    bs->wheel_time_clocks = 0;	/* no longer scheduled */
	    bfd_on_timeout (vm, rt, bm, bs, now);
	  }
      }
      if (expired)
	{
	  _vec_len (expired) = 0;
	}
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

/*
 * bfd process node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bfd_process_node, static) = {
  .function = bfd_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "bfd-process",
  .n_next_nodes = BFD_OUTPUT_N_NEXT,
  .next_nodes =
      {
#define F(t, n) [BFD_OUTPUT_##t] = n,
          foreach_bfd_transport (F)
#undef F
      },
};
/* *INDENT-ON* */

static clib_error_t *
bfd_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  // bfd_main_t *bm = &bfd_main;
  // vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      /* TODO */
    }
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (bfd_sw_interface_up_down);

static clib_error_t *
bfd_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  // bfd_main_t *bm = &bfd_main;
  if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
      /* TODO */
    }
  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (bfd_hw_interface_up_down);

/*
 * setup function
 */
static clib_error_t *
bfd_main_init (vlib_main_t * vm)
{
  bfd_main_t *bm = &bfd_main;
  bm->random_seed = random_default_seed ();
  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();
  memset (&bm->wheel, 0, sizeof (bm->wheel));
  bm->cpu_cps = 2590000000;	// vm->clib_time.clocks_per_second;
  BFD_DBG ("cps is %.2f", bm->cpu_cps);
  const u64 now = clib_cpu_time_now ();
  timing_wheel_init (&bm->wheel, now, bm->cpu_cps);

  return 0;
}

VLIB_INIT_FUNCTION (bfd_main_init);

bfd_session_t *
bfd_get_session (bfd_main_t * bm, bfd_transport_t t)
{
  bfd_session_t *result;
  pool_get (bm->sessions, result);
  memset (result, 0, sizeof (*result));
  result->bs_idx = result - bm->sessions;
  result->transport = t;
  result->local_discr = random_u32 (&bm->random_seed);
  bfd_set_defaults (bm, result);
  hash_set (bm->session_by_disc, result->local_discr, result->bs_idx);
  return result;
}

void
bfd_put_session (bfd_main_t * bm, bfd_session_t * bs)
{
  hash_unset (bm->session_by_disc, bs->local_discr);
  pool_put (bm->sessions, bs);
}

bfd_session_t *
bfd_find_session_by_idx (bfd_main_t * bm, uword bs_idx)
{
  if (!pool_is_free_index (bm->sessions, bs_idx))
    {
      return pool_elt_at_index (bm->sessions, bs_idx);
    }
  return NULL;
}

bfd_session_t *
bfd_find_session_by_disc (bfd_main_t * bm, u32 disc)
{
  uword *p = hash_get (bfd_main.session_by_disc, disc);
  if (p)
    {
      return pool_elt_at_index (bfd_main.sessions, *p);
    }
  return NULL;
}

/**
 * @brief verify bfd packet - common checks
 *
 * @param pkt
 *
 * @return 1 if bfd packet is valid
 */
int
bfd_verify_pkt_common (const bfd_pkt_t * pkt)
{
  if (1 != bfd_pkt_get_version (pkt))
    {
      BFD_ERR ("BFD verification failed - unexpected version: '%d'",
	       bfd_pkt_get_version (pkt));
      return 0;
    }
  if (pkt->head.length < sizeof (bfd_pkt_t) ||
      (bfd_pkt_get_auth_present (pkt) &&
       pkt->head.length < sizeof (bfd_pkt_with_auth_t)))
    {
      BFD_ERR ("BFD verification failed - unexpected length: '%d' (auth "
	       "present: %d)",
	       pkt->head.length, bfd_pkt_get_auth_present (pkt));
      return 0;
    }
  if (!pkt->head.detect_mult)
    {
      BFD_ERR ("BFD verification failed - unexpected detect-mult: '%d'",
	       pkt->head.detect_mult);
      return 0;
    }
  if (bfd_pkt_get_multipoint (pkt))
    {
      BFD_ERR ("BFD verification failed - unexpected multipoint: '%d'",
	       bfd_pkt_get_multipoint (pkt));
      return 0;
    }
  if (!pkt->my_disc)
    {
      BFD_ERR ("BFD verification failed - unexpected my-disc: '%d'",
	       pkt->my_disc);
      return 0;
    }
  if (!pkt->your_disc)
    {
      const u8 pkt_state = bfd_pkt_get_state (pkt);
      if (pkt_state != BFD_STATE_down && pkt_state != BFD_STATE_admin_down)
	{
	  BFD_ERR ("BFD verification failed - unexpected state: '%s' "
		   "(your-disc is zero)", bfd_state_string (pkt_state));
	  return 0;
	}
    }
  return 1;
}

/**
 * @brief verify bfd packet - authentication
 *
 * @param pkt
 *
 * @return 1 if bfd packet is valid
 */
int
bfd_verify_pkt_session (const bfd_pkt_t * pkt, u16 pkt_size,
			const bfd_session_t * bs)
{
  const bfd_pkt_with_auth_t *with_auth = (bfd_pkt_with_auth_t *) pkt;
  if (!bfd_pkt_get_auth_present (pkt))
    {
      if (pkt_size > sizeof (*pkt))
	{
	  BFD_ERR ("BFD verification failed - unexpected packet size '%d' "
		   "(auth not present)", pkt_size);
	  return 0;
	}
    }
  else
    {
      if (!with_auth->auth.type)
	{
	  BFD_ERR ("BFD verification failed - unexpected auth type: '%d'",
		   with_auth->auth.type);
	  return 0;
	}
      /* TODO FIXME - implement the actual verification */
    }
  return 1;
}

void
bfd_consume_pkt (bfd_main_t * bm, const bfd_pkt_t * pkt, u32 bs_idx)
{
  bfd_session_t *bs = bfd_find_session_by_idx (bm, bs_idx);
  if (!bs)
    {
      return;
    }
  BFD_DBG ("Scanning bfd packet, bs_idx=%d", bs->bs_idx);
  bs->remote_discr = pkt->my_disc;
  bs->remote_state = bfd_pkt_get_state (pkt);
  bs->remote_demand = bfd_pkt_get_demand (pkt);
  bs->remote_min_rx_us = clib_net_to_host_u32 (pkt->req_min_rx);
  bs->remote_min_rx_clocks = bfd_us_to_clocks (bm, bs->remote_min_rx_us);
  BFD_DBG ("Set remote min rx to %lu clocks/%.2fs", bs->remote_min_rx_clocks,
	   bs->remote_min_rx_clocks / bm->cpu_cps);
  bs->remote_desired_min_tx_us = clib_net_to_host_u32 (pkt->des_min_tx);
  bs->remote_detect_mult = pkt->head.detect_mult;
  bfd_recalc_detection_time (bm, bs);
  bs->last_rx_clocks = clib_cpu_time_now ();
  /* FIXME
     If the Required Min Echo RX Interval field is zero, the
     transmission of Echo packets, if any, MUST cease.

     If a Poll Sequence is being transmitted by the local system and
     the Final (F) bit in the received packet is set, the Poll Sequence
     MUST be terminated.
   */
  /* FIXME 6.8.2 */
  /* FIXME 6.8.4 */
  if (BFD_STATE_admin_down == bs->local_state)
    return;
  if (BFD_STATE_admin_down == bs->remote_state)
    {
      bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
      bfd_set_state (bm, bs, BFD_STATE_down, 0);
    }
  else if (BFD_STATE_down == bs->local_state)
    {
      if (BFD_STATE_down == bs->remote_state)
	{
	  bfd_set_state (bm, bs, BFD_STATE_init, 0);
	}
      else if (BFD_STATE_init == bs->remote_state)
	{
	  bfd_set_state (bm, bs, BFD_STATE_up, 0);
	}
    }
  else if (BFD_STATE_init == bs->local_state)
    {
      if (BFD_STATE_up == bs->remote_state ||
	  BFD_STATE_init == bs->remote_state)
	{
	  bfd_set_state (bm, bs, BFD_STATE_up, 0);
	}
    }
  else				/* BFD_STATE_up == bs->local_state */
    {
      if (BFD_STATE_down == bs->remote_state)
	{
	  bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
	  bfd_set_state (bm, bs, BFD_STATE_down, 0);
	}
    }
}

u8 *
format_bfd_session (u8 * s, va_list * args)
{
  const bfd_session_t *bs = va_arg (*args, bfd_session_t *);
  return format (s, "BFD(%u): bfd.SessionState=%s, "
		 "bfd.RemoteSessionState=%s, "
		 "bfd.LocalDiscr=%u, "
		 "bfd.RemoteDiscr=%u, "
		 "bfd.LocalDiag=%s, "
		 "bfd.DesiredMinTxInterval=%u, "
		 "bfd.RequiredMinRxInterval=%u, "
		 "bfd.RemoteMinRxInterval=%u, "
		 "bfd.DemandMode=%s, "
		 "bfd.RemoteDemandMode=%s, "
		 "bfd.DetectMult=%u, ",
		 bs->bs_idx, bfd_state_string (bs->local_state),
		 bfd_state_string (bs->remote_state), bs->local_discr,
		 bs->remote_discr, bfd_diag_code_string (bs->local_diag),
		 bs->desired_min_tx_us, bs->required_min_rx_us,
		 bs->remote_min_rx_us, (bs->local_demand ? "yes" : "no"),
		 (bs->remote_demand ? "yes" : "no"), bs->local_detect_mult);
}

bfd_main_t bfd_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
