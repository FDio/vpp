/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief BFD nodes implementation
 */

#include <vlibmemory/api.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/xxhash.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/bfd/bfd_debug.h>
#include <vnet/bfd/bfd_protocol.h>
#include <vnet/bfd/bfd_main.h>
#include <vlib/log.h>
#include <vnet/crypto/crypto.h>

const char *
bfd_hop_type_string (bfd_hop_type_e hoptype)
{
  switch (hoptype)
    {
#define F(x)                                                                  \
  case BFD_HOP_TYPE_##x:                                                      \
    return "BFD_HOP_TYPE_" #x;
      foreach_bfd_hop (F)
#undef F
    }
  return "UNKNOWN";
}

static void
bfd_validate_counters (bfd_main_t *bm)
{
  vlib_validate_combined_counter (&bm->rx_counter, pool_elts (bm->sessions));
  vlib_validate_combined_counter (&bm->rx_echo_counter,
				  pool_elts (bm->sessions));
  vlib_validate_combined_counter (&bm->tx_counter, pool_elts (bm->sessions));
  vlib_validate_combined_counter (&bm->tx_echo_counter,
				  pool_elts (bm->sessions));
}

static u64
bfd_calc_echo_checksum (u32 discriminator, u64 expire_time, u32 secret)
{
  u64 checksum = 0;
#if defined(clib_crc32c_uses_intrinsics) && !defined (__i386__)
  checksum = clib_crc32c_u64 (0, discriminator);
  checksum = clib_crc32c_u64 (checksum, expire_time);
  checksum = clib_crc32c_u64 (checksum, secret);
#else
  checksum = clib_xxhash (discriminator ^ expire_time ^ secret);
#endif
  return checksum;
}

static u64
bfd_usec_to_nsec (u64 us)
{
  return us * NSEC_PER_USEC;
}

u32
bfd_nsec_to_usec (u64 nsec)
{
  return nsec / NSEC_PER_USEC;
}

always_inline u64
bfd_time_now_nsec (vlib_main_t * vm, f64 * vm_time)
{
  f64 _vm_time = vlib_time_now (vm);
  if (vm_time)
    *vm_time = _vm_time;
  return _vm_time * NSEC_PER_SEC;
}

static vlib_node_registration_t bfd_process_node;

u8 *
format_bfd_auth_key (u8 * s, va_list * args)
{
  const bfd_auth_key_t *key = va_arg (*args, bfd_auth_key_t *);
  if (key)
    {
      s = format (s, "{auth-type=%u:%s, conf-key-id=%u, use-count=%u}, ",
		  key->auth_type, bfd_auth_type_str (key->auth_type),
		  key->conf_key_id, key->use_count);
    }
  else
    {
      s = format (s, "{none}");
    }
  return s;
}

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
  bs->remote_discr = 0;
  bs->hop_type = BFD_HOP_TYPE_SINGLE;
  bs->config_desired_min_tx_usec = BFD_DEFAULT_DESIRED_MIN_TX_USEC;
  bs->config_desired_min_tx_nsec = bm->default_desired_min_tx_nsec;
  bs->effective_desired_min_tx_nsec = bm->default_desired_min_tx_nsec;
  bs->remote_min_rx_usec = 1;
  bs->remote_min_rx_nsec = bfd_usec_to_nsec (bs->remote_min_rx_usec);
  bs->remote_min_echo_rx_usec = 0;
  bs->remote_min_echo_rx_nsec = 0;
  bs->remote_demand = 0;
  bs->auth.remote_seq_number = 0;
  bs->auth.remote_seq_number_known = 0;
  bs->auth.local_seq_number = random_u32 (&bm->random_seed);
  bs->echo_secret = random_u32 (&bm->random_seed);
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
bfd_set_state (vlib_main_t * vm, bfd_main_t * bm, bfd_session_t * bs,
	       bfd_state_e new_state, int handling_wakeup)
{
  if (bs->local_state != new_state)
    {
      BFD_DBG ("Change state, bs_idx=%d: %s->%s", bs->bs_idx,
	       bfd_state_string (bs->local_state),
	       bfd_state_string (new_state));
      bs->local_state = new_state;
      bfd_on_state_change (bm, bs, bfd_time_now_nsec (vm, NULL),
			   handling_wakeup);
    }
}

const char *
bfd_poll_state_string (bfd_poll_state_e state)
{
  switch (state)
    {
#define F(x)         \
  case BFD_POLL_##x: \
    return "BFD_POLL_" #x;
      foreach_bfd_poll_state (F)
#undef F
    }
  return "UNKNOWN";
}

static void
bfd_set_poll_state (bfd_session_t * bs, bfd_poll_state_e state)
{
  if (bs->poll_state != state)
    {
      BFD_DBG ("Setting poll state=%s, bs_idx=%u",
	       bfd_poll_state_string (state), bs->bs_idx);
      bs->poll_state = state;
    }
}

static void
bfd_recalc_tx_interval (bfd_session_t *bs)
{
  bs->transmit_interval_nsec =
    clib_max (bs->effective_desired_min_tx_nsec, bs->remote_min_rx_nsec);
  BFD_DBG ("Recalculated transmit interval " BFD_CLK_FMT,
	   BFD_CLK_PRN (bs->transmit_interval_nsec));
}

static void
bfd_recalc_echo_tx_interval (bfd_session_t *bs)
{
  bs->echo_transmit_interval_nsec =
    clib_max (bs->effective_desired_min_tx_nsec, bs->remote_min_echo_rx_nsec);
  BFD_DBG ("Recalculated echo transmit interval " BFD_CLK_FMT,
	   BFD_CLK_PRN (bs->echo_transmit_interval_nsec));
}

static void
bfd_calc_next_tx (bfd_main_t * bm, bfd_session_t * bs, u64 now)
{
  if (bs->local_detect_mult > 1)
    {
      /* common case - 75-100% of transmit interval */
      bs->tx_timeout_nsec = bs->last_tx_nsec +
	(1 - .25 * (random_f64 (&bm->random_seed))) *
	bs->transmit_interval_nsec;
      if (bs->tx_timeout_nsec < now)
	{
	  /*
	   * the timeout is in the past, which means that either remote
	   * demand mode was set or performance/clock issues ...
	   */
	  BFD_DBG ("Missed %lu transmit events (now is %lu, calc "
		   "tx_timeout is %lu)",
		   (now - bs->tx_timeout_nsec) /
		   bs->transmit_interval_nsec, now, bs->tx_timeout_nsec);
	  bs->tx_timeout_nsec = now;
	}
    }
  else
    {
      /* special case - 75-90% of transmit interval */
      bs->tx_timeout_nsec = bs->last_tx_nsec +
	(.9 - .15 * (random_f64 (&bm->random_seed))) *
	bs->transmit_interval_nsec;
      if (bs->tx_timeout_nsec < now)
	{
	  /*
	   * the timeout is in the past, which means that either remote
	   * demand mode was set or performance/clock issues ...
	   */
	  BFD_DBG ("Missed %lu transmit events (now is %lu, calc "
		   "tx_timeout is %lu)",
		   (now - bs->tx_timeout_nsec) /
		   bs->transmit_interval_nsec, now, bs->tx_timeout_nsec);
	  bs->tx_timeout_nsec = now;
	}
    }
  if (bs->tx_timeout_nsec)
    {
      BFD_DBG ("Next transmit in %lu nsec/%.02fs@%lu",
	       bs->tx_timeout_nsec - now,
	       (bs->tx_timeout_nsec - now) * SEC_PER_NSEC,
	       bs->tx_timeout_nsec);
    }
}

static void
bfd_calc_next_echo_tx (bfd_session_t *bs, u64 now)
{
  bs->echo_tx_timeout_nsec =
    bs->echo_last_tx_nsec + bs->echo_transmit_interval_nsec;
  if (bs->echo_tx_timeout_nsec < now)
    {
      /* huh, we've missed it already, transmit now */
      BFD_DBG ("Missed %lu echo transmit events (now is %lu, calc tx_timeout "
	       "is %lu)",
	       (now - bs->echo_tx_timeout_nsec) /
	       bs->echo_transmit_interval_nsec,
	       now, bs->echo_tx_timeout_nsec);
      bs->echo_tx_timeout_nsec = now;
    }
  BFD_DBG ("Next echo transmit in %lu nsec/%.02fs@%lu",
	   bs->echo_tx_timeout_nsec - now,
	   (bs->echo_tx_timeout_nsec - now) * SEC_PER_NSEC,
	   bs->echo_tx_timeout_nsec);
}

static void
bfd_recalc_detection_time (bfd_session_t *bs)
{
  if (bs->local_state == BFD_STATE_init || bs->local_state == BFD_STATE_up)
    {
      bs->detection_time_nsec =
	bs->remote_detect_mult *
	clib_max (bs->effective_required_min_rx_nsec,
		  bs->remote_desired_min_tx_nsec);
      BFD_DBG ("Recalculated detection time %lu nsec/%.3fs",
	       bs->detection_time_nsec,
	       bs->detection_time_nsec * SEC_PER_NSEC);
    }
}

static void
bfd_set_timer (bfd_main_t * bm, bfd_session_t * bs, u64 now,
	       int handling_wakeup)
{
  u64 next = 0;
  u64 rx_timeout = 0;
  u64 tx_timeout = 0;
  if (BFD_STATE_up == bs->local_state)
    {
      rx_timeout = bs->last_rx_nsec + bs->detection_time_nsec;
    }
  if (BFD_STATE_up != bs->local_state ||
      (!bs->remote_demand && bs->remote_min_rx_usec) ||
      BFD_POLL_NOT_NEEDED != bs->poll_state)
    {
      tx_timeout = bs->tx_timeout_nsec;
    }
  if (tx_timeout && rx_timeout)
    {
      next = clib_min (tx_timeout, rx_timeout);
    }
  else if (tx_timeout)
    {
      next = tx_timeout;
    }
  else if (rx_timeout)
    {
      next = rx_timeout;
    }
  if (bs->echo && next > bs->echo_tx_timeout_nsec)
    {
      next = bs->echo_tx_timeout_nsec;
    }
  BFD_DBG ("bs_idx=%u, tx_timeout=%lu, echo_tx_timeout=%lu, rx_timeout=%lu, "
	   "next=%s",
	   bs->bs_idx, tx_timeout, bs->echo_tx_timeout_nsec, rx_timeout,
	   next == tx_timeout
	   ? "tx" : (next == bs->echo_tx_timeout_nsec ? "echo tx" : "rx"));
  if (next)
    {
      int send_signal = 0;
      bs->event_time_nsec = next;
      /* add extra tick if it's not even */
      u32 wheel_time_ticks =
	(bs->event_time_nsec - now) / bm->nsec_per_tw_tick +
	((bs->event_time_nsec - now) % bm->nsec_per_tw_tick != 0);
      BFD_DBG ("event_time_nsec %lu (%lu nsec/%.3fs in future) -> "
	       "wheel_time_ticks %u", bs->event_time_nsec,
	       bs->event_time_nsec - now,
	       (bs->event_time_nsec - now) * SEC_PER_NSEC, wheel_time_ticks);
      wheel_time_ticks = wheel_time_ticks ? wheel_time_ticks : 1;
      bfd_lock (bm);
      if (bs->tw_id)
	{
	  TW (tw_timer_update) (&bm->wheel, bs->tw_id, wheel_time_ticks);
	  BFD_DBG ("tw_timer_update(%p, %u, %lu);", &bm->wheel, bs->tw_id,
		   wheel_time_ticks);
	}
      else
	{
	  bs->tw_id =
	    TW (tw_timer_start) (&bm->wheel, bs->bs_idx, 0, wheel_time_ticks);
	  BFD_DBG ("tw_timer_start(%p, %u, 0, %lu) == %u;", &bm->wheel,
		   bs->bs_idx, wheel_time_ticks);
	}

      if (!handling_wakeup)
	{

	  /* Send only if it is earlier than current awaited wakeup time */
	  send_signal =
	    (bs->event_time_nsec < bm->bfd_process_next_wakeup_nsec) &&
	    /*
	     * If the wake-up time is within 2x the delay of the event propagation delay,
	     * avoid the expense of sending the event. The 2x multiplier is to workaround the race whereby
	     * simultaneous event + expired timer create one recurring bogus wakeup/suspend instance,
	     * due to double scheduling of the node on the pending list.
	     */
	    (bm->bfd_process_next_wakeup_nsec - bs->event_time_nsec >
	     2 * bm->bfd_process_wakeup_event_delay_nsec) &&
	    /* Must be no events in flight to send an event */
	    (!bm->bfd_process_wakeup_events_in_flight);

	  /* If we do send the signal, note this down along with the start timestamp */
	  if (send_signal)
	    {
	      bm->bfd_process_wakeup_events_in_flight++;
	      bm->bfd_process_wakeup_event_start_nsec = now;
	    }
	}
      bfd_unlock (bm);

      /* Use the multithreaded event sending so the workers can send events too */
      if (send_signal)
	{
	  vlib_process_signal_event_mt (bm->vlib_main,
					bm->bfd_process_node_index,
					BFD_EVENT_RESCHEDULE, ~0);
	}
    }
}

static void
bfd_set_effective_desired_min_tx (bfd_main_t * bm,
				  bfd_session_t * bs, u64 now,
				  u64 desired_min_tx_nsec)
{
  bs->effective_desired_min_tx_nsec = desired_min_tx_nsec;
  BFD_DBG ("Set effective desired min tx to " BFD_CLK_FMT,
	   BFD_CLK_PRN (bs->effective_desired_min_tx_nsec));
  bfd_recalc_detection_time (bs);
  bfd_recalc_tx_interval (bs);
  bfd_recalc_echo_tx_interval (bs);
  bfd_calc_next_tx (bm, bs, now);
}

static void
bfd_set_effective_required_min_rx (bfd_session_t *bs, u64 required_min_rx_nsec)
{
  bs->effective_required_min_rx_nsec = required_min_rx_nsec;
  BFD_DBG ("Set effective required min rx to " BFD_CLK_FMT,
	   BFD_CLK_PRN (bs->effective_required_min_rx_nsec));
  bfd_recalc_detection_time (bs);
}

static void
bfd_set_remote_required_min_rx (bfd_session_t *bs,
				u32 remote_required_min_rx_usec)
{
  if (bs->remote_min_rx_usec != remote_required_min_rx_usec)
    {
      bs->remote_min_rx_usec = remote_required_min_rx_usec;
      bs->remote_min_rx_nsec = bfd_usec_to_nsec (remote_required_min_rx_usec);
      BFD_DBG ("Set remote min rx to " BFD_CLK_FMT,
	       BFD_CLK_PRN (bs->remote_min_rx_nsec));
      bfd_recalc_detection_time (bs);
      bfd_recalc_tx_interval (bs);
    }
}

static void
bfd_set_remote_required_min_echo_rx (bfd_session_t *bs,
				     u32 remote_required_min_echo_rx_usec)
{
  if (bs->remote_min_echo_rx_usec != remote_required_min_echo_rx_usec)
    {
      bs->remote_min_echo_rx_usec = remote_required_min_echo_rx_usec;
      bs->remote_min_echo_rx_nsec =
	bfd_usec_to_nsec (bs->remote_min_echo_rx_usec);
      BFD_DBG ("Set remote min echo rx to " BFD_CLK_FMT,
	       BFD_CLK_PRN (bs->remote_min_echo_rx_nsec));
      bfd_recalc_echo_tx_interval (bs);
    }
}

static void
bfd_notify_listeners (bfd_main_t * bm,
		      bfd_listen_event_e event, const bfd_session_t * bs)
{
  bfd_notify_fn_t *fn;
  vec_foreach (fn, bm->listeners)
  {
    (*fn) (event, bs);
  }
}

void
bfd_session_start (bfd_main_t * bm, bfd_session_t * bs)
{
  BFD_DBG ("\nStarting session: %U", format_bfd_session, bs);
  vlib_log_info (bm->log_class, "start BFD session: %U",
		 format_bfd_session_brief, bs);
  bfd_set_effective_required_min_rx (bs, bs->config_required_min_rx_nsec);
  bfd_recalc_tx_interval (bs);
  vlib_process_signal_event (bm->vlib_main, bm->bfd_process_node_index,
			     BFD_EVENT_NEW_SESSION, bs->bs_idx);
  bfd_notify_listeners (bm, BFD_LISTEN_EVENT_CREATE, bs);
}

void
bfd_session_stop (bfd_main_t *bm, bfd_session_t *bs)
{
  BFD_DBG ("\nStopping session: %U", format_bfd_session, bs);
  bfd_notify_listeners (bm, BFD_LISTEN_EVENT_DELETE, bs);
}

void
bfd_session_set_flags (vlib_main_t * vm, bfd_session_t * bs, u8 admin_up_down)
{
  bfd_main_t *bm = &bfd_main;
  u64 now = bfd_time_now_nsec (vm, NULL);
  if (admin_up_down)
    {
      BFD_DBG ("Session set admin-up, bs-idx=%u", bs->bs_idx);
      vlib_log_info (bm->log_class, "set session admin-up: %U",
		     format_bfd_session_brief, bs);
      bfd_set_state (vm, bm, bs, BFD_STATE_down, 0);
      bfd_set_diag (bs, BFD_DIAG_CODE_no_diag);
      bfd_calc_next_tx (bm, bs, now);
      bfd_set_timer (bm, bs, now, 0);
    }
  else
    {
      BFD_DBG ("Session set admin-down, bs-idx=%u", bs->bs_idx);
      vlib_log_info (bm->log_class, "set session admin-down: %U",
		     format_bfd_session_brief, bs);
      bfd_set_diag (bs, BFD_DIAG_CODE_admin_down);
      bfd_set_state (vm, bm, bs, BFD_STATE_admin_down, 0);
      bfd_calc_next_tx (bm, bs, now);
      bfd_set_timer (bm, bs, now, 0);
    }
}

u8 *
format_bfd_pkt (u8 *s, va_list *args)
{
  u32 len = va_arg (*args, u32);
  u8 *data = va_arg (*args, u8 *);

  const bfd_pkt_t *pkt = (bfd_pkt_t *) data;
  if (len > STRUCT_SIZE_OF (bfd_pkt_t, head))
    {
      s = format (
	s,
	"BFD v%u, diag=%u(%s), state=%u(%s),\n"
	"    flags=(P:%u, F:%u, C:%u, A:%u, D:%u, M:%u), "
	"detect_mult=%u, length=%u",
	bfd_pkt_get_version (pkt), bfd_pkt_get_diag_code (pkt),
	bfd_diag_code_string (bfd_pkt_get_diag_code (pkt)),
	bfd_pkt_get_state (pkt), bfd_state_string (bfd_pkt_get_state (pkt)),
	bfd_pkt_get_poll (pkt), bfd_pkt_get_final (pkt),
	bfd_pkt_get_control_plane_independent (pkt),
	bfd_pkt_get_auth_present (pkt), bfd_pkt_get_demand (pkt),
	bfd_pkt_get_multipoint (pkt), pkt->head.detect_mult, pkt->head.length);
      if (len >= sizeof (bfd_pkt_t) && pkt->head.length >= sizeof (bfd_pkt_t))
	{
	  s = format (s, "\n    my discriminator: %u\n",
		      clib_net_to_host_u32 (pkt->my_disc));
	  s = format (s, "    your discriminator: %u\n",
		      clib_net_to_host_u32 (pkt->your_disc));
	  s = format (s, "    desired min tx interval: %u\n",
		      clib_net_to_host_u32 (pkt->des_min_tx));
	  s = format (s, "    required min rx interval: %u\n",
		      clib_net_to_host_u32 (pkt->req_min_rx));
	  s = format (s, "    required min echo rx interval: %u",
		      clib_net_to_host_u32 (pkt->req_min_echo_rx));
	}
      if (len >= sizeof (bfd_pkt_with_common_auth_t) &&
	  pkt->head.length >= sizeof (bfd_pkt_with_common_auth_t) &&
	  bfd_pkt_get_auth_present (pkt))
	{
	  const bfd_pkt_with_common_auth_t *with_auth = (void *) pkt;
	  const bfd_auth_common_t *common = &with_auth->common_auth;
	  s = format (s, "\n    auth len: %u\n", common->len);
	  s = format (s, "    auth type: %u:%s", common->type,
		      bfd_auth_type_str (common->type));
	  if (len >= sizeof (bfd_pkt_with_sha1_auth_t) &&
	      pkt->head.length >= sizeof (bfd_pkt_with_sha1_auth_t) &&
	      (BFD_AUTH_TYPE_keyed_sha1 == common->type ||
	       BFD_AUTH_TYPE_meticulous_keyed_sha1 == common->type))
	    {
	      const bfd_pkt_with_sha1_auth_t *with_sha1 = (void *) pkt;
	      const bfd_auth_sha1_t *sha1 = &with_sha1->sha1_auth;
	      s = format (s, "    seq num: %u\n",
			  clib_net_to_host_u32 (sha1->seq_num));
	      s = format (s, "    key id: %u\n", sha1->key_id);
	      s = format (s, "    hash: %U", format_hex_bytes, sha1->hash,
			  sizeof (sha1->hash));
	    }
	}
    }

  return s;
}

u8 *
bfd_input_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  const bfd_input_trace_t *t = va_arg (*args, bfd_input_trace_t *);

  s = format (s, "%U", format_bfd_pkt, t->len, t->data);

  return s;
}

typedef struct
{
  u32 bs_idx;
} bfd_rpc_event_t;

static void
bfd_rpc_event_cb (const bfd_rpc_event_t * a)
{
  bfd_main_t *bm = &bfd_main;
  u32 bs_idx = a->bs_idx;
  u32 valid_bs = 0;
  bfd_session_t session_data;

  bfd_lock (bm);
  if (!pool_is_free_index (bm->sessions, bs_idx))
    {
      bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
      clib_memcpy (&session_data, bs, sizeof (bfd_session_t));
      valid_bs = 1;
    }
  else
    {
      BFD_DBG ("Ignoring event RPC for non-existent session index %u",
	       bs_idx);
    }
  bfd_unlock (bm);

  if (valid_bs)
    bfd_event (bm, &session_data);
}

static void
bfd_event_rpc (u32 bs_idx)
{
  const u32 data_size = sizeof (bfd_rpc_event_t);
  u8 data[data_size];
  bfd_rpc_event_t *event = (bfd_rpc_event_t *) data;

  event->bs_idx = bs_idx;
  vlib_rpc_call_main_thread (bfd_rpc_event_cb, data, data_size);
}

typedef struct
{
  u32 bs_idx;
} bfd_rpc_notify_listeners_t;

static void
bfd_rpc_notify_listeners_cb (const bfd_rpc_notify_listeners_t * a)
{
  bfd_main_t *bm = &bfd_main;
  u32 bs_idx = a->bs_idx;
  bfd_lock (bm);
  if (!pool_is_free_index (bm->sessions, bs_idx))
    {
      bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
      bfd_notify_listeners (bm, BFD_LISTEN_EVENT_UPDATE, bs);
    }
  else
    {
      BFD_DBG ("Ignoring notify RPC for non-existent session index %u",
	       bs_idx);
    }
  bfd_unlock (bm);
}

static void
bfd_notify_listeners_rpc (u32 bs_idx)
{
  const u32 data_size = sizeof (bfd_rpc_notify_listeners_t);
  u8 data[data_size];
  bfd_rpc_notify_listeners_t *notify = (bfd_rpc_notify_listeners_t *) data;
  notify->bs_idx = bs_idx;
  vlib_rpc_call_main_thread (bfd_rpc_notify_listeners_cb, data, data_size);
}

static void
bfd_on_state_change (bfd_main_t * bm, bfd_session_t * bs, u64 now,
		     int handling_wakeup)
{
  BFD_DBG ("\nState changed: %U", format_bfd_session, bs);

  if (vlib_get_thread_index () == 0)
    {
      bfd_event (bm, bs);
    }
  else
    {
      /* without RPC - a REGRESSION: BFD event are not propagated */
      bfd_event_rpc (bs->bs_idx);
    }

  switch (bs->local_state)
    {
    case BFD_STATE_admin_down:
      bs->echo = 0;
      bfd_set_effective_desired_min_tx (bm, bs, now,
					clib_max
					(bs->config_desired_min_tx_nsec,
					 bm->default_desired_min_tx_nsec));
      bfd_set_effective_required_min_rx (bs, bs->config_required_min_rx_nsec);
      bfd_set_timer (bm, bs, now, handling_wakeup);
      break;
    case BFD_STATE_down:
      bs->echo = 0;
      bfd_set_effective_desired_min_tx (bm, bs, now,
					clib_max
					(bs->config_desired_min_tx_nsec,
					 bm->default_desired_min_tx_nsec));
      bfd_set_effective_required_min_rx (bs, bs->config_required_min_rx_nsec);
      bfd_set_timer (bm, bs, now, handling_wakeup);
      break;
    case BFD_STATE_init:
      bs->echo = 0;
      bfd_set_effective_desired_min_tx (bm, bs, now,
					bs->config_desired_min_tx_nsec);
      bfd_set_timer (bm, bs, now, handling_wakeup);
      break;
    case BFD_STATE_up:
      bfd_set_effective_desired_min_tx (bm, bs, now,
					bs->config_desired_min_tx_nsec);
      if (BFD_POLL_NOT_NEEDED == bs->poll_state)
	{
	  bfd_set_effective_required_min_rx (bs,
					     bs->config_required_min_rx_nsec);
	}
      bfd_set_timer (bm, bs, now, handling_wakeup);
      break;
    }
  if (vlib_get_thread_index () == 0)
    {
      bfd_notify_listeners (bm, BFD_LISTEN_EVENT_UPDATE, bs);
    }
  else
    {
      /* without RPC - a REGRESSION: state changes are not propagated */
      bfd_notify_listeners_rpc (bs->bs_idx);
    }
}

static void
bfd_on_config_change (bfd_main_t *bm, bfd_session_t *bs, u64 now)
{
  /*
   * if remote demand mode is set and we need to do a poll, set the next
   * timeout so that the session wakes up immediately
   */
  if (bs->remote_demand && BFD_POLL_NEEDED == bs->poll_state &&
      bs->poll_state_start_or_timeout_nsec < now)
    {
      bs->tx_timeout_nsec = now;
    }
  bfd_recalc_detection_time (bs);
  bfd_set_timer (bm, bs, now, 0);
}

static void
bfd_add_transport_layer (vlib_main_t * vm, u32 bi, bfd_session_t * bs)
{
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      BFD_DBG ("Transport bfd via udp4, bs_idx=%u", bs->bs_idx);
      bfd_add_udp4_transport (vm, bi, bs, 0 /* is_echo */ );
      break;
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd via udp6, bs_idx=%u", bs->bs_idx);
      bfd_add_udp6_transport (vm, bi, bs, 0 /* is_echo */ );
      break;
    }
}

static int
bfd_transport_control_frame (vlib_main_t *vm, vlib_node_runtime_t *rt, u32 bi,
			     bfd_session_t *bs)
{
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      BFD_DBG ("Transport bfd via udp4, bs_idx=%u", bs->bs_idx);
      return bfd_transport_udp4 (vm, rt, bi, bs, 0 /* is_echo */);
      break;
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd via udp6, bs_idx=%u", bs->bs_idx);
      return bfd_transport_udp6 (vm, rt, bi, bs, 0 /* is_echo */);
      break;
    }
  return 0;
}

static int
bfd_echo_add_transport_layer (vlib_main_t * vm, u32 bi, bfd_session_t * bs)
{
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      BFD_DBG ("Transport bfd echo via udp4, bs_idx=%u", bs->bs_idx);
      return bfd_add_udp4_transport (vm, bi, bs, 1 /* is_echo */ );
      break;
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd echo via udp6, bs_idx=%u", bs->bs_idx);
      return bfd_add_udp6_transport (vm, bi, bs, 1 /* is_echo */ );
      break;
    }
  return 0;
}

static int
bfd_transport_echo (vlib_main_t *vm, vlib_node_runtime_t *rt, u32 bi,
		    bfd_session_t *bs)
{
  switch (bs->transport)
    {
    case BFD_TRANSPORT_UDP4:
      BFD_DBG ("Transport bfd echo via udp4, bs_idx=%u", bs->bs_idx);
      return bfd_transport_udp4 (vm, rt, bi, bs, 1 /* is_echo */);
      break;
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd echo via udp6, bs_idx=%u", bs->bs_idx);
      return bfd_transport_udp6 (vm, rt, bi, bs, 1 /* is_echo */);
      break;
    }
  return 0;
}

static void
bfd_add_sha1_auth_section (vlib_main_t *vm, vlib_buffer_t *b,
			   bfd_session_t *bs)
{
  bfd_pkt_with_sha1_auth_t *pkt = vlib_buffer_get_current (b);
  bfd_auth_sha1_t *auth = &pkt->sha1_auth;
  b->current_length += sizeof (*auth);
  pkt->pkt.head.length += sizeof (*auth);
  bfd_pkt_set_auth_present (&pkt->pkt);
  clib_memset (auth, 0, sizeof (*auth));
  auth->type_len.type = bs->auth.curr_key->auth_type;
  /*
   * only meticulous authentication types require incrementing seq number
   * for every message, but doing so doesn't violate the RFC
   */
  ++bs->auth.local_seq_number;
  auth->type_len.len = sizeof (bfd_auth_sha1_t);
  auth->key_id = bs->auth.curr_bfd_key_id;
  auth->seq_num = clib_host_to_net_u32 (bs->auth.local_seq_number);
  /*
   * first copy the password into the packet, then calculate the hash
   * and finally replace the password with the calculated hash
   */
  clib_memcpy (auth->hash, bs->auth.curr_key->key,
	       sizeof (bs->auth.curr_key->key));
  unsigned char hash[sizeof (auth->hash)];

  vnet_crypto_op_t op;
  vnet_crypto_op_init (&op, VNET_CRYPTO_OP_SHA1_HASH);
  op.src = (u8 *) pkt;
  op.len = sizeof (*pkt);
  op.digest = hash;
  vnet_crypto_process_ops (&op, 1);
  BFD_DBG ("hashing: %U", format_hex_bytes, pkt, sizeof (*pkt));
  clib_memcpy (auth->hash, hash, sizeof (hash));
}

static void
bfd_add_auth_section (vlib_main_t *vm, vlib_buffer_t *b, bfd_session_t *bs)
{
  bfd_main_t *bm = &bfd_main;
  if (bs->auth.curr_key)
    {
      const bfd_auth_type_e auth_type = bs->auth.curr_key->auth_type;
      switch (auth_type)
	{
	case BFD_AUTH_TYPE_reserved:
	  /* fallthrough */
	case BFD_AUTH_TYPE_simple_password:
	  /* fallthrough */
	case BFD_AUTH_TYPE_keyed_md5:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_md5:
	  vlib_log_crit (bm->log_class,
			 "internal error, unexpected BFD auth type '%d'",
			 auth_type);
	  break;
	case BFD_AUTH_TYPE_keyed_sha1:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_sha1:
	  bfd_add_sha1_auth_section (vm, b, bs);
	  break;
	}
    }
}

static int
bfd_is_echo_possible (bfd_session_t * bs)
{
  if (BFD_STATE_up == bs->local_state && BFD_STATE_up == bs->remote_state &&
      bs->remote_min_echo_rx_usec > 0)
    {
      switch (bs->transport)
	{
	case BFD_TRANSPORT_UDP4:
	  return bfd_udp_is_echo_available (BFD_TRANSPORT_UDP4);
	case BFD_TRANSPORT_UDP6:
	  return bfd_udp_is_echo_available (BFD_TRANSPORT_UDP6);
	}
    }
  return 0;
}

static void
bfd_init_control_frame (bfd_session_t *bs, vlib_buffer_t *b)
{
  bfd_pkt_t *pkt = vlib_buffer_get_current (b);
  u32 bfd_length = 0;
  bfd_length = sizeof (bfd_pkt_t);
  clib_memset (pkt, 0, sizeof (*pkt));
  bfd_pkt_set_version (pkt, 1);
  bfd_pkt_set_diag_code (pkt, bs->local_diag);
  bfd_pkt_set_state (pkt, bs->local_state);
  pkt->head.detect_mult = bs->local_detect_mult;
  pkt->head.length = bfd_length;
  pkt->my_disc = bs->local_discr;
  pkt->your_disc = bs->remote_discr;
  pkt->des_min_tx = clib_host_to_net_u32 (bs->config_desired_min_tx_usec);
  if (bs->echo)
    {
      pkt->req_min_rx =
	clib_host_to_net_u32 (bfd_nsec_to_usec
			      (bs->effective_required_min_rx_nsec));
    }
  else
    {
      pkt->req_min_rx =
	clib_host_to_net_u32 (bs->config_required_min_rx_usec);
    }
  pkt->req_min_echo_rx = clib_host_to_net_u32 (1);
  b->current_length = bfd_length;
}

typedef struct
{
  u32 bs_idx;
  u32 len;
  u8 data[400];
} bfd_process_trace_t;

static void
bfd_process_trace_buf (vlib_main_t *vm, vlib_node_runtime_t *rt,
		       vlib_buffer_t *b, bfd_session_t *bs)
{
  u32 n_trace = vlib_get_trace_count (vm, rt);
  if (n_trace > 0)
    {
      bfd_process_trace_t *tr;
      if (vlib_trace_buffer (vm, rt, 0, b, 0))
	{
	  tr = vlib_add_trace (vm, rt, b, sizeof (*tr));
	  tr->bs_idx = bs->bs_idx;
	  u64 len = (b->current_length < sizeof (tr->data)) ?
			    b->current_length :
			    sizeof (tr->data);
	  tr->len = len;
	  clib_memcpy_fast (tr->data, vlib_buffer_get_current (b), len);
	  --n_trace;
	  vlib_set_trace_count (vm, rt, n_trace);
	}
    }
}

static void
bfd_send_echo (vlib_main_t *vm, vlib_node_runtime_t *rt, bfd_main_t *bm,
	       bfd_session_t *bs, u64 now)
{
  if (!bfd_is_echo_possible (bs))
    {
      BFD_DBG ("\nSwitching off echo function: %U", format_bfd_session, bs);
      bs->echo = 0;
      return;
    }
  if (now >= bs->echo_tx_timeout_nsec)
    {
      BFD_DBG ("\nSending echo packet: %U", format_bfd_session, bs);
      u32 bi;
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  vlib_log_crit (bm->log_class, "buffer allocation failure");
	  return;
	}
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      ASSERT (b->current_data == 0);
      bfd_echo_pkt_t *pkt = vlib_buffer_get_current (b);
      clib_memset (pkt, 0, sizeof (*pkt));
      pkt->discriminator = bs->local_discr;
      pkt->expire_time_nsec =
	now + bs->echo_transmit_interval_nsec * bs->local_detect_mult;
      pkt->checksum =
	bfd_calc_echo_checksum (bs->local_discr, pkt->expire_time_nsec,
				bs->echo_secret);
      b->current_length = sizeof (*pkt);
      bfd_process_trace_buf (vm, rt, b, bs);
      if (!bfd_echo_add_transport_layer (vm, bi, bs))
	{
	  BFD_ERR ("cannot send echo packet out, turning echo off");
	  bs->echo = 0;
	  vlib_buffer_free_one (vm, bi);
	  return;
	}
      if (!bfd_transport_echo (vm, rt, bi, bs))
	{
	  BFD_ERR ("cannot send echo packet out, turning echo off");
	  bs->echo = 0;
	  vlib_buffer_free_one (vm, bi);
	  return;
	}
      bs->echo_last_tx_nsec = now;
      bfd_calc_next_echo_tx (bs, now);
    }
  else
    {
      BFD_DBG
	("No need to send echo packet now, now is %lu, tx_timeout is %lu",
	 now, bs->echo_tx_timeout_nsec);
    }
}

static void
bfd_send_periodic (vlib_main_t *vm, vlib_node_runtime_t *rt, bfd_main_t *bm,
		   bfd_session_t *bs, u64 now)
{
  if (!bs->remote_min_rx_usec && BFD_POLL_NOT_NEEDED == bs->poll_state)
    {
      BFD_DBG ("Remote min rx interval is zero, not sending periodic control "
	       "frame");
      return;
    }
  if (BFD_POLL_NOT_NEEDED == bs->poll_state && bs->remote_demand &&
      BFD_STATE_up == bs->local_state && BFD_STATE_up == bs->remote_state)
    {
      /*
       * A system MUST NOT periodically transmit BFD Control packets if Demand
       * mode is active on the remote system (bfd.RemoteDemandMode is 1,
       * bfd.SessionState is Up, and bfd.RemoteSessionState is Up) and a Poll
       * Sequence is not being transmitted.
       */
      BFD_DBG ("Remote demand is set, not sending periodic control frame");
      return;
    }
  if (now >= bs->tx_timeout_nsec)
    {
      BFD_DBG ("\nSending periodic control frame: %U", format_bfd_session,
	       bs);
      u32 bi;
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  vlib_log_crit (bm->log_class, "buffer allocation failure");
	  return;
	}
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      ASSERT (b->current_data == 0);
      bfd_init_control_frame (bs, b);
      switch (bs->poll_state)
	{
	case BFD_POLL_NEEDED:
	  if (now < bs->poll_state_start_or_timeout_nsec)
	    {
	      BFD_DBG ("Cannot start a poll sequence yet, need to wait for "
		       BFD_CLK_FMT,
		       BFD_CLK_PRN (bs->poll_state_start_or_timeout_nsec -
				    now));
	      break;
	    }
	  bs->poll_state_start_or_timeout_nsec = now;
	  bfd_set_poll_state (bs, BFD_POLL_IN_PROGRESS);
	  /* fallthrough */
	case BFD_POLL_IN_PROGRESS:
	case BFD_POLL_IN_PROGRESS_AND_QUEUED:
	  bfd_pkt_set_poll (vlib_buffer_get_current (b));
	  BFD_DBG ("Setting poll bit in packet, bs_idx=%u", bs->bs_idx);
	  break;
	case BFD_POLL_NOT_NEEDED:
	  /* fallthrough */
	  break;
	}
      bfd_add_auth_section (vm, b, bs);
      bfd_process_trace_buf (vm, rt, b, bs);
      bfd_add_transport_layer (vm, bi, bs);
      if (!bfd_transport_control_frame (vm, rt, bi, bs))
	{
	  vlib_buffer_free_one (vm, bi);
	}
      bs->last_tx_nsec = now;
      bfd_calc_next_tx (bm, bs, now);
    }
  else
    {
      BFD_DBG
	("No need to send control frame now, now is %lu, tx_timeout is %lu",
	 now, bs->tx_timeout_nsec);
    }
}

void
bfd_init_final_control_frame (vlib_main_t *vm, vlib_buffer_t *b,
			      bfd_session_t *bs)
{
  BFD_DBG ("Send final control frame for bs_idx=%lu", bs->bs_idx);
  bfd_init_control_frame (bs, b);
  bfd_pkt_set_final (vlib_buffer_get_current (b));
  bfd_add_auth_section (vm, b, bs);
  u32 bi = vlib_get_buffer_index (vm, b);
  bfd_add_transport_layer (vm, bi, bs);
  bs->last_tx_nsec = bfd_time_now_nsec (vm, NULL);
  /*
   * RFC allows to include changes in final frame, so if there were any
   * pending, we already did that, thus we can clear any pending poll needs
   */
  bfd_set_poll_state (bs, BFD_POLL_NOT_NEEDED);
}

static void
bfd_check_rx_timeout (vlib_main_t * vm, bfd_main_t * bm, bfd_session_t * bs,
		      u64 now, int handling_wakeup)
{
  if (bs->last_rx_nsec + bs->detection_time_nsec <= now)
    {
      BFD_DBG ("Rx timeout, session goes down");
      /*
       * RFC 5880 6.8.1. State Variables

       * bfd.RemoteDiscr

       * The remote discriminator for this BFD session.  This is the
       * discriminator chosen by the remote system, and is totally opaque
       * to the local system.  This MUST be initialized to zero.  If a
       * period of a Detection Time passes without the receipt of a valid,
       * authenticated BFD packet from the remote system, this variable
       * MUST be set to zero.
       */
      bs->remote_discr = 0;
      bfd_set_diag (bs, BFD_DIAG_CODE_det_time_exp);
      bfd_set_state (vm, bm, bs, BFD_STATE_down, handling_wakeup);
      /*
       * If the remote system does not receive any
       * BFD Control packets for a Detection Time, it SHOULD reset
       * bfd.RemoteMinRxInterval to its initial value of 1 (per section 6.8.1,
       * since it is no longer required to maintain previous session state)
       * and then can transmit at its own rate.
       */
      bfd_set_remote_required_min_rx (bs, 1);
    }
  else if (bs->echo
	   && bs->echo_last_rx_nsec +
	   bs->echo_transmit_interval_nsec * bs->local_detect_mult <= now)
    {
      BFD_DBG ("Echo rx timeout, session goes down");
      bfd_set_diag (bs, BFD_DIAG_CODE_echo_failed);
      bfd_set_state (vm, bm, bs, BFD_STATE_down, handling_wakeup);
    }
}

void
bfd_on_timeout (vlib_main_t *vm, vlib_node_runtime_t *rt, bfd_main_t *bm,
		bfd_session_t *bs, u64 now)
{
  BFD_DBG ("Timeout for bs_idx=%lu", bs->bs_idx);
  switch (bs->local_state)
    {
    case BFD_STATE_admin_down:
      /* fallthrough */
    case BFD_STATE_down:
      bfd_send_periodic (vm, rt, bm, bs, now);
      break;
    case BFD_STATE_init:
      bfd_check_rx_timeout (vm, bm, bs, now, 1);
      bfd_send_periodic (vm, rt, bm, bs, now);
      break;
    case BFD_STATE_up:
      bfd_check_rx_timeout (vm, bm, bs, now, 1);
      if (BFD_POLL_NOT_NEEDED == bs->poll_state && !bs->echo &&
	  bfd_is_echo_possible (bs))
	{
	  /* switch on echo function as main detection method now */
	  BFD_DBG ("Switching on echo function, bs_idx=%u", bs->bs_idx);
	  bs->echo = 1;
	  bs->echo_last_rx_nsec = now;
	  bs->echo_tx_timeout_nsec = now;
	  bfd_set_effective_required_min_rx (
	    bs, clib_max (bm->min_required_min_rx_while_echo_nsec,
			  bs->config_required_min_rx_nsec));
	  bfd_set_poll_state (bs, BFD_POLL_NEEDED);
	}
      bfd_send_periodic (vm, rt, bm, bs, now);
      if (bs->echo)
	{
	  bfd_send_echo (vm, rt, bm, bs, now);
	}
      break;
    }
}

u8 *
format_bfd_process_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bfd_process_trace_t *t = va_arg (*args, bfd_process_trace_t *);

  s =
    format (s, "bs_idx=%u => %U", t->bs_idx, format_bfd_pkt, t->len, t->data);

  return s;
}

/*
 * bfd process node function
 */
static uword
bfd_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
	     CLIB_UNUSED (vlib_frame_t *f))
{
  bfd_main_t *bm = &bfd_main;
  u32 *expired = 0;
  uword event_type, *event_data = 0;

  /* So we can send events to the bfd process */
  bm->bfd_process_node_index = bfd_process_node.index;

  while (1)
    {
      f64 vm_time;
      u64 now = bfd_time_now_nsec (vm, &vm_time);
      BFD_DBG ("wakeup, now is %llunsec, vlib_time_now() is %.9f", now,
	       vm_time);
      bfd_lock (bm);
      f64 timeout;
      if (pool_elts (bm->sessions))
	{
	  u32 first_expires_in_ticks =
	    TW (tw_timer_first_expires_in_ticks) (&bm->wheel);
	  if (!first_expires_in_ticks)
	    {
	      BFD_DBG
		("tw_timer_first_expires_in_ticks(%p) returns 0ticks",
		 &bm->wheel);
	      timeout = bm->wheel.next_run_time - vm_time;
	      BFD_DBG ("wheel.next_run_time is %.9f",
		       bm->wheel.next_run_time);
	      u64 next_expire_nsec = now + timeout * SEC_PER_NSEC;
	      bm->bfd_process_next_wakeup_nsec = next_expire_nsec;
	      bfd_unlock (bm);
	    }
	  else
	    {
	      BFD_DBG ("tw_timer_first_expires_in_ticks(%p) returns %luticks",
		       &bm->wheel, first_expires_in_ticks);
	      u64 next_expire_nsec =
		now + first_expires_in_ticks * bm->nsec_per_tw_tick;
	      bm->bfd_process_next_wakeup_nsec = next_expire_nsec;
	      bfd_unlock (bm);
	      ASSERT (next_expire_nsec - now <= UINT32_MAX);
	      // cast to u32 to avoid warning
	      timeout = (u32) (next_expire_nsec - now) * SEC_PER_NSEC;
	    }
	  BFD_DBG ("vlib_process_wait_for_event_or_clock(vm, %.09f)",
		   timeout);
	  (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	}
      else
	{
	  bfd_unlock (bm);
	  (void) vlib_process_wait_for_event (vm);
	}
      event_type = vlib_process_get_events (vm, &event_data);
      now = bfd_time_now_nsec (vm, &vm_time);
      uword *session_index;
      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  /* nothing to do here */
	  break;
	case BFD_EVENT_RESCHEDULE:
	  BFD_DBG ("reschedule event");
	  bfd_lock (bm);
	  bm->bfd_process_wakeup_event_delay_nsec =
	    now - bm->bfd_process_wakeup_event_start_nsec;
	  bm->bfd_process_wakeup_events_in_flight--;
	  bfd_unlock (bm);
	  /* nothing to do here - reschedule is done automatically after
	   * each event or timeout */
	  break;
	case BFD_EVENT_NEW_SESSION:
	  vec_foreach (session_index, event_data)
	  {
	    bfd_lock (bm);
	    if (!pool_is_free_index (bm->sessions, *session_index))
	      {
		bfd_session_t *bs =
		  pool_elt_at_index (bm->sessions, *session_index);
		bfd_send_periodic (vm, rt, bm, bs, now);
		bfd_set_timer (bm, bs, now, 1);
	      }
	    else
	      {
		BFD_DBG ("Ignoring event for non-existent session index %u",
			 (u32) * session_index);
	      }
	    bfd_unlock (bm);
	  }
	  break;
	case BFD_EVENT_CONFIG_CHANGED:
	  vec_foreach (session_index, event_data)
	  {
	    bfd_lock (bm);
	    if (!pool_is_free_index (bm->sessions, *session_index))
	      {
		bfd_session_t *bs =
		  pool_elt_at_index (bm->sessions, *session_index);
		bfd_on_config_change (bm, bs, now);
	      }
	    else
	      {
		BFD_DBG ("Ignoring event for non-existent session index %u",
			 (u32) * session_index);
	      }
	    bfd_unlock (bm);
	  }
	  break;
	default:
	  vlib_log_err (bm->log_class, "BUG: event type 0x%wx", event_type);
	  break;
	}
      BFD_DBG ("tw_timer_expire_timers_vec(%p, %.04f);", &bm->wheel, vm_time);
      bfd_lock (bm);
      expired =
	TW (tw_timer_expire_timers_vec) (&bm->wheel, vm_time, expired);
      BFD_DBG ("Expired %d elements", vec_len (expired));
      u32 *p = NULL;
      vec_foreach (p, expired)
      {
	const u32 bs_idx = *p;
	if (!pool_is_free_index (bm->sessions, bs_idx))
	  {
	    bfd_session_t *bs = pool_elt_at_index (bm->sessions, bs_idx);
	    bs->tw_id = 0;	/* timer is gone because it expired */
	    bfd_on_timeout (vm, rt, bm, bs, now);
	    bfd_set_timer (bm, bs, now, 1);
	  }
      }
      bfd_unlock (bm);
      if (expired)
	{
	  vec_set_len (expired, 0);
	}
      if (event_data)
	{
	  vec_set_len (event_data, 0);
	}
    }

  return 0;
}

/*
 * bfd process node declaration
 */
// clang-format off
VLIB_REGISTER_NODE (bfd_process_node, static) =
{
  .function = bfd_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "bfd-process",
  .flags = (VLIB_NODE_FLAG_TRACE_SUPPORTED),
  .format_trace = format_bfd_process_trace,
  .n_next_nodes = BFD_TX_N_NEXT,
  .next_nodes = {
    [BFD_TX_IP4_ARP] = "ip4-arp",
    [BFD_TX_IP6_NDP] = "ip6-discover-neighbor",
    [BFD_TX_IP4_REWRITE] = "ip4-rewrite",
    [BFD_TX_IP6_REWRITE] = "ip6-rewrite",
    [BFD_TX_IP4_MIDCHAIN] = "ip4-midchain",
    [BFD_TX_IP6_MIDCHAIN] = "ip6-midchain",
    [BFD_TX_IP4_LOOKUP] = "ip4-lookup",
    [BFD_TX_IP6_LOOKUP] = "ip6-lookup",
  }
};
// clang-format on

static clib_error_t *
bfd_sw_interface_up_down (CLIB_UNUSED (vnet_main_t *vnm),
			  CLIB_UNUSED (u32 sw_if_index), u32 flags)
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
bfd_hw_interface_up_down (CLIB_UNUSED (vnet_main_t *vnm),
			  CLIB_UNUSED (u32 hw_if_index), u32 flags)
{
  // bfd_main_t *bm = &bfd_main;
  if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
      /* TODO */
    }
  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (bfd_hw_interface_up_down);

void
bfd_register_listener (bfd_notify_fn_t fn)
{
  bfd_main_t *bm = &bfd_main;

  vec_add1 (bm->listeners, fn);
}

/*
 * setup function
 */
static clib_error_t *
bfd_main_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;
#if BFD_DEBUG
  setbuf (stdout, NULL);
#endif
  bfd_main_t *bm = &bfd_main;
  bm->random_seed = random_default_seed ();
  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();
  clib_memset (&bm->wheel, 0, sizeof (bm->wheel));
  bm->nsec_per_tw_tick = (f64) NSEC_PER_SEC / BFD_TW_TPS;
  bm->default_desired_min_tx_nsec =
    bfd_usec_to_nsec (BFD_DEFAULT_DESIRED_MIN_TX_USEC);
  bm->min_required_min_rx_while_echo_nsec =
    bfd_usec_to_nsec (BFD_REQUIRED_MIN_RX_USEC_WHILE_ECHO);
  BFD_DBG ("tw_timer_wheel_init(%p, %p, %.04f, %u)", &bm->wheel, NULL,
	   1.00 / BFD_TW_TPS, ~0);
  TW (tw_timer_wheel_init) (&bm->wheel, NULL, 1.00 / BFD_TW_TPS, ~0);
  bm->log_class = vlib_log_register_class ("bfd", 0);
  vlib_log_debug (bm->log_class, "initialized");
  bm->owner_thread_index = ~0;
  if (n_vlib_mains > 1)
    clib_spinlock_init (&bm->lock);
  bm->rx_counter.name = "bfd rx session counters";
  bm->rx_counter.stat_segment_name = "/bfd/rx-session-counters";
  bm->rx_echo_counter.name = "bfd rx session echo counters";
  bm->rx_echo_counter.stat_segment_name = "/bfd/rx-session-echo-counters";
  bm->tx_counter.name = "bfd tx session counters";
  bm->tx_counter.stat_segment_name = "/bfd/tx-session-counters";
  bm->tx_echo_counter.name = "bfd tx session echo counters";
  bm->tx_echo_counter.stat_segment_name = "/bfd/tx-session-echo-counters";
  return 0;
}

VLIB_INIT_FUNCTION (bfd_main_init);

bfd_session_t *
bfd_get_session (bfd_main_t * bm, bfd_transport_e t)
{
  bfd_session_t *result;

  bfd_lock (bm);

  pool_get (bm->sessions, result);
  clib_memset (result, 0, sizeof (*result));
  result->bs_idx = result - bm->sessions;
  result->transport = t;
  const unsigned limit = 1000;
  unsigned counter = 0;
  do
    {
      result->local_discr = random_u32 (&bm->random_seed);
      if (counter > limit)
	{
	  vlib_log_crit (bm->log_class,
			 "couldn't allocate unused session discriminator even "
			 "after %u tries!", limit);
	  pool_put (bm->sessions, result);
	  bfd_unlock (bm);
	  return NULL;
	}
      ++counter;
    }
  while (hash_get (bm->session_by_disc, result->local_discr));
  bfd_set_defaults (bm, result);
  hash_set (bm->session_by_disc, result->local_discr, result->bs_idx);
  bfd_validate_counters (bm);
  vlib_zero_combined_counter (&bm->rx_counter, result->bs_idx);
  vlib_zero_combined_counter (&bm->rx_echo_counter, result->bs_idx);
  vlib_zero_combined_counter (&bm->tx_counter, result->bs_idx);
  vlib_zero_combined_counter (&bm->tx_echo_counter, result->bs_idx);
  bfd_unlock (bm);
  return result;
}

void
bfd_put_session (bfd_main_t * bm, bfd_session_t * bs)
{
  bfd_lock (bm);

  vlib_log_info (bm->log_class, "delete session: %U",
		 format_bfd_session_brief, bs);
  if (bs->auth.curr_key)
    {
      --bs->auth.curr_key->use_count;
    }
  if (bs->auth.next_key)
    {
      --bs->auth.next_key->use_count;
    }
  hash_unset (bm->session_by_disc, bs->local_discr);
  vlib_zero_combined_counter (&bm->rx_counter, bs->bs_idx);
  vlib_zero_combined_counter (&bm->rx_echo_counter, bs->bs_idx);
  vlib_zero_combined_counter (&bm->tx_counter, bs->bs_idx);
  vlib_zero_combined_counter (&bm->tx_echo_counter, bs->bs_idx);
  pool_put (bm->sessions, bs);
  bfd_unlock (bm);
}

bfd_session_t *
bfd_find_session_by_idx (bfd_main_t * bm, uword bs_idx)
{
  bfd_lock_check (bm);
  if (!pool_is_free_index (bm->sessions, bs_idx))
    {
      return pool_elt_at_index (bm->sessions, bs_idx);
    }
  return NULL;
}

bfd_session_t *
bfd_find_session_by_disc (bfd_main_t * bm, u32 disc)
{
  bfd_lock_check (bm);
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
bfd_error_t
bfd_verify_pkt_common (const bfd_pkt_t *pkt)
{
  if (1 != bfd_pkt_get_version (pkt))
    {
      BFD_ERR ("BFD verification failed - unexpected version: '%d'",
	       bfd_pkt_get_version (pkt));
      return BFD_ERROR_VERSION;
    }
  if (pkt->head.length < sizeof (bfd_pkt_t) ||
      (bfd_pkt_get_auth_present (pkt) &&
       pkt->head.length < sizeof (bfd_pkt_with_common_auth_t)))
    {
      BFD_ERR ("BFD verification failed - unexpected length: '%d' (auth "
	       "present: %d)",
	       pkt->head.length, bfd_pkt_get_auth_present (pkt));
      return BFD_ERROR_LENGTH;
    }
  if (!pkt->head.detect_mult)
    {
      BFD_ERR ("BFD verification failed - unexpected detect-mult: '%d'",
	       pkt->head.detect_mult);
      return BFD_ERROR_DETECT_MULTI;
    }
  if (bfd_pkt_get_multipoint (pkt))
    {
      BFD_ERR ("BFD verification failed - unexpected multipoint: '%d'",
	       bfd_pkt_get_multipoint (pkt));
      return BFD_ERROR_MULTI_POINT;
    }
  if (!pkt->my_disc)
    {
      BFD_ERR ("BFD verification failed - unexpected my-disc: '%d'",
	       pkt->my_disc);
      return BFD_ERROR_MY_DISC;
    }
  if (!pkt->your_disc)
    {
      const u8 pkt_state = bfd_pkt_get_state (pkt);
      if (pkt_state != BFD_STATE_down && pkt_state != BFD_STATE_admin_down)
	{
	  BFD_ERR ("BFD verification failed - unexpected state: '%s' "
		   "(your-disc is zero)", bfd_state_string (pkt_state));
	  return BFD_ERROR_YOUR_DISC;
	}
    }
  return BFD_ERROR_NONE;
}

static void
bfd_session_switch_auth_to_next (bfd_session_t * bs)
{
  BFD_DBG ("Switching authentication key from %U to %U for bs_idx=%u",
	   format_bfd_auth_key, bs->auth.curr_key, format_bfd_auth_key,
	   bs->auth.next_key, bs->bs_idx);
  bs->auth.is_delayed = 0;
  if (bs->auth.curr_key)
    {
      --bs->auth.curr_key->use_count;
    }
  bs->auth.curr_key = bs->auth.next_key;
  bs->auth.next_key = NULL;
  bs->auth.curr_bfd_key_id = bs->auth.next_bfd_key_id;
}

static int
bfd_auth_type_is_meticulous (bfd_auth_type_e auth_type)
{
  if (BFD_AUTH_TYPE_meticulous_keyed_md5 == auth_type ||
      BFD_AUTH_TYPE_meticulous_keyed_sha1 == auth_type)
    {
      return 1;
    }
  return 0;
}

static int
bfd_verify_pkt_auth_seq_num (vlib_main_t * vm, bfd_session_t * bs,
			     u32 received_seq_num, int is_meticulous)
{
  /*
   * RFC 5880 6.8.1:
   *
   * This variable MUST be set to zero after no packets have been
   * received on this session for at least twice the Detection Time.
   */
  u64 now = bfd_time_now_nsec (vm, NULL);
  if (now - bs->last_rx_nsec > bs->detection_time_nsec * 2)
    {
      BFD_DBG ("BFD peer unresponsive for %lu nsec, which is > 2 * "
	       "detection_time=%u nsec, resetting remote_seq_number_known "
	       "flag", now - bs->last_rx_nsec, bs->detection_time_nsec * 2);
      bs->auth.remote_seq_number_known = 0;
    }
  if (bs->auth.remote_seq_number_known)
    {
      /* remote sequence number is known, verify its validity */
      const u32 max_u32 = 0xffffffff;
      /* the calculation might wrap, account for the special case... */
      if (bs->auth.remote_seq_number > max_u32 - 3 * bs->local_detect_mult)
	{
	  /*
	   * special case
	   *
	   *        x                   y                   z
	   *  |----------+----------------------------+-----------|
	   *  0          ^                            ^ 0xffffffff
	   *             |        remote_seq_num------+
	   *             |
	   *             +-----(remote_seq_num + 3*detect_mult) % * 0xffffffff
	   *
	   *    x + y + z = 0xffffffff
	   *    x + z = 3 * detect_mult
	   */
	  const u32 z = max_u32 - bs->auth.remote_seq_number;
	  const u32 x = 3 * bs->local_detect_mult - z;
	  if (received_seq_num > x &&
	      received_seq_num < bs->auth.remote_seq_number + is_meticulous)
	    {
	      BFD_ERR
		("Recvd sequence number=%u out of ranges <0, %u>, <%u, %u>",
		 received_seq_num, x,
		 bs->auth.remote_seq_number + is_meticulous, max_u32);
	      return 0;
	    }
	}
      else
	{
	  /* regular case */
	  const u32 min = bs->auth.remote_seq_number + is_meticulous;
	  const u32 max =
	    bs->auth.remote_seq_number + 3 * bs->local_detect_mult;
	  if (received_seq_num < min || received_seq_num > max)
	    {
	      BFD_ERR ("Recvd sequence number=%u out of range <%u, %u>",
		       received_seq_num, min, max);
	      return 0;
	    }
	}
    }
  return 1;
}

static int
bfd_verify_pkt_auth_key_sha1 (vlib_main_t *vm, const bfd_pkt_t *pkt,
			      u32 pkt_size, CLIB_UNUSED (bfd_session_t *bs),
			      u8 bfd_key_id, bfd_auth_key_t *auth_key)
{
  ASSERT (auth_key->auth_type == BFD_AUTH_TYPE_keyed_sha1 ||
	  auth_key->auth_type == BFD_AUTH_TYPE_meticulous_keyed_sha1);

  bfd_pkt_with_common_auth_t *with_common = (void *) pkt;
  if (pkt_size < sizeof (*with_common))
    {
      BFD_ERR ("Packet size too small to hold authentication common header");
      return 0;
    }
  if (with_common->common_auth.type != auth_key->auth_type)
    {
      BFD_ERR ("BFD auth type mismatch, packet auth=%d:%s doesn't match "
	       "in-use auth=%d:%s",
	       with_common->common_auth.type,
	       bfd_auth_type_str (with_common->common_auth.type),
	       auth_key->auth_type, bfd_auth_type_str (auth_key->auth_type));
      return 0;
    }
  bfd_pkt_with_sha1_auth_t *with_sha1 = (void *) pkt;
  if (pkt_size < sizeof (*with_sha1) ||
      with_sha1->sha1_auth.type_len.len < sizeof (with_sha1->sha1_auth))
    {
      BFD_ERR
	("BFD size mismatch, payload size=%u, expected=%u, auth_len=%u, "
	 "expected=%u", pkt_size, sizeof (*with_sha1),
	 with_sha1->sha1_auth.type_len.len, sizeof (with_sha1->sha1_auth));
      return 0;
    }
  if (with_sha1->sha1_auth.key_id != bfd_key_id)
    {
      BFD_ERR
	("BFD key ID mismatch, packet key ID=%u doesn't match key ID=%u%s",
	 with_sha1->sha1_auth.key_id, bfd_key_id,
	 bs->
	 auth.is_delayed ? " (but a delayed auth change is scheduled)" : "");
      return 0;
    }

  u8 hash_from_packet[STRUCT_SIZE_OF (bfd_auth_sha1_t, hash)];
  u8 calculated_hash[STRUCT_SIZE_OF (bfd_auth_sha1_t, hash)];
  clib_memcpy (hash_from_packet, with_sha1->sha1_auth.hash,
	       sizeof (with_sha1->sha1_auth.hash));
  clib_memcpy (with_sha1->sha1_auth.hash, auth_key->key,
	       sizeof (auth_key->key));
  vnet_crypto_op_t op;
  vnet_crypto_op_init (&op, VNET_CRYPTO_OP_SHA1_HASH);
  op.src = (u8 *) with_sha1;
  op.len = sizeof (*with_sha1);
  op.digest = calculated_hash;
  vnet_crypto_process_ops (&op, 1);

  /* Restore the modified data within the packet */
  clib_memcpy (with_sha1->sha1_auth.hash, hash_from_packet,
	       sizeof (with_sha1->sha1_auth.hash));

  if (0 ==
      memcmp (calculated_hash, hash_from_packet, sizeof (calculated_hash)))
    {
      clib_memcpy (with_sha1->sha1_auth.hash, hash_from_packet,
		   sizeof (hash_from_packet));
      return 1;
    }
  BFD_ERR ("SHA1 hash: %U doesn't match the expected value: %U",
	   format_hex_bytes, hash_from_packet, sizeof (hash_from_packet),
	   format_hex_bytes, calculated_hash, sizeof (calculated_hash));
  return 0;
}

static int
bfd_verify_pkt_auth_key (vlib_main_t * vm, const bfd_pkt_t * pkt,
			 u32 pkt_size, bfd_session_t * bs, u8 bfd_key_id,
			 bfd_auth_key_t * auth_key)
{
  bfd_main_t *bm = &bfd_main;
  switch (auth_key->auth_type)
    {
    case BFD_AUTH_TYPE_reserved:
      vlib_log_err (bm->log_class,
		    "internal error, unexpected auth_type=%d:%s",
		    auth_key->auth_type,
		    bfd_auth_type_str (auth_key->auth_type));
      return 0;
    case BFD_AUTH_TYPE_simple_password:
      /* fallthrough */
    case BFD_AUTH_TYPE_keyed_md5:
      /* fallthrough */
    case BFD_AUTH_TYPE_meticulous_keyed_md5:
      vlib_log_err (
	bm->log_class,
	"internal error, not implemented, unexpected auth_type=%d:%s",
	auth_key->auth_type, bfd_auth_type_str (auth_key->auth_type));
      return 0;
    case BFD_AUTH_TYPE_keyed_sha1:
      /* fallthrough */
    case BFD_AUTH_TYPE_meticulous_keyed_sha1:
      do
	{
	  const u32 seq_num = clib_net_to_host_u32 (((bfd_pkt_with_sha1_auth_t
						      *) pkt)->
						    sha1_auth.seq_num);
	  return bfd_verify_pkt_auth_seq_num (
		   vm, bs, seq_num,
		   bfd_auth_type_is_meticulous (auth_key->auth_type)) &&
		 bfd_verify_pkt_auth_key_sha1 (vm, pkt, pkt_size, bs,
					       bfd_key_id, auth_key);
	}
      while (0);
    }
  return 0;
}

/**
 * @brief verify bfd packet - authentication
 *
 * @param pkt
 *
 * @return 1 if bfd packet is valid
 */
int
bfd_verify_pkt_auth (vlib_main_t * vm, const bfd_pkt_t * pkt, u16 pkt_size,
		     bfd_session_t * bs)
{
  if (bfd_pkt_get_auth_present (pkt))
    {
      /* authentication present in packet */
      if (!bs->auth.curr_key)
	{
	  /* currently not using authentication - can we turn it on? */
	  if (bs->auth.is_delayed && bs->auth.next_key)
	    {
	      /* yes, switch is scheduled - make sure the auth is valid */
	      if (bfd_verify_pkt_auth_key (vm, pkt, pkt_size, bs,
					   bs->auth.next_bfd_key_id,
					   bs->auth.next_key))
		{
		  /* auth matches next key, do the switch, packet is valid */
		  bfd_session_switch_auth_to_next (bs);
		  return 1;
		}
	    }
	}
      else
	{
	  /* yes, using authentication, verify the key */
	  if (bfd_verify_pkt_auth_key (vm, pkt, pkt_size, bs,
				       bs->auth.curr_bfd_key_id,
				       bs->auth.curr_key))
	    {
	      /* verification passed, packet is valid */
	      return 1;
	    }
	  else
	    {
	      /* verification failed - but maybe we need to switch key */
	      if (bs->auth.is_delayed && bs->auth.next_key)
		{
		  /* delayed switch present, verify if that key works */
		  if (bfd_verify_pkt_auth_key (vm, pkt, pkt_size, bs,
					       bs->auth.next_bfd_key_id,
					       bs->auth.next_key))
		    {
		      /* auth matches next key, switch key, packet is valid */
		      bfd_session_switch_auth_to_next (bs);
		      return 1;
		    }
		}
	    }
	}
    }
  else
    {
      /* authentication in packet not present */
      if (pkt_size > sizeof (*pkt))
	{
	  BFD_ERR ("BFD verification failed - unexpected packet size '%d' "
		   "(auth not present)", pkt_size);
	  return 0;
	}
      if (bs->auth.curr_key)
	{
	  /* currently authenticating - could we turn it off? */
	  if (bs->auth.is_delayed && !bs->auth.next_key)
	    {
	      /* yes, delayed switch to NULL key is scheduled */
	      bfd_session_switch_auth_to_next (bs);
	      return 1;
	    }
	}
      else
	{
	  /* no auth in packet, no auth in use - packet is valid */
	  return 1;
	}
    }
  return 0;
}

bfd_error_t
bfd_consume_pkt (vlib_main_t *vm, bfd_main_t *bm, const bfd_pkt_t *pkt,
		 u32 bs_idx)
{
  bfd_lock_check (bm);

  bfd_session_t *bs = bfd_find_session_by_idx (bm, bs_idx);
  if (!bs || (pkt->your_disc && pkt->your_disc != bs->local_discr))
    {
      return BFD_ERROR_YOUR_DISC;
    }
  BFD_DBG ("Scanning bfd packet, bs_idx=%d", bs->bs_idx);
  bs->remote_discr = pkt->my_disc;
  bs->remote_state = bfd_pkt_get_state (pkt);
  bs->remote_demand = bfd_pkt_get_demand (pkt);
  bs->remote_diag = bfd_pkt_get_diag_code (pkt);
  u64 now = bfd_time_now_nsec (vm, NULL);
  bs->last_rx_nsec = now;
  if (bfd_pkt_get_auth_present (pkt))
    {
      bfd_auth_type_e auth_type =
	((bfd_pkt_with_common_auth_t *) (pkt))->common_auth.type;
      switch (auth_type)
	{
	case BFD_AUTH_TYPE_reserved:
	  /* fallthrough */
	case BFD_AUTH_TYPE_simple_password:
	  /* fallthrough */
	case BFD_AUTH_TYPE_keyed_md5:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_md5:
	  vlib_log_crit (bm->log_class,
			 "internal error, unexpected auth_type=%d:%s",
			 auth_type, bfd_auth_type_str (auth_type));
	  break;
	case BFD_AUTH_TYPE_keyed_sha1:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_sha1:
	  do
	    {
	      bfd_pkt_with_sha1_auth_t *with_sha1 =
		(bfd_pkt_with_sha1_auth_t *) pkt;
	      bs->auth.remote_seq_number =
		clib_net_to_host_u32 (with_sha1->sha1_auth.seq_num);
	      bs->auth.remote_seq_number_known = 1;
	      BFD_DBG ("Received sequence number %u",
		       bs->auth.remote_seq_number);
	    }
	  while (0);
	}
    }
  bs->remote_desired_min_tx_nsec =
    bfd_usec_to_nsec (clib_net_to_host_u32 (pkt->des_min_tx));
  bs->remote_detect_mult = pkt->head.detect_mult;
  bfd_set_remote_required_min_rx (bs, clib_net_to_host_u32 (pkt->req_min_rx));
  bfd_set_remote_required_min_echo_rx (
    bs, clib_net_to_host_u32 (pkt->req_min_echo_rx));
  if (bfd_pkt_get_final (pkt))
    {
      if (BFD_POLL_IN_PROGRESS == bs->poll_state)
	{
	  BFD_DBG ("Poll sequence terminated, bs_idx=%u", bs->bs_idx);
	  bfd_set_poll_state (bs, BFD_POLL_NOT_NEEDED);
	  if (BFD_STATE_up == bs->local_state)
	    {
	      bfd_set_effective_desired_min_tx (
		bm, bs, now, bs->config_desired_min_tx_nsec);
	      bfd_set_effective_required_min_rx (
		bs,
		clib_max (bs->echo * bm->min_required_min_rx_while_echo_nsec,
			  bs->config_required_min_rx_nsec));
	    }
	}
      else if (BFD_POLL_IN_PROGRESS_AND_QUEUED == bs->poll_state)
	{
	  /*
	   * next poll sequence must be delayed by at least the round trip
	   * time, so calculate that here
	   */
	  BFD_DBG ("Next poll sequence can commence in " BFD_CLK_FMT,
		   BFD_CLK_PRN (now - bs->poll_state_start_or_timeout_nsec));
	  bs->poll_state_start_or_timeout_nsec =
	    now + (now - bs->poll_state_start_or_timeout_nsec);
	  BFD_DBG
	    ("Poll sequence terminated, but another is needed, bs_idx=%u",
	     bs->bs_idx);
	  bfd_set_poll_state (bs, BFD_POLL_NEEDED);
	}
    }
  bfd_calc_next_tx (bm, bs, now);
  bfd_set_timer (bm, bs, now, 0);
  if (BFD_STATE_admin_down == bs->local_state)
    {
      BFD_DBG ("Session is admin-down, ignoring packet, bs_idx=%u",
	       bs->bs_idx);
      return BFD_ERROR_ADMIN_DOWN;
    }
  if (BFD_STATE_admin_down == bs->remote_state)
    {
      bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
      bfd_set_state (vm, bm, bs, BFD_STATE_down, 0);
    }
  else if (BFD_STATE_down == bs->local_state)
    {
      if (BFD_STATE_down == bs->remote_state)
	{
	  bfd_set_diag (bs, BFD_DIAG_CODE_no_diag);
	  bfd_set_state (vm, bm, bs, BFD_STATE_init, 0);
	}
      else if (BFD_STATE_init == bs->remote_state)
	{
	  bfd_set_diag (bs, BFD_DIAG_CODE_no_diag);
	  bfd_set_state (vm, bm, bs, BFD_STATE_up, 0);
	}
    }
  else if (BFD_STATE_init == bs->local_state)
    {
      if (BFD_STATE_up == bs->remote_state ||
	  BFD_STATE_init == bs->remote_state)
	{
	  bfd_set_diag (bs, BFD_DIAG_CODE_no_diag);
	  bfd_set_state (vm, bm, bs, BFD_STATE_up, 0);
	}
    }
  else				/* BFD_STATE_up == bs->local_state */
    {
      if (BFD_STATE_down == bs->remote_state)
	{
	  bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
	  bfd_set_state (vm, bm, bs, BFD_STATE_down, 0);
	}
    }
  return BFD_ERROR_NONE;
}

bfd_session_t *
bfd_consume_echo_pkt (vlib_main_t *vm, bfd_main_t *bm, vlib_buffer_t *b)
{
  bfd_echo_pkt_t *pkt = NULL;
  if (b->current_length != sizeof (*pkt))
    {
      return 0;
    }
  pkt = vlib_buffer_get_current (b);
  bfd_session_t *bs = bfd_find_session_by_disc (bm, pkt->discriminator);
  if (!bs)
    {
      return 0;
    }
  BFD_DBG ("Scanning bfd echo packet, bs_idx=%d", bs->bs_idx);
  u64 checksum =
    bfd_calc_echo_checksum (bs->local_discr, pkt->expire_time_nsec,
			    bs->echo_secret);
  if (checksum != pkt->checksum)
    {
      BFD_DBG ("Invalid echo packet, checksum mismatch");
      return 0;
    }
  u64 now = bfd_time_now_nsec (vm, NULL);
  if (pkt->expire_time_nsec < now)
    {
      BFD_DBG ("Stale packet received, expire time %lu < now %lu",
	       pkt->expire_time_nsec, now);
    }
  else
    {
      bs->echo_last_rx_nsec = now;
    }
  return bs;
}

u8 *
format_bfd_session (u8 * s, va_list * args)
{
  const bfd_session_t *bs = va_arg (*args, bfd_session_t *);
  s = format (
    s,
    "bs_idx=%u hop-type=%s local-state=%s remote-state=%s\n"
    "local-discriminator=%u remote-discriminator=%u\n"
    "local-diag=%s echo-active=%s\n"
    "desired-min-tx=%u required-min-rx=%u\n"
    "required-min-echo-rx=%u detect-mult=%u\n"
    "remote-min-rx=%u remote-min-echo-rx=%u\n"
    "remote-demand=%s poll-state=%s\n"
    "auth: local-seq-num=%u remote-seq-num=%u\n"
    "      is-delayed=%s\n"
    "      curr-key=%U\n"
    "      next-key=%U",
    bs->bs_idx, bfd_hop_type_string (bs->hop_type),
    bfd_state_string (bs->local_state), bfd_state_string (bs->remote_state),
    bs->local_discr, bs->remote_discr, bfd_diag_code_string (bs->local_diag),
    (bs->echo ? "yes" : "no"), bs->config_desired_min_tx_usec,
    bs->config_required_min_rx_usec, 1, bs->local_detect_mult,
    bs->remote_min_rx_usec, bs->remote_min_echo_rx_usec,
    (bs->remote_demand ? "yes" : "no"), bfd_poll_state_string (bs->poll_state),
    bs->auth.local_seq_number, bs->auth.remote_seq_number,
    (bs->auth.is_delayed ? "yes" : "no"), format_bfd_auth_key,
    bs->auth.curr_key, format_bfd_auth_key, bs->auth.next_key);
  return s;
}

u8 *
format_bfd_session_brief (u8 * s, va_list * args)
{
  const bfd_session_t *bs = va_arg (*args, bfd_session_t *);
  s =
    format (s, "bs_idx=%u local-state=%s remote-state=%s", bs->bs_idx,
	    bfd_state_string (bs->local_state),
	    bfd_state_string (bs->remote_state));
  return s;
}

unsigned
bfd_auth_type_supported (bfd_auth_type_e auth_type)
{
  if (auth_type == BFD_AUTH_TYPE_keyed_sha1 ||
      auth_type == BFD_AUTH_TYPE_meticulous_keyed_sha1)
    {
      return 1;
    }
  return 0;
}

vnet_api_error_t
bfd_auth_activate (bfd_session_t * bs, u32 conf_key_id,
		   u8 bfd_key_id, u8 is_delayed)
{
  bfd_main_t *bm = &bfd_main;
  const uword *key_idx_p =
    hash_get (bm->auth_key_by_conf_key_id, conf_key_id);
  if (!key_idx_p)
    {
      vlib_log_err (bm->log_class,
		    "authentication key with config ID %u doesn't exist)",
		    conf_key_id);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  const uword key_idx = *key_idx_p;
  bfd_auth_key_t *key = pool_elt_at_index (bm->auth_keys, key_idx);
  if (is_delayed)
    {
      if (bs->auth.next_key == key && bs->auth.next_bfd_key_id == bfd_key_id)
	{
	  /* already using this key, no changes required */
	  return 0;
	}
      if (bs->auth.next_key != key)
	{
	  ++key->use_count;
	  bs->auth.next_key = key;
	}
      bs->auth.next_bfd_key_id = bfd_key_id;
      bs->auth.is_delayed = 1;
    }
  else
    {
      if (bs->auth.curr_key == key && bs->auth.curr_bfd_key_id == bfd_key_id)
	{
	  /* already using this key, no changes required */
	  return 0;
	}
      ++key->use_count;
      if (bs->auth.curr_key)
	{
	  --bs->auth.curr_key->use_count;
	}
      bs->auth.curr_key = key;
      bs->auth.curr_bfd_key_id = bfd_key_id;
      bs->auth.is_delayed = 0;
    }
  BFD_DBG ("\nSession auth modified: %U", format_bfd_session, bs);
  vlib_log_info (bm->log_class, "session auth modified: %U",
		 format_bfd_session_brief, bs);
  return 0;
}

vnet_api_error_t
bfd_auth_deactivate (bfd_session_t * bs, u8 is_delayed)
{
  bfd_main_t *bm = &bfd_main;
  if (!is_delayed)
    {
      /* not delayed - deactivate the current key right now */
      if (bs->auth.curr_key)
	{
	  --bs->auth.curr_key->use_count;
	  bs->auth.curr_key = NULL;
	}
      bs->auth.is_delayed = 0;
    }
  else
    {
      /* delayed - mark as so */
      bs->auth.is_delayed = 1;
    }
  /*
   * clear the next key unconditionally - either the auth change is not delayed
   * in which case the caller expects the session to not use authentication
   * from this point forward, or it is delayed, in which case the next_key
   * needs to be set to NULL to make it so in the future
   */
  if (bs->auth.next_key)
    {
      --bs->auth.next_key->use_count;
      bs->auth.next_key = NULL;
    }
  BFD_DBG ("\nSession auth modified: %U", format_bfd_session, bs);
  vlib_log_info (bm->log_class, "session auth modified: %U",
		 format_bfd_session_brief, bs);
  return 0;
}

vnet_api_error_t
bfd_session_set_params (bfd_main_t * bm, bfd_session_t * bs,
			u32 desired_min_tx_usec,
			u32 required_min_rx_usec, u8 detect_mult)
{
  if (bs->local_detect_mult != detect_mult ||
      bs->config_desired_min_tx_usec != desired_min_tx_usec ||
      bs->config_required_min_rx_usec != required_min_rx_usec)
    {
      BFD_DBG ("\nChanging session params: %U", format_bfd_session, bs);
      switch (bs->poll_state)
	{
	case BFD_POLL_NOT_NEEDED:
	  if (BFD_STATE_up == bs->local_state ||
	      BFD_STATE_init == bs->local_state)
	    {
	      /* poll sequence is not needed for detect multiplier change */
	      if (bs->config_desired_min_tx_usec != desired_min_tx_usec ||
		  bs->config_required_min_rx_usec != required_min_rx_usec)
		{
		  bfd_set_poll_state (bs, BFD_POLL_NEEDED);
		}
	    }
	  break;
	case BFD_POLL_NEEDED:
	case BFD_POLL_IN_PROGRESS_AND_QUEUED:
	  /*
	   * nothing to do - will be handled in the future poll which is
	   * already scheduled for execution
	   */
	  break;
	case BFD_POLL_IN_PROGRESS:
	  /* poll sequence is not needed for detect multiplier change */
	  if (bs->config_desired_min_tx_usec != desired_min_tx_usec ||
	      bs->config_required_min_rx_usec != required_min_rx_usec)
	    {
	      BFD_DBG ("Poll in progress, queueing extra poll, bs_idx=%u",
		       bs->bs_idx);
	      bfd_set_poll_state (bs, BFD_POLL_IN_PROGRESS_AND_QUEUED);
	    }
	}

      bs->local_detect_mult = detect_mult;
      bs->config_desired_min_tx_usec = desired_min_tx_usec;
      bs->config_desired_min_tx_nsec = bfd_usec_to_nsec (desired_min_tx_usec);
      bs->config_required_min_rx_usec = required_min_rx_usec;
      bs->config_required_min_rx_nsec =
	bfd_usec_to_nsec (required_min_rx_usec);
      BFD_DBG ("\nChanged session params: %U", format_bfd_session, bs);

      vlib_log_info (bm->log_class, "changed session params: %U",
		     format_bfd_session_brief, bs);
      vlib_process_signal_event (bm->vlib_main, bm->bfd_process_node_index,
				 BFD_EVENT_CONFIG_CHANGED, bs->bs_idx);
    }
  else
    {
      BFD_DBG ("Ignore parameter change - no change, bs_idx=%u", bs->bs_idx);
    }
  return 0;
}

vnet_api_error_t
bfd_auth_set_key (u32 conf_key_id, u8 auth_type, u8 key_len,
		  const u8 * key_data)
{
  bfd_main_t *bm = &bfd_main;
  bfd_auth_key_t *auth_key = NULL;
  if (!key_len || key_len > bfd_max_key_len_for_auth_type (auth_type))
    {
      vlib_log_err (bm->log_class,
		    "invalid authentication key length for auth_type=%d:%s "
		    "(key_len=%u, must be non-zero, expected max=%u)",
		    auth_type, bfd_auth_type_str (auth_type), key_len,
		    (u32) bfd_max_key_len_for_auth_type (auth_type));
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (!bfd_auth_type_supported (auth_type))
    {
      vlib_log_err (bm->log_class, "unsupported auth type=%d:%s", auth_type,
		    bfd_auth_type_str (auth_type));
      return VNET_API_ERROR_BFD_NOTSUPP;
    }
  uword *key_idx_p = hash_get (bm->auth_key_by_conf_key_id, conf_key_id);
  if (key_idx_p)
    {
      /* modifying existing key - must not be used */
      const uword key_idx = *key_idx_p;
      auth_key = pool_elt_at_index (bm->auth_keys, key_idx);
      if (auth_key->use_count > 0)
	{
	  vlib_log_err (bm->log_class,
			"authentication key with conf ID %u in use by %u BFD "
			"session(s) - cannot modify", conf_key_id,
			auth_key->use_count);
	  return VNET_API_ERROR_BFD_EINUSE;
	}
    }
  else
    {
      /* adding new key */
      pool_get (bm->auth_keys, auth_key);
      auth_key->conf_key_id = conf_key_id;
      hash_set (bm->auth_key_by_conf_key_id, conf_key_id,
		auth_key - bm->auth_keys);
    }
  auth_key->auth_type = auth_type;
  clib_memset (auth_key->key, 0, sizeof (auth_key->key));
  clib_memcpy (auth_key->key, key_data, key_len);
  return 0;
}

vnet_api_error_t
bfd_auth_del_key (u32 conf_key_id)
{
  bfd_auth_key_t *auth_key = NULL;
  bfd_main_t *bm = &bfd_main;
  uword *key_idx_p = hash_get (bm->auth_key_by_conf_key_id, conf_key_id);
  if (key_idx_p)
    {
      /* deleting existing key - must not be used */
      const uword key_idx = *key_idx_p;
      auth_key = pool_elt_at_index (bm->auth_keys, key_idx);
      if (auth_key->use_count > 0)
	{
	  vlib_log_err (bm->log_class,
			"authentication key with conf ID %u in use by %u BFD "
			"session(s) - cannot delete", conf_key_id,
			auth_key->use_count);
	  return VNET_API_ERROR_BFD_EINUSE;
	}
      hash_unset (bm->auth_key_by_conf_key_id, conf_key_id);
      clib_memset (auth_key, 0, sizeof (*auth_key));
      pool_put (bm->auth_keys, auth_key);
    }
  else
    {
      /* no such key */
      vlib_log_err (bm->log_class,
		    "authentication key with conf ID %u does not exist",
		    conf_key_id);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  return 0;
}

bfd_main_t bfd_main;
