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
#if WITH_LIBSSL > 0
#include <openssl/sha.h>
#endif

static u64
bfd_us_to_clocks (bfd_main_t * bm, u64 us)
{
  return bm->cpu_cps * ((f64) us / USEC_PER_SECOND);
}

static vlib_node_registration_t bfd_process_node;

/* set to 0 here, real values filled at startup */
static u32 bfd_node_index_by_transport[] = {
#define F(t, n) [BFD_TRANSPORT_##t] = 0,
  foreach_bfd_transport (F)
#undef F
};

static u8 *
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
  bs->local_demand = 0;
  bs->remote_discr = 0;
  bs->desired_min_tx_us = BFD_DEFAULT_DESIRED_MIN_TX_US;
  bs->desired_min_tx_clocks = bfd_us_to_clocks (bm, bs->desired_min_tx_us);
  bs->remote_min_rx_us = 1;
  bs->remote_demand = 0;
  bs->auth.remote_seq_number = 0;
  bs->auth.remote_seq_number_known = 0;
  bs->auth.local_seq_number = random_u32 (&bm->random_seed);
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
	  bs->tx_timeout_clocks = bs->last_tx_clocks +
	    (1 - .25 * (random_f64 (&bm->random_seed))) *
	    bs->transmit_interval_clocks;
	  if (bs->tx_timeout_clocks < now)
	    {
	      /* huh, we've missed it already, transmit now */
	      BFD_DBG ("Missed %lu transmit events (now is %lu, calc "
		       "tx_timeout is %lu)",
		       (now - bs->tx_timeout_clocks) /
		       bs->transmit_interval_clocks,
		       now, bs->tx_timeout_clocks);
	      bs->tx_timeout_clocks = now;
	    }
	}
      else
	{
	  /* special case - 75-90% of transmit interval */
	  bs->tx_timeout_clocks =
	    bs->last_tx_clocks +
	    (.9 - .15 * (random_f64 (&bm->random_seed))) *
	    bs->transmit_interval_clocks;
	  if (bs->tx_timeout_clocks < now)
	    {
	      /* huh, we've missed it already, transmit now */
	      BFD_DBG ("Missed %lu transmit events (now is %lu, calc "
		       "tx_timeout is %lu)",
		       (now - bs->tx_timeout_clocks) /
		       bs->transmit_interval_clocks,
		       now, bs->tx_timeout_clocks);
	      bs->tx_timeout_clocks = now;
	    }
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
  /* sometimes the wheel expires an event a bit sooner than requested, account
     for that here */
  if (next && (now + bm->wheel_inaccuracy > bs->wheel_time_clocks ||
	       next < bs->wheel_time_clocks || !bs->wheel_time_clocks))
    {
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

static void
bfd_set_remote_required_min_rx (bfd_main_t * bm, bfd_session_t * bs,
				u64 now,
				u32 remote_required_min_rx_us,
				int handling_wakeup)
{
  bs->remote_min_rx_us = remote_required_min_rx_us;
  bs->remote_min_rx_clocks = bfd_us_to_clocks (bm, bs->remote_min_rx_us);
  BFD_DBG ("Set remote min rx to %uus/%lu clocks/%.2fs", bs->remote_min_rx_us,
	   bs->remote_min_rx_clocks, bs->remote_min_rx_clocks / bm->cpu_cps);
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
      return VNET_API_ERROR_BFD_ENOENT;
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

void
bfd_session_set_flags (bfd_session_t * bs, u8 admin_up_down)
{
  bfd_main_t *bm = &bfd_main;
  if (admin_up_down)
    {
      bfd_set_state (bm, bs, BFD_STATE_down, 0);
    }
  else
    {
      bfd_set_diag (bs, BFD_DIAG_CODE_neighbor_sig_down);
      bfd_set_state (bm, bs, BFD_STATE_admin_down, 0);
    }
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
		  "    flags=(P:%u, F:%u, C:%u, A:%u, D:%u, M:%u), "
		  "detect_mult=%u, length=%u\n",
		  bfd_pkt_get_version (pkt), bfd_pkt_get_diag_code (pkt),
		  bfd_diag_code_string (bfd_pkt_get_diag_code (pkt)),
		  bfd_pkt_get_state (pkt),
		  bfd_state_string (bfd_pkt_get_state (pkt)),
		  bfd_pkt_get_poll (pkt), bfd_pkt_get_final (pkt),
		  bfd_pkt_get_control_plane_independent (pkt),
		  bfd_pkt_get_auth_present (pkt), bfd_pkt_get_demand (pkt),
		  bfd_pkt_get_multipoint (pkt), pkt->head.detect_mult,
		  pkt->head.length);
      if (t->len >= sizeof (bfd_pkt_t) &&
	  pkt->head.length >= sizeof (bfd_pkt_t))
	{
	  s = format (s, "    my discriminator: %u\n", pkt->my_disc);
	  s = format (s, "    your discriminator: %u\n", pkt->your_disc);
	  s = format (s, "    desired min tx interval: %u\n",
		      clib_net_to_host_u32 (pkt->des_min_tx));
	  s = format (s, "    required min rx interval: %u\n",
		      clib_net_to_host_u32 (pkt->req_min_rx));
	  s = format (s, "    required min echo rx interval: %u",
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
      BFD_DBG ("Transport bfd via udp4, bs_idx=%u", bs->bs_idx);
      bfd_add_udp4_transport (vm, b, &bs->udp);
      break;
    case BFD_TRANSPORT_UDP6:
      BFD_DBG ("Transport bfd via udp6, bs_idx=%u", bs->bs_idx);
      bfd_add_udp6_transport (vm, b, &bs->udp);
      break;
    }
}

static vlib_buffer_t *
bfd_create_frame_to_next_node (vlib_main_t * vm, bfd_session_t * bs)
{
  u32 bi;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return NULL;
    }

  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  ASSERT (b->current_data == 0);

  vlib_frame_t *f =
    vlib_get_frame_to_node (vm, bfd_node_index_by_transport[bs->transport]);

  u32 *to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, bfd_node_index_by_transport[bs->transport], f);
  return b;
}

#if WITH_LIBSSL > 0
static void
bfd_add_sha1_auth_section (vlib_buffer_t * b, bfd_session_t * bs)
{
  bfd_pkt_with_sha1_auth_t *pkt = vlib_buffer_get_current (b);
  bfd_auth_sha1_t *auth = &pkt->sha1_auth;
  b->current_length += sizeof (*auth);
  pkt->pkt.head.length += sizeof (*auth);
  bfd_pkt_set_auth_present (&pkt->pkt);
  memset (auth, 0, sizeof (*auth));
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
  SHA1 ((unsigned char *) pkt, sizeof (*pkt), hash);
  BFD_DBG ("hashing: %U", format_hex_bytes, pkt, sizeof (*pkt));
  clib_memcpy (auth->hash, hash, sizeof (hash));
#endif
}

static void
bfd_add_auth_section (vlib_buffer_t * b, bfd_session_t * bs)
{
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
	  clib_warning ("Internal error, unexpected BFD auth type '%d'",
			auth_type);
	  break;
#if WITH_LIBSSL > 0
	case BFD_AUTH_TYPE_keyed_sha1:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_sha1:
	  bfd_add_sha1_auth_section (b, bs);
	  break;
#else
	case BFD_AUTH_TYPE_keyed_sha1:
	  /* fallthrough */
	case BFD_AUTH_TYPE_meticulous_keyed_sha1:
	  clib_warning ("Internal error, unexpected BFD auth type '%d'",
			auth_type);
	  break;
#endif
	}
    }
}

static void
bfd_init_control_frame (vlib_buffer_t * b, bfd_session_t * bs)
{
  bfd_pkt_t *pkt = vlib_buffer_get_current (b);

  u32 bfd_length = 0;
  bfd_length = sizeof (bfd_pkt_t);
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
  pkt->req_min_echo_rx = clib_host_to_net_u32 (bs->required_min_echo_rx_us);
  b->current_length = bfd_length;
  bfd_add_auth_section (b, bs);
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
  /* sometimes the wheel expires an event a bit sooner than requested, account
     for that here */
  if (now + bm->wheel_inaccuracy >= bs->tx_timeout_clocks)
    {
      BFD_DBG ("Send periodic control frame for bs_idx=%lu", bs->bs_idx);
      vlib_buffer_t *b = bfd_create_frame_to_next_node (vm, bs);
      if (!b)
	{
	  return;
	}
      bfd_init_control_frame (b, bs);
      bfd_add_transport_layer (vm, b, bs);
      bs->last_tx_clocks = now;
      bfd_calc_next_tx (bm, bs, now);
    }
  else
    {
      BFD_DBG
	("No need to send control frame now, now is %lu, tx_timeout is %lu",
	 now, bs->tx_timeout_clocks);
    }
  bfd_set_timer (bm, bs, now, handling_wakeup);
}

void
bfd_init_final_control_frame (vlib_main_t * vm, vlib_buffer_t * b,
			      bfd_session_t * bs)
{
  BFD_DBG ("Send final control frame for bs_idx=%lu", bs->bs_idx);
  bfd_init_control_frame (b, bs);
  bfd_pkt_set_final (vlib_buffer_get_current (b));
  bfd_add_transport_layer (vm, b, bs);
  bs->last_tx_clocks = clib_cpu_time_now ();
}

static void
bfd_check_rx_timeout (bfd_main_t * bm, bfd_session_t * bs, u64 now,
		      int handling_wakeup)
{
  /* sometimes the wheel expires an event a bit sooner than requested, account
     for that here */
  if (bs->last_rx_clocks + bs->detection_time_clocks <=
      now + bm->wheel_inaccuracy)
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
	  if (!pool_is_free_index (bm->sessions, *event_data))
	    {
	      bfd_session_t *bs =
		pool_elt_at_index (bm->sessions, *event_data);
	      bfd_send_periodic (vm, rt, bm, bs, now, 1);
	    }
	  else
	    {
	      BFD_DBG ("Ignoring event for non-existent session index %u",
		       (u32) * event_data);
	    }
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
  .n_next_nodes = 0,
  .next_nodes = {},
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
#if BFD_DEBUG
  setbuf (stdout, NULL);
#endif
  bfd_main_t *bm = &bfd_main;
  bm->random_seed = random_default_seed ();
  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();
  memset (&bm->wheel, 0, sizeof (bm->wheel));
  bm->cpu_cps = vm->clib_time.clocks_per_second;
  BFD_DBG ("cps is %.2f", bm->cpu_cps);
  const u64 now = clib_cpu_time_now ();
  timing_wheel_init (&bm->wheel, now, bm->cpu_cps);
  bm->wheel_inaccuracy = 2 << bm->wheel.log2_clocks_per_bin;

  vlib_node_t *node = NULL;
#define F(t, n)                                                 \
  node = vlib_get_node_by_name (vm, (u8 *)n);                   \
  bfd_node_index_by_transport[BFD_TRANSPORT_##t] = node->index; \
  BFD_DBG ("node '%s' has index %u", n, node->index);
  foreach_bfd_transport (F);
#undef F
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
  if (bs->auth.curr_key)
    {
      --bs->auth.curr_key->use_count;
    }
  if (bs->auth.next_key)
    {
      --bs->auth.next_key->use_count;
    }
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
       pkt->head.length < sizeof (bfd_pkt_with_common_auth_t)))
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
bfd_verify_pkt_auth_seq_num (bfd_session_t * bs,
			     u32 received_seq_num, int is_meticulous)
{
  /*
   * RFC 5880 6.8.1:
   *
   * This variable MUST be set to zero after no packets have been
   * received on this session for at least twice the Detection Time.
   */
  u64 now = clib_cpu_time_now ();
  if (now - bs->last_rx_clocks > bs->detection_time_clocks * 2)
    {
      BFD_DBG ("BFD peer unresponsive for %lu clocks, which is > 2 * "
	       "detection_time=%u clocks, resetting remote_seq_number_known "
	       "flag",
	       now - bs->last_rx_clocks, bs->detection_time_clocks * 2);
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
bfd_verify_pkt_auth_key_sha1 (const bfd_pkt_t * pkt, u32 pkt_size,
			      bfd_session_t * bs, u8 bfd_key_id,
			      bfd_auth_key_t * auth_key)
{
  ASSERT (auth_key->auth_type == BFD_AUTH_TYPE_keyed_sha1 ||
	  auth_key->auth_type == BFD_AUTH_TYPE_meticulous_keyed_sha1);

  u8 result[SHA_DIGEST_LENGTH];
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
  SHA_CTX ctx;
  if (!SHA1_Init (&ctx))
    {
      BFD_ERR ("SHA1_Init failed");
      return 0;
    }
  /* ignore last 20 bytes - use the actual key data instead pkt data */
  if (!SHA1_Update (&ctx, with_sha1,
		    sizeof (*with_sha1) - sizeof (with_sha1->sha1_auth.hash)))
    {
      BFD_ERR ("SHA1_Update failed");
      return 0;
    }
  if (!SHA1_Update (&ctx, auth_key->key, sizeof (auth_key->key)))
    {
      BFD_ERR ("SHA1_Update failed");
      return 0;
    }
  if (!SHA1_Final (result, &ctx))
    {
      BFD_ERR ("SHA1_Final failed");
      return 0;
    }
  if (0 == memcmp (result, with_sha1->sha1_auth.hash, SHA_DIGEST_LENGTH))
    {
      return 1;
    }
  BFD_ERR ("SHA1 hash: %U doesn't match the expected value: %U",
	   format_hex_bytes, with_sha1->sha1_auth.hash, SHA_DIGEST_LENGTH,
	   format_hex_bytes, result, SHA_DIGEST_LENGTH);
  return 0;
}

static int
bfd_verify_pkt_auth_key (const bfd_pkt_t * pkt, u32 pkt_size,
			 bfd_session_t * bs, u8 bfd_key_id,
			 bfd_auth_key_t * auth_key)
{
  switch (auth_key->auth_type)
    {
    case BFD_AUTH_TYPE_reserved:
      clib_warning ("Internal error, unexpected auth_type=%d:%s",
		    auth_key->auth_type,
		    bfd_auth_type_str (auth_key->auth_type));
      return 0;
    case BFD_AUTH_TYPE_simple_password:
      clib_warning
	("Internal error, not implemented, unexpected auth_type=%d:%s",
	 auth_key->auth_type, bfd_auth_type_str (auth_key->auth_type));
      return 0;
    case BFD_AUTH_TYPE_keyed_md5:
      /* fallthrough */
    case BFD_AUTH_TYPE_meticulous_keyed_md5:
      clib_warning
	("Internal error, not implemented, unexpected auth_type=%d:%s",
	 auth_key->auth_type, bfd_auth_type_str (auth_key->auth_type));
      return 0;
    case BFD_AUTH_TYPE_keyed_sha1:
      /* fallthrough */
    case BFD_AUTH_TYPE_meticulous_keyed_sha1:
#if WITH_LIBSSL > 0
      do
	{
	  const u32 seq_num = clib_net_to_host_u32 (((bfd_pkt_with_sha1_auth_t
						      *) pkt)->
						    sha1_auth.seq_num);
	  return bfd_verify_pkt_auth_seq_num (bs, seq_num,
					      bfd_auth_type_is_meticulous
					      (auth_key->auth_type))
	    && bfd_verify_pkt_auth_key_sha1 (pkt, pkt_size, bs, bfd_key_id,
					     auth_key);
	}
      while (0);
#else
      clib_warning
	("Internal error, attempt to use SHA1 without SSL support");
      return 0;
#endif
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
bfd_verify_pkt_auth (const bfd_pkt_t * pkt, u16 pkt_size, bfd_session_t * bs)
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
	      if (bfd_verify_pkt_auth_key (pkt, pkt_size, bs,
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
	  if (bfd_verify_pkt_auth_key (pkt, pkt_size, bs,
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
		  if (bfd_verify_pkt_auth_key (pkt, pkt_size, bs,
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
  u64 now = clib_cpu_time_now ();
  bs->last_rx_clocks = now;
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
	  clib_warning ("Internal error, unexpected auth_type=%d:%s",
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
  bs->remote_desired_min_tx_us = clib_net_to_host_u32 (pkt->des_min_tx);
  bs->remote_detect_mult = pkt->head.detect_mult;
  bfd_set_remote_required_min_rx (bm, bs, now,
				  clib_net_to_host_u32 (pkt->req_min_rx), 0);
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
  s = format (s, "BFD(%u): bfd.SessionState=%s, "
	      "bfd.RemoteSessionState=%s, "
	      "bfd.LocalDiscr=%u, "
	      "bfd.RemoteDiscr=%u, "
	      "bfd.LocalDiag=%s, "
	      "bfd.DesiredMinTxInterval=%u, "
	      "bfd.RequiredMinRxInterval=%u, "
	      "bfd.RequiredMinEchoRxInterval=%u, "
	      "bfd.RemoteMinRxInterval=%u, "
	      "bfd.DemandMode=%s, "
	      "bfd.RemoteDemandMode=%s, "
	      "bfd.DetectMult=%u, "
	      "Auth: {local-seq-num=%u, "
	      "remote-seq-num=%u, "
	      "is-delayed=%s, "
	      "curr-key=%U, "
	      "next-key=%U}",
	      bs->bs_idx, bfd_state_string (bs->local_state),
	      bfd_state_string (bs->remote_state), bs->local_discr,
	      bs->remote_discr, bfd_diag_code_string (bs->local_diag),
	      bs->desired_min_tx_us, bs->required_min_rx_us,
	      bs->required_min_echo_rx_us, bs->remote_min_rx_us,
	      (bs->local_demand ? "yes" : "no"),
	      (bs->remote_demand ? "yes" : "no"), bs->local_detect_mult,
	      bs->auth.local_seq_number, bs->auth.remote_seq_number,
	      (bs->auth.is_delayed ? "yes" : "no"), format_bfd_auth_key,
	      bs->auth.curr_key, format_bfd_auth_key, bs->auth.next_key);
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
      clib_warning ("Authentication key with config ID %u doesn't exist)",
		    conf_key_id);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  const uword key_idx = *key_idx_p;
  bfd_auth_key_t *key = pool_elt_at_index (bm->auth_keys, key_idx);
  if (is_delayed)
    {
      if (bs->auth.next_key == key)
	{
	  /* already using this key, no changes required */
	  return 0;
	}
      bs->auth.next_key = key;
      bs->auth.next_bfd_key_id = bfd_key_id;
      bs->auth.is_delayed = 1;
    }
  else
    {
      if (bs->auth.curr_key == key)
	{
	  /* already using this key, no changes required */
	  return 0;
	}
      if (bs->auth.curr_key)
	{
	  --bs->auth.curr_key->use_count;
	}
      bs->auth.curr_key = key;
      bs->auth.curr_bfd_key_id = bfd_key_id;
      bs->auth.is_delayed = 0;
    }
  ++key->use_count;
  BFD_DBG ("Session auth modified: %U", format_bfd_session, bs);
  return 0;
}

vnet_api_error_t
bfd_auth_deactivate (bfd_session_t * bs, u8 is_delayed)
{
#if WITH_LIBSSL > 0
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
  BFD_DBG ("Session auth modified: %U", format_bfd_session, bs);
  return 0;
#else
  clib_warning ("SSL missing, cannot deactivate BFD authentication");
  return VNET_API_ERROR_BFD_NOTSUPP;
#endif
}

bfd_main_t bfd_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
