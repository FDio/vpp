/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <wireguard/wireguard.h>
#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard_timer.h>

static u32
get_random_u32_max (u32 max)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 seed = (u32) (vlib_time_now (vm) * 1e6);
  return random_u32 (&seed) % max;
}

static u32
get_random_u32_max_opt (u32 max, f64 time)
{
  u32 seed = (u32) (time * 1e6);
  return random_u32 (&seed) % max;
}

static void
stop_timer (wg_peer_t * peer, u32 timer_id)
{
  if (peer->timers[timer_id] != ~0)
    {
      tw_timer_stop_16t_2w_512sl (peer->timer_wheel, peer->timers[timer_id]);
      peer->timers[timer_id] = ~0;
    }
}

static void
start_timer (wg_peer_t * peer, u32 timer_id, u32 interval_ticks)
{
  ASSERT (vlib_get_thread_index () == 0);

  if (peer->timers[timer_id] == ~0)
    {
      peer->timers[timer_id] =
	tw_timer_start_16t_2w_512sl (peer->timer_wheel, peer - wg_peer_pool,
				     timer_id, interval_ticks);
    }
}

typedef struct
{
  u32 peer_idx;
  u32 timer_id;
  u32 interval_ticks;

} wg_timers_args;

static void *
start_timer_thread_fn (void *arg)
{
  wg_timers_args *a = arg;
  wg_peer_t *peer = wg_peer_get (a->peer_idx);
  start_timer (peer, a->timer_id, a->interval_ticks);
  return 0;
}

static_always_inline void
start_timer_from_mt (u32 peer_idx, u32 timer_id, u32 interval_ticks)
{
  wg_timers_args a = {
    .peer_idx = peer_idx,
    .timer_id = timer_id,
    .interval_ticks = interval_ticks,
  };
  wg_peer_t *peer = wg_peer_get (peer_idx);
  if (PREDICT_FALSE (!peer->timers_dispatched[timer_id]))
    if (!clib_atomic_cmp_and_swap (&peer->timers_dispatched[timer_id], 0, 1))
      vl_api_rpc_call_main_thread (start_timer_thread_fn, (u8 *) &a,
				   sizeof (a));
}

static inline u32
timer_ticks_left (vlib_main_t * vm, f64 init_time_sec, u32 interval_ticks)
{
  static const int32_t rounding = (int32_t) (WHZ / 2);
  int32_t ticks_remain;

  ticks_remain = (init_time_sec - vlib_time_now (vm)) * WHZ + interval_ticks;
  return (ticks_remain > rounding) ? (u32) ticks_remain : 0;
}

static void
wg_expired_retransmit_handshake (vlib_main_t * vm, wg_peer_t * peer)
{
  if (peer->rehandshake_started == ~0)
    return;

  u32 ticks = timer_ticks_left (vm, peer->rehandshake_started,
				peer->rehandshake_interval_tick);
  if (ticks)
    {
      start_timer (peer, WG_TIMER_RETRANSMIT_HANDSHAKE, ticks);
      return;
    }

  if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES)
    {
      stop_timer (peer, WG_TIMER_SEND_KEEPALIVE);

      /* We set a timer for destroying any residue that might be left
       * of a partial exchange.
       */
      start_timer (peer, WG_TIMER_KEY_ZEROING, REJECT_AFTER_TIME * 3 * WHZ);

    }
  else
    {
      ++peer->timer_handshake_attempts;
      wg_send_handshake (vm, peer, true);
    }
}

static void
wg_expired_send_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  if (peer->last_sent_packet < peer->last_received_packet)
    {
      u32 ticks = timer_ticks_left (vm, peer->last_received_packet,
				    KEEPALIVE_TIMEOUT * WHZ);
      if (ticks)
	{
	  start_timer (peer, WG_TIMER_SEND_KEEPALIVE, ticks);
	  return;
	}

      wg_send_keepalive (vm, peer);
      if (peer->timer_need_another_keepalive)
	{
	  peer->timer_need_another_keepalive = false;
	  start_timer (peer, WG_TIMER_SEND_KEEPALIVE,
		       KEEPALIVE_TIMEOUT * WHZ);
	}
    }
}

static void
wg_expired_send_persistent_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  if (peer->persistent_keepalive_interval)
    {
      f64 latest_time = peer->last_sent_packet > peer->last_received_packet
	? peer->last_sent_packet : peer->last_received_packet;

      u32 ticks = timer_ticks_left (vm, latest_time,
				    peer->persistent_keepalive_interval *
				    WHZ);
      if (ticks)
	{
	  start_timer (peer, WG_TIMER_PERSISTENT_KEEPALIVE, ticks);
	  return;
	}

      wg_send_keepalive (vm, peer);
    }
}

static void
wg_expired_new_handshake (vlib_main_t * vm, wg_peer_t * peer)
{
  u32 ticks = timer_ticks_left (vm, peer->last_sent_packet,
				peer->new_handshake_interval_tick);
  if (ticks)
    {
      start_timer (peer, WG_TIMER_NEW_HANDSHAKE, ticks);
      return;
    }

  wg_send_handshake (vm, peer, false);
}

static void
wg_expired_zero_key_material (vlib_main_t * vm, wg_peer_t * peer)
{
  u32 ticks =
    timer_ticks_left (vm, peer->session_derived, REJECT_AFTER_TIME * 3 * WHZ);
  if (ticks)
    {
      start_timer (peer, WG_TIMER_KEY_ZEROING, ticks);
      return;
    }

  if (!wg_peer_is_dead (peer))
    {
      noise_remote_clear (vm, &peer->remote);
    }
}

inline void
wg_timers_any_authenticated_packet_traversal (wg_peer_t *peer)
{
  if (peer->persistent_keepalive_interval)
    {
      start_timer_from_mt (peer - wg_peer_pool,
			   WG_TIMER_PERSISTENT_KEEPALIVE,
			   peer->persistent_keepalive_interval * WHZ);
    }
}

void
wg_timers_any_authenticated_packet_sent (wg_peer_t * peer)
{
  peer->last_sent_packet = vlib_time_now (vlib_get_main ());
}

inline void
wg_timers_any_authenticated_packet_sent_opt (wg_peer_t *peer, f64 time)
{
  peer->last_sent_packet = time;
}

void
wg_timers_handshake_initiated (wg_peer_t * peer)
{
  peer->rehandshake_started = vlib_time_now (vlib_get_main ());
  peer->rehandshake_interval_tick =
    REKEY_TIMEOUT * WHZ + get_random_u32_max (REKEY_TIMEOUT_JITTER);

  start_timer_from_mt (peer - wg_peer_pool, WG_TIMER_RETRANSMIT_HANDSHAKE,
		       peer->rehandshake_interval_tick);
}

void
wg_timers_session_derived (wg_peer_t * peer)
{
  peer->session_derived = vlib_time_now (vlib_get_main ());

  start_timer_from_mt (peer - wg_peer_pool, WG_TIMER_KEY_ZEROING,
		       REJECT_AFTER_TIME * 3 * WHZ);
}

/* Should be called after an authenticated data packet is sent. */
void
wg_timers_data_sent (wg_peer_t * peer)
{
  peer->new_handshake_interval_tick =
    (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * WHZ +
    get_random_u32_max (REKEY_TIMEOUT_JITTER);

  start_timer_from_mt (peer - wg_peer_pool, WG_TIMER_NEW_HANDSHAKE,
		       peer->new_handshake_interval_tick);
}

inline void
wg_timers_data_sent_opt (wg_peer_t *peer, f64 time)
{
  peer->new_handshake_interval_tick =
    (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * WHZ +
    get_random_u32_max_opt (REKEY_TIMEOUT_JITTER, time);

  start_timer_from_mt (peer - wg_peer_pool, WG_TIMER_NEW_HANDSHAKE,
		       peer->new_handshake_interval_tick);
}

/* Should be called after an authenticated data packet is received. */
void
wg_timers_data_received (wg_peer_t * peer)
{
  if (peer->timers[WG_TIMER_SEND_KEEPALIVE] == ~0)
    {
      start_timer_from_mt (peer - wg_peer_pool, WG_TIMER_SEND_KEEPALIVE,
			   KEEPALIVE_TIMEOUT * WHZ);
    }
  else
    peer->timer_need_another_keepalive = true;
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void
wg_timers_handshake_complete (wg_peer_t * peer)
{
  peer->rehandshake_started = ~0;
  peer->timer_handshake_attempts = 0;
}

void
wg_timers_any_authenticated_packet_received (wg_peer_t * peer)
{
  peer->last_received_packet = vlib_time_now (vlib_get_main ());
}

inline void
wg_timers_any_authenticated_packet_received_opt (wg_peer_t *peer, f64 time)
{
  peer->last_received_packet = time;
}

static vlib_node_registration_t wg_timer_mngr_node;

static void
expired_timer_callback (u32 * expired_timers)
{
  int i;
  u32 timer_id;
  u32 pool_index;

  wg_main_t *wmp = &wg_main;
  vlib_main_t *vm = wmp->vlib_main;

  wg_peer_t *peer;

  /* Need to invalidate all of them because one can restart other */
  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      peer = wg_peer_get (pool_index);
      peer->timers[timer_id] = ~0;

      /* Under barrier, no sync needed */
      peer->timers_dispatched[timer_id] = 0;
    }

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      peer = wg_peer_get (pool_index);
      switch (timer_id)
	{
	case WG_TIMER_RETRANSMIT_HANDSHAKE:
	  wg_expired_retransmit_handshake (vm, peer);
	  break;
	case WG_TIMER_PERSISTENT_KEEPALIVE:
	  wg_expired_send_persistent_keepalive (vm, peer);
	  break;
	case WG_TIMER_SEND_KEEPALIVE:
	  wg_expired_send_keepalive (vm, peer);
	  break;
	case WG_TIMER_NEW_HANDSHAKE:
	  wg_expired_new_handshake (vm, peer);
	  break;
	case WG_TIMER_KEY_ZEROING:
	  wg_expired_zero_key_material (vm, peer);
	  break;
	default:
	  break;
	}
    }
}

void
wg_timer_wheel_init ()
{
  wg_main_t *wmp = &wg_main;
  tw_timer_wheel_16t_2w_512sl_t *tw = &wmp->timer_wheel;
  tw_timer_wheel_init_16t_2w_512sl (tw,
				    expired_timer_callback,
				    WG_TICK /* timer period in s */ , ~0);
}

static uword
wg_timer_mngr_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  wg_main_t *wmp = &wg_main;
  uword event_type = 0;

  /* Park the process until the feature is configured */
  while (1)
    {
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, 0);
      if (event_type == WG_START_EVENT)
	{
	  break;
	}
      else
	{
	  clib_warning ("Unknown event type %d", event_type);
	}
    }
  /*
   * Reset the timer wheel time so it won't try to
   * expire Avogadro's number of time slots.
   */
  wmp->timer_wheel.last_run_time = vlib_time_now (vm);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, WG_TICK);
      vlib_process_get_events (vm, NULL);

      tw_timer_expire_timers_16t_2w_512sl (&wmp->timer_wheel,
					   vlib_time_now (vm));
    }

  return 0;
}

void
wg_timers_stop (wg_peer_t * peer)
{
  ASSERT (vlib_get_thread_index () == 0);
  if (peer->timer_wheel)
    {
      stop_timer (peer, WG_TIMER_RETRANSMIT_HANDSHAKE);
      stop_timer (peer, WG_TIMER_PERSISTENT_KEEPALIVE);
      stop_timer (peer, WG_TIMER_SEND_KEEPALIVE);
      stop_timer (peer, WG_TIMER_NEW_HANDSHAKE);
      stop_timer (peer, WG_TIMER_KEY_ZEROING);
    }
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg_timer_mngr_node, static) = {
    .function = wg_timer_mngr_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name =
    "wg-timer-manager",
};
/* *INDENT-ON* */

void
wg_feature_init (wg_main_t * wmp)
{
  if (wmp->feature_init)
    return;
  vlib_process_signal_event (wmp->vlib_main, wg_timer_mngr_node.index,
			     WG_START_EVENT, 0);
  wmp->feature_init = 1;
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
