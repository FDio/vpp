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

#include <wg/wg.h>
#include <wg/wg_send.h>
#include <wg/wg_timer.h>
#include <wg/crypto/random.h>

static u32
get_random_u32_max (u32 max)
{
  return get_random_u32 () % max;
}

static void
stop_timer (wg_peer_t * peer, u32 timer_id)
{
  if (peer->timers[timer_id] != ~0)
    {
      tw_timer_stop_16t_2w_512sl (&peer->timer_wheel, peer->timers[timer_id]);
      peer->timers[timer_id] = ~0;
    }
}

static void
start_or_update_timer (wg_peer_t * peer, u32 timer_id, u32 interval)
{
  if (peer->timers[timer_id] == ~0)
    {
      wg_main_t *wmp = &wg_main;
      peer->timers[timer_id] =
	tw_timer_start_16t_2w_512sl (&peer->timer_wheel, peer - wmp->peers,
				     timer_id, interval);
    }
  else
    {
      tw_timer_update_16t_2w_512sl (&peer->timer_wheel,
				    peer->timers[timer_id], interval);
    }
}

static void
wg_expired_retransmit_handshake (vlib_main_t * vm, wg_peer_t * peer)
{

  if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES)
    {
      stop_timer (peer, WG_TIMER_SEND_KEEPALIVE);

      /* We set a timer for destroying any residue that might be left
       * of a partial exchange.
       */

      if (peer->timers[WG_TIMER_KEY_ZEROING] == ~0)
	{
	  wg_main_t *wmp = &wg_main;

	  peer->timers[WG_TIMER_KEY_ZEROING] =
	    tw_timer_start_16t_2w_512sl (&peer->timer_wheel,
					 peer - wmp->peers,
					 WG_TIMER_KEY_ZEROING,
					 REJECT_AFTER_TIME * 3 * WHZ);
	}
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
  wg_send_keepalive (vm, peer);

  if (peer->timer_need_another_keepalive)
    {
      peer->timer_need_another_keepalive = false;

      start_or_update_timer (peer, WG_TIMER_SEND_KEEPALIVE,
			     KEEPALIVE_TIMEOUT * WHZ);
    }
}

static void
wg_expired_send_persistent_keepalive (vlib_main_t * vm, wg_peer_t * peer)
{
  if (peer->persistent_keepalive_interval)
    wg_send_keepalive (vm, peer);
}

static void
wg_expired_new_handshake (vlib_main_t * vm, wg_peer_t * peer)
{
  wg_send_handshake (vm, peer, false);
}

static void
wg_expired_zero_key_material (wg_peer_t * peer)
{
  if (!peer->is_dead)
    {
      wg_noise_handshake_clear (&peer->handshake);
      wg_noise_keypairs_clear (&peer->keypairs);
    }
}


void
wg_timers_any_authenticated_packet_traversal (wg_peer_t * peer)
{
  if (peer->persistent_keepalive_interval)
    {
      start_or_update_timer (peer, WG_TIMER_PERSISTENT_KEEPALIVE,
			     peer->persistent_keepalive_interval * WHZ);
    }
}

void
wg_timers_any_authenticated_packet_sent (wg_peer_t * peer)
{
  stop_timer (peer, WG_TIMER_SEND_KEEPALIVE);
}

void
wg_timers_handshake_initiated (wg_peer_t * peer)
{
  u32 interval =
    REKEY_TIMEOUT * WHZ + get_random_u32_max (REKEY_TIMEOUT_JITTER);
  start_or_update_timer (peer, WG_TIMER_RETRANSMIT_HANDSHAKE, interval);
}

void
wg_timers_session_derived (wg_peer_t * peer)
{
  start_or_update_timer (peer, WG_TIMER_KEY_ZEROING,
			 REJECT_AFTER_TIME * 3 * WHZ);
}

/* Should be called after an authenticated data packet is sent. */
void
wg_timers_data_sent (wg_peer_t * peer)
{
  u32 interval = (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * WHZ +
    get_random_u32_max (REKEY_TIMEOUT_JITTER);

  if (peer->timers[WG_TIMER_NEW_HANDSHAKE] == ~0)
    {
      wg_main_t *wmp = &wg_main;
      peer->timers[WG_TIMER_NEW_HANDSHAKE] =
	tw_timer_start_16t_2w_512sl (&peer->timer_wheel, peer - wmp->peers,
				     WG_TIMER_NEW_HANDSHAKE, interval);
    }
}

/* Should be called after an authenticated data packet is received. */
void
wg_timers_data_received (wg_peer_t * peer)
{
  if (peer->timers[WG_TIMER_SEND_KEEPALIVE] == ~0)
    {
      wg_main_t *wmp = &wg_main;
      peer->timers[WG_TIMER_SEND_KEEPALIVE] =
	tw_timer_start_16t_2w_512sl (&peer->timer_wheel, peer - wmp->peers,
				     WG_TIMER_SEND_KEEPALIVE,
				     KEEPALIVE_TIMEOUT * WHZ);
    }
  else
    {
      peer->timer_need_another_keepalive = true;
    }
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void
wg_timers_handshake_complete (wg_peer_t * peer, f64 current_time)
{
  stop_timer (peer, WG_TIMER_RETRANSMIT_HANDSHAKE);

  peer->timer_handshake_attempts = 0;
  peer->sent_lastminute_handshake = false;
}

void
wg_timers_any_authenticated_packet_received (wg_peer_t * peer)
{
  stop_timer (peer, WG_TIMER_NEW_HANDSHAKE);
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

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      peer = pool_elt_at_index (wmp->peers, pool_index);
      peer->timers[timer_id] = ~0;
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
	  wg_expired_zero_key_material (peer);
	  break;
	default:
	  break;
	}
    }
}

void
wg_timers_init (wg_peer_t * peer, f64 now)
{
  for (int i = 0; i < WG_N_TIMERS; i++)
    {
      peer->timers[i] = ~0;
    }
  tw_timer_wheel_16t_2w_512sl_t *tw = &peer->timer_wheel;
  tw_timer_wheel_init_16t_2w_512sl (tw,
				    expired_timer_callback,
				    WG_TICK /* timer period in s */ , ~0);
  tw->last_run_time = now;
}

static uword
wg_timer_mngr_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  wg_main_t *wmp = &wg_main;
  wg_peer_t *peers;
  wg_peer_t *peer;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, WG_TICK);
      vlib_process_get_events (vm, NULL);

      peers = wmp->peers;
      pool_foreach (peer, peers, (
				   {
				   tw_timer_expire_timers_16t_2w_512sl
				   (&peer->timer_wheel, vlib_time_now (vm));
				   }
		    ));
    }

  return 0;
}

void
wg_timers_stop (wg_peer_t * peer)
{
  stop_timer (peer, WG_TIMER_RETRANSMIT_HANDSHAKE);
  stop_timer (peer, WG_TIMER_PERSISTENT_KEEPALIVE);
  stop_timer (peer, WG_TIMER_SEND_KEEPALIVE);
  stop_timer (peer, WG_TIMER_NEW_HANDSHAKE);
  stop_timer (peer, WG_TIMER_KEY_ZEROING);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (wg_timer_mngr_node, static) = {
    .function = wg_timer_mngr_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name =
    "wg-timer-manager",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
