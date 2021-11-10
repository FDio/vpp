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

#ifndef __included_wg_timer_h__
#define __included_wg_timer_h__

#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/tw_timer_16t_2w_512sl.h>

/** WG timers */
#define foreach_wg_timer                            \
  _(RETRANSMIT_HANDSHAKE, "RETRANSMIT HANDSHAKE")   \
  _(PERSISTENT_KEEPALIVE, "PERSISTENT KEEPALIVE")   \
  _(SEND_KEEPALIVE, "SEND KEEPALIVE")               \
  _(NEW_HANDSHAKE, "NEW HANDSHAKE")                 \
  _(KEY_ZEROING, "KEY ZEROING")                     \

typedef enum _wg_timers
{
#define _(sym, str) WG_TIMER_##sym,
  foreach_wg_timer
#undef _
  WG_N_TIMERS
} wg_timers_e;

typedef struct wg_peer wg_peer_t;

void wg_timer_wheel_init ();
void wg_timers_stop (wg_peer_t * peer);
void wg_timers_data_sent (wg_peer_t * peer);
void wg_timers_data_sent_opt (wg_peer_t *peer, f64 time);
void wg_timers_data_received (wg_peer_t * peer);
void wg_timers_any_authenticated_packet_sent (wg_peer_t * peer);
void wg_timers_any_authenticated_packet_sent_opt (wg_peer_t *peer, f64 time);
void wg_timers_any_authenticated_packet_received (wg_peer_t * peer);
void wg_timers_any_authenticated_packet_received_opt (wg_peer_t *peer,
						      f64 time);
void wg_timers_handshake_initiated (wg_peer_t * peer);
void wg_timers_handshake_complete (wg_peer_t * peer);
void wg_timers_session_derived (wg_peer_t * peer);
void wg_timers_any_authenticated_packet_traversal (wg_peer_t * peer);


static inline bool
wg_birthdate_has_expired (f64 birthday_seconds, f64 expiration_seconds)
{
  f64 now_seconds = vlib_time_now (vlib_get_main ());
  return (birthday_seconds + expiration_seconds) < now_seconds;
}

static_always_inline bool
wg_birthdate_has_expired_opt (f64 birthday_seconds, f64 expiration_seconds,
			      f64 time)
{
  return (birthday_seconds + expiration_seconds) < time;
}

#endif /* __included_wg_timer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
