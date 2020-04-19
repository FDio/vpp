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

#include <wg/wg_peer.h>

void
wg_peer_init (wg_peer_t * peer, f64 now)
{
  wg_timers_init (peer, now);
  wg_peer_clear (peer, now);
}

void
wg_peer_clear (wg_peer_t * peer, f64 now)
{
  wg_timers_stop (peer);
  wg_noise_handshake_clear (&peer->handshake);
  wg_noise_keypairs_clear (&peer->keypairs);
  wg_noise_reset_last_sent_handshake (&peer->last_sent_handshake, now);
  wg_cookie_init (&peer->latest_cookie);

  peer->allowed_ip.as_u32 = 0;
  peer->ip4_address.as_u32 = 0;

  peer->persistent_keepalive_interval = 0;
  peer->port = 0;
  peer->sent_lastminute_handshake = false;
  peer->timer_handshake_attempts = 0;
  peer->timer_need_another_keepalive = false;
  peer->is_dead = true;
}

void
wg_peer_fill (wg_peer_t * peer, ip4_address_t ip4, u16 port,
	      u16 persistent_keepalive_interval, ip4_address_t allowed_ip,
	      u32 tun_sw_if_index, f64 now)
{
  peer->ip4_address.as_u32 = ip4.as_u32;
  peer->port = port;
  peer->allowed_ip.as_u32 = allowed_ip.as_u32;
  peer->persistent_keepalive_interval = persistent_keepalive_interval;
  peer->tun_sw_if_index = tun_sw_if_index;
  wg_noise_reset_last_sent_handshake (&peer->last_sent_handshake, now);

  peer->is_dead = false;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
