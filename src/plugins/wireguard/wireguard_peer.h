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

#ifndef __included_wg_peer_h__
#define __included_wg_peer_h__

#include <vnet/ip/ip.h>

#include <wireguard/wireguard_cookie.h>
#include <wireguard/wireguard_timer.h>

typedef struct wg_peer
{
  noise_remote_t remote;
  cookie_maker_t cookie_maker;

  /*Peer addresses */
  ip4_address_t ip4_address;
  u16 port;
  ip4_address_t allowed_ip;
  u32 tun_sw_if_index;

  /*Timers */
  tw_timer_wheel_16t_2w_512sl_t timer_wheel;
  u32 timers[WG_N_TIMERS];
  u32 timer_handshake_attempts;
  u16 persistent_keepalive_interval;
  f64 last_sent_handshake;
  bool timer_need_another_keepalive;

  bool is_dead;
} wg_peer_t;

void wg_peer_init (vlib_main_t * vm, wg_peer_t * peer);
void wg_peer_clear (vlib_main_t * vm, wg_peer_t * peer);
void wg_peer_fill (vlib_main_t * vm, wg_peer_t * peer, ip4_address_t ip4,
		   u16 port, u16 persistent_keepalive_interval,
		   ip4_address_t allowed_ip, u32 tun_sw_if_index);

#endif // __included_wg_peer_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
