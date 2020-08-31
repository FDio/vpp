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
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_messages.h>

typedef struct wg_peer_allowed_ip_t_
{
  fib_prefix_t prefix;
  fib_node_index_t fib_entry_index;
} wg_peer_allowed_ip_t;

typedef struct wg_peer
{
  noise_remote_t remote;
  cookie_maker_t cookie_maker;

  /*Peer addresses */
  ip4_address_t ip4_address;
  u32 sw_if_index;
  u16 port;
  u32 table_id;

  /* Vector of allowed-ips */
  wg_peer_allowed_ip_t *allowed_ips;
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

int wg_peer_add (u32 tun_sw_if_index,
		 const u8 public_key_64[NOISE_KEY_LEN_BASE64],
		 u32 table_id,
		 ip4_address_t endpoint,
		 const fib_prefix_t * allowed_ips,
		 u16 port, u16 persistent_keepalive, index_t * peer_index);
int wg_peer_remove (u32 peer_index);

typedef walk_rc_t (*wg_peer_walk_cb_t) (index_t peeri, void *arg);
void wg_peer_walk (wg_peer_walk_cb_t fn, void *data);

u8 *format_wg_peer (u8 * s, va_list * va);
wg_peer_t *wg_peer_get (index_t peeri);

#endif // __included_wg_peer_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
