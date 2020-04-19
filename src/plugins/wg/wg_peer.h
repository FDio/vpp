/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_peer_h__
#define __included_wg_peer_h__

#include <vnet/ip/ip.h>

#include <wg/wg_cookie.h>
#include <wg/wg_timer.h>

typedef struct wg_peer
{
  noise_handshake_t handshake;
  cookie_t latest_cookie;
  noise_keypairs_t keypairs;

  ip4_address_t ip4_address;
  u16 port;
  u16 persistent_keepalive_interval;

  bool sent_lastminute_handshake;
  u32 timer_handshake_attempts;

  f64 last_sent_handshake;
  bool timer_need_another_keepalive;

  ip4_address_t allowed_ip;
  u32 tun_sw_if_index;

  tw_timer_wheel_16t_2w_512sl_t timer_wheel;
  u32 timers[WG_N_TIMERS];

  bool is_dead;
} wg_peer_t;

void wg_peer_init (wg_peer_t * peer, f64 now);
void wg_peer_clear (wg_peer_t * peer, f64 now);
void wg_peer_fill (wg_peer_t * peer, ip4_address_t ip4, u16 port,
		   u16 persistent_keepalive_interval,
		   ip4_address_t allowed_ip, u32 tun_sw_if_index, f64 now);

#endif // __included_wg_peer_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
