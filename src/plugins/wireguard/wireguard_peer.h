/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <wireguard/wireguard_if.h>

typedef struct ip4_udp_header_t_
{
  ip4_header_t ip4;
  udp_header_t udp;
} __clib_packed ip4_udp_header_t;

u8 *format_ip4_udp_header (u8 * s, va_list * va);

typedef struct wg_peer_allowed_ip_t_
{
  fib_prefix_t prefix;
  fib_node_index_t fib_entry_index;
} wg_peer_allowed_ip_t;

typedef struct wg_peer_endpoint_t_
{
  ip46_address_t addr;
  u16 port;
} wg_peer_endpoint_t;

typedef struct wg_peer
{
  noise_remote_t remote;
  cookie_maker_t cookie_maker;

  u32 input_thread_index;
  u32 output_thread_index;

  /* Peer addresses */
  wg_peer_endpoint_t dst;
  wg_peer_endpoint_t src;
  u32 table_id;
  adj_index_t adj_index;

  /* rewrite built from address information */
  u8 *rewrite;

  /* Vector of allowed-ips */
  wg_peer_allowed_ip_t *allowed_ips;

  /* The WG interface this peer is attached to */
  u32 wg_sw_if_index;

  /* Timers */
  tw_timer_wheel_16t_2w_512sl_t *timer_wheel;
  u32 timers[WG_N_TIMERS];
  u8 timers_dispatched[WG_N_TIMERS];
  u32 timer_handshake_attempts;
  u16 persistent_keepalive_interval;

  /* Timestamps */
  f64 last_sent_handshake;
  f64 last_sent_packet;
  f64 last_received_packet;
  f64 session_derived;
  f64 rehandshake_started;

  /* Variable intervals */
  u32 new_handshake_interval_tick;
  u32 rehandshake_interval_tick;

  bool timer_need_another_keepalive;

  bool is_dead;
} wg_peer_t;

typedef struct wg_peer_table_bind_ctx_t_
{
  ip_address_family_t af;
  u32 new_fib_index;
  u32 old_fib_index;
} wg_peer_table_bind_ctx_t;

int wg_peer_add (u32 tun_sw_if_index,
		 const u8 public_key_64[NOISE_PUBLIC_KEY_LEN],
		 u32 table_id,
		 const ip46_address_t * endpoint,
		 const fib_prefix_t * allowed_ips,
		 u16 port, u16 persistent_keepalive, index_t * peer_index);
int wg_peer_remove (u32 peer_index);

typedef walk_rc_t (*wg_peer_walk_cb_t) (index_t peeri, void *arg);
index_t wg_peer_walk (wg_peer_walk_cb_t fn, void *data);

u8 *format_wg_peer (u8 * s, va_list * va);

walk_rc_t wg_peer_if_admin_state_change (wg_if_t * wgi, index_t peeri,
					 void *data);
walk_rc_t wg_peer_if_table_change (wg_if_t * wgi, index_t peeri, void *data);

/*
 * Expoed for the data-plane
 */
extern index_t *wg_peer_by_adj_index;
extern wg_peer_t *wg_peer_pool;

static inline wg_peer_t *
wg_peer_get (index_t peeri)
{
  return (pool_elt_at_index (wg_peer_pool, peeri));
}

static inline index_t
wg_peer_get_by_adj_index (index_t ai)
{
  return (wg_peer_by_adj_index[ai]);
}

/*
 * Makes choice for thread_id should be assigned.
*/
static inline u32
wg_peer_assign_thread (u32 thread_id)
{
  return ((thread_id) ? thread_id
	  : (vlib_num_workers ()?
	     ((unix_time_now_nsec () % vlib_num_workers ()) +
	      1) : thread_id));
}

#endif // __included_wg_peer_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
