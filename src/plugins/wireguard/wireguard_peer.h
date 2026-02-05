/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __included_wg_peer_h__
#define __included_wg_peer_h__

#include <vlibapi/api_helper_macros.h>

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

typedef struct ip4_udp_wg_header_t_
{
  ip4_header_t ip4;
  udp_header_t udp;
  message_data_t wg;
} __clib_packed ip4_udp_wg_header_t;

typedef struct ip6_udp_header_t_
{
  ip6_header_t ip6;
  udp_header_t udp;
} __clib_packed ip6_udp_header_t;

typedef struct ip6_udp_wg_header_t_
{
  ip6_header_t ip6;
  udp_header_t udp;
  message_data_t wg;
} __clib_packed ip6_udp_wg_header_t;

u8 *format_ip4_udp_header (u8 * s, va_list * va);
u8 *format_ip6_udp_header (u8 *s, va_list *va);

typedef struct wg_peer_endpoint_t_
{
  ip46_address_t addr;
  u16 port;
} wg_peer_endpoint_t;

typedef enum
{
  WG_PEER_STATUS_DEAD = 0x1,
  WG_PEER_ESTABLISHED = 0x2,
} wg_peer_flags;

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
  adj_index_t *adj_indices;

  /* rewrite built from address information */
  u8 *rewrite;

  /* Vector of allowed-ips */
  fib_prefix_t *allowed_ips;

  /* The WG interface this peer is attached to */
  u32 wg_sw_if_index;

  /* API client registered for events */
  vpe_client_registration_t *api_clients;
  uword *api_client_by_client_index;
  wg_peer_flags flags;

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

  /* Handshake is sent to main thread? */
  bool handshake_is_sent;
} wg_peer_t;

typedef struct wg_peer_table_bind_ctx_t_
{
  ip_address_family_t af;
  u32 new_fib_index;
  u32 old_fib_index;
} wg_peer_table_bind_ctx_t;

int wg_peer_add (u32 tun_sw_if_index, const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN],
		 bool preshared_key_set, const u8 public_key_64[NOISE_PUBLIC_KEY_LEN], u32 table_id,
		 const ip46_address_t *endpoint, const fib_prefix_t *allowed_ips, u16 port,
		 u16 persistent_keepalive, index_t *peer_index);
int wg_peer_remove (u32 peer_index);

typedef walk_rc_t (*wg_peer_walk_cb_t) (index_t peeri, void *arg);
index_t wg_peer_walk (wg_peer_walk_cb_t fn, void *data);

u8 *format_wg_peer (u8 * s, va_list * va);

walk_rc_t wg_peer_if_admin_state_change (index_t peeri, void *data);
walk_rc_t wg_peer_if_delete (index_t peeri, void *data);
walk_rc_t wg_peer_if_adj_change (index_t peeri, void *data);
adj_walk_rc_t wg_peer_adj_walk (adj_index_t ai, void *data);

void wg_api_peer_event (index_t peeri, wg_peer_flags flags);
void wg_peer_update_flags (index_t peeri, wg_peer_flags flag, bool add_del);
void wg_peer_update_endpoint (index_t peeri, const ip46_address_t *addr,
			      u16 port);
void wg_peer_update_endpoint_from_mt (index_t peeri,
				      const ip46_address_t *addr, u16 port);

static inline bool
wg_peer_is_dead (wg_peer_t *peer)
{
  return peer && peer->flags & WG_PEER_STATUS_DEAD;
}

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
  if (ai >= vec_len (wg_peer_by_adj_index))
    return INDEX_INVALID;
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

static_always_inline bool
fib_prefix_is_cover_addr_46 (const fib_prefix_t *p1, const ip46_address_t *ip)
{
  switch (p1->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
      return (ip4_destination_matches_route (&ip4_main, &p1->fp_addr.ip4,
					     &ip->ip4, p1->fp_len) != 0);
    case FIB_PROTOCOL_IP6:
      return (ip6_destination_matches_route (&ip6_main, &p1->fp_addr.ip6,
					     &ip->ip6, p1->fp_len) != 0);
    case FIB_PROTOCOL_MPLS:
      break;
    }
  return (false);
}

static inline bool
wg_peer_can_send (wg_peer_t *peer)
{
  return peer && peer->rewrite;
}

#endif // __included_wg_peer_h__
