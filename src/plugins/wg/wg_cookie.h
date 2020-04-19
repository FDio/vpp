/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_cookie_h__
#define __included_wg_cookie_h__

#include <vnet/ip/ip4_packet.h>
#include <wg/wg_noise.h>

typedef struct wg_peer wg_peer_t;

typedef struct cookie_checker
{
  u8 secret[NOISE_HASH_LEN];
  u8 cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
  u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
  u64 secret_birthdate;
} cookie_checker_t;

typedef struct cookie
{
  u64 birthdate;
  bool is_valid;
  u8 cookie[COOKIE_LEN];
  bool have_sent_mac1;
  u8 last_mac1_sent[COOKIE_LEN];
  u8 cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
  u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
} cookie_t;

enum cookie_mac_state
{
  INVALID_MAC,
  VALID_MAC_BUT_NO_COOKIE,
  VALID_MAC_WITH_COOKIE
};

void wg_cookie_init (cookie_t * cookie);

void wg_cookie_checker_init (cookie_checker_t * checker, f64 now);

void wg_cookie_checker_precompute_keys (cookie_checker_t * checker,
					noise_static_identity_t *
					static_identity);

void wg_cookie_checker_precompute_peer_keys (wg_peer_t * peer);
void wg_cookie_add_mac_to_packet (void *message, size_t len,
				  wg_peer_t * peer, f64 now);

void wg_cookie_message_consume (vlib_main_t * vm,
				const wg_index_table_t * table,
				wg_peer_t * peer_pool,
				message_handshake_cookie_t * src);


enum cookie_mac_state wg_cookie_validate_packet (vlib_main_t * vm,
						 cookie_checker_t * checker,
						 void *message, size_t len,
						 ip4_address_t ip4,
						 u16 udp_src,
						 bool check_cookie);

#endif /* __included_wg_cookie_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
