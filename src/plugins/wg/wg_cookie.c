// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stddef.h>
#include <vlib/vlib.h>

#include <wg/crypto/random.h>
#include <wg/wg_cookie.h>
#include <wg/wg.h>

enum
{ COOKIE_KEY_LABEL_LEN = 8 };
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static void
precompute_key (u8 key[NOISE_SYMMETRIC_KEY_LEN],
		const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
		const u8 label[COOKIE_KEY_LABEL_LEN])
{
  blake2s_state_t blake;

  blake2s_init (&blake, NOISE_SYMMETRIC_KEY_LEN);
  blake2s_update (&blake, label, COOKIE_KEY_LABEL_LEN);
  blake2s_update (&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
  blake2s_final (&blake, key, NOISE_SYMMETRIC_KEY_LEN);
}

void
wg_cookie_init (cookie_t * cookie)
{
  clib_memset (cookie, 0, sizeof (*cookie));
}

void
wg_cookie_checker_init (cookie_checker_t * checker, f64 now)
{
  checker->secret_birthdate = now;
  for (int i = 0; i < NOISE_HASH_LEN; ++i)
    {
      checker->secret[i] = get_random_u32 ();
    }
}

void
wg_cookie_checker_precompute_keys (cookie_checker_t * checker,
				   noise_static_identity_t * static_identity)
{
  if (static_identity->has_identity)
    {
      precompute_key (checker->cookie_encryption_key,
		      static_identity->static_public, cookie_key_label);
      precompute_key (checker->message_mac1_key,
		      static_identity->static_public, mac1_key_label);
    }
  else
    {
      memset (checker->cookie_encryption_key, 0, NOISE_SYMMETRIC_KEY_LEN);
      memset (checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
    }
}

void
wg_cookie_checker_precompute_peer_keys (wg_peer_t * peer)
{
  precompute_key (peer->latest_cookie.cookie_decryption_key,
		  peer->handshake.remote_static, cookie_key_label);
  precompute_key (peer->latest_cookie.message_mac1_key,
		  peer->handshake.remote_static, mac1_key_label);
}

static void
compute_mac1 (u8 mac1[COOKIE_LEN], const void *message, size_t len,
	      const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
  len = len - sizeof (message_macs_t) + offsetof (message_macs_t, mac1);
  blake2s (mac1, COOKIE_LEN, message, len, key, NOISE_SYMMETRIC_KEY_LEN);
}

static void
compute_mac2 (u8 mac2[COOKIE_LEN], const void *message, size_t len,
	      const u8 cookie[COOKIE_LEN])
{
  len = len - sizeof (message_macs_t) + offsetof (message_macs_t, mac2);
  blake2s (mac2, COOKIE_LEN, message, len, cookie, COOKIE_LEN);
}

void
wg_cookie_add_mac_to_packet (void *message, size_t len,
			     wg_peer_t * peer, f64 now)
{
  message_macs_t *macs = (message_macs_t *)
    ((u8 *) message + len - sizeof (*macs));

  compute_mac1 (macs->mac1, message, len,
		peer->latest_cookie.message_mac1_key);

  clib_memcpy (peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
  peer->latest_cookie.have_sent_mac1 = true;

  if (peer->latest_cookie.is_valid &&
      !wg_birthdate_has_expired (peer->latest_cookie.birthdate,
				 COOKIE_SECRET_MAX_AGE -
				 COOKIE_SECRET_LATENCY, now))
    {
      compute_mac2 (macs->mac2, message, len, peer->latest_cookie.cookie);
    }
  else
    {
      clib_memset (macs->mac2, 0, COOKIE_LEN);
    }
}

void
wg_cookie_message_consume (vlib_main_t * vm, const wg_index_table_t * table,
			   wg_peer_t * peer_pool,
			   message_handshake_cookie_t * src)
{
  wg_peer_t *peer = NULL;
  u8 cookie[COOKIE_LEN];
  bool ret;

  index_table_entry_t *entry =
    wg_index_table_lookup (table, src->receiver_index);
  peer = pool_elt_at_index (peer_pool, entry->peer_pool_idx);
  if (!peer)
    return;

  if (!peer->latest_cookie.have_sent_mac1)
    return;

  ret =
    xchacha20poly1305_decrypt (cookie, src->encrypted_cookie,
			       sizeof (src->encrypted_cookie),
			       peer->latest_cookie.last_mac1_sent, COOKIE_LEN,
			       src->nonce,
			       peer->latest_cookie.cookie_decryption_key);

  if (ret)
    {
      memcpy (peer->latest_cookie.cookie, cookie, COOKIE_LEN);
      peer->latest_cookie.birthdate = vlib_time_now (vm);
      peer->latest_cookie.is_valid = true;
      peer->latest_cookie.have_sent_mac1 = false;
    }
}

static void
make_cookie (vlib_main_t * vm, u8 cookie[COOKIE_LEN], ip4_address_t ip4,
	     u16 udp_src, cookie_checker_t * checker)
{
  blake2s_state_t state;
  f64 now = vlib_time_now (vm);
  if (wg_birthdate_has_expired (checker->secret_birthdate,
				COOKIE_SECRET_MAX_AGE, now))
    {
      checker->secret_birthdate = now;
      for (int i = 0; i < NOISE_HASH_LEN; ++i)
	{
	  checker->secret[i] = get_random_u32 ();
	}
    }

  blake2s_init_key (&state, COOKIE_LEN, checker->secret, NOISE_HASH_LEN);
  blake2s_update (&state, ip4.as_u8, sizeof (ip4_address_t));	//TODO: IP6

  blake2s_update (&state, (u8 *) & udp_src, sizeof (u16));
  blake2s_final (&state, cookie, COOKIE_LEN);
}


enum cookie_mac_state
wg_cookie_validate_packet (vlib_main_t * vm, cookie_checker_t * checker,
			   void *message, size_t len, ip4_address_t ip4,
			   u16 udp_src, bool check_cookie)
{
  enum cookie_mac_state ret;
  u8 computed_mac[COOKIE_LEN];
  u8 cookie[COOKIE_LEN];

  message_macs_t *macs = (message_macs_t *)
    ((u8 *) message + len - sizeof (*macs));

  ret = INVALID_MAC;
  compute_mac1 (computed_mac, message, len, checker->message_mac1_key);
  if (memcmp (computed_mac, macs->mac1, COOKIE_LEN))
    return ret;

  ret = VALID_MAC_BUT_NO_COOKIE;

  if (!check_cookie)
    return ret;

  make_cookie (vm, cookie, ip4, udp_src, checker);

  compute_mac2 (computed_mac, message, len, cookie);
  if (memcmp (computed_mac, macs->mac2, COOKIE_LEN))
    return ret;

  ret = VALID_MAC_WITH_COOKIE;
  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
