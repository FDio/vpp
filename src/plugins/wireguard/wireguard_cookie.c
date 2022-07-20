/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>.
 * Copyright (c) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>.
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

#include <stddef.h>
#include <openssl/rand.h>
#include <vlib/vlib.h>

#include <wireguard/wireguard_cookie.h>
#include <wireguard/wireguard_chachapoly.h>
#include <wireguard/wireguard.h>

static void cookie_precompute_key (uint8_t *,
				   const uint8_t[COOKIE_INPUT_SIZE],
				   const char *);
static void cookie_macs_mac1 (message_macs_t *, const void *, size_t,
			      const uint8_t[COOKIE_KEY_SIZE]);
static void cookie_macs_mac2 (message_macs_t *, const void *, size_t,
			      const uint8_t[COOKIE_COOKIE_SIZE]);
static void cookie_checker_make_cookie (vlib_main_t *vm, cookie_checker_t *,
					uint8_t[COOKIE_COOKIE_SIZE],
					ip46_address_t *ip, u16 udp_port);

static void ratelimit_init (ratelimit_t *, ratelimit_entry_t *);
static void ratelimit_deinit (ratelimit_t *);
static void ratelimit_gc (ratelimit_t *, bool);
static bool ratelimit_allow (ratelimit_t *, ip46_address_t *);

/* Public Functions */
void
cookie_maker_init (cookie_maker_t * cp, const uint8_t key[COOKIE_INPUT_SIZE])
{
  clib_memset (cp, 0, sizeof (*cp));
  cookie_precompute_key (cp->cp_mac1_key, key, COOKIE_MAC1_KEY_LABEL);
  cookie_precompute_key (cp->cp_cookie_key, key, COOKIE_COOKIE_KEY_LABEL);
}

void
cookie_checker_init (cookie_checker_t *cc, ratelimit_entry_t *pool)
{
  clib_memset (cc, 0, sizeof (*cc));
  ratelimit_init (&cc->cc_ratelimit_v4, pool);
  ratelimit_init (&cc->cc_ratelimit_v6, pool);
}

void
cookie_checker_update (cookie_checker_t * cc, uint8_t key[COOKIE_INPUT_SIZE])
{
  if (key)
    {
      cookie_precompute_key (cc->cc_mac1_key, key, COOKIE_MAC1_KEY_LABEL);
      cookie_precompute_key (cc->cc_cookie_key, key, COOKIE_COOKIE_KEY_LABEL);
    }
  else
    {
      clib_memset (cc->cc_mac1_key, 0, sizeof (cc->cc_mac1_key));
      clib_memset (cc->cc_cookie_key, 0, sizeof (cc->cc_cookie_key));
    }
}

void
cookie_checker_deinit (cookie_checker_t *cc)
{
  ratelimit_deinit (&cc->cc_ratelimit_v4);
  ratelimit_deinit (&cc->cc_ratelimit_v6);
}

void
cookie_checker_create_payload (vlib_main_t *vm, cookie_checker_t *cc,
			       message_macs_t *cm,
			       uint8_t nonce[COOKIE_NONCE_SIZE],
			       uint8_t ecookie[COOKIE_ENCRYPTED_SIZE],
			       ip46_address_t *ip, u16 udp_port)
{
  uint8_t cookie[COOKIE_COOKIE_SIZE];

  cookie_checker_make_cookie (vm, cc, cookie, ip, udp_port);
  RAND_bytes (nonce, COOKIE_NONCE_SIZE);

  wg_xchacha20poly1305_encrypt (vm, cookie, COOKIE_COOKIE_SIZE, ecookie,
				cm->mac1, COOKIE_MAC_SIZE, nonce,
				cc->cc_cookie_key);

  wg_secure_zero_memory (cookie, sizeof (cookie));
}

bool
cookie_maker_consume_payload (vlib_main_t *vm, cookie_maker_t *cp,
			      uint8_t nonce[COOKIE_NONCE_SIZE],
			      uint8_t ecookie[COOKIE_ENCRYPTED_SIZE])
{
  uint8_t cookie[COOKIE_COOKIE_SIZE];

  if (cp->cp_mac1_valid == 0)
    {
      return false;
    }

  if (!wg_xchacha20poly1305_decrypt (vm, ecookie, COOKIE_ENCRYPTED_SIZE,
				     cookie, cp->cp_mac1_last, COOKIE_MAC_SIZE,
				     nonce, cp->cp_cookie_key))
    {
      return false;
    }

  clib_memcpy (cp->cp_cookie, cookie, COOKIE_COOKIE_SIZE);
  cp->cp_birthdate = vlib_time_now (vm);
  cp->cp_mac1_valid = 0;

  return true;
}

void
cookie_maker_mac (cookie_maker_t * cp, message_macs_t * cm, void *buf,
		  size_t len)
{
  len = len - sizeof (message_macs_t);
  cookie_macs_mac1 (cm, buf, len, cp->cp_mac1_key);

  clib_memcpy (cp->cp_mac1_last, cm->mac1, COOKIE_MAC_SIZE);
  cp->cp_mac1_valid = 1;

  if (!wg_birthdate_has_expired (cp->cp_birthdate,
				 COOKIE_SECRET_MAX_AGE -
				 COOKIE_SECRET_LATENCY))
    cookie_macs_mac2 (cm, buf, len, cp->cp_cookie);
  else
    clib_memset (cm->mac2, 0, COOKIE_MAC_SIZE);
}

enum cookie_mac_state
cookie_checker_validate_macs (vlib_main_t *vm, cookie_checker_t *cc,
			      message_macs_t *cm, void *buf, size_t len,
			      bool busy, ip46_address_t *ip, u16 udp_port)
{
  message_macs_t our_cm;
  uint8_t cookie[COOKIE_COOKIE_SIZE];

  len = len - sizeof (message_macs_t);
  cookie_macs_mac1 (&our_cm, buf, len, cc->cc_mac1_key);

  /* If mac1 is invalid, we want to drop the packet */
  if (clib_memcmp (our_cm.mac1, cm->mac1, COOKIE_MAC_SIZE) != 0)
    return INVALID_MAC;

  if (!busy)
    return VALID_MAC_BUT_NO_COOKIE;

  cookie_checker_make_cookie (vm, cc, cookie, ip, udp_port);
  cookie_macs_mac2 (&our_cm, buf, len, cookie);

  /* If the mac2 is invalid, we want to send a cookie response */
  if (clib_memcmp (our_cm.mac2, cm->mac2, COOKIE_MAC_SIZE) != 0)
    return VALID_MAC_BUT_NO_COOKIE;

  /* If the mac2 is valid, we may want to rate limit the peer */
  ratelimit_t *rl;
  rl = ip46_address_is_ip4 (ip) ? &cc->cc_ratelimit_v4 : &cc->cc_ratelimit_v6;

  if (!ratelimit_allow (rl, ip))
    return VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;

  return VALID_MAC_WITH_COOKIE;
}

/* Private functions */
static void
cookie_precompute_key (uint8_t * key, const uint8_t input[COOKIE_INPUT_SIZE],
		       const char *label)
{
  blake2s_state_t blake;

  blake2s_init (&blake, COOKIE_KEY_SIZE);
  blake2s_update (&blake, (const uint8_t *) label, strlen (label));
  blake2s_update (&blake, input, COOKIE_INPUT_SIZE);
  blake2s_final (&blake, key, COOKIE_KEY_SIZE);
}

static void
cookie_macs_mac1 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_KEY_SIZE])
{
  blake2s_state_t state;
  blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_KEY_SIZE);
  blake2s_update (&state, buf, len);
  blake2s_final (&state, cm->mac1, COOKIE_MAC_SIZE);

}

static void
cookie_macs_mac2 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_COOKIE_SIZE])
{
  blake2s_state_t state;
  blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_COOKIE_SIZE);
  blake2s_update (&state, buf, len);
  blake2s_update (&state, cm->mac1, COOKIE_MAC_SIZE);
  blake2s_final (&state, cm->mac2, COOKIE_MAC_SIZE);
}

static void
cookie_checker_make_cookie (vlib_main_t *vm, cookie_checker_t *cc,
			    uint8_t cookie[COOKIE_COOKIE_SIZE],
			    ip46_address_t *ip, u16 udp_port)
{
  blake2s_state_t state;

  if (wg_birthdate_has_expired (cc->cc_secret_birthdate,
				COOKIE_SECRET_MAX_AGE))
    {
      cc->cc_secret_birthdate = vlib_time_now (vm);
      RAND_bytes (cc->cc_secret, COOKIE_SECRET_SIZE);
    }

  blake2s_init_key (&state, COOKIE_COOKIE_SIZE, cc->cc_secret,
		    COOKIE_SECRET_SIZE);

  if (ip46_address_is_ip4 (ip))
    {
      blake2s_update (&state, ip->ip4.as_u8, sizeof (ip4_address_t));
    }
  else
    {
      blake2s_update (&state, ip->ip6.as_u8, sizeof (ip6_address_t));
    }
  blake2s_update (&state, (u8 *) & udp_port, sizeof (u16));
  blake2s_final (&state, cookie, COOKIE_COOKIE_SIZE);
}

static void
ratelimit_init (ratelimit_t *rl, ratelimit_entry_t *pool)
{
  rl->rl_pool = pool;
}

static void
ratelimit_deinit (ratelimit_t *rl)
{
  ratelimit_gc (rl, /* force */ true);
  hash_free (rl->rl_table);
}

static void
ratelimit_gc (ratelimit_t *rl, bool force)
{
  u32 r_key;
  u32 r_idx;
  ratelimit_entry_t *r;

  if (force)
    {
      /* clang-format off */
      hash_foreach (r_key, r_idx, rl->rl_table, {
	r = pool_elt_at_index (rl->rl_pool, r_idx);
	pool_put (rl->rl_pool, r);
      });
      /* clang-format on */
      return;
    }

  f64 now = vlib_time_now (vlib_get_main ());

  if ((rl->rl_last_gc + ELEMENT_TIMEOUT) < now)
    {
      u32 *r_key_to_del = NULL;
      u32 *pr_key;

      rl->rl_last_gc = now;

      /* clang-format off */
      hash_foreach (r_key, r_idx, rl->rl_table, {
	r = pool_elt_at_index (rl->rl_pool, r_idx);
	if ((r->r_last_time + ELEMENT_TIMEOUT) < now)
	  {
	    vec_add1 (r_key_to_del, r_key);
	    pool_put (rl->rl_pool, r);
	  }
      });
      /* clang-format on */

      vec_foreach (pr_key, r_key_to_del)
	{
	  hash_unset (rl->rl_table, *pr_key);
	}

      vec_free (r_key_to_del);
    }
}

static bool
ratelimit_allow (ratelimit_t *rl, ip46_address_t *ip)
{
  u32 r_key;
  uword *p;
  u32 r_idx;
  ratelimit_entry_t *r;
  f64 now = vlib_time_now (vlib_get_main ());

  if (ip46_address_is_ip4 (ip))
    /* Use all 4 bytes of IPv4 address */
    r_key = ip->ip4.as_u32;
  else
    /* Use top 8 bytes (/64) of IPv6 address */
    r_key = ip->ip6.as_u32[0] ^ ip->ip6.as_u32[1];

  /* Check if there is already an entry for the IP address */
  p = hash_get (rl->rl_table, r_key);
  if (p)
    {
      u64 tokens;
      f64 diff;

      r_idx = p[0];
      r = pool_elt_at_index (rl->rl_pool, r_idx);

      diff = now - r->r_last_time;
      r->r_last_time = now;

      tokens = r->r_tokens + diff * NSEC_PER_SEC;

      if (tokens > TOKEN_MAX)
	tokens = TOKEN_MAX;

      if (tokens >= INITIATION_COST)
	{
	  r->r_tokens = tokens - INITIATION_COST;
	  return true;
	}

      r->r_tokens = tokens;
      return false;
    }

  /* No entry for the IP address */
  ratelimit_gc (rl, /* force */ false);

  if (hash_elts (rl->rl_table) >= RATELIMIT_SIZE_MAX)
    return false;

  pool_get (rl->rl_pool, r);
  r_idx = r - rl->rl_pool;
  hash_set (rl->rl_table, r_key, r_idx);

  r->r_last_time = now;
  r->r_tokens = TOKEN_MAX - INITIATION_COST;

  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
