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

/* Public Functions */
void
cookie_maker_init (cookie_maker_t * cp, const uint8_t key[COOKIE_INPUT_SIZE])
{
  clib_memset (cp, 0, sizeof (*cp));
  cookie_precompute_key (cp->cp_mac1_key, key, COOKIE_MAC1_KEY_LABEL);
  cookie_precompute_key (cp->cp_cookie_key, key, COOKIE_COOKIE_KEY_LABEL);
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

  return VALID_MAC_WITH_COOKIE;
}

/* Private functions */
static void
cookie_precompute_key (uint8_t * key, const uint8_t input[COOKIE_INPUT_SIZE],
		       const char *label)
{
  if(wg_main.blake3 == false)
  {
    blake2s_state_t blake;

    blake2s_init (&blake, COOKIE_KEY_SIZE);
    blake2s_update (&blake, (const uint8_t *) label, strlen (label));
    blake2s_update (&blake, input, COOKIE_INPUT_SIZE);
    blake2s_final (&blake, key, COOKIE_KEY_SIZE);
  }
  else
  {
    blake3_hasher blake3_self;
    blake3_hasher_init (&blake3_self);
    blake3_hasher_update (&blake3_self, (const uint8_t *) label, strlen (label));
    blake3_hasher_update (&blake3_self, input, COOKIE_INPUT_SIZE);
    blake3_hasher_finalize (&blake3_self, key, COOKIE_KEY_SIZE);
  }
}

static void
cookie_macs_mac1 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_KEY_SIZE])
{
  if(wg_main.blake3 == false)
  {
    blake2s_state_t state;
    blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_KEY_SIZE);
    blake2s_update (&state, buf, len);
    blake2s_final (&state, cm->mac1, COOKIE_MAC_SIZE);
  }
  else
  {
    blake3_hasher blake3_self;
    blake3_hasher_init_keyed (&blake3_self, key);
    blake3_hasher_update (&blake3_self, buf, len);
    blake3_hasher_finalize (&blake3_self, cm->mac1, COOKIE_MAC_SIZE);

  }

}

static void
cookie_macs_mac2 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_COOKIE_SIZE])
{
  if(wg_main.blake3 == false)
  {
    blake2s_state_t state;
    blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_COOKIE_SIZE);
    blake2s_update (&state, buf, len);
    blake2s_update (&state, cm->mac1, COOKIE_MAC_SIZE);
    blake2s_final (&state, cm->mac2, COOKIE_MAC_SIZE);
  }
  else
  {
    blake3_hasher blake3_self;
    blake3_hasher_init_keyed (&blake3_self, key);
    blake3_hasher_update (&blake3_self, buf, len);
    blake3_hasher_update (&blake3_self, cm->mac1, COOKIE_MAC_SIZE);
    blake3_hasher_finalize (&blake3_self, cm->mac2, COOKIE_MAC_SIZE);
  }
}

static void
cookie_checker_make_cookie (vlib_main_t *vm, cookie_checker_t *cc,
			    uint8_t cookie[COOKIE_COOKIE_SIZE],
			    ip46_address_t *ip, u16 udp_port)
{
  if (wg_birthdate_has_expired (cc->cc_secret_birthdate,
				COOKIE_SECRET_MAX_AGE))
    {
      cc->cc_secret_birthdate = vlib_time_now (vm);
      RAND_bytes (cc->cc_secret, COOKIE_SECRET_SIZE);
    }
  if (wg_main.blake3 == false)
  {
    blake2s_state_t state;
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
  else
  {
    blake3_hasher blake3_self;
    blake3_hasher_init_keyed (&blake3_self, cc->cc_secret);
    if (ip46_address_is_ip4 (ip))
    {
      blake3_hasher_update (&blake3_self, ip4.as_u8, sizeof (ip4_address_t));
    }
    else
    {
      blake3_hasher_update (&blake3_self, ip6.as_u8, sizeof (ip6_address_t));
    }
    blake3_hasher_update (&blake3_self, (u8 *) & udp_port, sizeof (u16));
    blake3_hasher_finalize (&blake3_self, cookie, COOKIE_COOKIE_SIZE);
  }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
