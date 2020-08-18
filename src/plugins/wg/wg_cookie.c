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
#include <vlib/vlib.h>

#include <wg/crypto/random.h>
#include <wg/wg_cookie.h>
#include <wg/wg.h>

static void cookie_precompute_key (uint8_t *,
				   const uint8_t[COOKIE_INPUT_SIZE],
				   const char *);
static void cookie_macs_mac1 (message_macs_t *, const void *, size_t,
			      const uint8_t[COOKIE_KEY_SIZE]);
static void cookie_macs_mac2 (message_macs_t *, const void *, size_t,
			      const uint8_t[COOKIE_COOKIE_SIZE]);
static void cookie_checker_make_cookie (vlib_main_t * vm, cookie_checker_t *,
					uint8_t[COOKIE_COOKIE_SIZE],
					ip4_address_t ip4, u16 udp_port);

/* Public Functions */
void
cookie_maker_init (cookie_maker_t * cp, uint8_t key[COOKIE_INPUT_SIZE])
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

bool
cookie_maker_consume_payload (vlib_main_t * vm, cookie_maker_t * cp,
			      uint8_t nonce[COOKIE_NONCE_SIZE],
			      uint8_t ecookie[COOKIE_ENCRYPTED_SIZE])
{
  uint8_t cookie[COOKIE_COOKIE_SIZE];

  if (cp->cp_mac1_valid == 0)
    {
      return false;
    }

  if (!xchacha20poly1305_decrypt (cookie, ecookie, COOKIE_ENCRYPTED_SIZE,
				  cp->cp_mac1_last, COOKIE_MAC_SIZE, nonce,
				  cp->cp_cookie_key))
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
cookie_checker_validate_macs (vlib_main_t * vm, cookie_checker_t * cc,
			      message_macs_t * cm, void *buf, size_t len,
			      bool busy, ip4_address_t ip4, u16 udp_port)
{
  message_macs_t our_cm;
  uint8_t cookie[COOKIE_COOKIE_SIZE];

  len = len - sizeof (message_macs_t);
  cookie_macs_mac1 (&our_cm, buf, len, cc->cc_mac1_key);

  /* If mac1 is invald, we want to drop the packet */
  if (clib_memcmp (our_cm.mac1, cm->mac1, COOKIE_MAC_SIZE) != 0)
    return INVALID_MAC;

  if (!busy)
    return VALID_MAC_BUT_NO_COOKIE;

  cookie_checker_make_cookie (vm, cc, cookie, ip4, udp_port);
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
  blake2s_state_t blake;

  blake2s_init (&blake, COOKIE_KEY_SIZE);
  blake2s_update (&blake, (const uint8_t *) label, strlen (label));
  blake2s_update (&blake, input, COOKIE_INPUT_SIZE);
  blake2s_final (&blake, key);
}

static void
cookie_macs_mac1 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_KEY_SIZE])
{
  blake2s_state_t state;
  blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_KEY_SIZE);
  blake2s_update (&state, buf, len);
  blake2s_final (&state, cm->mac1);
}

static void
cookie_macs_mac2 (message_macs_t * cm, const void *buf, size_t len,
		  const uint8_t key[COOKIE_COOKIE_SIZE])
{
  blake2s_state_t state;
  blake2s_init_key (&state, COOKIE_MAC_SIZE, key, COOKIE_COOKIE_SIZE);
  blake2s_update (&state, buf, len);
  blake2s_update (&state, cm->mac1, COOKIE_MAC_SIZE);
  blake2s_final (&state, cm->mac2);
}

static void
cookie_checker_make_cookie (vlib_main_t * vm, cookie_checker_t * cc,
			    uint8_t cookie[COOKIE_COOKIE_SIZE],
			    ip4_address_t ip4, u16 udp_port)
{
  blake2s_state_t state;

  if (wg_birthdate_has_expired (cc->cc_secret_birthdate,
				COOKIE_SECRET_MAX_AGE))
    {

      cc->cc_secret_birthdate = vlib_time_now (vm);
      for (int i = 0; i < COOKIE_SECRET_SIZE; ++i)
	{
	  cc->cc_secret[i] = get_random_u32 ();
	}
    }
  blake2s_init_key (&state, COOKIE_COOKIE_SIZE, cc->cc_secret,
		    COOKIE_SECRET_SIZE);

  blake2s_update (&state, ip4.as_u8, sizeof (ip4_address_t));	//TODO: IP6
  blake2s_update (&state, (u8 *) & udp_port, sizeof (u16));
  blake2s_final (&state, cookie);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
