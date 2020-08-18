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

#ifndef __included_wg_cookie_h__
#define __included_wg_cookie_h__

#include <vnet/ip/ip4_packet.h>
#include <wg/wg_noise.h>

enum cookie_mac_state
{
  INVALID_MAC,
  VALID_MAC_BUT_NO_COOKIE,
  VALID_MAC_WITH_COOKIE
};

#define COOKIE_MAC_SIZE		16
#define COOKIE_KEY_SIZE		32
#define COOKIE_NONCE_SIZE	XCHACHA20POLY1305_NONCE_SIZE
#define COOKIE_COOKIE_SIZE	16
#define COOKIE_SECRET_SIZE	32
#define COOKIE_INPUT_SIZE	32
#define COOKIE_ENCRYPTED_SIZE	(COOKIE_COOKIE_SIZE + COOKIE_MAC_SIZE)

#define COOKIE_MAC1_KEY_LABEL	"mac1----"
#define COOKIE_COOKIE_KEY_LABEL	"cookie--"
#define COOKIE_SECRET_MAX_AGE	120
#define COOKIE_SECRET_LATENCY	5

/* Constants for initiation rate limiting */
#define RATELIMIT_SIZE		(1 << 13)
#define RATELIMIT_SIZE_MAX	(RATELIMIT_SIZE * 8)
#define NSEC_PER_SEC		1000000000LL
#define INITIATIONS_PER_SECOND	20
#define INITIATIONS_BURSTABLE	5
#define INITIATION_COST		(NSEC_PER_SEC / INITIATIONS_PER_SECOND)
#define TOKEN_MAX		(INITIATION_COST * INITIATIONS_BURSTABLE)
#define ELEMENT_TIMEOUT		1
#define IPV4_MASK_SIZE		4	/* Use all 4 bytes of IPv4 address */
#define IPV6_MASK_SIZE		8	/* Use top 8 bytes (/64) of IPv6 address */

typedef struct cookie_macs
{
  uint8_t mac1[COOKIE_MAC_SIZE];
  uint8_t mac2[COOKIE_MAC_SIZE];
} message_macs_t;

typedef struct cookie_maker
{
  uint8_t cp_mac1_key[COOKIE_KEY_SIZE];
  uint8_t cp_cookie_key[COOKIE_KEY_SIZE];

  uint8_t cp_cookie[COOKIE_COOKIE_SIZE];
  f64 cp_birthdate;
  int cp_mac1_valid;
  uint8_t cp_mac1_last[COOKIE_MAC_SIZE];
} cookie_maker_t;

typedef struct cookie_checker
{
  uint8_t cc_mac1_key[COOKIE_KEY_SIZE];
  uint8_t cc_cookie_key[COOKIE_KEY_SIZE];

  f64 cc_secret_birthdate;
  uint8_t cc_secret[COOKIE_SECRET_SIZE];
} cookie_checker_t;


void cookie_maker_init (cookie_maker_t *, uint8_t[COOKIE_INPUT_SIZE]);
void cookie_checker_update (cookie_checker_t *, uint8_t[COOKIE_INPUT_SIZE]);
bool cookie_maker_consume_payload (vlib_main_t * vm, cookie_maker_t *,
				   uint8_t[COOKIE_NONCE_SIZE],
				   uint8_t[COOKIE_ENCRYPTED_SIZE]);
void cookie_maker_mac (cookie_maker_t *, message_macs_t *, void *, size_t);
enum cookie_mac_state cookie_checker_validate_macs (vlib_main_t * vm,
						    cookie_checker_t *,
						    message_macs_t *, void *,
						    size_t, bool,
						    ip4_address_t ip4,
						    u16 udp_port);

#endif /* __included_wg_cookie_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
