/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>.
 * Copyright (c) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>.
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
/*
   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

#ifndef __included_crypto_blake2s_h__
#define __included_crypto_blake2s_h__

#include <vlib/vlib.h>

enum blake2s_lengths
{
  BLAKE2S_BLOCK_SIZE = 64,
  BLAKE2S_HASH_SIZE = 32,
  BLAKE2S_KEY_SIZE = 32
};

typedef struct blake2s_state
{
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[BLAKE2S_BLOCK_SIZE];
  unsigned int buflen;
  unsigned int outlen;
} blake2s_state_t;

void blake2s_init (blake2s_state_t * state, const size_t outlen);
void blake2s_init_key (blake2s_state_t * state, const size_t outlen,
		       const void *key, const size_t keylen);
void blake2s_update (blake2s_state_t * state, const uint8_t * in,
		     size_t inlen);
void blake2s_final (blake2s_state_t * state, uint8_t * out);

static inline void
blake2s (uint8_t * out, const uint8_t * in, const uint8_t * key,
	 const size_t outlen, const size_t inlen, const size_t keylen)
{
  blake2s_state_t state;
  if (keylen)
    blake2s_init_key (&state, outlen, key, keylen);
  else
    blake2s_init (&state, outlen);

  blake2s_update (&state, in, inlen);
  blake2s_final (&state, out);
}

void blake2s_hmac (uint8_t * out, const uint8_t * in, const uint8_t * key,
		   const size_t outlen, const size_t inlen,
		   const size_t keylen);

#endif /* __included_crypto_blake2s_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
