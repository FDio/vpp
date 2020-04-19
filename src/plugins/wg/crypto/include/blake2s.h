/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2012 Samuel Neves <sneves@dei.uc.pt>.
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

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif


enum blake2s_constant
{
  BLAKE2S_BLOCKBYTES = 64,
  BLAKE2S_OUTBYTES = 32,
  BLAKE2S_KEYBYTES = 32,
  BLAKE2S_HASHSIZE = BLAKE2S_OUTBYTES,
  BLAKE2S_SALTBYTES = 8,
  BLAKE2S_PERSONALBYTES = 8
};

typedef struct blake2s_state
{
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t buf[BLAKE2S_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
  uint8_t last_node;
} blake2s_state_t;



BLAKE2_PACKED (struct blake2s_param
	       {
	       uint8_t digest_length;	/* 1 */
	       uint8_t key_length;	/* 2 */
	       uint8_t fanout;	/* 3 */
	       uint8_t depth;	/* 4 */
	       uint32_t leaf_length;	/* 8 */
	       uint32_t node_offset;	/* 12 */
	       uint16_t xof_length;	/* 14 */
	       uint8_t node_depth;	/* 15 */
	       uint8_t inner_length;	/* 16 */
	       /* uint8_t  reserved[0]; */
	       uint8_t salt[BLAKE2S_SALTBYTES];	/* 24 */
	       uint8_t personal[BLAKE2S_PERSONALBYTES];	/* 32 */
	       });

typedef struct blake2s_param blake2s_param_t;


/* Streaming API */
int blake2s_init (blake2s_state_t * S, size_t outlen);
int blake2s_init_key (blake2s_state_t * S, size_t outlen, const void *key,
		      size_t keylen);
int blake2s_init_param (blake2s_state_t * S, const blake2s_param_t * P);
int blake2s_update (blake2s_state_t * S, const void *in, size_t inlen);
int blake2s_final (blake2s_state_t * S, void *out, size_t outlen);

int blake2s (void *out, size_t outlen, const void *in, size_t inlen,
	     const void *key, size_t keylen);

void blake2s_hmac (u8 * out, const u8 * in, const u8 * key,
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
