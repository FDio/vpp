/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>.
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

#ifndef __included_crypto_chachapoly1305_h__
#define __included_crypto_chachapoly1305_h__

#include <stdbool.h>
#include <vlib/vlib.h>

enum chacha20poly1305_lengths
{
  XCHACHA20POLY1305_NONCE_SIZE = 24,
  CHACHA20POLY1305_KEY_SIZE = 32,
  CHACHA20POLY1305_AUTHTAG_SIZE = 16
};

void chacha20poly1305_encrypt (u8 * dst, const u8 * src, const size_t src_len,
			       const u8 * ad, const size_t ad_len,
			       const u64 nonce,
			       const u8 key[CHACHA20POLY1305_KEY_SIZE]);

bool
chacha20poly1305_decrypt (u8 * dst, const u8 * src, const size_t src_len,
			  const u8 * ad, const size_t ad_len, const u64 nonce,
			  const u8 key[CHACHA20POLY1305_KEY_SIZE]);

void xchacha20poly1305_encrypt (u8 * dst, const u8 * src,
				const size_t src_len, const u8 * ad,
				const size_t ad_len,
				const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
				const u8 key[CHACHA20POLY1305_KEY_SIZE]);

bool xchacha20poly1305_decrypt (u8 * dst, const u8 * src,
				const size_t src_len, const u8 * ad,
				const size_t ad_len,
				const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
				const u8 key[CHACHA20POLY1305_KEY_SIZE]);

/* prevents compiler optimizing out memset() */
inline void
secure_zero_memory (void *v, size_t n)
{
  static void *(*const volatile memset_v) (void *, int, size_t) = &memset;
  memset_v (v, 0, n);
}

#endif /* __included_crypto_chachapoly1305_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
