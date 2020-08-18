/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
 * More information can be found at https://cr.yp.to/chacha.html
*/

#ifndef __included_crypto_chacha20_h__
#define __included_crypto_chacha20_h__

#include <vppinfra/types.h>
#include <wg/crypto/include/ecrypt-portable.h>

enum chacha20_lengths
{
  CHACHA20_NONCE_SIZE = 16,
  CHACHA20_KEY_SIZE = 32,
  CHACHA20_KEY_WORDS = CHACHA20_KEY_SIZE / sizeof (u32),
  CHACHA20_BLOCK_SIZE = 64,
  CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / sizeof (u32)
};

typedef struct chacha20_ctx
{
  u32 input[16];
} chacha20_ctx_t;

void chacha20_keysetup (chacha20_ctx_t * x, const u8 * k);
void chacha20_ivsetup (chacha20_ctx_t * x, const u64 iv);
void chacha20_encrypt_bytes (chacha20_ctx_t * x, const u8 * m, u8 * c,
			     u32 bytes);
void chacha20_decrypt_bytes (chacha20_ctx_t * x, const u8 * c, u8 * m,
			     u32 bytes);

void hchacha20 (u32 * out,
		const u8 nonce[CHACHA20_NONCE_SIZE],
		const u8 key[CHACHA20_KEY_SIZE]);

#endif /* __included_crypto_chacha20_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
