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

 /*
  * This is an implementation of the ChaCha20Poly1305 AEAD construction.
  *
  * Information: https://tools.ietf.org/html/rfc8439
  */

#include <stdio.h>
#include <vlib/vlib.h>

#include <wg/crypto/include/chacha20poly1305.h>
#include <wg/crypto/include/chacha20.h>
#include <wg/crypto/include/poly1305.h>

static const u8 pad0[CHACHA20_BLOCK_SIZE] = { 0 };

void
chacha20poly1305_encrypt (u8 * dst, const u8 * src, const size_t src_len,
			  const u8 * ad, const size_t ad_len,
			  const u64 nonce,
			  const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  poly1305_ctx_t poly1305_state;
  chacha20_ctx_t chacha20_state;
  union
  {
    u8 block0[POLY1305_KEY_LEN];
    u64 lens[2];
  } b =
  {
    {
  0}};

  chacha20_keysetup (&chacha20_state, key);
  chacha20_ivsetup (&chacha20_state, nonce);

  chacha20_encrypt_bytes (&chacha20_state, b.block0, b.block0,
			  sizeof (b.block0));

  poly1305_init (&poly1305_state, b.block0);

  poly1305_update (&poly1305_state, ad, ad_len);
  poly1305_update (&poly1305_state, pad0, (0x10 - ad_len) & 0xf);

  chacha20_encrypt_bytes (&chacha20_state, src, dst, src_len);

  poly1305_update (&poly1305_state, dst, src_len);
  poly1305_update (&poly1305_state, pad0, (0x10 - src_len) & 0xf);

  b.lens[0] = U64TO64_LITTLE (ad_len);
  b.lens[1] = U64TO64_LITTLE (src_len);

  poly1305_update (&poly1305_state, (u8 *) b.lens, sizeof (b.lens));

  poly1305_finish (&poly1305_state, dst + src_len);

  secure_zero_memory (&chacha20_state, sizeof (chacha20_state));
  secure_zero_memory (&b, sizeof (b));
}

bool
chacha20poly1305_decrypt (u8 * dst, const u8 * src, const size_t src_len,
			  const u8 * ad, const size_t ad_len,
			  const u64 nonce,
			  const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  poly1305_ctx_t poly1305_state;
  chacha20_ctx_t chacha20_state;
  int ret;
  size_t dst_len;
  union
  {
    u8 block0[POLY1305_KEY_LEN];
    u8 mac[POLY1305_MAC_LEN];
    u64 lens[2];
  } b =
  {
    {
  0}};

  if (src_len < POLY1305_MAC_LEN)
    return false;

  chacha20_keysetup (&chacha20_state, key);
  chacha20_ivsetup (&chacha20_state, nonce);

  chacha20_decrypt_bytes (&chacha20_state, b.block0, b.block0,
			  sizeof (b.block0));
  poly1305_init (&poly1305_state, b.block0);

  poly1305_update (&poly1305_state, ad, ad_len);
  poly1305_update (&poly1305_state, pad0, (0x10 - ad_len) & 0xf);

  dst_len = src_len - POLY1305_MAC_LEN;
  poly1305_update (&poly1305_state, src, dst_len);
  poly1305_update (&poly1305_state, pad0, (0x10 - dst_len) & 0xf);
  b.lens[0] = U64TO64_LITTLE (ad_len);
  b.lens[1] = U64TO64_LITTLE (dst_len);
  poly1305_update (&poly1305_state, (u8 *) b.lens, sizeof (b.lens));

  poly1305_finish (&poly1305_state, b.mac);

  ret = memcmp (b.mac, src + dst_len, POLY1305_MAC_LEN);
  if (!ret)
    {
      chacha20_decrypt_bytes (&chacha20_state, src, dst, dst_len);
    }
  secure_zero_memory (&chacha20_state, sizeof (chacha20_state));
  secure_zero_memory (&b, sizeof (b));

  return !ret;
}

void
xchacha20poly1305_encrypt (u8 * dst, const u8 * src, const size_t src_len,
			   const u8 * ad, const size_t ad_len,
			   const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			   const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  u32 derived_key[CHACHA20_KEY_WORDS];

  hchacha20 (derived_key, nonce, key);

  for (int i = 0; i < CHACHA20_KEY_WORDS; ++i)
    {
      derived_key[0] = U32TO32_LITTLE (derived_key[0]);
    }
  chacha20poly1305_encrypt (dst, src, src_len, ad, ad_len,
			    U8TO64_LITTLE (nonce + 16), (u8 *) derived_key);
  secure_zero_memory (derived_key, CHACHA20POLY1305_KEY_SIZE);
}

bool
xchacha20poly1305_decrypt (u8 * dst, const u8 * src, const size_t src_len,
			   const u8 * ad, const size_t ad_len,
			   const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			   const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
  bool ret;
  u32 derived_key[CHACHA20_KEY_WORDS];

  hchacha20 (derived_key, nonce, key);

  for (int i = 0; i < CHACHA20_KEY_WORDS; ++i)
    {
      derived_key[0] = U32TO32_LITTLE (derived_key[0]);
    }

  ret = chacha20poly1305_decrypt (dst, src, src_len, ad, ad_len,
				  U8TO64_LITTLE (nonce + 16),
				  (u8 *) derived_key);
  secure_zero_memory (derived_key, CHACHA20POLY1305_KEY_SIZE);
  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
