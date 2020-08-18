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

#include <string.h>
#include <wg/crypto/include/chacha20.h>

#define U32_MAX ((u32)~0U)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void
salsa20_wordtobyte (u8 output[64], const u32 input[16])
{
  u32 x[16];
  int i;

  for (i = 0; i < 16; ++i)
    x[i] = input[i];
  for (i = 20; i > 0; i -= 2)
    {
    QUARTERROUND (0, 4, 8, 12)
	QUARTERROUND (1, 5, 9, 13)
	QUARTERROUND (2, 6, 10, 14)
	QUARTERROUND (3, 7, 11, 15)
	QUARTERROUND (0, 5, 10, 15)
	QUARTERROUND (1, 6, 11, 12)
	QUARTERROUND (2, 7, 8, 13) QUARTERROUND (3, 4, 9, 14)}
  for (i = 0; i < 16; ++i)
    x[i] = PLUS (x[i], input[i]);
  for (i = 0; i < 16; ++i)
    U32TO8_LITTLE (output + 4 * i, x[i]);
}

static const char sigma[16] = "expand 32-byte k";

void
chacha20_keysetup (chacha20_ctx_t * x, const u8 * k)
{
  x->input[4] = U8TO32_LITTLE (k + 0);
  x->input[5] = U8TO32_LITTLE (k + 4);
  x->input[6] = U8TO32_LITTLE (k + 8);
  x->input[7] = U8TO32_LITTLE (k + 12);
  x->input[8] = U8TO32_LITTLE (k + 16);
  x->input[9] = U8TO32_LITTLE (k + 20);
  x->input[10] = U8TO32_LITTLE (k + 24);
  x->input[11] = U8TO32_LITTLE (k + 28);
  x->input[0] = U8TO32_LITTLE (sigma + 0);
  x->input[1] = U8TO32_LITTLE (sigma + 4);
  x->input[2] = U8TO32_LITTLE (sigma + 8);
  x->input[3] = U8TO32_LITTLE (sigma + 12);
}

void
chacha20_ivsetup (chacha20_ctx_t * x, const u64 iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = iv & U32_MAX;
  x->input[15] = iv >> 32;
}

void
chacha20_encrypt_bytes (chacha20_ctx_t * x, const u8 * m, u8 * c, u32 bytes)
{
  u8 output[64];
  int i;

  if (!bytes)
    return;
  for (;;)
    {
      salsa20_wordtobyte (output, x->input);
      x->input[12] = PLUSONE (x->input[12]);
      if (!x->input[12])
	{
	  x->input[13] = PLUSONE (x->input[13]);
	  /* stopping at 2^70 bytes per nonce is user's responsibility */
	}
      if (bytes <= 64)
	{
	  for (i = 0; i < bytes; ++i)
	    c[i] = m[i] ^ output[i];
	  return;
	}
      for (i = 0; i < 64; ++i)
	c[i] = m[i] ^ output[i];
      bytes -= 64;
      c += 64;
      m += 64;
    }
}

void
chacha20_decrypt_bytes (chacha20_ctx_t * x, const u8 * c, u8 * m, u32 bytes)
{
  chacha20_encrypt_bytes (x, c, m, bytes);
}

void
hchacha20 (u32 * out,
	   const u8 nonce[CHACHA20_NONCE_SIZE],
	   const u8 key[CHACHA20_KEY_SIZE])
{
  int i;
  u32 x[CHACHA20_NONCE_SIZE];

  x[0] = U8TO32_LITTLE (sigma + 0);
  x[1] = U8TO32_LITTLE (sigma + 4);
  x[2] = U8TO32_LITTLE (sigma + 8);
  x[3] = U8TO32_LITTLE (sigma + 12);
  x[4] = U8TO32_LITTLE (key + 0);
  x[5] = U8TO32_LITTLE (key + 4);
  x[6] = U8TO32_LITTLE (key + 8);
  x[7] = U8TO32_LITTLE (key + 12);
  x[8] = U8TO32_LITTLE (key + 16);
  x[9] = U8TO32_LITTLE (key + 20);
  x[10] = U8TO32_LITTLE (key + 24);
  x[11] = U8TO32_LITTLE (key + 28);
  x[12] = U8TO32_LITTLE (nonce + 0);
  x[13] = U8TO32_LITTLE (nonce + 4);
  x[14] = U8TO32_LITTLE (nonce + 8);
  x[15] = U8TO32_LITTLE (nonce + 12);

  for (i = 20; i > 0; i -= 2)
    {
    QUARTERROUND (0, 4, 8, 12)
	QUARTERROUND (1, 5, 9, 13)
	QUARTERROUND (2, 6, 10, 14)
	QUARTERROUND (3, 7, 11, 15)
	QUARTERROUND (0, 5, 10, 15)
	QUARTERROUND (1, 6, 11, 12)
	QUARTERROUND (2, 7, 8, 13) QUARTERROUND (3, 4, 9, 14)}

  memcpy (out + 0, x + 0, sizeof (u32) * 4);
  memcpy (out + 4, x + 12, sizeof (u32) * 4);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
