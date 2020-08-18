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
  * More information can be found at https://cr.yp.to/mac.html
  */

#include <wg/crypto/include/poly1305.h>
#include <wg/crypto/include/ecrypt-portable.h>

void
poly1305_init (poly1305_ctx_t * st, const unsigned char key[32])
{
  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  st->r[0] = (U8TO32_LITTLE (&key[0])) & 0x3ffffff;
  st->r[1] = (U8TO32_LITTLE (&key[3]) >> 2) & 0x3ffff03;
  st->r[2] = (U8TO32_LITTLE (&key[6]) >> 4) & 0x3ffc0ff;
  st->r[3] = (U8TO32_LITTLE (&key[9]) >> 6) & 0x3f03fff;
  st->r[4] = (U8TO32_LITTLE (&key[12]) >> 8) & 0x00fffff;

  /* h = 0 */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;
  st->h[3] = 0;
  st->h[4] = 0;

  /* save pad for later */
  st->pad[0] = U8TO32_LITTLE (&key[16]);
  st->pad[1] = U8TO32_LITTLE (&key[20]);
  st->pad[2] = U8TO32_LITTLE (&key[24]);
  st->pad[3] = U8TO32_LITTLE (&key[28]);

  st->leftover = 0;
  st->final = 0;
}

static void
poly1305_blocks (poly1305_ctx_t * st, const unsigned char *m, size_t bytes)
{
  const uint32_t hibit = (st->final) ? 0 : (1 << 24);	/* 1 << 128 */
  uint32_t r0, r1, r2, r3, r4;
  uint32_t s1, s2, s3, s4;
  uint32_t h0, h1, h2, h3, h4;
  uint64_t d0, d1, d2, d3, d4;
  uint32_t c;

  r0 = st->r[0];
  r1 = st->r[1];
  r2 = st->r[2];
  r3 = st->r[3];
  r4 = st->r[4];

  s1 = r1 * 5;
  s2 = r2 * 5;
  s3 = r3 * 5;
  s4 = r4 * 5;

  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];
  h3 = st->h[3];
  h4 = st->h[4];

  while (bytes >= POLY1305_BLOCK_SIZE)
    {
      /* h += m[i] */
      h0 += (U8TO32_LITTLE (m + 0)) & 0x3ffffff;
      h1 += (U8TO32_LITTLE (m + 3) >> 2) & 0x3ffffff;
      h2 += (U8TO32_LITTLE (m + 6) >> 4) & 0x3ffffff;
      h3 += (U8TO32_LITTLE (m + 9) >> 6) & 0x3ffffff;
      h4 += (U8TO32_LITTLE (m + 12) >> 8) | hibit;

      /* h *= r */
      d0 =
	((uint64_t) h0 * r0) + ((uint64_t) h1 * s4) + ((uint64_t) h2 * s3) +
	((uint64_t) h3 * s2) + ((uint64_t) h4 * s1);
      d1 =
	((uint64_t) h0 * r1) + ((uint64_t) h1 * r0) + ((uint64_t) h2 * s4) +
	((uint64_t) h3 * s3) + ((uint64_t) h4 * s2);
      d2 =
	((uint64_t) h0 * r2) + ((uint64_t) h1 * r1) + ((uint64_t) h2 * r0) +
	((uint64_t) h3 * s4) + ((uint64_t) h4 * s3);
      d3 =
	((uint64_t) h0 * r3) + ((uint64_t) h1 * r2) + ((uint64_t) h2 * r1) +
	((uint64_t) h3 * r0) + ((uint64_t) h4 * s4);
      d4 =
	((uint64_t) h0 * r4) + ((uint64_t) h1 * r3) + ((uint64_t) h2 * r2) +
	((uint64_t) h3 * r1) + ((uint64_t) h4 * r0);

      /* (partial) h %= p */
      c = (uint32_t) (d0 >> 26);
      h0 = (uint32_t) d0 & 0x3ffffff;
      d1 += c;
      c = (uint32_t) (d1 >> 26);
      h1 = (uint32_t) d1 & 0x3ffffff;
      d2 += c;
      c = (uint32_t) (d2 >> 26);
      h2 = (uint32_t) d2 & 0x3ffffff;
      d3 += c;
      c = (uint32_t) (d3 >> 26);
      h3 = (uint32_t) d3 & 0x3ffffff;
      d4 += c;
      c = (uint32_t) (d4 >> 26);
      h4 = (uint32_t) d4 & 0x3ffffff;
      h0 += c * 5;
      c = (h0 >> 26);
      h0 = h0 & 0x3ffffff;
      h1 += c;

      m += POLY1305_BLOCK_SIZE;
      bytes -= POLY1305_BLOCK_SIZE;
    }

  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
  st->h[3] = h3;
  st->h[4] = h4;
}

void
poly1305_finish (poly1305_ctx_t * st, unsigned char mac[16])
{
  uint32_t h0, h1, h2, h3, h4, c;
  uint32_t g0, g1, g2, g3, g4;
  uint64_t f;
  uint32_t mask;

  /* process the remaining block */
  if (st->leftover)
    {
      size_t i = st->leftover;
      st->buffer[i++] = 1;
      for (; i < POLY1305_BLOCK_SIZE; i++)
	st->buffer[i] = 0;
      st->final = 1;
      poly1305_blocks (st, st->buffer, POLY1305_BLOCK_SIZE);
    }

  /* fully carry h */
  h0 = st->h[0];
  h1 = st->h[1];
  h2 = st->h[2];
  h3 = st->h[3];
  h4 = st->h[4];

  c = h1 >> 26;
  h1 = h1 & 0x3ffffff;
  h2 += c;
  c = h2 >> 26;
  h2 = h2 & 0x3ffffff;
  h3 += c;
  c = h3 >> 26;
  h3 = h3 & 0x3ffffff;
  h4 += c;
  c = h4 >> 26;
  h4 = h4 & 0x3ffffff;
  h0 += c * 5;
  c = h0 >> 26;
  h0 = h0 & 0x3ffffff;
  h1 += c;

  /* compute h + -p */
  g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;
  g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;
  g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  g4 = h4 + c - (1 << 26);

  /* select h if h < p, or h + -p if h >= p */
  mask = (g4 >> ((sizeof (uint32_t) * 8) - 1)) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* h = h % (2^128) */
  h0 = ((h0) | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

  /* mac = (h + pad) % (2^128) */
  f = (uint64_t) h0 + st->pad[0];
  h0 = (uint32_t) f;
  f = (uint64_t) h1 + st->pad[1] + (f >> 32);
  h1 = (uint32_t) f;
  f = (uint64_t) h2 + st->pad[2] + (f >> 32);
  h2 = (uint32_t) f;
  f = (uint64_t) h3 + st->pad[3] + (f >> 32);
  h3 = (uint32_t) f;

  U32TO8_LITTLE (mac + 0, h0);
  U32TO8_LITTLE (mac + 4, h1);
  U32TO8_LITTLE (mac + 8, h2);
  U32TO8_LITTLE (mac + 12, h3);

  /* zero out the state */
  st->h[0] = 0;
  st->h[1] = 0;
  st->h[2] = 0;
  st->h[3] = 0;
  st->h[4] = 0;
  st->r[0] = 0;
  st->r[1] = 0;
  st->r[2] = 0;
  st->r[3] = 0;
  st->r[4] = 0;
  st->pad[0] = 0;
  st->pad[1] = 0;
  st->pad[2] = 0;
  st->pad[3] = 0;
}


void
poly1305_update (poly1305_ctx_t * st, const unsigned char *m, size_t bytes)
{
  size_t i;

  /* handle leftover */
  if (st->leftover)
    {
      size_t want = (POLY1305_BLOCK_SIZE - st->leftover);
      if (want > bytes)
	want = bytes;
      for (i = 0; i < want; i++)
	st->buffer[st->leftover + i] = m[i];
      bytes -= want;
      m += want;
      st->leftover += want;
      if (st->leftover < POLY1305_BLOCK_SIZE)
	return;
      poly1305_blocks (st, st->buffer, POLY1305_BLOCK_SIZE);
      st->leftover = 0;
    }

  /* process full blocks */
  if (bytes >= POLY1305_BLOCK_SIZE)
    {
      size_t want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
      poly1305_blocks (st, m, want);
      m += want;
      bytes -= want;
    }

  /* store leftover */
  if (bytes)
    {
      memcpy (st->buffer + st->leftover, m, bytes);
      st->leftover += bytes;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
