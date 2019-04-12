/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef included_sha2_h
#define included_sha2_h

#include <vppinfra/clib.h>

#define SHA224_DIGEST_SIZE	28
#define SHA224_BLOCK_SIZE	64

#define SHA256_DIGEST_SIZE	32
#define SHA256_BLOCK_SIZE	64
#define SHA256_ROTR(x, y)	((x >> y) | (x << (32 - y)))
#define SHA256_CH(a, b, c)	((a & b) ^ (~a & c))
#define SHA256_MAJ(a, b, c)	((a & b) ^ (a & c) ^ (b & c))
#define SHA256_CSIGMA0(x)	(SHA256_ROTR(x, 2) ^ \
				 SHA256_ROTR(x, 13) ^ \
				 SHA256_ROTR(x, 22));
#define SHA256_CSIGMA1(x)	(SHA256_ROTR(x, 6) ^ \
				 SHA256_ROTR(x, 11) ^ \
				 SHA256_ROTR(x, 25));
#define SHA256_SSIGMA0(x)	(SHA256_ROTR (x, 7) ^ \
				 SHA256_ROTR (x, 18) ^ \
				 (x >> 3))
#define SHA256_SSIGMA1(x)	(SHA256_ROTR (x, 17) ^ \
				 SHA256_ROTR (x, 19) ^ \
				 (x >> 10))

#define SHA256_MSG_SCHED(w, j) \
{					\
  w[j] = w[j - 7] + w[j - 16];		\
  w[j] += SHA256_SSIGMA0 (w[j - 15]);	\
  w[j] += SHA256_SSIGMA1 (w[j - 2]);	\
}

#define SHA256_TRANSFORM(s, w, i, k) \
{					\
  __typeof__(s[0]) t1, t2;		\
  t1 = k + w[i] + s[7];			\
  t1 += SHA256_CSIGMA1 (s[4]);		\
  t1 += SHA256_CH (s[4], s[5], s[6]);	\
  t2 = SHA256_CSIGMA0 (s[0]);		\
  t2 += SHA256_MAJ (s[0], s[1], s[2]);	\
  s[7] = s[6];				\
  s[6] = s[5];				\
  s[5] = s[4];				\
  s[4] = s[3] + t1;			\
  s[3] = s[2];				\
  s[2] = s[1];				\
  s[1] = s[0];				\
  s[0] = t1 + t2;			\
}

#define SHA512_224_DIGEST_SIZE	28
#define SHA512_224_BLOCK_SIZE	128

#define SHA512_256_DIGEST_SIZE  32
#define SHA512_256_BLOCK_SIZE	128

#define SHA384_DIGEST_SIZE	48
#define SHA384_BLOCK_SIZE	128

#define SHA512_DIGEST_SIZE	64
#define SHA512_BLOCK_SIZE	128
#define SHA512_ROTR(x, y)	((x >> y) | (x << (64 - y)))
#define SHA512_CH(a, b, c)	((a & b) ^ (~a & c))
#define SHA512_MAJ(a, b, c)	((a & b) ^ (a & c) ^ (b & c))
#define SHA512_CSIGMA0(x)	(SHA512_ROTR (x, 28) ^ \
				 SHA512_ROTR (x, 34) ^ \
				 SHA512_ROTR (x, 39))
#define SHA512_CSIGMA1(x)	(SHA512_ROTR (x, 14) ^ \
				 SHA512_ROTR (x, 18) ^ \
				 SHA512_ROTR (x, 41))
#define SHA512_SSIGMA0(x)	(SHA512_ROTR (x, 1) ^ \
				 SHA512_ROTR (x, 8) ^ \
				 (x >> 7))
#define SHA512_SSIGMA1(x)	(SHA512_ROTR (x, 19) ^ \
				 SHA512_ROTR (x, 61) ^ \
				 (x >> 6))

#define SHA512_MSG_SCHED(w, j) \
{					\
  w[j] = w[j - 7] + w[j - 16];		\
  w[j] += SHA512_SSIGMA0 (w[j - 15]);	\
  w[j] += SHA512_SSIGMA1 (w[j - 2]);	\
}

#define SHA512_TRANSFORM(s, w, i, k) \
{					\
  __typeof__(s[0]) t1, t2;		\
  t1 = k + w[i] + s[7];			\
  t1 += SHA512_CSIGMA1 (s[4]);		\
  t1 += SHA512_CH (s[4], s[5], s[6]);	\
  t2 = SHA512_CSIGMA0 (s[0]);		\
  t2 += SHA512_MAJ (s[0], s[1], s[2]);	\
  s[7] = s[6];				\
  s[6] = s[5];				\
  s[5] = s[4];				\
  s[4] = s[3] + t1;			\
  s[3] = s[2];				\
  s[2] = s[1];				\
  s[1] = s[0];				\
  s[0] = t1 + t2;			\
}

static const u32 sha224_h[8] = {
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const u32 sha256_h[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const u32 sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const u64 sha384_h[8] = {
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
  0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static const u64 sha512_h[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const u64 sha512_224_h[8] = {
  0x8c3d37c819544da2, 0x73e1996689dcd4d6,
  0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
  0x0f6d2b697bd44da8, 0x77e36f7304c48942,
  0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};

static const u64 sha512_256_h[8] = {
  0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
  0x2393b86b6f53b151, 0x963877195940eabd,
  0x96283ee2a88effe3, 0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

static const u64 sha512_k[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd,
  0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe,
  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
  0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
  0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210,
  0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926,
  0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8,
  0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910,
  0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60,
  0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9,
  0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6,
  0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493,
  0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

typedef enum
{
  CLIB_SHA2_224,
  CLIB_SHA2_256,
  CLIB_SHA2_384,
  CLIB_SHA2_512,
  CLIB_SHA2_512_224,
  CLIB_SHA2_512_256,
} clib_sha2_type_t;

#define SHA2_MAX_BLOCK_SIZE SHA512_BLOCK_SIZE
#define SHA2_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE

typedef struct
{
  u64 total_bytes;
  u16 n_pending;
  u8 block_size;
  u8 digest_size;
  union
  {
    u32 h32[8];
    u64 h64[8];
#if defined(__SHA__) && defined (__x86_64__)
    u32x4 h32x4[2];
#endif
  };
  union
  {
    u8 as_u8[SHA2_MAX_BLOCK_SIZE];
    u64 as_u64[SHA2_MAX_BLOCK_SIZE / sizeof (u64)];
    uword as_uword[SHA2_MAX_BLOCK_SIZE / sizeof (uword)];
  }
  pending;
}
clib_sha2_ctx_t;

static_always_inline void
clib_sha2_init (clib_sha2_ctx_t * ctx, clib_sha2_type_t type)
{
  const u32 *h32 = 0;
  const u64 *h64 = 0;

  ctx->total_bytes = 0;
  ctx->n_pending = 0;

  switch (type)
    {
    case CLIB_SHA2_224:
      h32 = sha224_h;
      ctx->block_size = SHA224_BLOCK_SIZE;
      ctx->digest_size = SHA224_DIGEST_SIZE;
      break;
    case CLIB_SHA2_256:
      h32 = sha256_h;
      ctx->block_size = SHA256_BLOCK_SIZE;
      ctx->digest_size = SHA256_DIGEST_SIZE;
      break;
    case CLIB_SHA2_384:
      h64 = sha384_h;
      ctx->block_size = SHA384_BLOCK_SIZE;
      ctx->digest_size = SHA384_DIGEST_SIZE;
      break;
    case CLIB_SHA2_512:
      h64 = sha512_h;
      ctx->block_size = SHA512_BLOCK_SIZE;
      ctx->digest_size = SHA512_DIGEST_SIZE;
      break;
    case CLIB_SHA2_512_224:
      h64 = sha512_224_h;
      ctx->block_size = SHA512_224_BLOCK_SIZE;
      ctx->digest_size = SHA512_224_DIGEST_SIZE;
      break;
    case CLIB_SHA2_512_256:
      h64 = sha512_256_h;
      ctx->block_size = SHA512_256_BLOCK_SIZE;
      ctx->digest_size = SHA512_256_DIGEST_SIZE;
      break;
    }
  if (h32)
    for (int i = 0; i < 8; i++)
      ctx->h32[i] = h32[i];

  if (h64)
    for (int i = 0; i < 8; i++)
      ctx->h64[i] = h64[i];
}

#if defined(__SHA__) && defined (__x86_64__)
static inline void
shani_sha256_cycle_w (u32x4 cw[], u8 a, u8 b, u8 c, u8 d)
{
  cw[a] = (u32x4) _mm_sha256msg1_epu32 ((__m128i) cw[a], (__m128i) cw[b]);
  cw[a] += (u32x4) _mm_alignr_epi8 ((__m128i) cw[d], (__m128i) cw[c], 4);
  cw[a] = (u32x4) _mm_sha256msg2_epu32 ((__m128i) cw[a], (__m128i) cw[d]);
}

static inline void
shani_sha256_4_rounds (u32x4 cw, u8 n, u32x4 s[])
{
  u32x4 r = *(u32x4 *) (sha256_k + 4 * n) + cw;
  s[0] = (u32x4) _mm_sha256rnds2_epu32 ((__m128i) s[0], (__m128i) s[1],
					(__m128i) r);
  r = (u32x4) u64x2_interleave_hi ((u64x2) r, (u64x2) r);
  s[1] = (u32x4) _mm_sha256rnds2_epu32 ((__m128i) s[1], (__m128i) s[0],
					(__m128i) r);
}

static inline void
shani_sha256_shuffle (u32x4 d[2], u32x4 s[2])
{
  /* {0, 1, 2, 3}, {4, 5, 6, 7} -> {7, 6, 3, 2}, {5, 4, 1, 0} */
  d[0] = (u32x4) _mm_shuffle_ps ((__m128) s[1], (__m128) s[0], 0xbb);
  d[1] = (u32x4) _mm_shuffle_ps ((__m128) s[1], (__m128) s[0], 0x11);
}
#endif

void
clib_sha256_block (clib_sha2_ctx_t * ctx, const u8 * msg, uword n_blocks)
{
#if defined(__SHA__) && defined (__x86_64__)
  u32x4 h[2], s[2], w[4];

  shani_sha256_shuffle (h, ctx->h32x4);

  while (n_blocks)
    {
      w[0] = u32x4_byte_swap (u32x4_load_unaligned ((u8 *) msg + 0));
      w[1] = u32x4_byte_swap (u32x4_load_unaligned ((u8 *) msg + 16));
      w[2] = u32x4_byte_swap (u32x4_load_unaligned ((u8 *) msg + 32));
      w[3] = u32x4_byte_swap (u32x4_load_unaligned ((u8 *) msg + 48));

      s[0] = h[0];
      s[1] = h[1];

      shani_sha256_4_rounds (w[0], 0, s);
      shani_sha256_4_rounds (w[1], 1, s);
      shani_sha256_4_rounds (w[2], 2, s);
      shani_sha256_4_rounds (w[3], 3, s);

      shani_sha256_cycle_w (w, 0, 1, 2, 3);
      shani_sha256_4_rounds (w[0], 4, s);
      shani_sha256_cycle_w (w, 1, 2, 3, 0);
      shani_sha256_4_rounds (w[1], 5, s);
      shani_sha256_cycle_w (w, 2, 3, 0, 1);
      shani_sha256_4_rounds (w[2], 6, s);
      shani_sha256_cycle_w (w, 3, 0, 1, 2);
      shani_sha256_4_rounds (w[3], 7, s);

      shani_sha256_cycle_w (w, 0, 1, 2, 3);
      shani_sha256_4_rounds (w[0], 8, s);
      shani_sha256_cycle_w (w, 1, 2, 3, 0);
      shani_sha256_4_rounds (w[1], 9, s);
      shani_sha256_cycle_w (w, 2, 3, 0, 1);
      shani_sha256_4_rounds (w[2], 10, s);
      shani_sha256_cycle_w (w, 3, 0, 1, 2);
      shani_sha256_4_rounds (w[3], 11, s);

      shani_sha256_cycle_w (w, 0, 1, 2, 3);
      shani_sha256_4_rounds (w[0], 12, s);
      shani_sha256_cycle_w (w, 1, 2, 3, 0);
      shani_sha256_4_rounds (w[1], 13, s);
      shani_sha256_cycle_w (w, 2, 3, 0, 1);
      shani_sha256_4_rounds (w[2], 14, s);
      shani_sha256_cycle_w (w, 3, 0, 1, 2);
      shani_sha256_4_rounds (w[3], 15, s);

      h[0] += s[0];
      h[1] += s[1];

      /* next */
      msg += SHA256_BLOCK_SIZE;
      n_blocks--;
    }

  shani_sha256_shuffle (ctx->h32x4, h);
#else
  u32 w[64], s[8], i;

  while (n_blocks)
    {
      for (i = 0; i < 8; i++)
	s[i] = ctx->h32[i];

      for (i = 0; i < 16; i++)
	{
	  w[i] = clib_net_to_host_u32 (*((u32 *) msg + i));
	  SHA256_TRANSFORM (s, w, i, sha256_k[i]);
	}

      for (i = 16; i < 64; i++)
	{
	  SHA256_MSG_SCHED (w, i);
	  SHA256_TRANSFORM (s, w, i, sha256_k[i]);
	}

      for (i = 0; i < 8; i++)
	ctx->h32[i] += s[i];

      /* next */
      msg += SHA256_BLOCK_SIZE;
      n_blocks--;
    }
#endif
}

static_always_inline void
clib_sha512_block (clib_sha2_ctx_t * ctx, const u8 * msg, uword n_blocks)
{
  u64 w[80], s[8], i;

  while (n_blocks)
    {
      for (i = 0; i < 8; i++)
	s[i] = ctx->h64[i];

      for (i = 0; i < 16; i++)
	{
	  w[i] = clib_net_to_host_u64 (*((u64 *) msg + i));
	  SHA512_TRANSFORM (s, w, i, sha512_k[i]);
	}

      for (i = 16; i < 80; i++)
	{
	  SHA512_MSG_SCHED (w, i);
	  SHA512_TRANSFORM (s, w, i, sha512_k[i]);
	}

      for (i = 0; i < 8; i++)
	ctx->h64[i] += s[i];

      /* next */
      msg += SHA512_BLOCK_SIZE;
      n_blocks--;
    }
}

static_always_inline void
clib_sha2_update (clib_sha2_ctx_t * ctx, const u8 * msg, uword n_bytes)
{
  uword n_blocks;
  if (ctx->n_pending)
    {
      uword n_left = ctx->block_size - ctx->n_pending;
      if (n_bytes < n_left)
	{
	  clib_memcpy_fast (ctx->pending.as_u8 + ctx->n_pending, msg,
			    n_bytes);
	  ctx->n_pending += n_bytes;
	  return;
	}
      else
	{
	  clib_memcpy_fast (ctx->pending.as_u8 + ctx->n_pending, msg, n_left);
	  if (ctx->block_size == SHA512_BLOCK_SIZE)
	    clib_sha512_block (ctx, ctx->pending.as_u8, 1);
	  else
	    clib_sha256_block (ctx, ctx->pending.as_u8, 1);
	  ctx->n_pending = 0;
	  ctx->total_bytes += ctx->block_size;
	  n_bytes -= n_left;
	  msg += n_left;
	}
    }

  if ((n_blocks = n_bytes / ctx->block_size))
    {
      if (ctx->block_size == SHA512_BLOCK_SIZE)
	clib_sha512_block (ctx, msg, n_blocks);
      else
	clib_sha256_block (ctx, msg, n_blocks);
      n_bytes -= n_blocks * ctx->block_size;
      msg += n_blocks * ctx->block_size;
      ctx->total_bytes += n_blocks * ctx->block_size;
    }

  if (n_bytes)
    {
      clib_memset_u8 (ctx->pending.as_u8, 0, ctx->block_size);
      clib_memcpy_fast (ctx->pending.as_u8, msg, n_bytes);
      ctx->n_pending = n_bytes;
    }
  else
    ctx->n_pending = 0;
}

static_always_inline void
clib_sha2_final (clib_sha2_ctx_t * ctx, u8 * digest)
{
  int i;

  ctx->total_bytes += ctx->n_pending;
  if (ctx->n_pending == 0)
    {
      clib_memset (ctx->pending.as_u8, 0, ctx->block_size);
      ctx->pending.as_u8[0] = 0x80;
    }
  else if (ctx->n_pending + sizeof (u64) + sizeof (u8) > ctx->block_size)
    {
      ctx->pending.as_u8[ctx->n_pending] = 0x80;
      if (ctx->block_size == SHA512_BLOCK_SIZE)
	clib_sha512_block (ctx, ctx->pending.as_u8, 1);
      else
	clib_sha256_block (ctx, ctx->pending.as_u8, 1);
      clib_memset (ctx->pending.as_u8, 0, ctx->block_size);
    }
  else
    ctx->pending.as_u8[ctx->n_pending] = 0x80;

  ctx->pending.as_u64[ctx->block_size / 8 - 1] =
    clib_net_to_host_u64 (ctx->total_bytes * 8);
  if (ctx->block_size == SHA512_BLOCK_SIZE)
    clib_sha512_block (ctx, ctx->pending.as_u8, 1);
  else
    clib_sha256_block (ctx, ctx->pending.as_u8, 1);

  if (ctx->block_size == SHA512_BLOCK_SIZE)
    {
      for (i = 0; i < ctx->digest_size / sizeof (u64); i++)
	*((u64 *) digest + i) = clib_net_to_host_u64 (ctx->h64[i]);

      /* sha512-224 case - write half of u64 */
      if (i * sizeof (u64) < ctx->digest_size)
	*((u32 *) digest + 2 * i) = clib_net_to_host_u32 (ctx->h64[i] >> 32);
    }
  else
    for (i = 0; i < ctx->digest_size / sizeof (u32); i++)
      *((u32 *) digest + i) = clib_net_to_host_u32 (ctx->h32[i]);
}

static_always_inline void
clib_sha2 (clib_sha2_type_t type, const u8 * msg, uword len, u8 * digest)
{
  clib_sha2_ctx_t ctx;
  clib_sha2_init (&ctx, type);
  clib_sha2_update (&ctx, msg, len);
  clib_sha2_final (&ctx, digest);
}

#define clib_sha224(...) clib_sha2 (CLIB_SHA2_224, __VA_ARGS__)
#define clib_sha256(...) clib_sha2 (CLIB_SHA2_256, __VA_ARGS__)
#define clib_sha384(...) clib_sha2 (CLIB_SHA2_384, __VA_ARGS__)
#define clib_sha512(...) clib_sha2 (CLIB_SHA2_512, __VA_ARGS__)
#define clib_sha512_224(...) clib_sha2 (CLIB_SHA2_512_224, __VA_ARGS__)
#define clib_sha512_256(...) clib_sha2 (CLIB_SHA2_512_256, __VA_ARGS__)

static_always_inline void
clib_hmac_sha2 (clib_sha2_type_t type, const u8 * key, uword key_len,
		const u8 * msg, uword len, u8 * digest)
{
  clib_sha2_ctx_t _ctx, *ctx = &_ctx;
  uword key_data[SHA2_MAX_BLOCK_SIZE / sizeof (uword)];
  u8 i_digest[SHA2_MAX_DIGEST_SIZE];
  int i, n_words;

  clib_sha2_init (ctx, type);
  n_words = ctx->block_size / sizeof (uword);

  /* key */
  if (key_len > ctx->block_size)
    {
      /* key is longer than block, calculate hash of key */
      clib_sha2_update (ctx, key, key_len);
      for (i = (ctx->digest_size / sizeof (uword)) / 2; i < n_words; i++)
	key_data[i] = 0;
      clib_sha2_final (ctx, (u8 *) key_data);
      clib_sha2_init (ctx, type);
    }
  else
    {
      for (i = 0; i < n_words; i++)
	key_data[i] = 0;
      clib_memcpy_fast (key_data, key, key_len);
    }

  /* ipad */
  for (i = 0; i < n_words; i++)
    ctx->pending.as_uword[i] = key_data[i] ^ (uword) 0x3636363636363636;
  if (ctx->block_size == SHA512_BLOCK_SIZE)
    clib_sha512_block (ctx, ctx->pending.as_u8, 1);
  else
    clib_sha256_block (ctx, ctx->pending.as_u8, 1);
  ctx->total_bytes += ctx->block_size;

  /* message */
  clib_sha2_update (ctx, msg, len);
  clib_sha2_final (ctx, i_digest);

  /* opad */
  clib_sha2_init (ctx, type);
  for (i = 0; i < n_words; i++)
    ctx->pending.as_uword[i] = key_data[i] ^ (uword) 0x5c5c5c5c5c5c5c5c;
  if (ctx->block_size == SHA512_BLOCK_SIZE)
    clib_sha512_block (ctx, ctx->pending.as_u8, 1);
  else
    clib_sha256_block (ctx, ctx->pending.as_u8, 1);
  ctx->total_bytes += ctx->block_size;

  /* digest */
  clib_sha2_update (ctx, i_digest, ctx->digest_size);
  clib_sha2_final (ctx, digest);
}

#define clib_hmac_sha224(...) clib_hmac_sha2 (CLIB_SHA2_224, __VA_ARGS__)
#define clib_hmac_sha256(...) clib_hmac_sha2 (CLIB_SHA2_256, __VA_ARGS__)
#define clib_hmac_sha384(...) clib_hmac_sha2 (CLIB_SHA2_384, __VA_ARGS__)
#define clib_hmac_sha512(...) clib_hmac_sha2 (CLIB_SHA2_512, __VA_ARGS__)
#define clib_hmac_sha512_224(...) clib_hmac_sha2 (CLIB_SHA2_512_224, __VA_ARGS__)
#define clib_hmac_sha512_256(...) clib_hmac_sha2 (CLIB_SHA2_512_256, __VA_ARGS__)

#endif /* included_sha2_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
