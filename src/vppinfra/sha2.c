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

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/sha2.h>
#include <vppinfra/format.h>

typedef struct
{
  union
  {
    u32 h32[8];
    u64 h64[8];
  };
  u8 pending_bytes[SHA512_BLOCK_SIZE];
  u64 total_bytes, n_pending_bytes;
} clib_sha2_ctx_t;

static_always_inline void
clib_sha2_init (clib_sha2_ctx_t * ctx, u8 digest_sz)
{
  if (digest_sz == SHA224_DIGEST_SIZE)
    for (int i = 0; i < 8; i++)
      ctx->h32[i] = sha224_h[i];
  else if (digest_sz == SHA256_DIGEST_SIZE)
    for (int i = 0; i < 8; i++)
      ctx->h32[i] = sha256_h[i];
  else if (digest_sz == SHA384_DIGEST_SIZE)
    for (int i = 0; i < 8; i++)
      ctx->h64[i] = sha384_h[i];
  else if (digest_sz == SHA512_DIGEST_SIZE)
    for (int i = 0; i < 8; i++)
      ctx->h64[i] = sha512_h[i];
  ctx->total_bytes = ctx->n_pending_bytes = 0;
}

static_always_inline void
clib_sha256_block (clib_sha2_ctx_t * ctx, const u8 * data)
{
  u32 w[64], s[8], i;

  for (i = 0; i < 8; i++)
    s[i] = ctx->h32[i];

  for (i = 0; i < 16; i++)
    {
      w[i] = clib_net_to_host_u32 (*((u32 *) data + i));
      SHA256_TRANSFORM (s, w, i, sha256_k[i]);
    }

  for (i = 16; i < 64; i++)
    {
      SHA256_MSG_SCHED (w, i);
      SHA256_TRANSFORM (s, w, i, sha256_k[i]);
    }

  for (i = 0; i < 8; i++)
    ctx->h32[i] += s[i];

  ctx->total_bytes += SHA256_BLOCK_SIZE;
}

static_always_inline void
clib_sha512_block (clib_sha2_ctx_t * ctx, const u8 * data)
{
  u64 w[80], s[8], i;

  for (i = 0; i < 8; i++)
    s[i] = ctx->h64[i];

  for (i = 0; i < 16; i++)
    {
      w[i] = clib_net_to_host_u64 (*((u64 *) data + i));
      SHA512_TRANSFORM (s, w, i, sha512_k[i]);
    }

  for (i = 16; i < 80; i++)
    {
      SHA512_MSG_SCHED (w, i);
      SHA512_TRANSFORM (s, w, i, sha512_k[i]);
    }

  for (i = 0; i < 8; i++)
    ctx->h64[i] += s[i];

  ctx->total_bytes += SHA512_BLOCK_SIZE;
}

static_always_inline void
clib_sha2_update (clib_sha2_ctx_t * ctx, const u8 * data, u64 n_bytes,
		  u8 block_sz)
{
  while (n_bytes >= block_sz)
    {
      if (block_sz == SHA512_BLOCK_SIZE)
	clib_sha512_block (ctx, data);
      else
	clib_sha256_block (ctx, data);
      data += block_sz;
      n_bytes -= block_sz;
    }

  if (n_bytes)
    {
      clib_memset_u8 (ctx->pending_bytes, 0, block_sz);
      clib_memcpy_fast (ctx->pending_bytes, data, n_bytes);
      ctx->n_pending_bytes = n_bytes;
    }
  else
    ctx->n_pending_bytes = 0;
}

static_always_inline void
clib_sha2_final (clib_sha2_ctx_t * ctx, u8 * hash, u8 block_sz, u8 digest_sz)
{
  u64 *total_bits = (u64 *) (ctx->pending_bytes + block_sz - sizeof (u64));
  int i;

  ctx->total_bytes += ctx->n_pending_bytes;
  if (ctx->n_pending_bytes == 0)
    {
      clib_memset (ctx->pending_bytes, 0, block_sz);
      ctx->pending_bytes[0] = 0x80;
    }
  else if (ctx->n_pending_bytes + sizeof (u64) + sizeof (u8) > block_sz)
    {
      ctx->pending_bytes[ctx->n_pending_bytes] = 0x80;
      if (block_sz == SHA512_BLOCK_SIZE)
	clib_sha512_block (ctx, ctx->pending_bytes);
      else
	clib_sha256_block (ctx, ctx->pending_bytes);
      ctx->total_bytes -= block_sz;
      clib_memset (ctx->pending_bytes, 0, block_sz);
    }
  else
    ctx->pending_bytes[ctx->n_pending_bytes] = 0x80;

  total_bits[0] = clib_net_to_host_u64 (ctx->total_bytes * 8);
  if (block_sz == SHA512_BLOCK_SIZE)
    clib_sha512_block (ctx, ctx->pending_bytes);
  else
    clib_sha256_block (ctx, ctx->pending_bytes);

  if (block_sz == SHA512_BLOCK_SIZE)
    for (i = 0; i < digest_sz / 8; i++)
      *((u64 *) hash + i) = clib_net_to_host_u64 (ctx->h64[i]);
  else
    for (i = 0; i < digest_sz / 4; i++)
      *((u32 *) hash + i) = clib_net_to_host_u32 (ctx->h32[i]);
}

void
clib_sha224 (const u8 * in, u64 len, u8 * out)
{
  clib_sha2_ctx_t ctx;
  clib_sha2_init (&ctx, SHA224_DIGEST_SIZE);
  clib_sha2_update (&ctx, in, len, SHA224_BLOCK_SIZE);
  clib_sha2_final (&ctx, out, SHA224_BLOCK_SIZE, SHA224_DIGEST_SIZE);
}

void
clib_sha256 (const u8 * in, u64 len, u8 * out)
{
  clib_sha2_ctx_t ctx;
  clib_sha2_init (&ctx, SHA256_DIGEST_SIZE);
  clib_sha2_update (&ctx, in, len, SHA256_BLOCK_SIZE);
  clib_sha2_final (&ctx, out, SHA256_BLOCK_SIZE, SHA256_DIGEST_SIZE);
}

void
clib_sha384 (const u8 * in, u64 len, u8 * out)
{
  clib_sha2_ctx_t ctx;
  clib_sha2_init (&ctx, SHA384_DIGEST_SIZE);
  clib_sha2_update (&ctx, in, len, SHA384_BLOCK_SIZE);
  clib_sha2_final (&ctx, out, SHA384_BLOCK_SIZE, SHA384_DIGEST_SIZE);
}

void
clib_sha512 (const u8 * in, u64 len, u8 * out)
{
  clib_sha2_ctx_t ctx;
  clib_sha2_init (&ctx, SHA512_DIGEST_SIZE);
  clib_sha2_update (&ctx, in, len, SHA512_BLOCK_SIZE);
  clib_sha2_final (&ctx, out, SHA512_BLOCK_SIZE, SHA512_DIGEST_SIZE);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
