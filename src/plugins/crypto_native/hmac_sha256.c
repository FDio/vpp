/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vppinfra/sha2.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

#define N_WORDS_256 (SHA256_BLOCK_SIZE / sizeof (uword));

#if defined(__SHA__) && defined (__x86_64__)

typedef struct hmac_sha256_key_data_t_
{
  union
  {
    u32x4 h32x4[2];
  } i_key;
  union
  {
    u32x4 h32x4[2];
  } o_key;
  clib_sha2_ctx_t ctx;
} hmac_sha256_key_data_t;

/**
 * Expanded the key.
 *  Construct the inner and outer keys and perform the first round
 *  of SHA2
 */
static void *
hmac_sha256_key_exp (vnet_crypto_key_t *key)
{
  clib_sha2_ctx_t o_ctx, i_ctx;
  hmac_sha256_key_data_t * kd;
  int i, n_words;

  if (VNET_CRYPTO_KEY_TYPE_DATA != key->type)
    return 0;

  // not supporting hashing the key - get the size right!
  if (SHA256_BLOCK_SIZE < vec_len(key->data))
    return 0;

  n_words = SHA256_BLOCK_SIZE / sizeof (uword);
  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  clib_sha2_init (&i_ctx, CLIB_SHA2_256);

  for (i = 0; i < n_words; i++)
    i_ctx.pending.as_uword[i] = (((uword*)key->data)[i] ^
                                 (uword) 0x3636363636363636);
  clib_sha256_block (&i_ctx, i_ctx.pending.as_u8, 1);

  clib_sha2_init (&o_ctx, CLIB_SHA2_256);

  for (i = 0; i < n_words; i++)
    o_ctx.pending.as_uword[i] = (((uword*)key->data)[i] ^
                                 (uword) 0x5c5c5c5c5c5c5c5c);

  clib_sha256_block (&o_ctx, o_ctx.pending.as_u8, 1);

  for (i = 0; i < 2; i++)
    {
      kd->i_key.h32x4[i] = i_ctx.h32x4[i];
      kd->o_key.h32x4[0] = o_ctx.h32x4[i];
    }

  //ctx->total_bytes += ctx->block_size;
  clib_sha2_init (&kd->ctx, CLIB_SHA2_256);

  return (kd);
}

static_always_inline void
hmac_sha256 (hmac_sha256_key_data_t *kd,
             const u8 *msg,
             u8 n_bytes,
             u8 *digest)
{
  u8 i_digest[SHA256_DIGEST_SIZE];
  clib_sha2_ctx_t * ctx;

  ctx = &kd->ctx;

  /* load the i_key/i_pad from the key-data */
  ctx->h32x4[0] = kd->i_key.h32x4[0];
  ctx->h32x4[1] = kd->i_key.h32x4[1];

  ctx->n_pending = 0;
  ctx->total_bytes = SHA256_BLOCK_SIZE;

  /* hash the data */
  clib_sha2_update (ctx, msg, n_bytes);
  clib_sha2_final (ctx, i_digest);

  /* fold in the o_key/o_pad */
  ctx->h32x4[0] += kd->o_key.h32x4[0];
  ctx->h32x4[1] += kd->o_key.h32x4[1];
  ctx->total_bytes += SHA256_BLOCK_SIZE;

  /* fold in the inner digest */
  clib_sha2_update (ctx, i_digest, SHA256_BLOCK_SIZE);
  clib_sha2_final (ctx, digest);
}

static u32
hmac_sha256_ops (vlib_main_t * vm,
                 vnet_crypto_op_t * ops[],
                 u32 n_ops)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  hmac_sha256_key_data_t *kd;
  u32 n_left = n_ops;

  while (n_left)
    {
      kd = (hmac_sha256_key_data_t *) cm->key_data[op->key_index];

      hmac_sha256 (kd, op->src, op->len, op->digest);

      op++;
      n_left--;
    }
  return n_ops;
}

clib_error_t *
crypto_native_hmac_sha256_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;

  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index,        \
				    VNET_CRYPTO_OP_SHA256_HMAC, \
				    hmac_sha256_ops); \
  cm->key_fn[VNET_CRYPTO_ALG_HMAC_SHA256] = hmac_sha256_key_exp;
  return 0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
