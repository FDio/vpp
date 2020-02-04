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
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>
#include <vppinfra/sha2.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

#define foreach_hmac_sha2_type \
  _(224) _(256) _(384) _(512)

static_always_inline void
copy_and_xor (u8 * src, u8 * dst, u8 c, int len)
{
  for (int i = 0; i < len; i++)
    dst[i] = src[i] ^ c;
}

static_always_inline void *
crypto_native_key_exp_hmac_sha2_inline (vnet_crypto_key_t * key,
					clib_sha2_type_t type)
{
  clib_sha2_ctx_t _ctx, *ctx = &_ctx;
  u8 *kd;
  u8 key_data[SHA2_MAX_BLOCK_SIZE];
  u8 buffer[SHA2_MAX_BLOCK_SIZE];

  /* we pre-calculate 1st round of SHA-2 HMAC calculation for both ipad and
     opad and we store state of H[0..7] into key data */

  clib_sha2_init (ctx, type);

  /* key */
  if (vec_len (key->data) > ctx->block_size)
    {
      /* key is longer than block, calculate hash of key */
      clib_sha2_update (ctx, key->data, vec_len (key->data));
      clib_memset_u8 (key_data + ctx->digest_size, 0,
		      ctx->block_size - ctx->digest_size);
      clib_sha2_final (ctx, key_data);
      clib_sha2_init (ctx, type);
    }
  else
    {
      clib_memset_u8 (key_data, 0, ctx->block_size);
      clib_memcpy_fast (key_data, key->data, vec_len (key->data));
    }

  kd = clib_mem_alloc_aligned (ctx->block_size, CLIB_CACHE_LINE_BYTES);

  /* ipad */
  copy_and_xor (key_data, buffer, 0x36, ctx->block_size);
  clib_sha2_block (ctx, buffer, 1);
  clib_memcpy_fast (kd, ctx->h, ctx->block_size / 2);

  /* opad */
  clib_sha2_init (ctx, type);
  copy_and_xor (key_data, buffer, 0x5c, ctx->block_size);
  clib_sha2_block (ctx, buffer, 1);
  clib_memcpy_fast (kd + ctx->block_size / 2, ctx->h, ctx->block_size / 2);

  return kd;
}

#define _(a) \
static void * \
crypto_native_key_exp_hmac_sha ##a (vnet_crypto_key_t * key) \
{ return crypto_native_key_exp_hmac_sha2_inline (key, CLIB_SHA2_ ##a); }

foreach_hmac_sha2_type;
#undef _

static_always_inline u32
crypto_native_ops_hmac_sha2_inline (vlib_main_t * vm,
				    vnet_crypto_op_t * ops[], u32 n_ops,
				    clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  u8 *kd;
  clib_sha2_ctx_t _ctx, *ctx = &_ctx;
  u8 buffer[SHA2_MAX_BLOCK_SIZE];
  u32 i, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      kd = (u8 *) cm->key_data[op->key_index];

      clib_sha2_init (ctx, type);

      /* ipad */
      clib_memcpy_fast (ctx->h, kd, ctx->block_size / 2);
      ctx->total_bytes += ctx->block_size;

      /* message */
      clib_sha2_update (ctx, op->src, op->len);
      clib_sha2_final (ctx, buffer);

      /* opad */
      kd += ctx->block_size / 2;
      clib_sha2_init (ctx, type);
      clib_memcpy_fast (ctx->h, kd, ctx->block_size / 2);
      ctx->total_bytes += ctx->block_size;

      /* digest */
      clib_sha2_update (ctx, buffer, ctx->digest_size);
      clib_sha2_final (ctx, buffer);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->digest, buffer, ctx->digest_size)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->digest, buffer, ctx->digest_size);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

#define _(a) \
static_always_inline u32 \
crypto_native_ops_hmac_sha ##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return crypto_native_ops_hmac_sha2_inline (vm, ops, n_ops, CLIB_SHA2_ ##a); }

foreach_hmac_sha2_type;
#undef _

clib_error_t *
crypto_native_sha2_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;

#define _(a) \
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index, \
				    VNET_CRYPTO_OP_SHA ##a## _HMAC, \
                                    crypto_native_ops_hmac_sha ##a); \
  cm->key_fn[VNET_CRYPTO_ALG_HMAC_SHA##a] = crypto_native_key_exp_hmac_sha ##a;
  foreach_hmac_sha2_type;
#undef _
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
