/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <native/sha2.h>

static_always_inline u32
crypto_native_ops_hash_sha2 (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
			     clib_sha2_type_t type, int maybe_chained)
{
  clib_sha2_ctx_t ctx;
  u32 i;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
	  clib_sha2_init (&ctx, type);
	  for (int j = 0; j < op->n_chunks; j++, chp++)
	    clib_sha2_update (&ctx, chp->src, chp->len);
	  clib_sha2_final (&ctx, op->auth);
	}
      else
	clib_sha2 (type, op->src, op->len, op->auth);

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops;
}

static void
sha2_key_add (vnet_crypto_ctx_t *ctx, u8 *key_data, clib_sha2_type_t type)
{
  clib_sha2_hmac_key_data (type, vnet_crypto_get_auth_key (ctx), ctx->auth_key_sz,
			   (clib_sha2_hmac_key_data_t *) key_data);
}

static void
sha2_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;

  if (ctx->alg != VNET_CRYPTO_ALG_SHA_224 && ctx->alg != VNET_CRYPTO_ALG_SHA_256 &&
      ctx->alg != VNET_CRYPTO_ALG_SHA_256_ICV12 && ctx->alg != VNET_CRYPTO_ALG_SHA_256_ICV16)
    return;

  if (ctx->alg == VNET_CRYPTO_ALG_SHA_224)
    sha2_key_add (ctx, key_data, CLIB_SHA2_224);
  else
    sha2_key_add (ctx, key_data, CLIB_SHA2_256);
}

VNET_CRYPTO_REG_ALG_GROUP (native_sha2_group) = {
  .probe_fn = sha2_probe,
  .max_key_data_sz = sizeof (clib_sha2_hmac_key_data_t),
  .key_change_fn = sha2_key_change_handler,
};

#define _(n, b)                                                                                      \
  static u32 crypto_native_ops_hash_sha##b (                                                         \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,                \
    clib_thread_index_t thread_index __clib_unused)                                                  \
  {                                                                                                  \
    return crypto_native_ops_hash_sha2 (ops, n_ops, 0, CLIB_SHA2_##b, 0);                            \
  }                                                                                                  \
                                                                                                     \
  static u32 crypto_native_ops_chained_hash_sha##b (                                                 \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                              \
    clib_thread_index_t thread_index __clib_unused)                                                  \
  {                                                                                                  \
    return crypto_native_ops_hash_sha2 (ops, n_ops, chunks, CLIB_SHA2_##b, 1);                       \
  }                                                                                                  \
                                                                                                     \
  static u32 crypto_native_ops_hmac_sha##b (vnet_crypto_op_t *ops[],                                 \
					    vnet_crypto_op_chunk_t *chunks __clib_unused,            \
					    u32 n_ops, clib_thread_index_t thread_index)             \
  {                                                                                                  \
    return crypto_native_ops_hmac_sha2 (ops, n_ops, 0, CLIB_SHA2_##b, thread_index);                 \
  }                                                                                                  \
                                                                                                     \
  static u32 crypto_native_ops_chained_hmac_sha##b (vnet_crypto_op_t *ops[],                         \
						    vnet_crypto_op_chunk_t *chunks, u32 n_ops,       \
						    clib_thread_index_t thread_index)                \
  {                                                                                                  \
    return crypto_native_ops_hmac_sha2 (ops, n_ops, chunks, CLIB_SHA2_##b, thread_index);            \
  }                                                                                                  \
                                                                                                     \
  VNET_CRYPTO_REG_ALG (crypto_native_hash_sha##b) = {                                              \
    .group = &native_sha2_group,                                                                   \
    .alg_id = VNET_CRYPTO_ALG_##n,                                                                 \
    .simple = { .hash_fn = crypto_native_ops_hash_sha##b, },                                       \
    .chained = { .hash_fn = crypto_native_ops_chained_hash_sha##b, },                              \
  }; \
  VNET_CRYPTO_REG_ALG (crypto_native_hmac_sha##b) = {                                              \
    .group = &native_sha2_group,                                                                   \
    .alg_id = VNET_CRYPTO_ALG_##n,                                                                 \
    .simple = { .hmac_fn = crypto_native_ops_hmac_sha##b, },                                       \
    .chained = { .hmac_fn = crypto_native_ops_chained_hmac_sha##b, },                              \
  };

_ (SHA_224, 224)
_ (SHA_256, 256)

#undef _

VNET_CRYPTO_REG_ALG (crypto_native_hmac_sha256_icv12) = {
  .group = &native_sha2_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_256_ICV12,
  .simple = { .hmac_fn = crypto_native_ops_hmac_sha256, },
  .chained = { .hmac_fn = crypto_native_ops_chained_hmac_sha256, },
};

VNET_CRYPTO_REG_ALG (crypto_native_hmac_sha256_icv16) = {
  .group = &native_sha2_group,
  .alg_id = VNET_CRYPTO_ALG_SHA_256_ICV16,
  .simple = { .hmac_fn = crypto_native_ops_hmac_sha256, },
  .chained = { .hmac_fn = crypto_native_ops_chained_hmac_sha256, },
};
