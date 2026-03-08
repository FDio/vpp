/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <native/sha2.h>

static_always_inline u32
crypto_native_ops_hash_sha2 (vnet_crypto_op_t *ops[],
			     vnet_crypto_key_data_t *key_data[] __clib_unused, u32 n_ops,
			     vnet_crypto_op_chunk_t *chunks, clib_sha2_type_t type,
			     int maybe_chained)
{
  vnet_crypto_op_t *op = ops[0];
  clib_sha2_ctx_t ctx;
  u32 n_left = n_ops;

next:
  if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
    {
      vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
      clib_sha2_init (&ctx, type);
      for (int j = 0; j < op->n_chunks; j++, chp++)
	clib_sha2_update (&ctx, chp->src, chp->len);
      clib_sha2_final (&ctx, op->digest);
    }
  else
    clib_sha2 (type, op->src, op->len, op->digest);

  op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static void
sha2_key_add (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data, clib_sha2_type_t type)
{
  clib_sha2_hmac_key_data (type, vnet_crypto_get_cypher_key (key),
			   key->cipher_key_sz + key->integ_key_sz,
			   (clib_sha2_hmac_key_data_t *) key_data);
}

static void
sha2_key_add_handler (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  if (key->alg != VNET_CRYPTO_ALG_SHA224 && key->alg != VNET_CRYPTO_ALG_SHA256)
    return;

  if (key->alg == VNET_CRYPTO_ALG_SHA224)
    sha2_key_add (key, key_data, CLIB_SHA2_224);
  else
    sha2_key_add (key, key_data, CLIB_SHA2_256);
}

VNET_CRYPTO_REG_OP_GROUP (native_sha2_group) = {
  .probe_fn = sha2_probe,
  .max_key_data_sz = sizeof (clib_sha2_hmac_key_data_t),
  .key_add_fn = sha2_key_add_handler,
};

#define _(b)                                                                                       \
  static u32 crypto_native_ops_hash_sha##b (vnet_crypto_op_t *ops[],                               \
					    vnet_crypto_key_data_t *key_data[], u32 n_ops)         \
  {                                                                                                \
    return crypto_native_ops_hash_sha2 (ops, key_data, n_ops, 0, CLIB_SHA2_##b, 0);                \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_chained_hash_sha##b (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks,                \
						    vnet_crypto_key_data_t *key_data[], u32 n_ops) \
  {                                                                                                \
    return crypto_native_ops_hash_sha2 (ops, key_data, n_ops, chunks, CLIB_SHA2_##b, 1);           \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_hmac_sha##b (vnet_crypto_op_t *ops[],                               \
					    vnet_crypto_key_data_t *key_data[], u32 n_ops)         \
  {                                                                                                \
    return crypto_native_ops_hmac_sha2 (ops, key_data, n_ops, 0, CLIB_SHA2_##b);                   \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_chained_hmac_sha##b (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks,                \
						    vnet_crypto_key_data_t *key_data[], u32 n_ops) \
  {                                                                                                \
    return crypto_native_ops_hmac_sha2 (ops, key_data, n_ops, chunks, CLIB_SHA2_##b);              \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REG_OP (crypto_native_hash_sha##b) = {                                               \
    .group = &native_sha2_group,                                                                   \
    .op_id = VNET_CRYPTO_OP_SHA##b##_HASH,                                                         \
    .fn = crypto_native_ops_hash_sha##b,                                                           \
    .cfn = crypto_native_ops_chained_hash_sha##b,                                                  \
  };                                                                                               \
  VNET_CRYPTO_REG_OP (crypto_native_hmac_sha##b) = {                                               \
    .group = &native_sha2_group,                                                                   \
    .op_id = VNET_CRYPTO_OP_SHA##b##_HMAC,                                                         \
    .fn = crypto_native_ops_hmac_sha##b,                                                           \
    .cfn = crypto_native_ops_chained_hmac_sha##b,                                                  \
  };

_ (224)
_ (256)

#undef _
