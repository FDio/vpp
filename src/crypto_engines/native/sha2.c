/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <native/sha2.h>

static_always_inline u32
crypto_native_ops_hash_sha2 (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
			     clib_sha2_type_t type, int maybe_chained)
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
sha2_key_exp (vnet_crypto_key_op_t kop, clib_sha2_hmac_key_data_t *key_data, const u8 *data,
	      u16 length, clib_sha2_type_t type)
{
  if (kop == VNET_CRYPTO_KEY_OP_ADD || kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      clib_sha2_hmac_key_data (type, data, length, key_data);
    }
}

#define _(b)                                                                                       \
  static u32 crypto_native_ops_hash_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)                    \
  {                                                                                                \
    return crypto_native_ops_hash_sha2 (ops, n_ops, 0, CLIB_SHA2_##b, 0);                          \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_chained_hash_sha##b (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks, u32 n_ops)     \
  {                                                                                                \
    return crypto_native_ops_hash_sha2 (ops, n_ops, chunks, CLIB_SHA2_##b, 1);                     \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops)                    \
  {                                                                                                \
    return crypto_native_ops_hmac_sha2 (ops, n_ops, 0, CLIB_SHA2_##b);                             \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_chained_hmac_sha##b (vnet_crypto_op_t *ops[],                       \
						    vnet_crypto_op_chunk_t *chunks, u32 n_ops)     \
  {                                                                                                \
    return crypto_native_ops_hmac_sha2 (ops, n_ops, chunks, CLIB_SHA2_##b);                        \
  }                                                                                                \
                                                                                                   \
  static void sha2_key_exp_##b (vnet_crypto_key_op_t kop, vnet_crypto_key_handler_args_t arg)      \
  {                                                                                                \
    sha2_key_exp (kop, arg.per_thread_key_data, arg.key, arg.key_length, CLIB_SHA2_##b);           \
  }                                                                                                \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (crypto_native_hash_sha##b) = {                                         \
    .op_id = VNET_CRYPTO_OP_SHA##b##_HASH,                                                         \
    .fn = crypto_native_ops_hash_sha##b,                                                           \
    .cfn = crypto_native_ops_chained_hash_sha##b,                                                  \
    .probe = sha2_probe,                                                                           \
  };                                                                                               \
  CRYPTO_NATIVE_OP_HANDLER (crypto_native_hmac_sha##b) = {                                         \
    .op_id = VNET_CRYPTO_OP_SHA##b##_HMAC,                                                         \
    .fn = crypto_native_ops_hmac_sha##b,                                                           \
    .cfn = crypto_native_ops_chained_hmac_sha##b,                                                  \
    .probe = sha2_probe,                                                                           \
  };                                                                                               \
  CRYPTO_NATIVE_KEY_HANDLER (crypto_native_hmac_sha##b) = {                                        \
    .alg_id = VNET_CRYPTO_ALG_HMAC_SHA##b,                                                         \
    .key_fn = sha2_key_exp_##b,                                                                    \
    .probe = sha2_probe,                                                                           \
    .key_data_sz = sizeof (clib_sha2_hmac_key_data_t),                                             \
  };

_ (224)
_ (256)

#undef _
