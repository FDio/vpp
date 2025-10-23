/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/crypto/aes_ctr.h>
#include <native/sha2.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_aes_ctr (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		 vnet_crypto_op_chunk_t *chunks, aes_key_size_t ks,
		 int maybe_chained)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_key_data_t *kd;
  aes_ctr_ctx_t ctx;
  u32 n_left = n_ops;

next:
  {
    vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
    u32 key_index = key->is_link ? key->index_crypto : key->index;
    kd = (aes_ctr_key_data_t *) cm->key_data[key_index];

    clib_aes_ctr_init (&ctx, kd, op->iv, ks);
    if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
      {
	vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
	for (int j = 0; j < op->n_chunks; j++, chp++)
	  clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);
      }
    else
      clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void *
aes_ctr_key_exp (vnet_crypto_key_t *key, aes_key_size_t ks)
{
  aes_ctr_key_data_t *kd;

  kd = clib_mem_alloc_aligned (sizeof (*kd), CLIB_CACHE_LINE_BYTES);

  clib_aes_ctr_key_expand (kd, key->data, ks);

  return kd;
}

#define foreach_aes_ctr_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                  \
  static u32 aes_ops_aes_ctr_##x (vlib_main_t *vm, vnet_crypto_op_t *ops[],   \
				  u32 n_ops)                                  \
  {                                                                           \
    return aes_ops_aes_ctr (vm, ops, n_ops, 0, AES_KEY_##x, 0);               \
  }                                                                           \
  static u32 aes_ops_aes_ctr_##x##_chained (                                  \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return aes_ops_aes_ctr (vm, ops, n_ops, chunks, AES_KEY_##x, 1);          \
  }                                                                           \
  static void *aes_ctr_key_exp_##x (vnet_crypto_key_t *key)                   \
  {                                                                           \
    return aes_ctr_key_exp (key, AES_KEY_##x);                                \
  }

foreach_aes_ctr_handler_type;
#undef _

static int
probe ()
{
#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vaes () && clib_cpu_supports_avx512f ())
    return 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vaes ())
    return 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_avx512f ())
    return 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_avx2 ())
    return 20;
#elif __AES__
  if (clib_cpu_supports_aes ())
    return 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    return 10;
#endif
  return -1;
}

static int
aes_ctr_sha2_probe ()
{
  int r_ctr = probe ();
  int r_sha2 = sha2_probe ();
  return clib_min (r_ctr, r_sha2);
}

#define _(b)                                                                  \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_enc) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_ENC,                                \
    .fn = aes_ops_aes_ctr_##b,                                                \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                     \
    .probe = probe,                                                           \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_dec) = {                            \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_DEC,                                \
    .fn = aes_ops_aes_ctr_##b,                                                \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                     \
    .probe = probe,                                                           \
  };                                                                          \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##b##_ctr) = {                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_CTR,                                  \
    .key_fn = aes_ctr_key_exp_##b,                                            \
    .probe = probe,                                                           \
  };

_ (128)
_ (192)
_ (256)
#undef _

#define _(a, b, c)                                                            \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (                \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    aes_ops_aes_ctr (vm, ops, n_ops, 0, AES_KEY_##a, 0);                      \
    return crypto_native_ops_hmac_sha2 (vm, ops, n_ops, 0, CLIB_SHA2_##b);    \
  }                                                                           \
                                                                              \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (      \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    aes_ops_aes_ctr (vm, ops, n_ops, chunks, AES_KEY_##a, 1);                 \
    return crypto_native_ops_hmac_sha2 (vm, ops, n_ops, chunks,               \
					CLIB_SHA2_##b);                       \
  }                                                                           \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (                \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    u32 r = crypto_native_ops_hmac_sha2 (vm, ops, n_ops, 0, CLIB_SHA2_##b);   \
    if (r != n_ops)                                                           \
      return r;                                                               \
    return aes_ops_aes_ctr (vm, ops, n_ops, 0, AES_KEY_##a, 0);               \
  }                                                                           \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (      \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    u32 r =                                                                   \
      crypto_native_ops_hmac_sha2 (vm, ops, n_ops, chunks, CLIB_SHA2_##b);    \
    if (r != n_ops)                                                           \
      return r;                                                               \
    return aes_ops_aes_ctr (vm, ops, n_ops, chunks, AES_KEY_##a, 1);          \
  }                                                                           \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_ctr_hmac_sha##b##_enc) = {              \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_ENC,              \
    .fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                    \
    .cfn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,         \
    .probe = aes_ctr_sha2_probe,                                              \
  };                                                                          \
                                                                              \
  CRYPTO_NATIVE_OP_HANDLER (aes_##a##_ctr_hmac_sha##b##_dec) = {              \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_DEC,              \
    .fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                    \
    .cfn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,         \
    .probe = aes_ctr_sha2_probe,                                              \
  };

_ (128, 256, 16)
_ (192, 256, 16)
_ (256, 256, 16)

#undef _
