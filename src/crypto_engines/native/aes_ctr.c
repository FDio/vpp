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

typedef struct
{
  aes_ctr_key_data_t crypto_key;
  clib_sha2_hmac_key_data_t integ_key;
} aes_ctr_hmac_key_data_t;

static_always_inline u32
aes_ops_enc_aes_ctr_hmac (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			  aes_key_size_t ks, clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];

next:
  {
    kd = (aes_ctr_hmac_key_data_t *) key_data[0];

    clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);
    clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, op->digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      key_data += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  vnet_crypto_key_data_t *key_data[], u32 n_ops, aes_key_size_t ks,
				  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];

next:
  {
    kd = (aes_ctr_hmac_key_data_t *) key_data[0];

    clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);

    vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
    for (int j = 0; j < op->n_chunks; j++, chp++)
      clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

    chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, op->digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      key_data += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops,
			  aes_key_size_t ks, clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];

next:
  {
    kd = (aes_ctr_hmac_key_data_t *) key_data[0];

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, op->digest_len)))
      {
	n_fail++;
	op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    else
      {
	clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);
	clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      }
  }
  if (--n_left)
    {
      op += 1;
      key_data += 1;
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  vnet_crypto_key_data_t *key_data[], u32 n_ops, aes_key_size_t ks,
				  clib_sha2_type_t type)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];

next:
  {
    kd = (aes_ctr_hmac_key_data_t *) key_data[0];

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

    vnet_crypto_op_chunk_t *chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, op->digest_len)))
      {
	n_fail++;
	op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    else
      {
	clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);

	vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
	for (int j = 0; j < op->n_chunks; j++, chp++)
	  clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      }
  }
  if (--n_left)
    {
      op += 1;
      key_data += 1;
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_aes_ctr (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
		 vnet_crypto_key_data_t *key_data[], aes_key_size_t ks,
		 int maybe_chained __clib_unused)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  u32 n_left = n_ops;

next:
  kd = (aes_ctr_key_data_t *) key_data[0];

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

  if (--n_left)
    {
      op += 1;
      key_data += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void
aes_ctr_key_exp (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data, aes_key_size_t ks)
{
  clib_aes_ctr_key_expand ((aes_ctr_key_data_t *) key_data, key->data, ks);
}

#define foreach_aes_ctr_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                                       \
  static u32 aes_ops_aes_ctr_##x (vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[],     \
				  u32 n_ops)                                                       \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, 0, key_data, AES_KEY_##x, 0);                              \
  }                                                                                                \
  static u32 aes_ops_aes_ctr_##x##_chained (vnet_crypto_op_t *ops[],                               \
					    vnet_crypto_op_chunk_t *chunks,                        \
					    vnet_crypto_key_data_t *key_data[], u32 n_ops)         \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, chunks, key_data, AES_KEY_##x, 1);                         \
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

static_always_inline aes_key_size_t
aes_ctr_key_size_from_alg (vnet_crypto_alg_t alg)
{
  switch (alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CTR:
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_128_CTR_SHA512_TAG32:
      return AES_KEY_128;
    case VNET_CRYPTO_ALG_AES_192_CTR:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_192_CTR_SHA512_TAG32:
      return AES_KEY_192;
    case VNET_CRYPTO_ALG_AES_256_CTR:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_256_CTR_SHA512_TAG32:
      return AES_KEY_256;
    default:
      return 0;
    }
}

static void
aes_ctr_key_add_handler (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  aes_key_size_t ks;

  ks = aes_ctr_key_size_from_alg (key->alg);
  if (ks == 0)
    return;

  aes_ctr_key_exp (key, key_data, ks);
}

static void
aes_ctr_sha2_key_add_handler (vnet_crypto_key_t *key, vnet_crypto_key_data_t *key_data)
{
  aes_key_size_t ks;
  aes_ctr_hmac_key_data_t *kd = (aes_ctr_hmac_key_data_t *) key_data;
  u16 crypto_len;
  u16 integ_len;

  if (key->alg != VNET_CRYPTO_ALG_AES_128_CTR_SHA256_TAG16 &&
      key->alg != VNET_CRYPTO_ALG_AES_192_CTR_SHA256_TAG16 &&
      key->alg != VNET_CRYPTO_ALG_AES_256_CTR_SHA256_TAG16)
    return;

  ks = aes_ctr_key_size_from_alg (key->alg);
  if (ks == AES_KEY_128)
    crypto_len = 16;
  else if (ks == AES_KEY_192)
    crypto_len = 24;
  else
    crypto_len = 32;

  if (key->length < crypto_len)
    return;

  integ_len = key->length - crypto_len;
  aes_ctr_key_exp (key, (vnet_crypto_key_data_t *) &kd->crypto_key, ks);
  clib_sha2_hmac_key_data (CLIB_SHA2_256, key->data + crypto_len, integ_len, &kd->integ_key);
}

VNET_CRYPTO_REG_OP_GROUP (native_ctr_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_expaned_key_t) * (AES_KEY_ROUNDS (AES_KEY_256) + 1),
  .key_add_fn = aes_ctr_key_add_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_add_fn = aes_ctr_sha2_key_add_handler,
};

#define _(b)                                                                                       \
  VNET_CRYPTO_REG_OP (aes_##b##_ctr_enc) = {                                                       \
    .group = &native_ctr_group,                                                                    \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_ENC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##b##_ctr_dec) = {                                                       \
    .group = &native_ctr_group,                                                                    \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_DEC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
  };

_ (128)
_ (192)
_ (256)
#undef _

#define _(a, b, c)                                                                                 \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (                                     \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac (ops, key_data, n_ops, AES_KEY_##a, CLIB_SHA2_##b);            \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, chunks, key_data, n_ops, AES_KEY_##a,            \
					     CLIB_SHA2_##b);                                       \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (                                     \
    vnet_crypto_op_t *ops[], vnet_crypto_key_data_t *key_data[], u32 n_ops)                        \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac (ops, key_data, n_ops, AES_KEY_##a, CLIB_SHA2_##b);            \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, vnet_crypto_key_data_t *key_data[],   \
    u32 n_ops)                                                                                     \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, chunks, key_data, n_ops, AES_KEY_##a,            \
					     CLIB_SHA2_##b);                                       \
  }                                                                                                \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_enc) = {                                         \
    .group = &native_ctr_sha2_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_ENC,                                   \
    .fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_dec) = {                                         \
    .group = &native_ctr_sha2_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_DEC,                                   \
    .fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };

_ (128, 256, 16)
_ (192, 256, 16)
_ (256, 256, 16)

#undef _
