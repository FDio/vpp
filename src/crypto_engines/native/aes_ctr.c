/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024-2026 Cisco Systems, Inc.
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

static_always_inline aes_ctr_key_data_t *
aes_ctr_get_key_data (vnet_crypto_op_t *op, clib_thread_index_t thread_index)
{
  return (aes_ctr_key_data_t *) vnet_crypto_get_simple_key_data (op->key);
}

static_always_inline aes_ctr_hmac_key_data_t *
aes_ctr_hmac_get_key_data (vnet_crypto_op_t *op, clib_thread_index_t thread_index)
{
  return (aes_ctr_hmac_key_data_t *) vnet_crypto_get_simple_key_data (op->key);
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, clib_thread_index_t thread_index)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];

next:
  {
    u32 digest_len = vnet_crypto_get_op_data (op->op)->digest_len;

    if (digest_len == 0)
      digest_len = op->digest_len;

    kd = aes_ctr_hmac_get_key_data (op, thread_index);

    clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);
    clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, aes_key_size_t ks, clib_sha2_type_t type,
				  clib_thread_index_t thread_index)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];

next:
  {
    u32 digest_len = vnet_crypto_get_op_data (op->op)->digest_len;

    if (digest_len == 0)
      digest_len = op->digest_len;

    kd = aes_ctr_hmac_get_key_data (op, thread_index);

    clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);

    vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
    for (int j = 0; j < op->n_chunks; j++, chp++)
      clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

    chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, digest_len);

    op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  }
  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, clib_thread_index_t thread_index)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];

next:
  {
    u32 digest_len = vnet_crypto_get_op_data (op->op)->digest_len;

    if (digest_len == 0)
      digest_len = op->digest_len;

    kd = aes_ctr_hmac_get_key_data (op, thread_index);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, digest_len)))
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
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, aes_key_size_t ks, clib_sha2_type_t type,
				  clib_thread_index_t thread_index)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];

next:
  {
    u32 digest_len = vnet_crypto_get_op_data (op->op)->digest_len;

    if (digest_len == 0)
      digest_len = op->digest_len;

    kd = aes_ctr_hmac_get_key_data (op, thread_index);

    clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

    vnet_crypto_op_chunk_t *chp = chunks + op->integ_chunk_index;
    for (int j = 0; j < op->integ_n_chunks; j++, chp++)
      clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, digest_len)))
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
      goto next;
    }

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_aes_ctr (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
		 aes_key_size_t ks, clib_thread_index_t thread_index,
		 int maybe_chained __clib_unused)
{
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  u32 n_left = n_ops;

next:
  kd = aes_ctr_get_key_data (op, thread_index);

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
      goto next;
    }

  return n_ops;
}

static_always_inline void
aes_ctr_key_exp (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks)
{
  clib_aes_ctr_key_expand ((aes_ctr_key_data_t *) key_data, vnet_crypto_get_cipher_key (key), ks);
}

#define foreach_aes_ctr_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                                       \
  static u32 aes_ops_aes_ctr_##x (vnet_crypto_op_t *ops[], u32 n_ops,                              \
				  clib_thread_index_t thread_index)                                \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, 0, AES_KEY_##x, thread_index, 0);                          \
  }                                                                                                \
  static u32 aes_ops_aes_ctr_##x##_chained (vnet_crypto_op_t *ops[],                               \
					    vnet_crypto_op_chunk_t *chunks, u32 n_ops,             \
					    clib_thread_index_t thread_index)                      \
  {                                                                                                \
    return aes_ops_aes_ctr (ops, n_ops, chunks, AES_KEY_##x, thread_index, 1);                     \
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

static void
aes_ctr_key_add (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks)
{
  aes_ctr_key_exp (key, key_data, ks);
}

static void
aes_ctr_128_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (key, key_data, AES_KEY_128);
}

static void
aes_ctr_192_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (key, key_data, AES_KEY_192);
}

static void
aes_ctr_256_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (key, key_data, AES_KEY_256);
}

static_always_inline void
aes_ctr_sha2_key_add (vnet_crypto_key_t *key, u8 *key_data, aes_key_size_t ks, u16 crypto_len)
{
  aes_ctr_hmac_key_data_t *kd = (aes_ctr_hmac_key_data_t *) key_data;
  u16 integ_len;

  if (key->cipher_key_sz < crypto_len || key->integ_key_sz == 0)
    return;

  integ_len = key->integ_key_sz;
  aes_ctr_key_exp (key, (u8 *) &kd->crypto_key, ks);
  clib_sha2_hmac_key_data (CLIB_SHA2_256, vnet_crypto_get_integ_key (key), integ_len,
			   &kd->integ_key);
}

static void
aes_ctr_sha2_128_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (key, key_data, AES_KEY_128, 16);
}

static void
aes_ctr_sha2_192_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (key, key_data, AES_KEY_192, 24);
}

static void
aes_ctr_sha2_256_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (key, key_data, AES_KEY_256, 32);
}

VNET_CRYPTO_REG_OP_GROUP (native_ctr128_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_128_key_change_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr192_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_192_key_change_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr256_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_256_key_change_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr128_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_128_key_change_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr192_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_192_key_change_handler,
};

VNET_CRYPTO_REG_OP_GROUP (native_ctr256_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_256_key_change_handler,
};

#define _(b)                                                                                       \
  VNET_CRYPTO_REG_OP (aes_##b##_ctr_enc) = {                                                       \
    .group = &native_ctr##b##_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_ENC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##b##_ctr_dec) = {                                                       \
    .group = &native_ctr##b##_group,                                                               \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_DEC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
  };

_ (128)
_ (192)
_ (256)
#undef _

#define _(a, b, c)                                                                                 \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops,  \
							      clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, thread_index);        \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b,       \
					     thread_index);                                        \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (vnet_crypto_op_t *ops[], u32 n_ops,  \
							      clib_thread_index_t thread_index)    \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, thread_index);        \
  }                                                                                                \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (                           \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b,       \
					     thread_index);                                        \
  }                                                                                                \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_enc) = {                                         \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_ENC,                                            \
    .fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_dec) = {                                         \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_DEC,                                            \
    .fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_tag##c##_enc) = {                                \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_ENC,                                   \
    .fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };                                                                                               \
                                                                                                   \
  VNET_CRYPTO_REG_OP (aes_##a##_ctr_hmac_sha##b##_tag##c##_dec) = {                                \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .op_id = VNET_CRYPTO_OP_AES_##a##_CTR_SHA##b##_TAG##c##_DEC,                                   \
    .fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                                         \
    .cfn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,                              \
  };

_ (128, 256, 16)
_ (192, 256, 16)
_ (256, 256, 16)

#undef _
