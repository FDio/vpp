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
  return (aes_ctr_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx, 0);
}

static_always_inline aes_ctr_hmac_key_data_t *
aes_ctr_hmac_get_key_data (vnet_crypto_op_t *op, clib_thread_index_t thread_index)
{
  return (aes_ctr_hmac_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx, 0);
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, u32 auth_len, clib_thread_index_t thread_index)
{
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 i;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;

      kd = aes_ctr_hmac_get_key_data (op, thread_index);

      clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);
      clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

      clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
      clib_sha2_hmac_update (&h_ctx, op->auth_src, op->auth_src_len);
      clib_sha2_hmac_final (&h_ctx, buffer);
      clib_memcpy_fast (op->auth, buffer, len);

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_enc_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, aes_key_size_t ks, clib_sha2_type_t type, u32 auth_len,
				  clib_thread_index_t thread_index)
{
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 i;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;

      kd = aes_ctr_hmac_get_key_data (op, thread_index);

      clib_aes_ctr_init (&ctx, &kd->crypto_key, op->iv, ks);

      vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
      for (int j = 0; j < op->n_chunks; j++, chp++)
	clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

      clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

      chp = chunks + op->auth_chunk_index;
      for (int j = 0; j < op->auth_n_chunks; j++, chp++)
	clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
      clib_sha2_hmac_final (&h_ctx, buffer);
      clib_memcpy_fast (op->auth, buffer, len);

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac (vnet_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
			  clib_sha2_type_t type, u32 auth_len, clib_thread_index_t thread_index)
{
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 i, n_fail = 0;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;

      kd = aes_ctr_hmac_get_key_data (op, thread_index);

      clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);
      clib_sha2_hmac_update (&h_ctx, op->auth_src, op->auth_src_len);
      clib_sha2_hmac_final (&h_ctx, buffer);

      if ((memcmp (op->auth, buffer, len)))
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

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac_chained (vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks,
				  u32 n_ops, aes_key_size_t ks, clib_sha2_type_t type, u32 auth_len,
				  clib_thread_index_t thread_index)
{
  aes_ctr_hmac_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  clib_sha2_hmac_ctx_t h_ctx;
  u32 i, n_fail = 0;
  u8 buffer[64];

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      u32 len = auth_len ? auth_len : op->auth_len;

      kd = aes_ctr_hmac_get_key_data (op, thread_index);

      clib_sha2_hmac_init (&h_ctx, type, &kd->integ_key);

      vnet_crypto_op_chunk_t *chp = chunks + op->auth_chunk_index;
      for (int j = 0; j < op->auth_n_chunks; j++, chp++)
	clib_sha2_hmac_update (&h_ctx, chp->src, chp->len);
      clib_sha2_hmac_final (&h_ctx, buffer);

      if ((memcmp (op->auth, buffer, len)))
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

  return n_ops - n_fail;
}

static_always_inline u32
aes_ops_aes_ctr (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
		 aes_key_size_t ks, clib_thread_index_t thread_index,
		 int maybe_chained __clib_unused)
{
  aes_ctr_key_data_t *kd;
  aes_ctr_ctx_t ctx = {};
  u32 i;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

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
    }

  return n_ops;
}

static_always_inline void
aes_ctr_key_exp (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_key_size_t ks)
{
  clib_aes_ctr_key_expand ((aes_ctr_key_data_t *) key_data, vnet_crypto_get_cipher_key (ctx), ks);
}

#define foreach_aes_ctr_handler_type _ (128) _ (192) _ (256)

#define _(x)                                                                                       \
  static u32 aes_ops_aes_ctr_##x (vnet_crypto_op_t *ops[],                                         \
				  vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,         \
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
aes_ctr_key_add (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_key_size_t ks)
{
  aes_ctr_key_exp (ctx, key_data, ks);
}

static void
aes_ctr_128_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (ctx, key_data, AES_KEY_128);
}

static void
aes_ctr_192_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (ctx, key_data, AES_KEY_192);
}

static void
aes_ctr_256_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_key_add (ctx, key_data, AES_KEY_256);
}

static_always_inline void
aes_ctr_sha2_key_add (vnet_crypto_ctx_t *ctx, u8 *key_data, aes_key_size_t ks, u16 crypto_len)
{
  aes_ctr_hmac_key_data_t *kd = (aes_ctr_hmac_key_data_t *) key_data;
  u16 integ_len;

  if (ctx->cipher_key_sz < crypto_len || ctx->auth_key_sz == 0)
    return;

  integ_len = ctx->auth_key_sz;
  aes_ctr_key_exp (ctx, (u8 *) &kd->crypto_key, ks);
  clib_sha2_hmac_key_data (CLIB_SHA2_256, vnet_crypto_get_auth_key (ctx), integ_len,
			   &kd->integ_key);
}

static void
aes_ctr_sha2_128_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (ctx, key_data, AES_KEY_128, 16);
}

static void
aes_ctr_sha2_192_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (ctx, key_data, AES_KEY_192, 24);
}

static void
aes_ctr_sha2_256_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  u8 *key_data;

  if (args->action != VNET_CRYPTO_KEY_DATA_ADD)
    return;
  key_data = args->key_data;
  aes_ctr_sha2_key_add (ctx, key_data, AES_KEY_256, 32);
}

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr128_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_128_key_change_handler,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr192_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_192_key_change_handler,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr256_group) = {
  .probe_fn = probe,
  .max_key_data_sz = sizeof (aes_ctr_key_data_t),
  .key_change_fn = aes_ctr_256_key_change_handler,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr128_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_128_key_change_handler,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr192_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_192_key_change_handler,
};

VNET_CRYPTO_REGISTER_ALG_GROUP (native_ctr256_sha2_group) = {
  .probe_fn = aes_ctr_sha2_probe,
  .max_key_data_sz = sizeof (aes_ctr_hmac_key_data_t),
  .key_change_fn = aes_ctr_sha2_256_key_change_handler,
};

#define _(b)                                                                                       \
  VNET_CRYPTO_REGISTER_ALG (aes_##b##_ctr) = {                                                          \
    .group = &native_ctr##b##_group,                                                               \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_CTR,                                                       \
    .simple = {                                                                                    \
      .enc_fn = aes_ops_aes_ctr_##b,                                                               \
      .dec_fn = aes_ops_aes_ctr_##b,                                                               \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = aes_ops_aes_ctr_##b##_chained,                                                     \
      .dec_fn = aes_ops_aes_ctr_##b##_chained,                                                     \
    },                                                                                             \
  };

_ (128)
_ (192)
_ (256)
#undef _

#define _(a, n, b, c)                                                                                     \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (                                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,                     \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_enc_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, 0, thread_index);            \
  }                                                                                                       \
                                                                                                          \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (                                  \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                                   \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b, 0,           \
					     thread_index);                                               \
  }                                                                                                       \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (                                            \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,                     \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_dec_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, 0, thread_index);            \
  }                                                                                                       \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (                                  \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                                   \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b, 0,           \
					     thread_index);                                               \
  }                                                                                                       \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_tag##c (                                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,                     \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_enc_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, c, thread_index);            \
  }                                                                                                       \
                                                                                                          \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_tag##c##_chained (                         \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                                   \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b, c,           \
					     thread_index);                                               \
  }                                                                                                       \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_tag##c (                                   \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,                     \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_dec_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_##b, c, thread_index);            \
  }                                                                                                       \
                                                                                                          \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_tag##c##_chained (                         \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                                   \
    clib_thread_index_t thread_index)                                                                     \
  {                                                                                                       \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_##b, c,           \
					     thread_index);                                               \
  }                                                                                                       \
  VNET_CRYPTO_REGISTER_ALG (aes_##a##_ctr_hmac_sha##b) = {                                              \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .alg_id = VNET_CRYPTO_ALG_AES_##a##_CTR_##n,                                                   \
    .simple = {                                                                                    \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b,                                   \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b,                                   \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained,                         \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained,                         \
    },                                                                                             \
  }; \
                                                                                                          \
  VNET_CRYPTO_REGISTER_ALG (aes_##a##_ctr_hmac_sha##b##_tag##c) = {                                     \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .alg_id = VNET_CRYPTO_ALG_AES_##a##_CTR_##n##_ICV##c,                                          \
    .simple = {                                                                                    \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_tag##c,                          \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_tag##c,                          \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_tag##c##_chained,                \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_tag##c##_chained,                \
    },                                                                                             \
  };

_ (128, SHA2_256, 256, 16)
_ (192, SHA2_256, 256, 16)
_ (256, SHA2_256, 256, 16)

#undef _

#define _(a, c)                                                                                    \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha256_tag##c##_extra (                      \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_256, c, thread_index);     \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha256_tag##c##_chained_extra (              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_enc_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_256, c,    \
					     thread_index);                                        \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha256_tag##c##_extra (                      \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks __clib_unused, u32 n_ops,              \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac (ops, n_ops, AES_KEY_##a, CLIB_SHA2_256, c, thread_index);     \
  }                                                                                                \
                                                                                                   \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha256_tag##c##_chained_extra (              \
    vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, u32 n_ops,                            \
    clib_thread_index_t thread_index)                                                              \
  {                                                                                                \
    return aes_ops_dec_aes_ctr_hmac_chained (ops, chunks, n_ops, AES_KEY_##a, CLIB_SHA2_256, c,    \
					     thread_index);                                        \
  }                                                                                                \
                                                                                                   \
  VNET_CRYPTO_REGISTER_ALG (aes_##a##_ctr_hmac_sha256_tag##c##_extra) = {                              \
    .group = &native_ctr##a##_sha2_group,                                                          \
    .alg_id = VNET_CRYPTO_ALG_AES_##a##_CTR_SHA2_256_ICV##c,                                        \
    .simple = {                                                                                    \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha256_tag##c##_extra,                    \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha256_tag##c##_extra,                    \
    },                                                                                             \
    .chained = {                                                                                   \
      .enc_fn = crypto_native_ops_enc_aes_ctr_##a##_hmac_sha256_tag##c##_chained_extra,            \
      .dec_fn = crypto_native_ops_dec_aes_ctr_##a##_hmac_sha256_tag##c##_chained_extra,            \
    },                                                                                             \
  };

_ (128, 12)
_ (192, 12)
_ (256, 12)

#undef _
