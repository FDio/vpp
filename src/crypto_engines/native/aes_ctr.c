/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/crypto/aes_ctr.h>
#include <vppinfra/crypto/sha2.h>
#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_enc_aes_ctr_hmac (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
			  aes_key_size_t ks, clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  const u32 thrd_stride = vm->thread_index * cm->stride;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];
  crypto_native_per_thread_data_t *ptd;

next:
  {
    ptd = (crypto_native_per_thread_data_t *) ((u8 *) op->keys + thrd_stride);

    clib_aes_ctr_init (&ctx, ptd->crypto_key_data, op->iv, ks);
    clib_aes_ctr_transform (&ctx, op->src, op->dst, op->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, ptd->hmac_key_data);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);
    clib_memcpy_fast (op->digest, buffer, op->digest_len);

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
aes_ops_enc_aes_ctr_hmac_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				  u32 n_ops, vnet_crypto_op_chunk_t *chunks,
				  aes_key_size_t ks, clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  const u32 thrd_stride = vm->thread_index * cm->stride;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops;
  u8 buffer[64];
  crypto_native_per_thread_data_t *ptd;

next:
  {
    ptd = (crypto_native_per_thread_data_t *) ((u8 *) op->keys + thrd_stride);

    clib_aes_ctr_init (&ctx, ptd->crypto_key_data, op->iv, ks);

    vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
    for (int j = 0; j < op->n_chunks; j++, chp++)
      clib_aes_ctr_transform (&ctx, chp->src, chp->dst, chp->len, ks);

    clib_sha2_hmac_init (&h_ctx, type, ptd->hmac_key_data);

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
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_ctr_hmac (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
			  aes_key_size_t ks, clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  const u32 thrd_stride = vm->thread_index * cm->stride;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];
  crypto_native_per_thread_data_t *ptd;

next:
  {
    ptd = (crypto_native_per_thread_data_t *) ((u8 *) op->keys + thrd_stride);

    clib_sha2_hmac_init (&h_ctx, type, ptd->hmac_key_data);
    clib_sha2_hmac_update (&h_ctx, op->integ_src, op->integ_len);
    clib_sha2_hmac_final (&h_ctx, buffer);

    if ((memcmp (op->digest, buffer, op->digest_len)))
      {
	n_fail++;
	op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      }
    else
      {
	clib_aes_ctr_init (&ctx, ptd->crypto_key_data, op->iv, ks);
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
aes_ops_dec_aes_ctr_hmac_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],
				  u32 n_ops, vnet_crypto_op_chunk_t *chunks,
				  aes_key_size_t ks, clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  const u32 thrd_stride = vm->thread_index * cm->stride;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  clib_sha2_hmac_ctx_t h_ctx;
  u32 n_left = n_ops, n_fail = 0;
  u8 buffer[64];
  crypto_native_per_thread_data_t *ptd;

next:
  {
    ptd = (crypto_native_per_thread_data_t *) ((u8 *) op->keys + thrd_stride);

    clib_sha2_hmac_init (&h_ctx, type, ptd->hmac_key_data);
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
	clib_aes_ctr_init (&ctx, ptd->crypto_key_data, op->iv, ks);

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
aes_ops_aes_ctr (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops,
		 vnet_crypto_op_chunk_t *chunks, aes_key_size_t ks,
		 int maybe_chained)
{
  crypto_native_main_t *cm = &crypto_native_main;
  const u32 thrd_stride = vm->thread_index * cm->stride;
  vnet_crypto_op_t *op = ops[0];
  aes_ctr_ctx_t ctx;
  u32 n_left = n_ops;
  crypto_native_per_thread_data_t *ptd;

next:
  ptd = (crypto_native_per_thread_data_t *) ((u8 *) op->keys + thrd_stride);

  clib_aes_ctr_init (&ctx, ptd->crypto_key_data, op->iv, ks);
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
aes_ctr_key_exp (vnet_crypto_key_op_t kop, crypto_native_per_thread_data_t *ptd, const u8 *data,
		 aes_key_size_t ks)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      for (u32 i = 0; i < cm->num_threads;
	   i++, ptd = (crypto_native_per_thread_data_t *) ((u8 *) ptd + cm->stride))
	{
	  if (ptd->crypto_key_data)
	    {
	      clib_mem_free_s (ptd->crypto_key_data);
	      ptd->crypto_key_data = 0;
	    }
	}
    }
  else if (kop == VNET_CRYPTO_KEY_OP_MODIFY)
    {
      for (u32 i = 0; i < cm->num_threads;
	   i++, ptd = (crypto_native_per_thread_data_t *) ((u8 *) ptd + cm->stride))
	{
	  if (ptd->crypto_key_data)
	    clib_mem_free_s (ptd->crypto_key_data);
	  ptd->crypto_key_data =
	    clib_mem_alloc_aligned (sizeof (aes_ctr_key_data_t), CLIB_CACHE_LINE_BYTES);
	  clib_aes_ctr_key_expand (ptd->crypto_key_data, data, ks);
	}
    }
  else if (kop == VNET_CRYPTO_KEY_OP_ADD)
    {
      for (u32 i = 0; i < cm->num_threads;
	   i++, ptd = (crypto_native_per_thread_data_t *) ((u8 *) ptd + cm->stride))
	{
	  ptd->crypto_key_data =
	    clib_mem_alloc_aligned (sizeof (aes_ctr_key_data_t), CLIB_CACHE_LINE_BYTES);
	  clib_aes_ctr_key_expand (ptd->crypto_key_data, data, ks);
	}
    }
}

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
  int r_ctr = -1, r_sha2 = -1;

#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vaes () && clib_cpu_supports_avx512f ())
    r_ctr = 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vaes ())
    r_ctr = 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_avx512f ())
    r_ctr = 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_avx2 ())
    r_ctr = 20;
#elif __AES__
  if (clib_cpu_supports_aes ())
    r_ctr = 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    r_ctr = 10;
#endif

#if defined(__x86_64__)
#if defined(__SHA__) && defined(__AVX512F__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx512f ())
    r_sha2 = 30;
#elif defined(__SHA__) && defined(__AVX2__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx2 ())
    r_sha2 = 20;
#elif defined(__SHA__)
  if (clib_cpu_supports_sha ())
    r_sha2 = 10;
#endif

#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA2)
  if (clib_cpu_supports_sha2 ())
    r_sha2 = 10;
#endif
#endif

  return clib_min (r_ctr, r_sha2);
}

#define _(b)                                                                                       \
  static u32 aes_ops_aes_ctr_##b (vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)             \
  {                                                                                                \
    return aes_ops_aes_ctr (vm, ops, n_ops, 0, AES_KEY_##b, 0);                                    \
  }                                                                                                \
  static u32 aes_ops_aes_ctr_##b##_chained (vlib_main_t *vm, vnet_crypto_op_t *ops[],              \
					    vnet_crypto_op_chunk_t *chunks, u32 n_ops)             \
  {                                                                                                \
    return aes_ops_aes_ctr (vm, ops, n_ops, chunks, AES_KEY_##b, 1);                               \
  }                                                                                                \
  static void aes_ctr_key_exp_##b (vnet_crypto_key_op_t kop, crypto_native_per_thread_data_t *ptd, \
				   const u8 *data, u16 length)                                     \
  {                                                                                                \
    return aes_ctr_key_exp (kop, ptd, data, AES_KEY_##b);                                          \
  }                                                                                                \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_enc) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_ENC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  CRYPTO_NATIVE_OP_HANDLER (aes_##b##_ctr_dec) = {                                                 \
    .op_id = VNET_CRYPTO_OP_AES_##b##_CTR_DEC,                                                     \
    .fn = aes_ops_aes_ctr_##b,                                                                     \
    .cfn = aes_ops_aes_ctr_##b##_chained,                                                          \
    .probe = probe,                                                                                \
  };                                                                                               \
  CRYPTO_NATIVE_KEY_HANDLER (aes_##b##_ctr) = {                                                    \
    .alg_id = VNET_CRYPTO_ALG_AES_##b##_CTR,                                                       \
    .key_fn = aes_ctr_key_exp_##b,                                                                 \
    .probe = probe,                                                                                \
  };

_ (128)
_ (192)
_ (256)

#undef _

#define _(a, b, c)                                                            \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b (                \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return aes_ops_enc_aes_ctr_hmac (vm, ops, n_ops, AES_KEY_##a,             \
				     CLIB_SHA2_##b);                          \
  }                                                                           \
                                                                              \
  static u32 crypto_native_ops_enc_aes_ctr_##a##_hmac_sha##b##_chained (      \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return aes_ops_enc_aes_ctr_hmac_chained (vm, ops, n_ops, chunks,          \
					     AES_KEY_##a, CLIB_SHA2_##b);     \
  }                                                                           \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b (                \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], u32 n_ops)                      \
  {                                                                           \
    return aes_ops_dec_aes_ctr_hmac (vm, ops, n_ops, AES_KEY_##a,             \
				     CLIB_SHA2_##b);                          \
  }                                                                           \
  static u32 crypto_native_ops_dec_aes_ctr_##a##_hmac_sha##b##_chained (      \
    vlib_main_t *vm, vnet_crypto_op_t *ops[], vnet_crypto_op_chunk_t *chunks, \
    u32 n_ops)                                                                \
  {                                                                           \
    return aes_ops_dec_aes_ctr_hmac_chained (vm, ops, n_ops, chunks,          \
					     AES_KEY_##a, CLIB_SHA2_##b);     \
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
