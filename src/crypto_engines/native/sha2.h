/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025-2026 Cisco and/or its affiliates.
 */

#pragma once
#include <vppinfra/crypto/sha2.h>
#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>

static_always_inline u32
crypto_native_ops_hmac_sha2 (vnet_crypto_op_t *ops[], u32 n_ops, vnet_crypto_op_chunk_t *chunks,
			     clib_sha2_type_t type, clib_thread_index_t thread_index)
{
  clib_sha2_hmac_ctx_t ctx;
  u8 buffer[64];
  u32 i, sz, n_fail = 0;

  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];

      clib_sha2_hmac_init (
	&ctx, type, (clib_sha2_hmac_key_data_t *) vnet_crypto_get_simple_key_data (op->ctx, 0));
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  vnet_crypto_op_chunk_t *chp = chunks + op->auth_chunk_index;
	  for (int j = 0; j < op->auth_n_chunks; j++, chp++)
	    clib_sha2_hmac_update (&ctx, chp->src, chp->len);
	}
      else
	clib_sha2_hmac_update (&ctx, op->auth_src, op->auth_src_len);

      clib_sha2_hmac_final (&ctx, buffer);

      if (op->auth_len)
	{
	  sz = op->auth_len;
	  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	    {
	      if ((memcmp (op->auth, buffer, sz)))
		{
		  n_fail++;
		  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
		  continue;
		}
	    }
	  else
	    clib_memcpy_fast (op->auth, buffer, sz);
	}
      else
	{
	  sz = clib_sha2_variants[type].digest_size;
	  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	    {
	      if ((memcmp (op->auth, buffer, sz)))
		{
		  n_fail++;
		  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
		  continue;
		}
	    }
	  else
	    clib_memcpy_fast (op->auth, buffer, sz);
	}

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops - n_fail;
}

static int
sha2_probe ()
{
#if defined(__x86_64__)

#if defined(__SHA__) && defined(__AVX512F__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx512f ())
    return 30;
#elif defined(__SHA__) && defined(__AVX2__)
  if (clib_cpu_supports_sha () && clib_cpu_supports_avx2 ())
    return 20;
#elif defined(__SHA__)
  if (clib_cpu_supports_sha ())
    return 10;
#endif

#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA2)
  if (clib_cpu_supports_sha2 ())
    return 10;
#endif
#endif
  return -1;
}
