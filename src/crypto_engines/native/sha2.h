/*
 *------------------------------------------------------------------
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#ifndef __sha2_h__
#define __sha2_h__
#include <vppinfra/crypto/sha2.h>
#include <vnet/crypto/crypto.h>
#include <native/crypto_native.h>

static_always_inline u32
crypto_native_ops_hmac_sha2 (vlib_main_t *vm, vnet_crypto_op_t *ops[],
			     u32 n_ops, vnet_crypto_op_chunk_t *chunks,
			     clib_sha2_type_t type)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_op_t *op = ops[0];
  u32 n_left = n_ops;
  clib_sha2_hmac_ctx_t ctx;
  u8 buffer[64];
  u32 sz, n_fail = 0;

  for (; n_left; n_left--, op++)
    {
      clib_sha2_hmac_init (
	&ctx, type, (clib_sha2_hmac_key_data_t *) cm->key_data[op->key_index]);
      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  vnet_crypto_op_chunk_t *chp = chunks + op->chunk_index;
	  for (int j = 0; j < op->n_chunks; j++, chp++)
	    clib_sha2_hmac_update (&ctx, chp->src, chp->len);
	}
      else
	clib_sha2_hmac_update (&ctx, op->src, op->len);

      clib_sha2_hmac_final (&ctx, buffer);

      if (op->digest_len)
	{
	  sz = op->digest_len;
	  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	    {
	      if ((memcmp (op->digest, buffer, sz)))
		{
		  n_fail++;
		  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
		  continue;
		}
	    }
	  else
	    clib_memcpy_fast (op->digest, buffer, sz);
	}
      else
	{
	  sz = clib_sha2_variants[type].digest_size;
	  if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	    {
	      if ((memcmp (op->digest, buffer, sz)))
		{
		  n_fail++;
		  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
		  continue;
		}
	    }
	  else
	    clib_memcpy_fast (op->digest, buffer, sz);
	}

      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  return n_ops - n_fail;
}
#endif /* __sha2_h__ */