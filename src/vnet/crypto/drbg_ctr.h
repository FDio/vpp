/* Copyright (c) 2022 Cisco and/or its affiliates.
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
 * limitations under the License. */

#ifndef included_vnet_crypto_drbg_h
#define included_vnet_crypto_drbg_h

#include "crypto.h"

static_always_inline clib_error_t *
vnet_crypto_drbg_ctr_block_encrypt (vlib_main_t *vm,
				    vnet_crypto_drbg_ctr_t *drbg, void *dest,
				    const void *src, u32 bytes)
{
  vnet_crypto_op_t op = {
    .op = VNET_CRYPTO_OP_AES_128_CTR_ENC,
    .src = (void *) src,
    .dst = dest,
    .len = bytes,
    .key_index = drbg->key_index,
    .iv = drbg->kv.v,
  };
  u64 cntr = clib_byte_swap_u64 (drbg->kv.cntr_be);
  u32 rv;

  drbg->kv.cntr_be = clib_byte_swap_u64 (cntr + 1);
  rv = vnet_crypto_process_ops (vm, &op, 1);
  drbg->kv.cntr_be =
    clib_byte_swap_u64 (cntr + bytes / VNET_CRYPTO_DRBG_CTR_BLOCK_LEN);
  if (PREDICT_FALSE (rv != 1 || VNET_CRYPTO_OP_STATUS_COMPLETED != op.status))
    return clib_error_return (0, "aes-128-ctr failed");
  return 0;
}

/* NIST SP800-90Ar1 section 10.2.1.2 */
static_always_inline clib_error_t *
vnet_crypto_drbg_ctr_update (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			     const vnet_crypto_drbg_ctr_seed_t *provided_data)
{
  vnet_crypto_drbg_ctr_seed_t tmp;
  clib_memset_u8 (&tmp, 0, sizeof (tmp));
  vnet_crypto_drbg_ctr_block_encrypt (vm, drbg, &tmp, &tmp, sizeof (tmp));

  if (provided_data)
    {
      drbg->kv._.as_u64[0] = tmp.as_u64[0] ^ provided_data->as_u64[0];
      drbg->kv._.as_u64[1] = tmp.as_u64[1] ^ provided_data->as_u64[1];
      drbg->kv._.as_u64[2] = tmp.as_u64[2] ^ provided_data->as_u64[2];
      drbg->kv._.as_u64[3] = tmp.as_u64[3] ^ provided_data->as_u64[3];
    }
  else
    {
      clib_memcpy_fast (&drbg->kv, &tmp, sizeof (drbg->kv));
    }

  vnet_crypto_key_modify (vm, drbg->key_index, drbg->kv.key,
			  sizeof (drbg->kv.key));
  return 0;
}

/* NIST SP800-90Ar1 section 10.2.1.5.1 without derivation function
 * No additional data supported */
static_always_inline clib_error_t *
vnet_crypto_drbg_ctr_generate (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			       void *dest, u32 bytes)
{
  clib_error_t *err;

  if (PREDICT_FALSE (bytes > VNET_CRYPTO_DRBG_CTR_MAX_REQ_LEN))
    return clib_error_return (0, "request too big");

  if (PREDICT_FALSE (drbg->reseed_counter >
		     VNET_CRYPTO_DRBG_CTR_RESEED_INTERVAL))
    {
      err = vnet_crypto_drbg_ctr_reseed (vm, drbg, 0);
      if (PREDICT_FALSE (err != 0))
	return err;
    }

  clib_memset_u8 (dest, 0, bytes);
  err = vnet_crypto_drbg_ctr_block_encrypt (vm, drbg, dest, dest, bytes);
  if (PREDICT_FALSE (err != 0))
    return err;

  err = vnet_crypto_drbg_ctr_update (vm, drbg, 0);
  if (PREDICT_FALSE (err != 0))
    return err;

  drbg->reseed_counter++;
  return 0;
}

static_always_inline clib_error_t *
vnet_crypto_drbg_ctr_generate_buffered (vlib_main_t *vm,
					vnet_crypto_drbg_ctr_t *drbg,
					void *dest, u32 bytes)
{
  if (PREDICT_FALSE (bytes > VNET_CRYPTO_DRBG_CTR_BUFSZ))
    return clib_error_return (0, "request too big");

  if (bytes > drbg->bufsz)
    {
      clib_error_t *err = vnet_crypto_drbg_ctr_generate (
	vm, drbg, &drbg->buf[drbg->bufsz],
	VNET_CRYPTO_DRBG_CTR_BUFSZ - drbg->bufsz);
      if (PREDICT_FALSE (err != 0))
	return err;
      drbg->bufsz = VNET_CRYPTO_DRBG_CTR_BUFSZ;
    }

  clib_memcpy_fast (dest, &drbg->buf[VNET_CRYPTO_DRBG_CTR_BUFSZ - bytes],
		    bytes);
  drbg->bufsz -= bytes;
  return 0;
}

static_always_inline void
vnet_crypto_rand (vlib_main_t *vm, void *dest, u32 bytes)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  clib_error_t *err =
    vnet_crypto_drbg_ctr_generate_buffered (vm, &ct->drbg, dest, bytes);
  if (PREDICT_FALSE (err != 0))
    clib_panic ("%U", format_clib_error, err);
}

#endif /* included_vnet_crypto_drbg_h */
