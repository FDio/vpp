/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_ia32/crypto_ia32.h>
#include <crypto_ia32/aesni.h>

crypto_ia32_main_t crypto_ia32_main;

static void
crypto_ia32_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			 vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  aesni_key_data_t *kd;

  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC:
    case VNET_CRYPTO_ALG_AES_192_CBC:
    case VNET_CRYPTO_ALG_AES_256_CBC:
      break;
    default:
      return;
    }

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->key_data))
	return;

      if (cm->key_data[idx] == 0)
	return;

      clib_memset_u8 (cm->key_data[idx], 0,
		      clib_mem_size (cm->key_data[idx]));
      clib_mem_free (cm->key_data[idx]);
      cm->key_data[idx] = 0;
      return;
    }

  vec_validate_aligned (cm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && cm->key_data[idx])
    {
      clib_memset_u8 (cm->key_data[idx], 0,
		      clib_mem_size (cm->key_data[idx]));
      clib_mem_free (cm->key_data[idx]);
    }

  kd = cm->key_data[idx] = clib_mem_alloc_aligned (sizeof (aesni_key_data_t),
						   CLIB_CACHE_LINE_BYTES);

  /* ADD or MODIFY */
  switch (key->alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC:
      aes_key_expand (kd->encrypt_key, key->data, AESNI_KEY_128);
      aes_key_expand (kd->decrypt_key, key->data, AESNI_KEY_128);
      aes_key_enc_to_dec (kd->decrypt_key, AESNI_KEY_128);
      break;
    case VNET_CRYPTO_ALG_AES_192_CBC:
      aes_key_expand (kd->encrypt_key, key->data, AESNI_KEY_192);
      aes_key_expand (kd->decrypt_key, key->data, AESNI_KEY_192);
      aes_key_enc_to_dec (kd->decrypt_key, AESNI_KEY_192);
      break;
    case VNET_CRYPTO_ALG_AES_256_CBC:
      aes_key_expand (kd->encrypt_key, key->data, AESNI_KEY_256);
      aes_key_expand (kd->decrypt_key, key->data, AESNI_KEY_256);
      aes_key_enc_to_dec (kd->decrypt_key, AESNI_KEY_256);
      break;
    default:
      break;
    }
  return;
}

clib_error_t *
crypto_ia32_init (vlib_main_t * vm)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vnet_crypto_init)))
    return error;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "ia32", 100,
				 "Intel IA32 ISA Optimized Crypto");

  if (clib_cpu_supports_x86_aes () &&
      (error = crypto_ia32_aesni_cbc_init (vm)))
    goto error;

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_ia32_key_handler);


error:
  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

VLIB_INIT_FUNCTION (crypto_ia32_init);

#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel AESNI Software Crypto Backend Plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
