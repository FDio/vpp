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

crypto_ia32_main_t crypto_ia32_main;

static void
crypto_ia32_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			 vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_ia32_main_t *cm = &crypto_ia32_main;

  if (cm->key_fn[key->alg] == 0)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->key_data))
	return;

      if (cm->key_data[idx] == 0)
	return;

      clib_mem_free_s (cm->key_data[idx]);
      cm->key_data[idx] = 0;
      return;
    }

  vec_validate_aligned (cm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && cm->key_data[idx])
    {
      clib_mem_free_s (cm->key_data[idx]);
    }

  cm->key_data[idx] = cm->key_fn[key->alg] (key);
}

clib_error_t *
crypto_ia32_init (vlib_main_t * vm)
{
  crypto_ia32_main_t *cm = &crypto_ia32_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;

  if (clib_cpu_supports_x86_aes () == 0)
    return 0;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "ia32", 100,
				 "Intel IA32 ISA Optimized Crypto");

  if (clib_cpu_supports_avx512f ())
    error = crypto_ia32_aesni_cbc_init_avx512 (vm);
  else if (clib_cpu_supports_avx2 ())
    error = crypto_ia32_aesni_cbc_init_avx2 (vm);
  else
    error = crypto_ia32_aesni_cbc_init_sse42 (vm);

  if (error)
    goto error;

  if (clib_cpu_supports_pclmulqdq ())
    {
      if (clib_cpu_supports_avx512f ())
	error = crypto_ia32_aesni_gcm_init_avx512 (vm);
      else if (clib_cpu_supports_avx2 ())
	error = crypto_ia32_aesni_gcm_init_avx2 (vm);
      else
	error = crypto_ia32_aesni_gcm_init_sse42 (vm);

      if (error)
	goto error;
    }

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_ia32_key_handler);


error:
  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_ia32_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */

#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel IA32 Software Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
