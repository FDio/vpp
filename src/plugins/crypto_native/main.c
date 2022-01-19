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
#include <crypto_native/crypto_native.h>

crypto_native_main_t crypto_native_main;

static void
crypto_native_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			   vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_native_main_t *cm = &crypto_native_main;

  /** TODO: add linked alg support **/
  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    return;

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
crypto_native_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;
  clib_error_t *error = 0;

  if (clib_cpu_supports_x86_aes () == 0 &&
      clib_cpu_supports_aarch64_aes () == 0)
    return 0;

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "native", 100,
				 "Native ISA Optimized Crypto");

  if (0);
#if __x86_64__
  else if (crypto_native_aes_cbc_init_icl && clib_cpu_supports_vaes ())
    error = crypto_native_aes_cbc_init_icl (vm);
  else if (crypto_native_aes_cbc_init_skx && clib_cpu_supports_avx512f ())
    error = crypto_native_aes_cbc_init_skx (vm);
  else if (crypto_native_aes_cbc_init_hsw && clib_cpu_supports_avx2 ())
    error = crypto_native_aes_cbc_init_hsw (vm);
  else if (crypto_native_aes_cbc_init_slm)
    error = crypto_native_aes_cbc_init_slm (vm);
#endif
#if __aarch64__
  else if (crypto_native_aes_cbc_init_neon)
    error = crypto_native_aes_cbc_init_neon (vm);
#endif
  else
    error = clib_error_return (0, "No AES CBC implemenation available");

  if (error)
    return error;

#if __x86_64__
  if (clib_cpu_supports_pclmulqdq ())
    {
      if (crypto_native_aes_gcm_init_icl && clib_cpu_supports_vaes ())
	error = crypto_native_aes_gcm_init_icl (vm);
      else if (crypto_native_aes_gcm_init_skx && clib_cpu_supports_avx512f ())
	error = crypto_native_aes_gcm_init_skx (vm);
      else if (crypto_native_aes_gcm_init_hsw && clib_cpu_supports_avx2 ())
	error = crypto_native_aes_gcm_init_hsw (vm);
      else if (crypto_native_aes_gcm_init_slm)
	error = crypto_native_aes_gcm_init_slm (vm);
      else
	error = clib_error_return (0, "No AES GCM implemenation available");

      if (error)
	return error;
    }
#endif
#if __aarch64__
  if (crypto_native_aes_gcm_init_neon)
    error = crypto_native_aes_gcm_init_neon (vm);
  else
    error = clib_error_return (0, "No AES GCM implemenation available");

  if (error)
    return error;
#endif

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_native_key_handler);
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_native_init) =
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
