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
