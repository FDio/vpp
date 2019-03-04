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
#include <x86intrin.h>
#include <crypto_aesni/crypto_aesni.h>

clib_error_t *
crypto_aesni_init (vlib_main_t * vm)
{
  u32 eidx;

  if (clib_cpu_supports_x86_aes () == 0)
    return 0;

  eidx = vnet_crypto_register_engine (vm, "aesni", 100, "Intel AES-NI");
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_CBC_ENC,
				    aesni_ops_enc_aes_cbc_128);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_192_CBC_ENC,
				    aesni_ops_enc_aes_cbc_192);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_256_CBC_ENC,
				    aesni_ops_enc_aes_cbc_256);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_128_CBC_DEC,
				    aesni_ops_dec_aes_cbc_128);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_192_CBC_DEC,
				    aesni_ops_dec_aes_cbc_192);

  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_AES_256_CBC_DEC,
				    aesni_ops_dec_aes_cbc_256);

  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CBC_ENC,
					    aesni_queue_enc_aes_cbc_128);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CBC_DEC,
					    aesni_queue_dec_aes_cbc_128);
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_aesni_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
