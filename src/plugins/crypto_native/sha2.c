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
#include <vppinfra/sha2.h>

#if __GNUC__ > 4  && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize ("O3")
#endif

static_always_inline u32
ipsecmb_ops_hmac_sha512 (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops)
{
  return n_ops;
}

clib_error_t *
crypto_native_sha2_init_neon (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vnet_crypto_register_ops_handler (vm, cm->crypto_engine_index,
				    VNET_CRYPTO_OP_SHA512_HMAC,
                                    ipsecmb_ops_hmac_sha512);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
