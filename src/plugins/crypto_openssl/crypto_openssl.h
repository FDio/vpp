/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 ARM Ltd and/or its affiliates.
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

#ifndef __crypto_openssl_h__
#define __crypto_openssl_h__

typedef void *(crypto_openssl_ctx_fn_t) (vnet_crypto_key_t *key,
					 vnet_crypto_key_op_t kop,
					 vnet_crypto_key_index_t idx);

typedef struct
{
  u32 crypto_engine_index;
  crypto_openssl_ctx_fn_t *ctx_fn[VNET_CRYPTO_N_ALGS];
} crypto_openssl_main_t;

extern crypto_openssl_main_t crypto_openssl_main;

#endif /* __crypto_openssl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
