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

#ifndef __crypto_native_h__
#define __crypto_native_h__

typedef void *(crypto_native_key_fn_t) (vnet_crypto_key_t * key);

typedef struct
{
  __m128i cbc_iv[4];
} crypto_native_per_thread_data_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_native_per_thread_data_t *per_thread_data;
  crypto_native_key_fn_t *key_fn[VNET_CRYPTO_N_ALGS];
  void **key_data;
} crypto_native_main_t;

extern crypto_native_main_t crypto_native_main;

clib_error_t *crypto_native_aes_cbc_init_sse42 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_avx2 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_avx512 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_vaes (vlib_main_t * vm);

clib_error_t *crypto_native_aes_gcm_init_sse42 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_avx2 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_avx512 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_vaes (vlib_main_t * vm);
#endif /* __crypto_native_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
