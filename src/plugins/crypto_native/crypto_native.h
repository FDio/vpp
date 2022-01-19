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
  u32 crypto_engine_index;
  crypto_native_key_fn_t *key_fn[VNET_CRYPTO_N_ALGS];
  void **key_data;
} crypto_native_main_t;

extern crypto_native_main_t crypto_native_main;

#define foreach_crypto_native_march_variant _(slm) _(hsw) _(skx) _(icl) _(neon)

#define _(v) \
clib_error_t __clib_weak *crypto_native_aes_cbc_init_##v (vlib_main_t * vm); \
clib_error_t __clib_weak *crypto_native_aes_gcm_init_##v (vlib_main_t * vm); \

foreach_crypto_native_march_variant;
#undef _

#endif /* __crypto_native_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
