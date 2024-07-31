/*
 *------------------------------------------------------------------
 * Copyright (c) 2024 Cisco and/or its affiliates.
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
#include <vppinfra/cpu.h>
#include <vppinfra/crypto/aes_ctr.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

void CLIB_MULTIARCH_FN (clib_aes_ctr_init_internal)
(aes_ctr_ctx_t *ctx, const aes_ctr_key_data_t *kd, const u8 *iv,
 aes_key_size_t ks)
{
  clib_aes_ctr_init (ctx, kd, iv, ks);
}

void CLIB_MULTIARCH_FN (clib_aes_ctr_transform_internal)
(aes_ctr_ctx_t *ctx, const u8 *src, u8 *dst, u32 n_bytes, aes_key_size_t ks)
{
  clib_aes_ctr_transform (ctx, src, dst, n_bytes, ks);
}

void CLIB_MULTIARCH_FN (clib_aes_ctr_key_expand_internal)
(aes_ctr_key_data_t *kd, const u8 *key, aes_key_size_t ks)
{
  clib_aes_ctr_key_expand (kd, key, ks);
}