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
#include <vppinfra/crypto/aes_gcm.h>

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

int CLIB_MULTIARCH_FN (aes_gcm_internal)
(const u8 *src, u8 *dst, const u8 *aad, u8 *ivp, u8 *tag, u32 data_bytes,
 u32 aad_bytes, u8 tag_len, const aes_gcm_key_data_t *kd, int aes_rounds,
 aes_gcm_op_t op)
{
  return aes_gcm (src, dst, aad, ivp, tag, data_bytes, aad_bytes, tag_len, kd,
		  aes_rounds, op);
}

void CLIB_MULTIARCH_FN (clib_aes_gcm_key_expand_internal)
(aes_gcm_key_data_t *kd, const u8 *key, aes_key_size_t ks)
{
  clib_aes_gcm_key_expand (kd, key, ks);
}