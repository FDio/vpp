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

#ifndef __crypto_ia32_h__
#define __crypto_ia32_h__

typedef struct
{
  __m128i cbc_iv[4];
} crypto_ia32_per_thread_data_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_ia32_per_thread_data_t *per_thread_data;
  void **key_data;
} crypto_ia32_main_t;

extern crypto_ia32_main_t crypto_ia32_main;

clib_error_t *crypto_ia32_aesni_cbc_init (vlib_main_t * vm);

#endif /* __crypto_ia32_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
