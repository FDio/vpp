/*
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
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

u8 *
format_vnet_crypto_alg (u8 * s, va_list * args)
{
  vnet_crypto_alg_t alg = va_arg (*args, vnet_crypto_alg_t);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *d = vec_elt_at_index (cm->algs, alg);
  return format (s, "%s", d->name);
}

u8 *
format_vnet_crypto_op (u8 * s, va_list * args)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_type_t op = va_arg (*args, vnet_crypto_op_type_t);
  vnet_crypto_op_type_data_t *otd = cm->opt_data + op;

  return format (s, "%U %s", format_vnet_crypto_alg, otd->alg, otd->desc);
}

u8 *
format_vnet_crypto_engine (u8 * s, va_list * args)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 crypto_engine_index = va_arg (*args, u32);
  vnet_crypto_engine_t *e;

  if (crypto_engine_index == ~0)
    return s;

  e = vec_elt_at_index (cm->engines, crypto_engine_index);

  return format (s, "%s", e->name);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
