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

uword
unformat_vnet_crypto_alg (unformat_input_t * input, va_list * args)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_t *alg = va_arg (*args, vnet_crypto_alg_t *);
  uword *p;
  u8 *name;

  if (!unformat (input, "%s", &name))
    return 0;

  p = hash_get_mem (cm->alg_index_by_name, name);
  vec_free (name);
  if (p == 0)
    return 0;

  *alg = p[0];

  return 1;
}

u8 *
format_vnet_crypto_op (u8 * s, va_list * args)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_id_t op = va_arg (*args, int);	// vnet_crypto_op_id_t);
  vnet_crypto_op_data_t *otd = cm->opt_data + op;

  return format (s, "%U-%U", format_vnet_crypto_op_type, otd->type,
		 format_vnet_crypto_alg, otd->alg);
}

u8 *
format_vnet_crypto_op_type (u8 * s, va_list * args)
{
  vnet_crypto_op_type_t opt = va_arg (*args, vnet_crypto_op_type_t);
  char *strings[] = {
#define _(n, s) [VNET_CRYPTO_OP_TYPE_##n] = s,
    foreach_crypto_op_type
#undef _
  };

  if (opt >= VNET_CRYPTO_OP_N_TYPES)
    return format (s, "unknown");

  return format (s, "%s", strings[opt]);
}

u8 *
format_vnet_crypto_op_status (u8 * s, va_list * args)
{
  vnet_crypto_op_status_t st = va_arg (*args, vnet_crypto_op_status_t);
  char *strings[] = {
#define _(n, s) [VNET_CRYPTO_OP_STATUS_##n] = s,
    foreach_crypto_op_status
#undef _
  };

  if (st >= VNET_CRYPTO_OP_N_STATUS)
    return format (s, "unknown");

  return format (s, "%s", strings[st]);
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
