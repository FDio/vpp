/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

u8 *
format_vnet_crypto_alg (u8 * s, va_list * args)
{
  vnet_crypto_alg_t alg = va_arg (*args, int);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *d = cm->algs + alg;
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
format_crypto_op_type_short (u8 *s, va_list *args)
{
  vnet_crypto_op_type_t opt = va_arg (*args, vnet_crypto_op_type_t);

  switch (opt)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
      return format (s, "enc");
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      return format (s, "dec");
    case VNET_CRYPTO_OP_TYPE_HASH:
      return format (s, "hash");
    case VNET_CRYPTO_OP_TYPE_HMAC:
      return format (s, "hmac");
    case VNET_CRYPTO_OP_N_TYPES:
      break;
    }

  return format (s, "%U", format_vnet_crypto_op_type, opt);
}

u8 *
format_vnet_crypto_op_status (u8 * s, va_list * args)
{
  vnet_crypto_op_status_t st = va_arg (*args, int);
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
  vnet_crypto_engine_id_t engine = va_arg (*args, int);
  vnet_crypto_engine_t *e;

  if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
    return s;

  e = vec_elt_at_index (cm->engines, engine);

  return format (s, "%s", e->name);
}

uword
unformat_vnet_crypto_engine (unformat_input_t *input, va_list *args)
{
  vnet_crypto_engine_id_t *engine = va_arg (*args, vnet_crypto_engine_id_t *);
  u8 *name;

  if (!unformat (input, "%s", &name))
    return 0;

  *engine = vnet_crypto_get_engine_index_by_name ("%s", name);
  vec_free (name);

  return *engine != VNET_CRYPTO_ENGINE_ID_INVALID;
}

#if 0
u8 *
format_vnet_crypto_async_op_type (u8 * s, va_list * args)
{
  vnet_crypto_async_op_type_t opt =
    va_arg (*args, vnet_crypto_async_op_type_t);
  char *strings[] = {
#define _(n, s) [VNET_CRYPTO_ASYNC_OP_TYPE_##n] = s,
    foreach_crypto_async_op_type
#undef _
  };

  if (opt >= VNET_CRYPTO_ASYNC_OP_N_TYPES)
    return format (s, "unknown");

  return format (s, "%s", strings[opt]);
}

u8 *
format_vnet_crypto_async_alg (u8 * s, va_list * args)
{
  vnet_crypto_alg_t alg = va_arg (*args, vnet_crypto_alg_t);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_async_alg_data_t *d = vec_elt_at_index (cm->async_algs, alg);
  return format (s, "%s", d->name);
}

u8 *
format_vnet_crypto_async_op (u8 * s, va_list * args)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_async_op_id_t op = va_arg (*args, vnet_crypto_async_op_id_t);
  vnet_crypto_async_op_data_t *otd = cm->async_opt_data + op;

  return format (s, "%U-%U", format_vnet_crypto_async_op_type, otd->type,
		 format_vnet_crypto_async_alg, otd->alg);
}
#endif
