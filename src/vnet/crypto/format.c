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
format_vnet_crypto_op_type (u8 * s, va_list * args)
{
  vnet_crypto_op_type_t opt = va_arg (*args, int);
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
  vnet_crypto_op_type_t opt = va_arg (*args, int);

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
  u8 st = va_arg (*args, int);
  char *strings[] = {
    [VNET_CRYPTO_OP_STATUS_COMPLETED] = "completed",
    [VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER] = "fail-no-handler",
    [VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC] = "fail-bad-hmac",
    [VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR] = "fail-engine-err",
    [VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS] = "work-in-progress",
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
    return format (s, "-");

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
