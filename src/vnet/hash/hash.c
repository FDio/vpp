/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/hash/hash.h>

vnet_hash_main_t vnet_hash_main;

u8 *
format_vnet_hash_type (u8 *s, va_list *args)
{
  vnet_hash_type_t htype = va_arg (*args, vnet_hash_type_t);

#define _(name, bit, ss)                                                      \
  if (htype & VNET_HASH_TYPE_##name)                                          \
    s = format (s, "%s ", #name);
  foreach_vnet_hash_types
#undef _
    return s;
}

u8 *
format_vnet_hash (u8 *s, va_list *args)
{
  vnet_hash_function_registration_t *hash =
    va_arg (*args, vnet_hash_function_registration_t *);

  s = format (s, "[name: %s ", hash->name);
  s = format (s, "type: %U ", format_vnet_hash_type, hash->type);
  s = format (s, "description: %s]", hash->description);
  return s;
}

uword
unformat_vnet_hash_type (unformat_input_t *input, va_list *args)
{
  vnet_hash_type_t *htypep = va_arg (*args, vnet_hash_type_t *);
  int rv = 0;
  vnet_hash_type_t htype;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(enum, bit, str)                                                     \
  else if (unformat (input, str))                                             \
  {                                                                           \
    htype = (1 << bit);                                                       \
    rv = 1;                                                                   \
  }
      foreach_vnet_hash_types
#undef _
	else break;
    }
  if (rv)
    *htypep = htype;
  return rv;
}

vnet_hash_func
vnet_hash_function_from_default_type (vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  while (hash)
    {
      if (hash->type == VNET_HASH_TYPE_CRC32C_5TUPLE)
	break;
      hash = hash->next;
    }
  return hash->function[ftype];
}

vnet_hash_func
vnet_hash_function_from_type (vnet_hash_type_t htype,
			      vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  while (hash)
    {
      if (hash->type == htype)
	break;
      hash = hash->next;
    }
  return hash->function[ftype];
}

vnet_hash_function_registration_t *
vnet_hash_function_from_func (vnet_hash_func func, vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  while (hash)
    {
      if (hash->function[ftype] == func)
	break;
      hash = hash->next;
    }
  return hash;
}

static clib_error_t *
vnet_hash_init (vlib_main_t *vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (vnet_hash_init);
