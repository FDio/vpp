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
format_vnet_hash (u8 *s, va_list *args)
{
  vnet_hash_function_registration_t *hash =
    va_arg (*args, vnet_hash_function_registration_t *);

  s = format (s, "[name: %s ", hash->name);
  s = format (s, "priority: %u ", hash->priority);
  s = format (s, "description: %s]", hash->description);
  return s;
}

/**
 * select hash func with highest priority
 */
vnet_hash_fn_t
vnet_hash_default_function (vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  vnet_hash_function_registration_t *tmp_hash = hash;
  while (hash)
    {
      if (hash->priority > tmp_hash->priority)
	tmp_hash = hash;
      hash = hash->next;
    }
  return tmp_hash->function[ftype];
}

vnet_hash_fn_t
vnet_hash_function_from_name (const char *name, vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  while (hash)
    {
      if (strcmp (hash->name, name) == 0)
	break;
      hash = hash->next;
    }
  if (!hash)
    return (0);
  return hash->function[ftype];
}

vnet_hash_function_registration_t *
vnet_hash_function_from_func (vnet_hash_fn_t fn, vnet_hash_fn_type_t ftype)
{
  vnet_hash_function_registration_t *hash = vnet_hash_main.hash_registrations;
  while (hash)
    {
      if (hash->function[ftype] == fn)
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
