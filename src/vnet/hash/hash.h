/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __VNET_HASH_H__
#define __VNET_HASH_H__

#include <vlib/vlib.h>

#define foreach_vnet_hash_fn_types                                            \
  _ (ETHERNET, 0, "hash-fn-ethernet")                                         \
  _ (IP, 1, "hash-fn-ip")

typedef enum
{
#define _(f, n, s) VNET_HASH_FN_TYPE_##f,
  foreach_vnet_hash_fn_types
#undef _
    VNET_HASH_FN_TYPE_N,
} vnet_hash_fn_type_t;

typedef void (*vnet_hash_fn_t) (void **p, u32 *h, u32 n_packets);

typedef struct vnet_hash_function_registration
{
  const char *name;
  const char *description;
  int priority;
  vnet_hash_fn_t function[VNET_HASH_FN_TYPE_N];

  struct vnet_hash_function_registration *next;
} vnet_hash_function_registration_t;

typedef struct
{
  vnet_hash_function_registration_t *hash_registrations;
} vnet_hash_main_t;

extern vnet_hash_main_t vnet_hash_main;

#define VNET_REGISTER_HASH_FUNCTION(x, ...)                                   \
  __VA_ARGS__ vnet_hash_function_registration_t __vnet_hash_function_##x;     \
  static void __clib_constructor __vnet_hash_function_registration_##x (void) \
  {                                                                           \
    vnet_hash_main_t *hm = &vnet_hash_main;                                   \
    __vnet_hash_function_##x.next = hm->hash_registrations;                   \
    hm->hash_registrations = &__vnet_hash_function_##x;                       \
  }                                                                           \
  __VA_ARGS__ vnet_hash_function_registration_t __vnet_hash_function_##x

vnet_hash_fn_t vnet_hash_default_function (vnet_hash_fn_type_t ftype);
vnet_hash_fn_t vnet_hash_function_from_name (const char *name,
					     vnet_hash_fn_type_t ftype);
vnet_hash_function_registration_t *
vnet_hash_function_from_func (vnet_hash_fn_t fn, vnet_hash_fn_type_t ftype);
format_function_t format_vnet_hash;

#endif
