/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef __VNET_HASH_H__
#define __VNET_HASH_H__

#include <vlib/vlib.h>

#define foreach_vnet_hash_types                                               \
  _ (ETHERNET, 1, "hash-ethernet")                                            \
  _ (IP, 2, "hash-ip")

typedef enum
{
#define _(f, n, s) VNET_HASH_FN_TYPE_##f = (1 << n),
  foreach_vnet_hash_types
#undef _
} vnet_hash_type_t;

typedef void (*vnet_hash_func) (void **p, u32 *h, u32 n_packets);

typedef struct vnet_hash_function_registration
{
  char *name;
  vnet_hash_type_t type;
  vnet_hash_func function;

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

vnet_hash_function_registration_t *
vnet_hash_function_from_type (vnet_hash_type_t htype);
vnet_hash_function_registration_t *
vnet_hash_function_from_func (vnet_hash_func func);
format_function_t format_vnet_hash_type;
format_function_t format_vnet_hash;
unformat_function_t unformat_vnet_hash_type;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
