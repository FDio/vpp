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
#ifndef __included_sfdp_service_h__
#define __included_sfdp_service_h__
#include <vlib/vlib.h>
#include <vnet/sfdp/common.h>

typedef struct _sfdp_service_registration_t
{
  struct _sfdp_service_registration_t *next;
  const char *node_name;
  const char *scope;
  char **runs_before;
  char **runs_after;
  u8 *index_in_bitmap;
  sfdp_bitmap_t *service_mask;
  u8 is_terminal;
} sfdp_service_registration_t;

typedef struct
{
  sfdp_service_registration_t *next_service;
  sfdp_service_registration_t ***services_per_scope_index;
  uword *scope_index_by_name;
  const char **scope_names;
  uword n_scopes;
  uword *service_index_by_name;
} sfdp_service_main_t;

extern sfdp_service_main_t sfdp_service_main;

#define SFDP_SERVICE_DECLARE(x)                                               \
  extern u8 sfdp_service_index_in_bitmap_##x;                                 \
  extern sfdp_bitmap_t sfdp_service_mask_##x;

#define SFDP_SERVICE_MASK(x)  sfdp_service_mask_##x
#define SFDP_SERVICE_INDEX(x) sfdp_service_index_in_bitmap_##x

#ifndef CLIB_MARCH_VARIANT
#define SFDP_SERVICE_DEFINE(x)                                                \
  static sfdp_service_registration_t sfdp_service_registration_##x;           \
  static void __sfdp_service_add_registration_##x (void)                      \
    __attribute__ ((__constructor__));                                        \
  u8 sfdp_service_index_in_bitmap_##x;                                        \
  sfdp_bitmap_t sfdp_service_mask_##x;                                        \
  static void __sfdp_service_add_registration_##x (void)                      \
  {                                                                           \
    sfdp_service_main_t *sm = &sfdp_service_main;                             \
    sfdp_service_registration_t *r = &sfdp_service_registration_##x;          \
    r->next = sm->next_service;                                               \
    sm->next_service = r;                                                     \
    r->index_in_bitmap = &sfdp_service_index_in_bitmap_##x;                   \
    r->service_mask = &sfdp_service_mask_##x;                                 \
  }                                                                           \
  static sfdp_service_registration_t sfdp_service_registration_##x
#else
#define SFDP_SERVICE_DEFINE(x)                                                \
  SFDP_SERVICE_DECLARE (x);                                                   \
  static sfdp_service_registration_t __clib_unused                            \
    unused_sfdp_service_registration_##x

#endif

#define SFDP_SERVICES(...)                                                    \
  (char *[])                                                                  \
  {                                                                           \
    __VA_ARGS__, 0                                                            \
  }

static_always_inline void
sfdp_next (vlib_buffer_t *b, u16 *next_index)
{
  sfdp_bitmap_t bmp = sfdp_buffer (b)->service_bitmap;
  u8 first = __builtin_ffsll (bmp);
  ASSERT (first != 0);
  *next_index = (first - 1);
  sfdp_buffer (b)->service_bitmap ^= 1ULL << (first - 1);
}

#define foreach_sfdp_scope_index(s_var)                                       \
  for (s_var = 0; s_var < sfdp_service_main.n_scopes; s_var++)
void sfdp_service_next_indices_init (vlib_main_t *vm, uword node_index,
				     sfdp_service_registration_t **services);

static_always_inline u8
sfdp_get_service_index_by_name (const char *name)
{
  sfdp_service_main_t *sm = &sfdp_service_main;
  uword *res = hash_get_mem (sm->service_index_by_name, name);
  if (res == NULL)
    {
      clib_panic ("Unknown service name '%s'", name);
    }
  return *res;
}

#endif //__included_service_h__