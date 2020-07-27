/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_ip_table_h
#define included_ip_table_h

#include <vlib/vlib.h>

/* ip table add delete callback */
typedef struct _vnet_ip_table_function_list_elt
{
  struct _vnet_ip_table_function_list_elt *next_ip_table_function;
  clib_error_t *(*fp) (struct vnet_main_t * vnm, u32 table_id, u32 flags);
} _vnet_ip_table_function_list_elt_t;

typedef enum vnet_ip_table_function_priority_t_
{
  VNET_IP_TABLE_FUNC_PRIORITY_LOW,
  VNET_IP_TABLE_FUNC_PRIORITY_HIGH,
} vnet_ip_table_function_priority_t;
#define VNET_IP_TABLE_FUNC_N_PRIO ((vnet_ip_table_function_priority_t)VNET_IP_TABLE_FUNC_PRIORITY_HIGH+1)

#ifndef CLIB_MARCH_VARIANT
#define _VNET_IP_TABLE_FUNCTION_DECL_PRIO(f,tag,p)                    \
                                                                        \
static void __vnet_ip_table_function_init_##tag##_##f (void)           \
    __attribute__((__constructor__)) ;                                  \
                                                                        \
static void __vnet_ip_table_function_init_##tag##_##f (void)           \
{                                                                       \
 vnet_main_t * vnm = vnet_get_main();                                   \
 static _vnet_ip_table_function_list_elt_t init_function;              \
 init_function.next_ip_table_function = vnm->tag##_functions[p];       \
 vnm->tag##_functions[p] = &init_function;                              \
 init_function.fp = (void *) &f;                                        \
}                                                                       \
static void __vnet_ip_table_function_deinit_##tag##_##f (void)         \
    __attribute__((__destructor__)) ;                                   \
                                                                        \
static void __vnet_ip_table_function_deinit_##tag##_##f (void)         \
{                                                                       \
 vnet_main_t * vnm = vnet_get_main();                                   \
 _vnet_ip_table_function_list_elt_t *next;                             \
 if (vnm->tag##_functions[p]->fp == f)                                  \
    {                                                                   \
      vnm->tag##_functions[p] =                                         \
        vnm->tag##_functions[p]->next_ip_table_function;               \
      return;                                                           \
    }                                                                   \
  next = vnm->tag##_functions[p];                                       \
  while (next->next_ip_table_function)                                 \
    {                                                                   \
      if (next->next_ip_table_function->fp == f)                       \
        {                                                               \
          next->next_ip_table_function =                               \
            next->next_ip_table_function->next_ip_table_function;     \
          return;                                                       \
        }                                                               \
      next = next->next_ip_table_function;                             \
    }                                                                   \
}
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define _VNET_IP_TABLE_FUNCTION_DECL_PRIO(f,tag,p)                    \
static __clib_unused void * __clib_unused_##f = f;
#endif

#define _VNET_IP_TABLE_FUNCTION_DECL(f,tag)                            \
  _VNET_IP_TABLE_FUNCTION_DECL_PRIO(f,tag,VNET_ITF_FUNC_PRIORITY_LOW)

#define VNET_IP_TABLE_ADD_DEL_FUNCTION(f)			\
  _VNET_IP_TABLE_FUNCTION_DECL(f,ip_table_add_del)

#endif /* included_ip_table_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
