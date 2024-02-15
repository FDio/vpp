/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_ARGS_H_
#define _VNET_DEV_ARGS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/errors.h>

#define foreach_vnet_dev_arg_type                                             \
  _ (BOOL, "%u", boolean)                                                     \
  _ (UINT32, "%u", uint32)                                                    \
  _ (STRING, "\'%v\'", string)

typedef enum
{
  VNET_DEV_ARG_END,
#define _(n, f, v) VNET_DEV_ARG_TYPE_##n,
  foreach_vnet_dev_arg_type
#undef _
} __clib_packed vnet_dev_arg_type_t;

typedef union
{
  u8 boolean;
  u32 uint32;
  u8 *string;
} vnet_dev_arg_value_t;

typedef struct
{
  char *name;
  char *desc;
  vnet_dev_arg_type_t type;
  u8 val_set;
  u32 min;
  u32 max;
  u64 id;
  vnet_dev_arg_value_t val;
  vnet_dev_arg_value_t default_val;
} vnet_dev_arg_t;

#define VNET_DEV_ARG_BOOL(ud, n, d, ...)                                      \
  {                                                                           \
    .type = VNET_DEV_ARG_TYPE_BOOL, .id = ud, .name = n, .desc = d,           \
    __VA_ARGS__                                                               \
  }
#define VNET_DEV_ARG_UINT32(ud, n, d, ...)                                    \
  {                                                                           \
    .type = VNET_DEV_ARG_TYPE_UINT32, .id = ud, .name = n, .desc = d,         \
    __VA_ARGS__                                                               \
  }
#define VNET_DEV_ARG_STRING(ud, n, d, ...)                                    \
  {                                                                           \
    .type = VNET_DEV_ARG_TYPE_STRING, .id = ud, .name = n, .desc = d,         \
    __VA_ARGS__                                                               \
  }
#define VNET_DEV_ARG_END()                                                    \
  {                                                                           \
    .type = VNET_DEV_ARG_END                                                  \
  }

#define VNET_DEV_ARGS(...)                                                    \
  (vnet_dev_arg_t[]) { __VA_ARGS__, VNET_DEV_ARG_END () }

#define foreach_vnet_dev_args(a, d)                                           \
  for (typeof ((d)->args[0]) *(a) = (d)->args; (a) < vec_end ((d)->args);     \
       (a)++)
#define foreach_vnet_dev_port_args(a, p)                                      \
  for (typeof ((p)->args[0]) *(a) = (p)->args; (a) < vec_end ((p)->args);     \
       (a)++)

#endif /* _VNET_DEV_ARGS_H_ */
