/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _included_clib_args_h
#define _included_clib_args_h

#include <vppinfra/clib.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>

#define foreach_clib_arg_type                                                 \
  _ (BOOL)                                                                    \
  _ (UINT32)                                                                  \
  _ (HEX32)                                                                   \
  _ (STRING)                                                                  \
  _ (ENUM)

typedef enum
{
  CLIB_ARG_END,
#define _(n) CLIB_ARG_TYPE_##n,
  foreach_clib_arg_type
#undef _
} __clib_packed clib_arg_type_t;

typedef union
{
  u8 boolean;
  u32 uint32;
  int enum_val;
  u8 *string;
} clib_arg_value_t;

typedef struct
{
  char *name;
  int val;
} clib_arg_enum_val_t;

typedef struct
{
  char *name;
  char *desc;
  clib_arg_type_t type;
  u32 min;
  u32 max;
  u64 id;
  clib_arg_enum_val_t *enum_vals;
  clib_arg_value_t default_val;
} clib_arg_t;

typedef struct
{
  clib_arg_t *args;
  clib_arg_value_t *values;
  clib_bitmap_t *value_set_bmp;
} clib_args_t;

typedef clib_args_t *clib_args_handle_t;

#define CLIB_ARG_ENUM_VALS(...)                                               \
  (clib_arg_enum_val_t[])                                                     \
  {                                                                           \
    __VA_ARGS__                                                               \
    {                                                                         \
    }                                                                         \
  }

#define CLIB_ARG_BOOL(ud, n, d, ...)                                          \
  {                                                                           \
    .type = CLIB_ARG_TYPE_BOOL, .id = ud, .name = n, .desc = d, __VA_ARGS__   \
  }
#define CLIB_ARG_UINT32(ud, n, d, ...)                                        \
  {                                                                           \
    .type = CLIB_ARG_TYPE_UINT32, .id = ud, .name = n, .desc = d, __VA_ARGS__ \
  }
#define CLIB_ARG_HEX32(ud, n, d, ...)                                         \
  {                                                                           \
    .type = CLIB_ARG_TYPE_HEX32, .id = ud, .name = n, .desc = d, __VA_ARGS__  \
  }
#define CLIB_ARG_ENUM(ud, n, d, ...)                                          \
  {                                                                           \
    .type = CLIB_ARG_TYPE_ENUM, .id = ud, .name = n, .desc = d, __VA_ARGS__   \
  }
#define CLIB_ARG_STRING(ud, n, d, ...)                                        \
  {                                                                           \
    .type = CLIB_ARG_TYPE_STRING, .id = ud, .name = n, .desc = d, __VA_ARGS__ \
  }
#define CLIB_ARG_END()                                                        \
  {                                                                           \
    .type = CLIB_ARG_END                                                      \
  }

#define CLIB_ARGS(...)                                                        \
  (clib_arg_t[])                                                              \
  {                                                                           \
    __VA_ARGS__, CLIB_ARG_END ()                                              \
  }

u32 clib_args_get_uint32_val_by_name (clib_args_handle_t h, char *fmt, ...);
int clib_args_get_bool_val_by_name (clib_args_handle_t h, char *fmt, ...);
int clib_args_get_enum_val_by_name (clib_args_handle_t h, char *fmt, ...);
clib_error_t *clib_args_parse (clib_args_handle_t h, u8 *str);
format_function_t format_clib_arg_type;
format_function_t format_clib_arg_value;
format_function_t format_clib_args;
clib_args_handle_t clib_args_init (clib_arg_t *args);
clib_args_handle_t clib_args_clone (clib_args_handle_t h);
void clib_args_free (clib_args_handle_t h);

#endif /* _included_clib_args_h */
