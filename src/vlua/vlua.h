/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vlib/cli.h>
#include <vppinfra/error.h>
#include <vppinfra/clib.h>

typedef struct vlua_handle_t *vlua_handle_t;
typedef struct vlua_table_handle *vlua_table_handle_t;
typedef struct vlua_ns_t *vlua_ns_handle_t;
typedef struct vlua_method_t *vlua_method_handle_t;

typedef enum
{
  VLUA_LOG_LEVEL_DEBUG,
  VLUA_LOG_LEVEL_INFO,
  VLUA_LOG_LEVEL_WARN,
  VLUA_LOG_LEVEL_ERR,
} vlua_log_level_t;

typedef void (*vlua_log_callback_t) (vlua_handle_t handle,
				     vlua_log_level_t level, const char *fmt,
				     va_list *va);

__clib_export void vlua_log_set_callback (vlua_handle_t handle,
					  vlua_log_callback_t cb);

typedef enum
{
  VLUA_T_STRING,
  VLUA_T_NUMBER,
  VLUA_T_INTEGER,
  VLUA_T_BOOL,
  VLUA_T_NIL,
} vlua_type_t;

typedef struct
{
  vlua_type_t type;
  union
  {
    u8 *string_value;
    double number_value;
    i64 integer_value;
    bool bool_value;
  };
} vlua_val_t;

typedef struct
{
  vlua_handle_t handle;
  const void *context;
  size_t context_size;
  vlua_val_t *args;
  vlua_val_t *returns;
} vlua_method_fn_args_t;

typedef clib_error_t *(*vlua_method_fn_t) (vlua_method_fn_args_t *args);

__clib_export void vlua_val_vec_add_nil (vlua_val_t **vec);
__clib_export void vlua_val_vec_add_bool (vlua_val_t **vec, bool value);
__clib_export void vlua_val_vec_add_number (vlua_val_t **vec, i64 number);
__clib_export void vlua_val_vec_add_integer (vlua_val_t **vec, i64 value);
__clib_export void vlua_val_vec_add_string (vlua_val_t **vec, const char *fmt,
					    ...);
__clib_export void vlua_val_vec_free (vlua_val_t **vec);

__clib_export bool vlua_val_is_string (const vlua_val_t *v, const char *fmt,
				       ...);
__clib_export bool vlua_val_is_bool (const vlua_val_t *v, bool expected);
__clib_export bool vlua_val_is_integer (const vlua_val_t *v, i64 expected);
__clib_export bool vlua_val_is_number (const vlua_val_t *v, double expected);
__clib_export bool vlua_val_is_nil (const vlua_val_t *v);

__clib_export bool vlua_val_type_is_string (const vlua_val_t *v);
__clib_export bool vlua_val_type_is_number (const vlua_val_t *v);
__clib_export bool vlua_val_type_is_integer (const vlua_val_t *v);
__clib_export bool vlua_val_type_is_bool (const vlua_val_t *v);
__clib_export bool vlua_val_type_is_nil (const vlua_val_t *v);

__clib_export bool vlua_val_vec_type_is_string (const vlua_val_t *vec,
						u32 index);
__clib_export bool vlua_val_vec_type_is_number (const vlua_val_t *vec,
						u32 index);
__clib_export bool vlua_val_vec_type_is_integer (const vlua_val_t *vec,
						 u32 index);
__clib_export bool vlua_val_vec_type_is_bool (const vlua_val_t *vec,
					      u32 index);
__clib_export bool vlua_val_vec_type_is_nil (const vlua_val_t *vec, u32 index);

__clib_export const u8 *vlua_val_get_string (const vlua_val_t *v, u32 *len);
__clib_export const u8 *vlua_val_vec_get_string (const vlua_val_t *vec,
						 u32 index, u32 *len);
__clib_export void vlua_val_set_string (vlua_val_t *v, const char *fmt, ...);

__clib_export double vlua_val_get_number (const vlua_val_t *v);
__clib_export double vlua_val_vec_get_number (const vlua_val_t *vec,
					      u32 index);
__clib_export void vlua_val_set_number (vlua_val_t *v, double value);

__clib_export i64 vlua_val_get_integer (const vlua_val_t *v);
__clib_export i64 vlua_val_vec_get_integer (const vlua_val_t *vec, u32 index);
__clib_export void vlua_val_set_integer (vlua_val_t *v, i64 value);

__clib_export bool vlua_val_get_bool (const vlua_val_t *v);
__clib_export bool vlua_val_vec_get_bool (const vlua_val_t *vec, u32 index);
__clib_export void vlua_val_set_bool (vlua_val_t *v, bool value);

__clib_export void vlua_val_set_nil (vlua_val_t *v);

__clib_export format_function_t format_vlua_value;

__clib_export void vlua_metadata_dump (vlua_handle_t h);

typedef struct vlua_ns_resolver_fn_args_t_
{
  void *context;
  const char *name;
  size_t name_len;
  const vlua_val_t *args;
} vlua_ns_resolver_fn_args_t;

typedef clib_error_t *(*vlua_ns_resolver_fn_t) (
  vlua_ns_resolver_fn_args_t *args);

__clib_export vlua_handle_t vlua_create (void);
__clib_export void vlua_destroy (vlua_handle_t h);
__clib_export vlua_table_handle_t vlua_table_add (vlua_handle_t h,
						  const char *name,
						  vlua_table_handle_t parent);

__clib_export vlua_method_handle_t vlua_method_add (vlua_handle_t h,
						    vlua_table_handle_t table,
						    const char *fmt, ...);

__clib_export void vlua_method_add_call_args (vlua_method_handle_t mh,
					      vlua_method_fn_t func,
					      u32 n_args, ...);

__clib_export clib_error_t *vlua_run_string (vlua_handle_t h,
					     const char *code);
__clib_export clib_error_t *vlua_run_file (vlua_handle_t h, const char *fmt,
					   ...);

__clib_export vlua_ns_handle_t vlua_ns_create (vlua_handle_t h,
					       vlua_table_handle_t table,
					       size_t context_size);

__clib_export void vlua_ns_add_call_args (vlua_ns_handle_t nh,
					  vlua_ns_resolver_fn_t fn, u32 n_args,
					  ...);
