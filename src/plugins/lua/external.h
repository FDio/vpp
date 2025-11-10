/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vlib/cli.h>
#include <vppinfra/error.h>

typedef struct vlua_handle_t *vlua_handle_t;
typedef struct vlua_table_handle *vlua_table_handle_t;
typedef struct vlua_ns_t *vlua_ns_handle_t;
typedef struct vlua_method_t *vlua_method_handle_t;

typedef enum
{
  VPP_LUA_T_STRING,
  VPP_LUA_T_NUMBER,
  VPP_LUA_T_INTEGER,
  VPP_LUA_T_BOOL,
  VPP_LUA_T_NIL,
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
} vlua_value_t;

typedef struct
{
  vlua_handle_t handle;
  void *cookie;
  const void *context;
  size_t context_size;
  vlua_value_t *args;
  vlua_value_t *returns;
} vlua_method_fn_args_t;

typedef clib_error_t *(*vlua_method_fn_t) (vlua_method_fn_args_t *args);

void vlua_value_add_nil (vlua_value_t **vec);
void vlua_value_add_bool (vlua_value_t **vec, bool value);
void vlua_value_add_number (vlua_value_t **vec, i64 number);
void vlua_value_add_integer (vlua_value_t **vec, i64 value);
void vlua_value_add_string (vlua_value_t **vec, const char *fmt, ...);
void vlua_value_vec_free (vlua_value_t **vec);

bool vlua_value_is_string (const vlua_value_t *v, const char *fmt, ...);
bool vlua_value_is_bool (const vlua_value_t *v, bool expected);
bool vlua_value_is_integer (const vlua_value_t *v, i64 expected);
bool vlua_value_is_number (const vlua_value_t *v, double expected);
bool vlua_value_is_nil (const vlua_value_t *v);

format_function_t format_vlua_value;

typedef struct vlua_ns_resolver_fn_args_t_
{
  void *context;
  const char *name;
  size_t name_len;
} vlua_ns_resolver_fn_args_t;

typedef clib_error_t *(*vlua_ns_resolver_fn_t) (
  vlua_ns_resolver_fn_args_t *args);

vlua_handle_t vlua_create (void);
void vlua_destroy (vlua_handle_t h);
vlua_table_handle_t vlua_table_add (vlua_handle_t h, const char *name,
				    vlua_table_handle_t parent);

vlua_method_handle_t vlua_method_add (vlua_handle_t h,
				      vlua_table_handle_t table,
				      const char *fmt, ...);

void vlua_method_add_call_args (vlua_method_handle_t mh, vlua_method_fn_t func,
				u32 n_args, ...);

clib_error_t *vlua_run_string (vlua_handle_t h, const char *code);
clib_error_t *vlua_run_file (vlua_handle_t h, const char *fmt, ...);

vlua_ns_handle_t vlua_ns_create (vlua_handle_t h, vlua_table_handle_t table,
				 size_t context_size);

void vlua_ns_add_call_args (vlua_ns_handle_t nh, vlua_ns_resolver_fn_t fn,
			    u32 n_args, ...);
