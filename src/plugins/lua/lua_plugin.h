/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vlib/cli.h>
#include <vppinfra/error.h>

typedef struct vpp_lua_handle_t *vpp_lua_handle_t;
typedef struct vpp_lua_table_handle *vpp_lua_table_handle_t;
typedef struct vpp_lua_ns_t *vpp_lua_ns_handle_t;
typedef struct vpp_lua_method_t *vpp_lua_method_handle_t;

typedef struct
{
  vpp_lua_handle_t handle;
  void *cookie;
  const char *argument;
  size_t argument_length;
  const void *context;
  size_t context_size;
  const char *error_message;
} vpp_lua_string_function_args_t;

typedef const char *(*vpp_lua_string_function_t) (
  vpp_lua_string_function_args_t *args);

typedef enum
{
  VPP_LUA_T_STRING,
  VPP_LUA_T_NUMBER,
  VPP_LUA_T_BOOL,
} vpp_lua_type_t;

typedef struct
{
  vpp_lua_table_handle_t table_handle;
  const char *method;
  vpp_lua_string_function_t func;
  void *cookie;
  u8 ns_needs_argument : 1;
} vpp_lua_string_func_desc_t;

typedef struct vpp_lua_ns_resolver_fn_args_t_
{
  void *context;
  const char *name;
  size_t name_len;
  const char **error_message;
} vpp_lua_ns_resolver_fn_args_t;

typedef bool (*vpp_lua_ns_resolver_fn_t) (vpp_lua_ns_resolver_fn_args_t *args);

typedef struct
{
  vpp_lua_table_handle_t table_handle;
  size_t context_size;
} vpp_lua_ns_create_args_t;

vpp_lua_handle_t vpp_lua_create (void);
void vpp_lua_destroy (vpp_lua_handle_t h);
vpp_lua_table_handle_t vpp_lua_table_add (vpp_lua_handle_t h, const char *name,
					  vpp_lua_table_handle_t parent);

vpp_lua_method_handle_t
vpp_lua_method_add (vpp_lua_handle_t h,
		    const vpp_lua_string_func_desc_t *desc);

clib_error_t *vpp_lua_run_string (vpp_lua_handle_t h, const char *code);

vpp_lua_ns_handle_t vpp_lua_ns_create (vpp_lua_handle_t h,
				       const vpp_lua_ns_create_args_t *desc);

void vpp_lua_ns_add_call_args (vpp_lua_ns_handle_t nh,
			       vpp_lua_ns_resolver_fn_t fn, u32 n_args, ...);
