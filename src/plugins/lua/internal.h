/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <lua.h>
#include <lauxlib.h>
#include "external.h"

typedef struct
{
  const char *name;
} vlua_ns_rt_method_t;

typedef struct
{
  union
  {
    vlua_method_fn_t method_fn;
    vlua_ns_resolver_fn_t context_resolver;
    void *opaque;
  };
  vlua_type_t *args;
} vlua_fn_and_args_t;

struct vlua_table_handle
{
  vlua_table_handle_t parent;
  vlua_table_handle_t *children;
  u8 *name;
  int ref;
  vlua_ns_handle_t ns_handle;
};

struct vlua_handle_t
{
  lua_State *L;
  vlua_table_handle_t *table_handles;
  vlua_ns_handle_t *namespaces;
  vlua_method_handle_t *methods;
};

struct vlua_method_t
{
  vlua_method_fn_t func;
  void *cookie;
  vlua_handle_t handle;
  u8 *name;
  const void *context;
  size_t context_size;
  u8 *context_storage;
  size_t context_storage_len;
  vlua_fn_and_args_t *fn_and_args_vec;
};

void vlua_method_handle_free (vlua_method_handle_t mh);

struct vlua_ns_t
{
  u32 context_size;
  vlua_ns_rt_method_t *methods;
  vlua_table_handle_t table_handle;
  vlua_fn_and_args_t *fn_and_args_vec;
};

/* lua_format.c */
u8 *vlua_format_table_path (u8 *s, va_list *args);

/* lua.c */
vlua_method_handle_t vlua_cfunction_runtime (lua_State *L, int idx,
					     vlua_table_handle_t th,
					     const char *method_name);

/* lua_value.c */
bool vlua_value_from_lua (lua_State *L, int index, vlua_value_t *value);
void vlua_value_push (lua_State *L, vlua_value_t *value);
bool vlua_value_match_types (const vlua_value_t *values, u32 value_count,
			     const vlua_type_t *types);

/* lua_helpers.c */
void vlua_pushfstring (lua_State *L, const char *fmt, ...);
void vlua_pushlstring (lua_State *L, const char *fmt, ...);
int vlua_errorf (lua_State *L, const char *fmt, ...);
bool vlua_lua_types_match (lua_State *L, int start_index,
			   const vlua_type_t *types, u32 count);
vlua_type_t vlua_type_from_lua (lua_State *L, int index);
vlua_fn_and_args_t *vlua_fn_and_args_find (vlua_fn_and_args_t *vec,
					   const vlua_value_t *values);

/* inline helpers */
static_always_inline lua_State *
vlua_get_state (vlua_handle_t h)
{
  ASSERT (h);
  return h->L;
}

/* logging helpers */
#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (lua_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
