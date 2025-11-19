/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <lua.h>
#include <lauxlib.h>
#include <vlua/vlua.h>
#include <vppinfra/pool.h>

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

typedef struct
{
  lua_State *thread;
  int ref;
  f64 wake_time;
  int start_nargs;
  u32 index;
} vlua_sched_task_t;

struct vlua_table_handle
{
  vlua_handle_t handle;
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
  vlua_log_callback_t log_cb;
  u8 *path_prefix;
  vlua_hook_fn_t hook_fn;
  u32 hook_inst_count;
  int coroutine_create_ref;
  int coroutine_wrap_ref;
  vlua_sched_task_t *scheduler_tasks;
  vlua_sched_task_t *current_task;
};

struct vlua_method_t
{
  vlua_method_fn_t func;
  void *cookie;
  vlua_handle_t handle;
  u8 *name;
  vlua_table_handle_t table_handle;
  const void *context;
  size_t context_size;
  u8 *context_storage;
  size_t context_storage_len;
  vlua_fn_and_args_t *signatures;
};

void vlua_method_handle_free (vlua_method_handle_t mh);
void vlua_state_attach_handle (vlua_handle_t h, lua_State *L);

struct vlua_ns_t
{
  u32 context_size;
  vlua_ns_rt_method_t *methods;
  vlua_table_handle_t table_handle;
  vlua_fn_and_args_t *signatures;
  vlua_handle_t handle;
};

/* scheduler.c */
clib_error_t *vlua_scheduler_task_resume (vlua_handle_t h, u32 task_index,
					  int nargs);

/* format.c */
u8 *vlua_format_table_path (u8 *s, va_list *args);

/* table.c */
vlua_table_handle_t vlua_table_ensure_path (vlua_handle_t h, const char *path);

/* lua.c */
vlua_method_handle_t vlua_cfunction_runtime (lua_State *L, vlua_handle_t h,
					     int idx, vlua_table_handle_t th,
					     const char *method_name);

/* value.c */
bool vlua_val_from_lua (lua_State *L, int index, vlua_val_t *value);
void vlua_val_push (lua_State *L, vlua_val_t *value);
bool vlua_val_match_types (const vlua_val_t *values, u32 value_count,
			   const vlua_type_t *types);

/* helpers.c */
void vlua_pushfstring (lua_State *L, const char *fmt, ...);
void vlua_pushlstring (lua_State *L, const char *fmt, ...);
int vlua_return_err (lua_State *L, const char *fmt, ...);
int vlua_errorf (lua_State *L, const char *fmt, ...);
bool vlua_lua_types_match (lua_State *L, int start_index,
			   const vlua_type_t *types, u32 count);
vlua_type_t vlua_type_from_lua (lua_State *L, int index);
vlua_fn_and_args_t *vlua_fn_and_args_find (vlua_fn_and_args_t *vec,
					   const vlua_val_t *values);

/* inline helpers */
static_always_inline lua_State *
vlua_get_state (vlua_handle_t h)
{
  ASSERT (h);
  return h->L;
}
