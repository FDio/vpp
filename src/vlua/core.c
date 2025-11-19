/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <vlua/vlua.h>
#include <vlua/internal.h>

__clib_export vlua_init_fn_registration_t *vlua_init_registrations;

static void
vlua_lua_hook_trampoline (lua_State *L, lua_Debug *ar __clib_unused)
{
  void **slot = (void **) lua_getextraspace (L);
  vlua_handle_t h = (vlua_handle_t) *slot;
  h->hook_fn (h);
}

void
vlua_state_attach_handle (vlua_handle_t h, lua_State *L)
{
  void **slot;

  slot = (void **) lua_getextraspace (L);
  *slot = h;

  if (h->hook_fn && h->hook_inst_count > 0)
    lua_sethook (L, vlua_lua_hook_trampoline, LUA_MASKCOUNT,
		 h->hook_inst_count);
  else
    lua_sethook (L, 0, 0, 0);
}

static vlua_handle_t
vlua_state_get_handle (lua_State *L)
{
  return *(void **) lua_getextraspace (L);
}

static int
vlua_coroutine_create (lua_State *L)
{
  vlua_handle_t h = vlua_state_get_handle (L);
  vlua_sched_task_t *task;
  lua_State *thread;
  int arg_count = lua_gettop (L);

  ASSERT (h && h->coroutine_create_ref != LUA_NOREF);
  luaL_checktype (L, 1, LUA_TFUNCTION);

  lua_rawgeti (L, LUA_REGISTRYINDEX, h->coroutine_create_ref);
  lua_insert (L, 1);
  lua_call (L, 1, 1);

  thread = lua_tothread (L, -1);
  if (!thread)
    return vlua_errorf (L, "failed to create coroutine");

  int extra_args = arg_count - 1;
  if (extra_args > 0)
    {
      for (int i = 1; i <= extra_args; ++i)
	lua_pushvalue (L, i);
      lua_xmove (L, thread, extra_args);
      for (int i = extra_args; i >= 1; --i)
	lua_remove (L, i);
    }

  pool_get_zero (h->scheduler_tasks, task);
  task->thread = thread;
  task->index = task - h->scheduler_tasks;
  task->ref = luaL_ref (L, LUA_REGISTRYINDEX);
  vlua_state_attach_handle (h, thread);
  task->start_nargs = extra_args;

  /* Task will be started by scheduler */
  return 1;
}

static int
vlua_coroutine_wrap (lua_State *L)
{
  vlua_handle_t h = vlua_state_get_handle (L);
  int arg_count = lua_gettop (L);
  vlua_sched_task_t *task;
  clib_error_t *err;

  ASSERT (h && h->coroutine_wrap_ref != LUA_NOREF);

  lua_rawgeti (L, LUA_REGISTRYINDEX, h->coroutine_wrap_ref);
  lua_insert (L, 1);
  lua_call (L, 1, 1);

  if (!lua_isfunction (L, -1))
    return 1;

  lua_pushvalue (L, -1);
  if (!lua_getupvalue (L, -1, 1))
    {
      lua_pop (L, 1); /* remove duplicate wrapper */
      return vlua_errorf (L, "failed to inspect coroutine");
    }

  lua_remove (L, -2); /* drop duplicate wrapper */
  lua_State *co = lua_tothread (L, -1);
  if (!co)
    {
      lua_pop (L, 1);
      return vlua_errorf (L, "failed to create coroutine");
    }

  int extra_args = arg_count - 1;
  if (extra_args > 0)
    {
      for (int i = 1; i <= extra_args; ++i)
	lua_pushvalue (L, i);
      lua_xmove (L, co, extra_args);
      for (int i = extra_args; i >= 1; --i)
	lua_remove (L, i);
    }

  pool_get_zero (h->scheduler_tasks, task);
  task->thread = co;
  task->index = task - h->scheduler_tasks;
  lua_pushvalue (L, -1);
  task->ref = luaL_ref (L, LUA_REGISTRYINDEX);
  vlua_state_attach_handle (h, co);

  err = vlua_scheduler_task_resume (h, task->index, 0);
  if (err)
    {
      int rv = vlua_errorf (L, "%U", format_clib_error, err);
      clib_error_free (err);
      lua_pop (L, 1);
      return rv;
    }

  lua_pop (L, 1); /* remove coroutine */
  return 1;
}

static int
vlua_coroutine_yield (lua_State *L)
{
  vlua_handle_t h = vlua_state_get_handle (L);
  int arg_count = lua_gettop (L);

  if (h && h->hook_fn)
    h->hook_fn (h);

  return lua_yieldk (L, arg_count, 0, 0);
}

__clib_export vlua_handle_t
vlua_create (vlua_create_args_t *args)
{
  struct vlua_handle_t *h = clib_mem_alloc (sizeof (struct vlua_handle_t));
  lua_State *L = luaL_newstate ();
  int top;
  const char *prefix;

  ASSERT (args);

  *h = (struct vlua_handle_t){
    .L = L,
    .log_cb = args->log_cb,
    .hook_fn = args->hook_fn,
    .hook_inst_count = args->hook_inst_count,
    .coroutine_create_ref = LUA_NOREF,
    .coroutine_wrap_ref = LUA_NOREF,
  };

  luaL_openlibs (L);

  vlua_state_attach_handle (h, L);
  top = lua_gettop (L);
  lua_getglobal (L, "coroutine");

  if (lua_istable (L, -1))
    {
      lua_getfield (L, -1, "create");
      if (lua_isfunction (L, -1))
	{
	  h->coroutine_create_ref = luaL_ref (L, LUA_REGISTRYINDEX);
	  lua_pushcfunction (L, vlua_coroutine_create);
	  lua_setfield (L, -2, "create");
	}
      else
	lua_pop (L, 1);

      lua_getfield (L, -1, "wrap");
      if (lua_isfunction (L, -1))
	{
	  h->coroutine_wrap_ref = luaL_ref (L, LUA_REGISTRYINDEX);
	  lua_pushcfunction (L, vlua_coroutine_wrap);
	  lua_setfield (L, -2, "wrap");
	}
      else
	lua_pop (L, 1);

      lua_pushcfunction (L, vlua_coroutine_yield);
      lua_setfield (L, -2, "yield");

      lua_pop (L, 1);
    }
  else
    lua_pop (L, 1);
  ASSERT (lua_gettop (L) == top);

  prefix =
    (args->path_prefix && args->path_prefix[0]) ? args->path_prefix : "vlua";
  h->path_prefix = format (0, "%s", prefix);

  return h;
}

__clib_export void
vlua_destroy (vlua_handle_t h)
{
  lua_State *L;

  if (h == 0)
    return;

  L = h->L;
  if (h->table_handles)
    {
      vec_foreach_pointer (th, h->table_handles)
	{
	  ASSERT (th);
	  vec_free (th->children);
	  vec_free (th->name);
	  if (L && th->ref != LUA_NOREF)
	    luaL_unref (L, LUA_REGISTRYINDEX, th->ref);
	  clib_mem_free (th);
	}
      vec_free (h->table_handles);
    }
  if (h->namespaces)
    {
      vec_foreach_pointer (nh, h->namespaces)
	{
	  ASSERT (nh);
	  if (nh->signatures)
	    {
	      vlua_fn_and_args_t *fa;
	      vec_foreach (fa, nh->signatures)
		vec_free (fa->args);
	      vec_free (nh->signatures);
	    }
	  vec_free (nh->methods);
	  clib_mem_free (nh);
	}
      vec_free (h->namespaces);
      h->namespaces = 0;
    }
  if (h->methods)
    {
      vec_foreach_pointer (mh, h->methods)
	{
	  ASSERT (mh);
	  vlua_method_handle_free (mh);
	}
      vec_free (h->methods);
      h->methods = 0;
    }
  if (h->scheduler_tasks)
    {
      vlua_sched_task_t *task;
      pool_foreach (task, h->scheduler_tasks)
	{
	  if (task->ref != LUA_NOREF && L)
	    luaL_unref (L, LUA_REGISTRYINDEX, task->ref);
	}
      pool_free (h->scheduler_tasks);
      h->scheduler_tasks = 0;
    }
  if (L)
    {
      if (h->coroutine_create_ref != LUA_NOREF)
	luaL_unref (L, LUA_REGISTRYINDEX, h->coroutine_create_ref);
      if (h->coroutine_wrap_ref != LUA_NOREF)
	luaL_unref (L, LUA_REGISTRYINDEX, h->coroutine_wrap_ref);
    }
  vec_free (h->path_prefix);
  lua_close (h->L);
  clib_mem_free (h);
}

__clib_export clib_error_t *
vlua_run_string (vlua_handle_t h, const char *code)
{
  lua_State *L = vlua_get_state (h);
  vlua_sched_task_t *task;
  lua_State *thread;
  clib_error_t *err;
  u32 task_index;

  ASSERT (L != 0);
  ASSERT (code != 0);

  pool_get_zero (h->scheduler_tasks, task);

  thread = lua_newthread (L);
  if (!thread)
    {
      pool_put (h->scheduler_tasks, task);
      return clib_error_return (0, "failed to create coroutine");
    }
  vlua_state_attach_handle (h, thread);
  task->thread = thread;
  task->ref = luaL_ref (L, LUA_REGISTRYINDEX);
  task_index = task - h->scheduler_tasks;

  if (luaL_loadstring (thread, code) != LUA_OK)
    {
      const char *msg = lua_tostring (thread, -1);
      err = clib_error_return (0, "lua load failure: '%s'", msg ? msg : "");
      lua_pop (thread, 1);
      lua_settop (thread, 0);
      luaL_unref (L, LUA_REGISTRYINDEX, task->ref);
      pool_put (h->scheduler_tasks, task);
      return err;
    }

  err = vlua_scheduler_task_resume (h, task_index, 0);
  return err;
}

__clib_export clib_error_t *
vlua_run_file (vlua_handle_t h, const char *fmt, ...)
{
  lua_State *L = vlua_get_state (h);
  clib_error_t *err;
  vlua_sched_task_t *task;
  lua_State *thread;
  va_list va;
  u8 *path;
  u32 task_index;

  ASSERT (L != 0);
  ASSERT (fmt != 0);

  va_start (va, fmt);
  path = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (path, 0);

  pool_get_zero (h->scheduler_tasks, task);

  thread = lua_newthread (L);
  if (!thread)
    {
      pool_put (h->scheduler_tasks, task);
      err = clib_error_return (0, "failed to create coroutine");
      goto done;
    }
  vlua_state_attach_handle (h, thread);
  task->thread = thread;
  task->ref = luaL_ref (L, LUA_REGISTRYINDEX);
  task_index = task - h->scheduler_tasks;

  if (luaL_loadfile (thread, (const char *) path) != LUA_OK)
    {
      const char *msg = lua_tostring (thread, -1);
      err = clib_error_return (0, "lua load failure: '%s'", msg ? msg : "");
      lua_pop (thread, 1);
      lua_settop (thread, 0);
      luaL_unref (L, LUA_REGISTRYINDEX, task->ref);
      pool_put (h->scheduler_tasks, task);
      goto done;
    }

  err = vlua_scheduler_task_resume (h, task_index, 0);

done:
  vec_free (path);
  return err;
}

__clib_export clib_error_t *
vlua_run_init_functions (vlua_handle_t h)
{
  vlua_init_fn_registration_t *it;
  clib_error_t *error = 0;
  u8 *prefixed = 0;

  for (it = vlua_init_registrations; it; it = it->next)
    {
      if (!it->paths)
	continue;

      for (const char *const *path = it->paths; *path; ++path)
	{
	  const char *use_path = *path;
	  vlua_table_handle_t th;
	  if (use_path[0] == '.')
	    {
	      prefixed = format (prefixed, "%s%s%c",
				 (const char *) h->path_prefix, use_path, 0);
	      use_path = (const char *) prefixed;
	    }
	  th = vlua_table_ensure_path (h, use_path);
	  vec_add1 (it->table_handles_by_path, th);
	  vec_reset_length (prefixed);
	}
    }
  vec_free (prefixed);

  for (it = vlua_init_registrations; it; it = it->next)
    {
      if (it->init_fn)
	{
	  vlua_init_fn_args_t args = {
	    .table_handles = it->table_handles_by_path,
	  };
	  error = it->init_fn (h, &args);
	  if (error)
	    break;
	}
    }

  for (it = vlua_init_registrations; it; it = it->next)
    vec_free (it->table_handles_by_path);

  return error;
}
