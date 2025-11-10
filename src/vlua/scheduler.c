/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#include <math.h>

clib_error_t *
vlua_scheduler_task_resume (vlua_handle_t h, u32 task_index, int nargs)
{
  vlua_sched_task_t *task = pool_elt_at_index (h->scheduler_tasks, task_index);
  lua_State *L = task->thread;
  lua_State *main = vlua_get_state (h);
  clib_error_t *err = 0;
  int nresults = 0;
  int status;

  h->current_task = task;
  status = lua_resume (L, main, nargs, &nresults);
  h->current_task = 0;

  if (status == LUA_YIELD)
    {
      lua_settop (L, 0);
      return 0;
    }

  if (status != LUA_OK)
    {
      const char *err_str = lua_tostring (L, -1);
      err_str = err_str ? err_str : "<unknown>";
      vlua_log_err (h, "lua coroutine %p failed: %s", L, err_str);
      err = clib_error_return (0, "%s", err_str);
    }
  else
    vlua_log_debug (h, "lua coroutine %p completed", L);

  lua_settop (L, 0);
  if (task->ref != LUA_NOREF)
    luaL_unref (h->L, LUA_REGISTRYINDEX, task->ref);
  pool_put_index (h->scheduler_tasks, task_index);
  return err;
}

__clib_export f64
vlua_scheduler_run_cycle (vlua_handle_t h)
{
  vlua_sched_task_t *task;
  u32 *indices = 0, i, *index;
  f64 next_wake = NAN;
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);

  pool_foreach_index (i, h->scheduler_tasks)
    vec_add1 (indices, i);

  vec_foreach (index, indices)
    {
      task = pool_elt_at_index (h->scheduler_tasks, *index);
      if (task->wake_time < now)
	{
	  clib_error_t *err = vlua_scheduler_task_resume (h, *index, 0);
	  if (err)
	    clib_error_free (err);
	}

      if (!pool_is_free_index (h->scheduler_tasks, *index))
	{
	  if (task->wake_time == 0)
	    next_wake = now;
	  else if (isnan (next_wake))
	    next_wake = task->wake_time;
	  else
	    next_wake = fmin (next_wake, task->wake_time);
	}
    }

  vec_free (indices);

  if (pool_elts (h->scheduler_tasks) == 0)
    return NAN;

  if (!isnan (next_wake))
    return fmax (next_wake - now, 0);

  return 0;
}

static void
vlua_scheduler_do_yield (vlua_handle_t h)
{
  vlib_main_t *vm = vlib_get_main ();
  vlua_sched_task_t *task = h ? h->current_task : 0;

  if (!task || !task->thread)
    {
      vlib_process_yield (vm);
      return;
    }

  if (h->hook_fn)
    h->hook_fn (h);
  lua_yieldk (task->thread, 0, 0, 0);
}

__clib_export void
vlua_yield (vlua_handle_t h)
{
  if (h && h->current_task)
    h->current_task->wake_time = 0;
  vlua_scheduler_do_yield (h);
}

__clib_export void
vlua_sleep (vlua_handle_t h, f64 seconds)
{
  vlib_main_t *vm = vlib_get_main ();
  vlua_sched_task_t *task = h->current_task;

  if (seconds > 0)
    task->wake_time = vlib_time_now (vm) + seconds;
  else
    task->wake_time = 0;

  vlua_scheduler_do_yield (h);
}

static int
vlua_spawn_lua (lua_State *L)
{
  vlua_handle_t h = lua_touserdata (L, lua_upvalueindex (1));
  vlua_sched_task_t *task;
  clib_error_t *err;
  int nargs = lua_gettop (L);
  int rv = 0, i;

  luaL_checktype (L, 1, LUA_TFUNCTION);
  lua_getglobal (L, "coroutine");
  lua_getfield (L, -1, "create");
  lua_pushvalue (L, 1);
  lua_call (L, 1, 1);
  lua_remove (L, -2);

  pool_get_zero (h->scheduler_tasks, task);
  task->thread = lua_tothread (L, -1);
  if (!task->thread)
    {
      pool_put (h->scheduler_tasks, task);
      return vlua_errorf (L, "failed to create coroutine");
    }
  task->ref = luaL_ref (L, LUA_REGISTRYINDEX);
  vlua_state_attach_handle (h, task->thread);

  if (nargs > 1)
    {
      for (i = 2; i <= nargs; ++i)
	lua_pushvalue (L, i);
      lua_xmove (L, task->thread, nargs - 1);
    }

  err = vlua_scheduler_task_resume (h, task - h->scheduler_tasks, nargs - 1);

  if (err)
    {
      rv = vlua_errorf (L, "%U", format_clib_error, err);
      clib_error_free (err);
    }

  return rv;
}

__clib_export void
vlua_scheduler_register_spawn (vlua_handle_t h, vlua_table_handle_t table,
			       const char *name)
{
  const char *method = (name && name[0]) ? name : "spawn";
  lua_State *L = vlua_get_state (h);

  lua_rawgeti (L, LUA_REGISTRYINDEX, table->ref);
  lua_pushlightuserdata (L, h);
  lua_pushcclosure (L, vlua_spawn_lua, 1);
  lua_setfield (L, -2, method);
  lua_pop (L, 1);
  vlua_log_debug (h, "registered %U.%s coroutine spawner",
		  vlua_format_table_path, table, method);
}
