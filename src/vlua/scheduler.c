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
      vlua_log_debug (h, "lua task %u yielded", task_index);
      lua_settop (L, 0);
      return 0;
    }

  if (status != LUA_OK)
    {
      const char *err_str = lua_tostring (L, -1);
      err_str = err_str ? err_str : "<unknown>";

      luaL_traceback (L, L, err_str, 1);
      const char *trace = lua_tostring (L, -1);

      vlua_log_err (h, "lua task %u failed: %s", task_index, trace);
      err = clib_error_return (0, "%s", trace);
      lua_pop (L, 1);
    }
  else
    vlua_log_debug (h, "lua task %u completed", task_index);

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
	  clib_error_t *err =
	    vlua_scheduler_task_resume (h, *index, task->start_nargs);
	  task->start_nargs = 0;
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

__clib_export clib_error_t *
vlua_scheduler_kill_task (vlua_handle_t h, u32 task_index)
{
  vlua_sched_task_t *task;

  if (!h || !h->scheduler_tasks ||
      pool_is_free_index (h->scheduler_tasks, task_index))
    return clib_error_return (0, "invalid task index %u", task_index);

  task = pool_elt_at_index (h->scheduler_tasks, task_index);
  if (task == h->current_task)
    return clib_error_return (0, "task %u is currently running", task_index);

  if (task->thread)
    lua_settop (task->thread, 0);
  if (task->ref != LUA_NOREF)
    luaL_unref (h->L, LUA_REGISTRYINDEX, task->ref);
  task->thread = 0;
  pool_put_index (h->scheduler_tasks, task_index);
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
