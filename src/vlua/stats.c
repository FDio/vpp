/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#include <math.h>

static inline const char *
vlua_task_status_string (vlua_sched_task_t *task, int lua_status_code)
{
  if (task == 0)
    return "none";

  if (lua_status_code == LUA_YIELD)
    return "yielded";

  if (lua_status_code == LUA_OK)
    {
      if (lua_gettop (task->thread) == 0)
	return "idle";
      return "ready";
    }

  return "error";
}

static u8 *
vlua_format_thread_stack (u8 *s, lua_State *co, const char *indent)
{
  lua_Debug ar;
  int level = 0;
  int top = lua_gettop (co);

  while (lua_getstack (co, level, &ar))
    {
      lua_getinfo (co, "Snlu", &ar);
      const char *src =
	ar.short_src[0] ? ar.short_src : (ar.source ? ar.source : "?");
      const char *name = (ar.name && ar.name[0]) ? ar.name : ar.what;
      s = format (s, "%s#%d %s:%d", indent, level, src, ar.currentline);
      if (name && name[0])
	s = format (s, " (%s)", name);
      s = format (s, " defined=%d last=%d\n", ar.linedefined,
		  ar.lastlinedefined);
      level++;
    }

  if (level == 0)
    s = format (s, "%s<empty>\n", indent);

  lua_settop (co, top);
  return s;
}

static u8 *
vlua_format_stack_values (u8 *s, lua_State *co, const char *indent)
{
  int top = lua_gettop (co);

  if (top == 0)
    return format (s, "%sstack: <empty>\n", indent);

  s = format (s, "%sstack (%d values):\n", indent, top);
  for (int i = 1; i <= top; ++i)
    {
      int type = lua_type (co, i);
      const char *type_name = lua_typename (co, type);

      s = format (s, "%s  [%d] %s", indent, i, type_name);

      switch (type)
	{
	case LUA_TSTRING:
	  {
	    size_t len = 0;
	    const char *preview;
	    lua_pushvalue (co, i);
	    luaL_tolstring (co, -1, &len);
	    preview = lua_tostring (co, -1);
	    if (preview)
	      {
		size_t show = len > 64 ? 64 : len;
		s = format (s, " \"%.*s\"%s", show, preview,
			    len > show ? "..." : "");
	      }
	    lua_pop (co, 2);
	    break;
	  }
	case LUA_TBOOLEAN:
	  s = format (s, " %s", lua_toboolean (co, i) ? "true" : "false");
	  break;
	case LUA_TNUMBER:
	  if (lua_isinteger (co, i))
	    s = format (s, " %lld", (long long) lua_tointeger (co, i));
	  else
	    s = format (s, " %f", lua_tonumber (co, i));
	  break;
	case LUA_TNIL:
	  break;
	case LUA_TTABLE:
	  s = format (s, " len=%u", (u32) lua_rawlen (co, i));
	  break;
	case LUA_TUSERDATA:
	  if (lua_getmetatable (co, i))
	    {
	      lua_getfield (co, -1, "__name");
	      if (lua_type (co, -1) == LUA_TSTRING)
		s = format (s, " %s", lua_tostring (co, -1));
	      lua_pop (co, 2);
	    }
	  break;
	default:
	  s = format (s, " %p", lua_topointer (co, i));
	  break;
	}
      s = format (s, "\n");
    }
  return s;
}

static u8 *
vlua_format_hook_state (u8 *s, lua_State *co, const char *indent)
{
  lua_Hook hook = lua_gethook (co);
  if (!hook)
    return format (s, "%shook: none\n", indent);

  int mask = lua_gethookmask (co);
  int count = lua_gethookcount (co);
  s = format (s, "%shook:", indent);
  if (mask & LUA_MASKCALL)
    s = format (s, " call");
  if (mask & LUA_MASKRET)
    s = format (s, " ret");
  if (mask & LUA_MASKLINE)
    s = format (s, " line");
  if (mask & LUA_MASKCOUNT)
    s = format (s, " count(%d)", count);
  s = format (s, "\n");
  return s;
}

__clib_export u8 *
vlua_format_stats (u8 *s, va_list *va)
{
  vlua_handle_t h = va_arg (*va, vlua_handle_t);
  lua_State *L;
  vlib_main_t *vm;
  f64 now = 0;
  size_t total_bytes;
  int gc_running;
  u32 idx, table_count = 0, ns_count = 0, method_count = 0;

  if (!h)
    return format (s, "lua handle: <null>\n");

  L = vlua_get_state (h);
  vm = vlib_get_main ();
  if (vm)
    now = vlib_time_now (vm);

  total_bytes = (size_t) lua_gc (L, LUA_GCCOUNT) * 1024 +
		(size_t) lua_gc (L, LUA_GCCOUNTB);
  gc_running = lua_gc (L, LUA_GCISRUNNING, 0);
  table_count = h->table_handles ? vec_len (h->table_handles) : 0;
  ns_count = h->namespaces ? vec_len (h->namespaces) : 0;
  method_count = h->methods ? vec_len (h->methods) : 0;

  s = format (s, "Lua handle %p\n", h);
  s = format (s, "  path prefix: %s\n",
	      h->path_prefix ? (char *) h->path_prefix : "<unset>");
  s = format (s, "  tables: %u  namespaces: %u  methods: %u\n", table_count,
	      ns_count, method_count);
  s = format (s, "  memory: %.2f KiB (%llu bytes)\n",
	      (double) total_bytes / 1024.0, (unsigned long long) total_bytes);
  s = format (s, "  GC running: %s\n", gc_running ? "yes" : "no");
  s = vlua_format_hook_state (s, L, "  ");
  s = format (s, "  main stack depth: %d\n", lua_gettop (L));
  s = format (s, "Main stack frames:\n");
  s = vlua_format_thread_stack (s, L, "    ");
  s = vlua_format_stack_values (s, L, "    ");

  if (!h->scheduler_tasks || pool_elts (h->scheduler_tasks) == 0)
    {
      s = format (s, "  coroutines: none\n");
      return s;
    }

  s = format (s, "Coroutines:\n");

  u32 total_tasks = 0, waiting_tasks = 0;
  pool_foreach_index (idx, h->scheduler_tasks)
    {
      vlua_sched_task_t *task = pool_elt_at_index (h->scheduler_tasks, idx);
      bool waiting = false;
      const char *status;
      int lua_status_code;
      int stack_depth;
      f64 wake_offset = 0;

      if (!task)
	continue;

      ++total_tasks;
      lua_status_code = lua_status (task->thread);
      status = vlua_task_status_string (task, lua_status_code);
      stack_depth = lua_gettop (task->thread);

      if (task->wake_time > 0)
	{
	  if (now > 0)
	    {
	      wake_offset = task->wake_time - now;
	      waiting = wake_offset > 0;
	    }
	  else
	    waiting = 1;
	}

      if (waiting)
	++waiting_tasks;

      s = format (s, "  - task %u: status=%s", idx, status);
      if (task == h->current_task)
	s = format (s, " (running)");
      s = format (s, ", stack=%d, yieldable=%s", stack_depth,
		  lua_isyieldable (task->thread) ? "yes" : "no");

      if (lua_status_code != LUA_YIELD && lua_status_code != LUA_OK &&
	  lua_gettop (task->thread) > 0)
	{
	  const char *err = lua_tostring (task->thread, -1);
	  if (err)
	    s = format (s, ", error=%s", err);
	}
      if (waiting)
	s = format (s, ", waiting %.3fs", wake_offset);
      else if (task->wake_time > 0 && now > 0)
	s = format (s, ", wake overdue by %.3fs", now - task->wake_time);
      s = format (s, "\n");
      s = vlua_format_thread_stack (s, task->thread, "        ");
      s = vlua_format_stack_values (s, task->thread, "        ");
      s = vlua_format_hook_state (s, task->thread, "        ");
    }

  s = format (s, "  totals: %u task(s), %u waiting\n", total_tasks,
	      waiting_tasks);

  if (h->current_task && h->scheduler_tasks)
    {
      s = format (s, "  active task index: %u\n", h->current_task->index);
    }

  return s;
}
