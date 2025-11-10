/* SPDX-License-Identifier: Apache-2.0 */

#include "internal.h"

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <stdarg.h>

VLIB_REGISTER_LOG_CLASS (lua_log, static) = {
  .class_name = "lua",
  .subclass_name = "ns",
};

static int
vlua_namespace_method_call (lua_State *L)
{
  vlua_ns_rt_method_t *method = lua_touserdata (L, lua_upvalueindex (1));
  vlua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (4));
  u32 ctx_sz = nh->context_size;
  vlua_method_handle_t mh = lua_touserdata (L, lua_upvalueindex (5));
  void *context_mem =
    ctx_sz > 0 ? lua_touserdata (L, lua_upvalueindex (2)) : 0;
  int argc = lua_gettop (L);

  log_debug ("ns_call method=%s argc=%d ctx_bytes=%u",
	     method && method->name ? method->name : "<unnamed>", argc,
	     ctx_sz);

  lua_pushvalue (L, lua_upvalueindex (3));
  lua_insert (L, 1);
  int call_base = lua_gettop (L) - (argc + 1);

  /* Copy Lua-owned context data into our stable storage before invoking
   * the underlying method so the thunk can reference it safely. */
  if (mh && context_mem && ctx_sz > 0)
    {
      log_debug ("ns_call method=%s copying %u context bytes",
		 method && method->name ? method->name : "<unnamed>", ctx_sz);
      if (mh->context_storage_len < ctx_sz)
	{
	  if (mh->context_storage)
	    clib_mem_free (mh->context_storage);
	  mh->context_storage = clib_mem_alloc (ctx_sz);
	  mh->context_storage_len = ctx_sz;
	}
      clib_memcpy_fast (mh->context_storage, context_mem, ctx_sz);
      mh->context = mh->context_storage;
      mh->context_size = ctx_sz;
    }
  else if (ctx_sz > 0)
    log_err ("ns_call missing context for method '%s' (expected %u bytes)",
	     method && method->name ? method->name : "<unnamed>", ctx_sz);

  if (lua_pcall (L, argc, LUA_MULTRET, 0) != LUA_OK)
    {
      if (mh)
	{
	  mh->context = 0;
	  mh->context_size = 0;
	}
      return lua_error (L);
    }

  if (mh)
    {
      mh->context = 0;
      mh->context_size = 0;
    }

  return lua_gettop (L) - call_base;
}

static int
vlua_namespace_call (lua_State *L)
{
  vlua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (2));
  vlua_ns_rt_method_t *method = 0;
  vlua_method_handle_t mh = 0;
  vlua_table_handle_t th = nh->table_handle;
  vlua_ns_resolver_fn_t cr = 0;
  void *context_mem = 0;
  int namespace_index = 0;
  int context_index = 0;
  int handle_index = 0;
  uword method_count = 0;
  u32 ctx_sz = nh->context_size;
  int total_args = lua_gettop (L);
  int user_argc = total_args - 1;

  method_count = vec_len (nh->methods);
  if (method_count == 0)
    {
      log_err ("namespace '%U' has no methods", vlua_format_table_path, th);
      return vlua_errorf (L, "namespace '%U' has no methods",
			  vlua_format_table_path, th);
    }

  luaL_checktype (L, 1, LUA_TTABLE);

  if (vec_len (nh->fn_and_args_vec) > 0)
    {
      vlua_value_t *values = 0;
      for (int i = 0; i < user_argc; ++i)
	{
	  vlua_value_t v = {
	    .type = vlua_type_from_lua (L, 2 + i),
	  };
	  vec_add1 (values, v);
	}

      vlua_fn_and_args_t *match =
	vlua_fn_and_args_find (nh->fn_and_args_vec, values);

      if (!match)
	{
	  log_err ("namespace '%U' called with unsupported arguments",
		   vlua_format_table_path, th);
	  vlua_value_vec_free (&values);
	  return vlua_errorf (
	    L, "namespace '%U' called with unsupported arguments",
	    vlua_format_table_path, th);
	}

      cr = match->context_resolver;
      vlua_value_vec_free (&values);
    }
  else
    {
      luaL_argcheck (L, user_argc == 1, 2, "single argument expected");
      luaL_checktype (L, 2, LUA_TSTRING);
    }

  size_t name_len = 0;
  const char *name = (ctx_sz > 0) ? luaL_checklstring (L, 2, &name_len) : 0;

  lua_pushvalue (L, lua_upvalueindex (1));
  namespace_index = lua_gettop (L);

  if (ctx_sz > 0)
    {
      context_mem = lua_newuserdatauv (L, ctx_sz, 0);
      clib_memset (context_mem, 0, ctx_sz);
      if (cr)
	{
	  vlua_ns_resolver_fn_args_t resolver_args = {
	    .context = context_mem,
	    .name = name,
	    .name_len = name_len,
	  };
	  clib_error_t *err = cr (&resolver_args);
	  if (err)
	    {
	      u8 *msg = format (0, "%U", format_clib_error, err);
	      log_warn ("context resolution failed for %U('%.*s'): %U",
			vlua_format_table_path, nh->table_handle,
			(int) name_len, name, format_clib_error, err);
	      lua_pop (L, 1);
	      clib_error_free (err);
	      int rv = vlua_errorf (
		L, "%s",
		msg ? (char *) msg : "namespace context resolution failed");
	      vec_free (msg);
	      return rv;
	    }
	}
    }
  else
    lua_pushnil (L);
  context_index = lua_gettop (L);

  lua_createtable (L, 0, method_count);
  handle_index = lua_gettop (L);

  vec_foreach (method, nh->methods)
    {
      ASSERT (method->name);

      lua_pushvalue (L, namespace_index);
      lua_getfield (L, -1, method->name);
      if (!lua_isfunction (L, -1))
	{
	  log_warn ("namespace '%U' method '%s' is not callable",
		    vlua_format_table_path, nh->table_handle,
		    method->name ? method->name : "<unnamed>");
	  lua_pop (L, 2);
	  continue;
	}

      mh = vlua_cfunction_runtime (L, -1, th,
				   method->name ? method->name : "<unnamed>");
      if (mh == 0)
	{
	  lua_pop (L, 2);
	  continue;
	}

      lua_pushlightuserdata (L, method);
      lua_pushvalue (L, context_index);
      lua_pushvalue (L, -3);
      lua_pushlightuserdata (L, nh);
      lua_pushlightuserdata (L, mh);
      lua_pushcclosure (L, vlua_namespace_method_call, 5);
      lua_setfield (L, handle_index, method->name);

      lua_pop (L, 2);
    }

  lua_remove (L, context_index);
  lua_remove (L, namespace_index);

  return 1;
}

vlua_ns_handle_t
vlua_ns_create (vlua_handle_t h, vlua_table_handle_t th, size_t context_size)
{
  lua_State *L = vlua_get_state (h);
  vlua_ns_handle_t nh = 0;
  int ns_index;
  int mt_index;

  ASSERT (th);
  ASSERT (!th->ns_handle);

  nh = clib_mem_alloc (sizeof (*nh));
  vec_add1 (h->namespaces, nh);

  *nh = (struct vlua_ns_t){
    .table_handle = th,
    .context_size = context_size,
  };

  th->ns_handle = nh;

  lua_rawgeti (L, LUA_REGISTRYINDEX, th->ref);
  ASSERT (lua_istable (L, -1));

  ns_index = lua_gettop (L);

  if (!lua_getmetatable (L, ns_index))
    {
      lua_newtable (L);
      lua_pushvalue (L, -1);
      lua_setmetatable (L, ns_index);
    }
  mt_index = lua_gettop (L);

  lua_pushvalue (L, ns_index);
  lua_pushlightuserdata (L, nh);
  lua_pushcclosure (L, vlua_namespace_call, 2);
  lua_setfield (L, mt_index, "__call");
  lua_pop (L, 2);

  log_debug ("enabled namespace %U", vlua_format_table_path, th);
  return nh;
}

void
vlua_ns_add_call_args (vlua_ns_handle_t nh, vlua_ns_resolver_fn_t fn,
		       u32 n_args, ...)
{
  vlua_fn_and_args_t *fa;
  va_list va;

  vec_add2 (nh->fn_and_args_vec, fa, 1);
  fa->context_resolver = fn;
  va_start (va, n_args);

  for (u32 i = 0; i < n_args; i++)
    {
      vlua_type_t t = (vlua_type_t) va_arg (va, int);
      vec_add1 (fa->args, t);
    }

  va_end (va);
}
