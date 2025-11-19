/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <stdarg.h>

static int
vlua_namespace_method_call (lua_State *L)
{
  vlua_ns_rt_method_t *method = lua_touserdata (L, lua_upvalueindex (1));
  vlua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (4));
  vlua_method_handle_t mh = lua_touserdata (L, lua_upvalueindex (5));
  vlua_handle_t h = nh->handle;
  u32 ctx_sz = nh->context_size;
  void *context_mem = 0;
  int argc, rv;
  int call_base;

  if (ctx_sz)
    context_mem = lua_touserdata (L, lua_upvalueindex (2));
  argc = lua_gettop (L);

  lua_pushvalue (L, lua_upvalueindex (3));
  lua_insert (L, 1);
  call_base = lua_gettop (L) - (argc + 1);

  /* Copy Lua-owned context data into our stable storage before invoking
   * the underlying method so the thunk can reference it safely. */
  if (context_mem && ctx_sz > 0)
    {
      if (!mh->context_storage || mh->context_storage_len < ctx_sz)
	vlua_log_debug (h, "%s allocating %u-byte namespace context",
			method && method->name ? method->name : "<unnamed>",
			ctx_sz);
      else
	vlua_log_debug (h, "%s swapping namespace context (%u bytes)",
			method && method->name ? method->name : "<unnamed>",
			ctx_sz);
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
    vlua_log_err (
      h, "ns_call missing context for method '%s' (expected %u bytes)",
      method && method->name ? method->name : "<unnamed>", ctx_sz);

  if (lua_pcall (L, argc, LUA_MULTRET, 0) != LUA_OK)
    rv = lua_error (L);
  else
    rv = lua_gettop (L) - call_base;

  if (mh)
    {
      if (mh->context)
	vlua_log_debug (h, "%s clearing namespace context",
			method && method->name ? method->name : "<unnamed>");
      mh->context = 0;
      mh->context_size = 0;
    }
  return rv;
}

static int
vlua_namespace_call (lua_State *L)
{
  vlua_ns_handle_t nh = lua_touserdata (L, lua_upvalueindex (2));
  vlua_handle_t h = nh->handle;
  vlua_ns_rt_method_t *method;
  vlua_method_handle_t mh;
  vlua_table_handle_t th = nh->table_handle;
  vlua_ns_resolver_fn_t cr = 0;
  vlua_val_t *arg_values = 0;
  int namespace_index;
  int context_index;
  int handle_index;
  uword method_count;
  u32 ctx_sz = nh->context_size;
  int rv;
  int total_args = lua_gettop (L);
  int user_argc = total_args - 1;

  method_count = vec_len (nh->methods);
  if (method_count == 0)
    {
      vlua_log_err (h, "namespace '%U' has no methods", vlua_format_table_path,
		    th);
      rv = vlua_return_err (L, "namespace '%U' has no methods",
			    vlua_format_table_path, th);
      goto done;
    }

  luaL_checktype (L, 1, LUA_TTABLE);

  if (vec_len (nh->signatures) > 0)
    {
      vlua_fn_and_args_t *match;

      for (int i = 0; i < user_argc; ++i)
	{
	  vlua_val_t v = { 0 };
	  if (!vlua_val_from_lua (L, 2 + i, &v))
	    {
	      rv =
		vlua_return_err (L, "namespace '%U' argument #%d unsupported",
				 vlua_format_table_path, th, i + 1);
	      goto done;
	    }
	  vec_add1 (arg_values, v);
	}

      match = vlua_fn_and_args_find (nh->signatures, arg_values);

      if (!match)
	{
	  vlua_log_err (h, "namespace '%U' called with unsupported arguments",
			vlua_format_table_path, th);
	  rv = vlua_return_err (
	    L, "namespace '%U' called with unsupported arguments",
	    vlua_format_table_path, th);
	  goto done;
	}

      cr = match->context_resolver;
      vlua_log_debug (h, "namespace %U resolved signature",
		      vlua_format_table_path, th);
    }
  else
    {
      luaL_argcheck (L, user_argc == 1, 2, "single argument expected");
      luaL_checktype (L, 2, LUA_TSTRING);
    }

  lua_pushvalue (L, lua_upvalueindex (1));
  namespace_index = lua_gettop (L);

  if (ctx_sz > 0)
    {
      void *context_mem;
      context_mem = lua_newuserdatauv (L, ctx_sz, 0);
      clib_memset (context_mem, 0, ctx_sz);
      if (cr)
	{
	  vlua_ns_resolver_fn_args_t resolver_args = {
	    .handle = h,
	    .context = context_mem,
	    .args = arg_values,
	  };
	  clib_error_t *err = cr (&resolver_args);
	  if (err)
	    {
	      const u8 *name = 0;
	      u8 *msg = 0;
	      if (vec_len (arg_values) > 0 &&
		  vlua_val_type_is_string (&arg_values[0]))
		name = vlua_val_get_string (&arg_values[0], 0);
	      msg = format (0, "%U", format_clib_error, err);
	      vlua_log_warn (h, "context resolution failed for %U('%v'): %U",
			     vlua_format_table_path, nh->table_handle, name,
			     format_clib_error, err);
	      lua_pop (L, 1);
	      clib_error_free (err);
	      rv = vlua_return_err (
		L, "%s",
		msg ? (char *) msg : "namespace context resolution failed");
	      vec_free (msg);
	      goto done;
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
	  vlua_log_warn (h, "namespace '%U' method '%s' is not callable",
			 vlua_format_table_path, nh->table_handle,
			 method->name ? method->name : "<unnamed>");
	  lua_pop (L, 2);
	  continue;
	}

      mh = vlua_cfunction_runtime (L, h, -1, th,
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
  rv = 1;

done:
  vlua_val_vec_free (&arg_values);
  return rv;
}

__clib_export vlua_ns_handle_t
vlua_ns_create (vlua_handle_t h, vlua_table_handle_t th, size_t context_size)
{
  lua_State *L = vlua_get_state (h);
  vlua_ns_handle_t nh;
  int ns_index;
  int mt_index;

  ASSERT (th);
  ASSERT (!th->ns_handle);

  nh = clib_mem_alloc (sizeof (*nh));
  vec_add1 (h->namespaces, nh);

  *nh = (struct vlua_ns_t){
    .table_handle = th,
    .context_size = context_size,
    .handle = h,
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

  vlua_log_debug (h, "enabled namespace %U", vlua_format_table_path, th);
  return nh;
}

__clib_export void
vlua_ns_add_call_args (vlua_ns_handle_t nh, vlua_ns_resolver_fn_t fn,
		       u32 n_args, ...)
{
  vlua_fn_and_args_t *fa;
  va_list va;

  ASSERT (nh && fn);

  vec_add2 (nh->signatures, fa, 1);
  fa->context_resolver = fn;
  va_start (va, n_args);

  for (u32 i = 0; i < n_args; i++)
    {
      vlua_type_t t = (vlua_type_t) va_arg (va, int);
      vec_add1 (fa->args, t);
    }

  va_end (va);
}
