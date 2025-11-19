/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

void
vlua_method_handle_free (vlua_method_handle_t mh)
{
  vlua_fn_and_args_t *sig;

  if (mh == 0)
    return;

  vec_foreach (sig, mh->signatures)
    vec_free (sig->args);
  vec_free (mh->signatures);

  vec_free (mh->name);

  if (mh->context_storage)
    clib_mem_free (mh->context_storage);

  clib_mem_free (mh);
}

vlua_method_handle_t
vlua_cfunction_runtime (lua_State *L, vlua_handle_t h, int idx,
			vlua_table_handle_t th, const char *method_name)
{
  const char *upvalue_name;
  vlua_method_handle_t *mh_slot;

  if (!lua_iscfunction (L, idx))
    {
      vlua_log_err (h, "namespace '%U' method '%s' is not a C function",
		    vlua_format_table_path, th,
		    method_name ? method_name : "<unnamed>");
      return 0;
    }

  upvalue_name = lua_getupvalue (L, idx, 1);
  if (upvalue_name == 0)
    {
      vlua_log_err (h, "namespace '%U' method '%s' has no runtime upvalue",
		    vlua_format_table_path, th,
		    method_name ? method_name : "<unnamed>");
      return 0;
    }

  mh_slot = lua_touserdata (L, -1);
  lua_pop (L, 1);

  if (mh_slot == 0 || *mh_slot == 0)
    {
      vlua_log_err (h, "namespace '%U' method '%s' runtime pointer is NULL",
		    vlua_format_table_path, th,
		    method_name ? method_name : "<unnamed>");
      return 0;
    }

  return *mh_slot;
}

static int
vlua_args_guard_gc (lua_State *L)
{
  vlua_val_t **args_ptr = lua_touserdata (L, 1);
  if (args_ptr && *args_ptr)
    vlua_val_vec_free (args_ptr);
  return 0;
}

static int
vlua_method_fn_thunk (lua_State *L)
{
  vlua_method_handle_t mh =
    *(vlua_method_handle_t *) lua_touserdata (L, lua_upvalueindex (1));
  int argc = lua_gettop (L);
  int data_results = 0;
  vlua_method_fn_t target_func;
  clib_error_t *err;
  vlua_val_t **args_guard;

  vlua_method_fn_args_t a = {
    .handle = mh->handle,
    .context = mh->context,
    .context_size = mh->context_size,
  };

  if (mh == 0 || mh->func == 0)
    {
      lua_pushnil (L);
      lua_pushstring (L, "method missing");
      return 2;
    }

  args_guard = lua_newuserdatauv (L, sizeof (vlua_val_t *), 0);
  *args_guard = 0;
  if (luaL_newmetatable (L, "vlua_args_guard"))
    {
      lua_pushcfunction (L, vlua_args_guard_gc);
      lua_setfield (L, -2, "__gc");
    }
  lua_setmetatable (L, -2);

  /* Convert Lua stack arguments into typed plugin values. */
  for (int i = 1; i <= argc; ++i)
    {
      vlua_val_t value = { 0 };
      if (!vlua_val_from_lua (L, i, &value))
	{
	  vec_free (a.args);
	  return luaL_error (L, "unsupported argument #%d (%s)", i,
			     luaL_typename (L, i));
	}
      vec_add1 (a.args, value);
    }
  *args_guard = a.args;

  if (mh->context_size > 0 && a.context == 0)
    vlua_log_err (mh->handle,
		  "method thunk missing context (expected %u bytes)",
		  (u32) mh->context_size);
  if (0)
    vlua_log_debug (mh->handle,
		    "method thunk invoked (context_bytes=%u argc=%d)",
		    (u32) a.context_size, argc);

  target_func = mh->func;
  if (vec_len (mh->signatures) > 0)
    {
      vlua_fn_and_args_t *match =
	vlua_fn_and_args_find (mh->signatures, a.args);

      if (!match)
	{
	  const char *name =
	    mh->name ? (const char *) mh->name : "<unnamed method>";
	  vlua_log_err (mh->handle,
			"method '%s' called with unsupported arguments", name);
	  *args_guard = 0;
	  vlua_val_vec_free (&a.args);
	  return luaL_error (
	    L, "method '%s' called with unsupported arguments", name);
	}

      target_func = match->method_fn ? match->method_fn : mh->func;
    }

  err = target_func (&a);
  *args_guard = 0;
  vlua_val_vec_free (&a.args);
  mh->context = 0;
  mh->context_size = 0;
  if (err)
    {
      vlua_val_vec_free (&a.returns);
      lua_pushnil (L);
      vlua_pushlstring (L, "%U", format_clib_error, err);
      clib_error_free (err);
      return 2;
    }

  if (vec_len (a.returns) == 0)
    {
      lua_pushnil (L);
      data_results = 1;
    }
  else
    {
      vlua_val_t *v;
      vec_foreach (v, a.returns)
	{
	  vlua_val_push (L, v);
	  data_results++;
	}
    }
  lua_pushnil (L);
  vlua_val_vec_free (&a.returns);
  return data_results + 1;
}

__clib_export vlua_method_handle_t
vlua_method_add (vlua_handle_t h, vlua_table_handle_t th, const char *fmt, ...)
{
  lua_State *L = vlua_get_state (h);
  vlua_method_handle_t mh;
  va_list va;
  u8 *name;
  const char *method;

  ASSERT (th);
  ASSERT (fmt && fmt[0] != '\0');

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  if (vec_len (name) == 0)
    {
      vec_free (name);
      return 0;
    }

  vec_add1 (name, 0);

  lua_rawgeti (L, LUA_REGISTRYINDEX, th->ref);
  ASSERT (lua_istable (L, -1));

  mh = clib_mem_alloc (sizeof (*mh));
  *mh = (struct vlua_method_t){
    .handle = h,
    .name = name,
  };
  mh->table_handle = th;

  method = (const char *) mh->name;
  *(vlua_method_handle_t *) lua_newuserdatauv (
    L, sizeof (vlua_method_handle_t), 0) = mh;

  /* lua_pushcclosure creates the callable C closure with one upvalue. */
  /* lua_setfield assigns the closure into the namespace table. */
  lua_pushcclosure (L, vlua_method_fn_thunk, 1);
  lua_setfield (L, -2, method);

  if (th->ns_handle)
    {
      vlua_ns_handle_t nh = th->ns_handle;
      vlua_ns_rt_method_t slot;
      lua_getfield (L, -1, method);
      ASSERT (lua_isfunction (L, -1));
      if (!vlua_cfunction_runtime (L, h, -1, th, method ? method : ""))
	{
	  lua_pop (L, 2); /* drop function and table */
	  vlua_log_err (h, "%U.%s is not callable", vlua_format_table_path, th,
			method);
	  goto error;
	}
      lua_pop (L, 1); /* drop function; leave table on stack */
      slot = (vlua_ns_rt_method_t){
	.name = method,
      };
      vec_add1 (nh->methods, slot);
      vlua_log_debug (h, "attached method %U.%s", vlua_format_table_path, th,
		      method);
    }
  /* lua_pop removes the namespace table from the stack. */
  lua_pop (L, 1);
  vec_add1 (h->methods, mh);
  vlua_log_debug (h, "registered %U.%s()", vlua_format_table_path, th, method);
  return mh;
error:
  if (mh)
    vlua_method_handle_free (mh);
  return 0;
}

__clib_export void
vlua_method_add_call_args (vlua_method_handle_t mh, vlua_method_fn_t func,
			   u32 n_args, ...)
{
  vlua_fn_and_args_t *sig;
  va_list va;

  ASSERT (mh);
  ASSERT (func);

  vec_add2 (mh->signatures, sig, 1);
  sig->method_fn = func;
  if (mh->func == 0)
    mh->func = func;
  va_start (va, n_args);
  for (u32 i = 0; i < n_args; ++i)
    {
      vlua_type_t t = (vlua_type_t) va_arg (va, int);
      vec_add1 (sig->args, t);
    }
  va_end (va);
}
