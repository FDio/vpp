/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <vlua/vlua.h>
#include <vlua/internal.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>
#include <string.h>

__clib_export vlua_init_fn_registration_t *vlua_init_registrations;

static vlua_table_handle_t
vlua_table_ensure_path (vlua_handle_t h, const char *path)
{
  vlua_table_handle_t parent = 0;
  vlua_table_handle_t handle = 0;
  const char *segment = path;

  if (!segment || !segment[0])
    return 0;

  while (*segment)
    {
      const char *dot = strchr (segment, '.');
      size_t len = dot ? (size_t) (dot - segment) : strlen (segment);
      u8 *name = 0;

      vec_add (name, segment, len);
      vec_add1 (name, 0);

      handle = vlua_table_add (h, (const char *) name, parent);
      vec_free (name);

      if (!handle)
	return 0;

      parent = handle;

      if (!dot)
	break;
      segment = dot + 1;
    }

  return handle;
}

__clib_export vlua_handle_t
vlua_create (vlua_create_args_t *args)
{
  struct vlua_handle_t *h = clib_mem_alloc (sizeof (struct vlua_handle_t));
  *h = (struct vlua_handle_t){
    .L = luaL_newstate (),
    .log_cb = args ? args->log_cb : 0,
    .path_prefix = 0,
  };
  luaL_openlibs (h->L);
  const char *prefix = (args && args->path_prefix && args->path_prefix[0]) ?
			 args->path_prefix :
			 "vlua";
  h->path_prefix = format (0, "%s", prefix);
  return h;
}

__clib_export void
vlua_destroy (vlua_handle_t h)
{
  if (h == 0)
    return;
  lua_State *L = h->L;
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
  vec_free (h->path_prefix);
  lua_close (h->L);
  clib_mem_free (h);
}

__clib_export clib_error_t *
vlua_run_string (vlua_handle_t h, const char *code)
{
  lua_State *L = vlua_get_state (h);
  clib_error_t *err;
  const char *msg;
  ASSERT (L != 0);
  ASSERT (code != 0);

  if (luaL_loadstring (L, code) != LUA_OK)
    {
      msg = lua_tostring (L, -1);
      err = clib_error_return (0, "lua load failure: '%s'", msg ? msg : "");
      lua_pop (L, 1); /* drop error message */
      return err;
    }

  if (lua_pcall (L, 0, 0, 0) != LUA_OK)
    {
      msg = lua_tostring (L, -1);
      err = clib_error_return (0, "lua runtime failure: '%s;", msg ? msg : "");
      lua_pop (L, 1); /* drop runtime error */
      return err;
    }
  return 0;
}

__clib_export clib_error_t *
vlua_run_file (vlua_handle_t h, const char *fmt, ...)
{
  lua_State *L = vlua_get_state (h);
  clib_error_t *err = 0;
  const char *msg;
  va_list va;
  u8 *path = 0;

  ASSERT (L != 0);
  ASSERT (fmt != 0);

  va_start (va, fmt);
  path = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (path, 0);

  if (luaL_loadfile (L, (const char *) path) != LUA_OK)
    {
      msg = lua_tostring (L, -1);
      err = clib_error_return (0, "lua load failure: '%s'", msg ? msg : "");
      lua_pop (L, 1);
      vec_free (path);
      goto done;
    }

  if (lua_pcall (L, 0, 0, 0) != LUA_OK)
    {
      msg = lua_tostring (L, -1);
      err = clib_error_return (0, "lua runtime failure: '%s'", msg ? msg : "");
      lua_pop (L, 1);
      goto done;
    }

done:
  vec_free (path);
  return err;
}

__clib_export void
vlua_run_init_functions (vlua_handle_t handle)
{
  for (vlua_init_fn_registration_t *it = vlua_init_registrations; it;
       it = it->next)
    {
      if (!it->paths)
	continue;

      for (const char *const *path = it->paths; *path; ++path)
	{
	  const char *raw = *path;
	  const char *use_path = raw;
	  u8 *prefixed = 0;
	  if (use_path && use_path[0] == '.')
	    {
	      const char *prefix =
		(handle && handle->path_prefix && handle->path_prefix[0]) ?
		  (const char *) handle->path_prefix :
		  "vlua";
	      prefixed = format (0, "%s%s", prefix, use_path);
	      use_path = (const char *) prefixed;
	    }
	  vlua_table_handle_t th = vlua_table_ensure_path (handle, use_path);
	  vec_add1 (it->table_handles_by_path, th);
	  vec_free (prefixed);
	}
    }

  for (vlua_init_fn_registration_t *it = vlua_init_registrations; it;
       it = it->next)
    {
      if (it->init_fn)
	{
	  vlua_init_fn_args_t args = {
	    .table_handles = it->table_handles_by_path,
	  };
	  it->init_fn (handle, &args);
	}

      vec_free (it->table_handles_by_path);
    }
}
