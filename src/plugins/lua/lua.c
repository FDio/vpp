#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "external.h"
#include "internal.h"

#include <stdarg.h>

#include <vppinfra/format.h>

VLIB_REGISTER_LOG_CLASS (lua_log) = {
  .class_name = "lua",
  .subclass_name = "main",
};

vlua_handle_t
vlua_create (void)
{
  struct vlua_handle_t *h = clib_mem_alloc (sizeof (struct vlua_handle_t));
  *h = (struct vlua_handle_t){
    .L = luaL_newstate (),
  };
  luaL_openlibs (h->L);
  return h;
}

void
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
  lua_close (h->L);
  clib_mem_free (h);
}

clib_error_t *
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

clib_error_t *
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
