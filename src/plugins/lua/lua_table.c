/* SPDX-License-Identifier: Apache-2.0 */

#include "internal.h"

#include <string.h>

#include <vppinfra/vec.h>
#include <vppinfra/format.h>

VLIB_REGISTER_LOG_CLASS (lua_log, static) = {
  .class_name = "lua",
  .subclass_name = "table",
};

static vlua_table_handle_t
vlua_table_find_child (vlua_handle_t h, vlua_table_handle_t parent,
		       const char *name)
{
  if (h == 0 || name == 0)
    return 0;

  if (parent)
    {
      vlua_table_handle_t *hp = 0;
      vec_foreach (hp, parent->children)
	{
	  vlua_table_handle_t child = *hp;
	  if (child && child->name &&
	      strcmp ((const char *) child->name, name) == 0)
	    return child;
	}
      return 0;
    }

  vlua_table_handle_t *hp = 0;
  vec_foreach (hp, h->table_handles)
    {
      vlua_table_handle_t handle = *hp;
      if (handle && handle->parent == 0 && handle->name &&
	  strcmp ((const char *) handle->name, name) == 0)
	return handle;
    }

  return 0;
}

vlua_table_handle_t
vlua_table_add (vlua_handle_t h, const char *name, vlua_table_handle_t parent)
{
  lua_State *L = vlua_get_state (h);

  if (h == 0 || L == 0)
    return 0;

  vlua_table_handle_t existing = vlua_table_find_child (h, parent, name);
  if (existing)
    return existing;

  int table_index = 0;

  if (parent == 0)
    {
      /* Root namespaces are stored as globals. */
      lua_getglobal (L, name);
      if (lua_isnil (L, -1))
	{
	  lua_pop (L, 1);
	  lua_newtable (L);
	  lua_pushvalue (L, -1);
	  lua_setglobal (L, name);
	}
      else if (!lua_istable (L, -1))
	{
	  lua_pop (L, 1);
	  log_err ("global '%s' exists but is not a table", name);
	  return 0;
	}
      table_index = lua_gettop (L);
    }
  else
    {
      /* Child tables hang under the parent's registry reference. */
      lua_rawgeti (L, LUA_REGISTRYINDEX, parent->ref);
      if (!lua_istable (L, -1))
	{
	  lua_pop (L, 1);
	  log_err ("parent table handle for '%s' is invalid", name);
	  return 0;
	}

      lua_getfield (L, -1, name);
      if (lua_isnil (L, -1))
	{
	  lua_pop (L, 1);
	  lua_newtable (L);
	  lua_pushvalue (L, -1);
	  lua_setfield (L, -3, name);
	}
      else if (!lua_istable (L, -1))
	{
	  u8 *parent_path = format (0, "%U", vlua_format_table_path, parent);
	  lua_pop (L, 2);
	  log_err ("'%v.%s' exists but is not a table", parent_path, name);
	  vec_free (parent_path);
	  return 0;
	}

      lua_remove (L, -2);
      table_index = lua_gettop (L);
    }

  lua_pushvalue (L, table_index);
  int ref = luaL_ref (L, LUA_REGISTRYINDEX);
  lua_pop (L, 1);

  vlua_table_handle_t handle = clib_mem_alloc (sizeof (*handle));
  *handle = (struct vlua_table_handle){
    .parent = parent,
    .name = (u8 *) format (0, "%s", name),
    .ref = ref,
    .ns_handle = 0,
    .children = 0,
  };

  if (parent)
    vec_add1 (parent->children, handle);

  vec_add1 (h->table_handles, handle);
  return handle;
}
