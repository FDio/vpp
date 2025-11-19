/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <stdarg.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

static void
vlua_pushvfstring (lua_State *L, const char *fmt, va_list *va)
{
  u8 *msg = va_format (0, fmt, va);
  msg = format (msg, "%c", 0);
  lua_pushlstring (L, (const char *) msg, vec_len (msg));
  vec_free (msg);
}

void
vlua_pushfstring (lua_State *L, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_pushvfstring (L, fmt, &va);
  va_end (va);
}

int
vlua_return_err (lua_State *L, const char *fmt, ...)
{
  va_list va;
  lua_pushnil (L);
  va_start (va, fmt);
  vlua_pushvfstring (L, fmt, &va);
  va_end (va);
  return 2;
}

int
vlua_errorf (lua_State *L, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_pushvfstring (L, fmt, &va);
  va_end (va);
  return lua_error (L);
}

bool
vlua_lua_types_match (lua_State *L, int start_index, const vlua_type_t *types,
		      u32 count)
{
  if (!types)
    return count == 0;

  for (u32 i = 0; i < count; ++i)
    {
      if (types[i] != vlua_type_from_lua (L, start_index + i))
	return false;
    }
  return true;
}

vlua_type_t
vlua_type_from_lua (lua_State *L, int index)
{
  switch (lua_type (L, index))
    {
    case LUA_TSTRING:
      return VLUA_T_STRING;
    case LUA_TNUMBER:
      return lua_isinteger (L, index) ? VLUA_T_INTEGER : VLUA_T_NUMBER;
    case LUA_TBOOLEAN:
      return VLUA_T_BOOL;
    case LUA_TNIL:
      return VLUA_T_NIL;
    default:
      return (vlua_type_t) ~0;
    }
}

vlua_fn_and_args_t *
vlua_fn_and_args_find (vlua_fn_and_args_t *vec, const vlua_val_t *values)
{
  vlua_fn_and_args_t *entry;
  u32 count = vec_len (values);

  if (!vec)
    return 0;

  vec_foreach (entry, vec)
    {
      bool match = true;

      if (vec_len (entry->args) != count)
	continue;

      for (u32 i = 0; i < count; ++i)
	{
	  if (entry->args[i] != values[i].type)
	    {
	      match = false;
	      break;
	    }
	}

      if (match)
	return entry;
    }
  return 0;
}
void
vlua_pushlstring (lua_State *L, const char *fmt, ...)
{
  va_list va;
  u8 *msg;

  va_start (va, fmt);
  msg = va_format (0, fmt, &va);
  va_end (va);

  lua_pushlstring (L, (const char *) msg, vec_len (msg));
  vec_free (msg);
}
