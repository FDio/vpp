/* SPDX-License-Identifier: Apache-2.0 */

#include "internal.h"

#include <stdarg.h>
#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

VLIB_REGISTER_LOG_CLASS (lua_log, static) = {
  .class_name = "lua",
  .subclass_name = "value",
};

void
vlua_value_add_nil (vlua_value_t **vecp)
{
  vlua_value_t v = {
    .type = VPP_LUA_T_NIL,
  };
  vec_add1 (*vecp, v);
}

void
vlua_value_add_bool (vlua_value_t **vecp, bool value)
{
  vlua_value_t v = {
    .type = VPP_LUA_T_BOOL,
    .bool_value = value,
  };
  vec_add1 (*vecp, v);
}

void
vlua_value_add_number (vlua_value_t **vecp, i64 number)
{
  vlua_value_t v = {
    .type = VPP_LUA_T_NUMBER,
    .number_value = (double) number,
  };
  vec_add1 (*vecp, v);
}

void
vlua_value_add_integer (vlua_value_t **vecp, i64 value)
{
  vlua_value_t v = {
    .type = VPP_LUA_T_INTEGER,
    .integer_value = value,
  };
  vec_add1 (*vecp, v);
}

void
vlua_value_add_string (vlua_value_t **vecp, const char *fmt, ...)
{
  va_list va;
  vlua_value_t v = {
    .type = VPP_LUA_T_STRING,
  };

  va_start (va, fmt);
  v.string_value = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (*vecp, v);
}

void
vlua_value_vec_free (vlua_value_t **vecp)
{
  vlua_value_t *vec = *vecp;
  if (!vec)
    return;
  /* Strings own heap memory; release them before dropping the vector. */
  vlua_value_t *value;
  vec_foreach (value, vec)
    {
      if (value->type == VPP_LUA_T_STRING && value->string_value)
	vec_free (value->string_value);
    }
  vec_free (vec);
  *vecp = 0;
}

bool
vlua_value_from_lua (lua_State *L, int index, vlua_value_t *value)
{
  clib_memset (value, 0, sizeof (*value));
  switch (lua_type (L, index))
    {
    case LUA_TSTRING:
      {
	size_t sz;
	const char *str = lua_tolstring (L, index, &sz);
	vec_add (value->string_value, str, sz);
	value->type = VPP_LUA_T_STRING;
	return true;
      }
    case LUA_TNUMBER:
      if (lua_isinteger (L, index))
	{
	  value->type = VPP_LUA_T_INTEGER;
	  value->integer_value = lua_tointeger (L, index);
	}
      else
	{
	  value->type = VPP_LUA_T_NUMBER;
	  value->number_value = lua_tonumber (L, index);
	}
      return true;
    case LUA_TBOOLEAN:
      value->type = VPP_LUA_T_BOOL;
      value->bool_value = lua_toboolean (L, index);
      return true;
    case LUA_TNIL:
      value->type = VPP_LUA_T_NIL;
      return true;
    default:
      return false;
    }
}

void
vlua_value_push (lua_State *L, vlua_value_t *value)
{
  switch (value->type)
    {
    case VPP_LUA_T_STRING:
      if (vec_len (value->string_value))
	{
	  lua_pushlstring (L, (const char *) value->string_value,
			   vec_len (value->string_value));
	  vec_free (value->string_value);
	}
      else
	lua_pushnil (L);
      break;
    case VPP_LUA_T_NUMBER:
      lua_pushnumber (L, value->number_value);
      break;
    case VPP_LUA_T_INTEGER:
      lua_pushinteger (L, value->integer_value);
      break;
    case VPP_LUA_T_BOOL:
      lua_pushboolean (L, value->bool_value);
      break;
    case VPP_LUA_T_NIL:
      lua_pushnil (L);
      break;
    default:
      ASSERT (0);
      break;
    }
}

u8 *
format_vlua_value (u8 *s, va_list *args)
{
  vlua_value_t *value = va_arg (*args, vlua_value_t *);

  switch (value->type)
    {
    case VPP_LUA_T_STRING:
      return format (s, "%v", value->string_value);
    case VPP_LUA_T_NUMBER:
      return format (s, "%f", value->number_value);
    case VPP_LUA_T_INTEGER:
      return format (s, "%lld", (long long) value->integer_value);
    case VPP_LUA_T_BOOL:
      return format (s, "%s", value->bool_value ? "true" : "false");
    case VPP_LUA_T_NIL:
      return format (s, "nil");
    default:
      return format (s, "<unknown>");
    }
}

bool
vlua_value_match_types (const vlua_value_t *values, u32 value_count,
			const vlua_type_t *types)
{
  if (!types)
    return value_count == 0;

  for (u32 i = 0; i < value_count; ++i)
    {
      if (values[i].type != types[i])
	return false;
    }
  return true;
}

bool
vlua_value_is_string (const vlua_value_t *value, const char *fmt, ...)
{
  ASSERT (value && value->type == VPP_LUA_T_STRING);
  bool result = false;
  va_list va;
  va_start (va, fmt);
  u8 *s = va_format (0, fmt, &va);
  va_end (va);

  if (vec_len (s) == vec_len (value->string_value) &&
      memcmp (s, value->string_value, vec_len (s)) == 0)
    result = true;

  vec_free (s);
  return result;
}

bool
vlua_value_is_bool (const vlua_value_t *value, bool expected)
{
  ASSERT (value && value->type == VPP_LUA_T_BOOL);
  return value->bool_value == expected;
}

bool
vlua_value_is_integer (const vlua_value_t *value, i64 expected)
{
  ASSERT (value && value->type == VPP_LUA_T_INTEGER);
  return value->integer_value == expected;
}

bool
vlua_value_is_number (const vlua_value_t *value, double expected)
{
  ASSERT (value && value->type == VPP_LUA_T_NUMBER);
  return value->number_value == expected;
}

bool
vlua_value_is_nil (const vlua_value_t *value)
{
  ASSERT (value);
  return value->type == VPP_LUA_T_NIL;
}
