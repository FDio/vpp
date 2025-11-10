/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <stdarg.h>
#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

void
vlua_val_vec_add_nil (vlua_val_t **vecp)
{
  vlua_val_t v = {
    .type = VLUA_T_NIL,
  };
  vec_add1 (*vecp, v);
}

void
vlua_val_vec_add_bool (vlua_val_t **vecp, bool value)
{
  vlua_val_t v = {
    .type = VLUA_T_BOOL,
    .bool_value = value,
  };
  vec_add1 (*vecp, v);
}

void
vlua_val_vec_add_number (vlua_val_t **vecp, i64 number)
{
  vlua_val_t v = {
    .type = VLUA_T_NUMBER,
    .number_value = (double) number,
  };
  vec_add1 (*vecp, v);
}

void
vlua_val_vec_add_integer (vlua_val_t **vecp, i64 value)
{
  vlua_val_t v = {
    .type = VLUA_T_INTEGER,
    .integer_value = value,
  };
  vec_add1 (*vecp, v);
}

void
vlua_val_vec_add_string (vlua_val_t **vecp, const char *fmt, ...)
{
  va_list va;
  vlua_val_t v = {
    .type = VLUA_T_STRING,
  };

  va_start (va, fmt);
  v.string_value = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (*vecp, v);
}

void
vlua_val_vec_free (vlua_val_t **vecp)
{
  vlua_val_t *vec = *vecp;
  if (!vec)
    return;
  /* Strings own heap memory; release them before dropping the vector. */
  vlua_val_t *value;
  vec_foreach (value, vec)
    {
      if (value->type == VLUA_T_STRING && value->string_value)
	vec_free (value->string_value);
    }
  vec_free (vec);
  *vecp = 0;
}

static void
vlua_val_reset (vlua_val_t *v)
{
  if (!v)
    return;

  if (v->type == VLUA_T_STRING && v->string_value)
    vec_free (v->string_value);

  clib_memset (v, 0, sizeof (*v));
}

bool
vlua_val_from_lua (lua_State *L, int index, vlua_val_t *value)
{
  vlua_val_reset (value);
  switch (lua_type (L, index))
    {
    case LUA_TSTRING:
      {
	size_t sz;
	const char *str = lua_tolstring (L, index, &sz);
	vec_add (value->string_value, str, sz);
	value->type = VLUA_T_STRING;
	return true;
      }
    case LUA_TNUMBER:
      if (lua_isinteger (L, index))
	{
	  value->type = VLUA_T_INTEGER;
	  value->integer_value = lua_tointeger (L, index);
	}
      else
	{
	  value->type = VLUA_T_NUMBER;
	  value->number_value = lua_tonumber (L, index);
	}
      return true;
    case LUA_TBOOLEAN:
      value->type = VLUA_T_BOOL;
      value->bool_value = lua_toboolean (L, index);
      return true;
    case LUA_TNIL:
      value->type = VLUA_T_NIL;
      return true;
    default:
      return false;
    }
}

void
vlua_val_push (lua_State *L, vlua_val_t *value)
{
  switch (value->type)
    {
    case VLUA_T_STRING:
      if (vec_len (value->string_value))
	{
	  lua_pushlstring (L, (const char *) value->string_value,
			   vec_len (value->string_value));
	  vec_free (value->string_value);
	}
      else
	lua_pushnil (L);
      break;
    case VLUA_T_NUMBER:
      lua_pushnumber (L, value->number_value);
      break;
    case VLUA_T_INTEGER:
      lua_pushinteger (L, value->integer_value);
      break;
    case VLUA_T_BOOL:
      lua_pushboolean (L, value->bool_value);
      break;
    case VLUA_T_NIL:
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
  vlua_val_t *value = va_arg (*args, vlua_val_t *);

  switch (value->type)
    {
    case VLUA_T_STRING:
      return format (s, "%v", value->string_value);
    case VLUA_T_NUMBER:
      return format (s, "%f", value->number_value);
    case VLUA_T_INTEGER:
      return format (s, "%lld", (long long) value->integer_value);
    case VLUA_T_BOOL:
      return format (s, "%s", value->bool_value ? "true" : "false");
    case VLUA_T_NIL:
      return format (s, "nil");
    default:
      return format (s, "<unknown>");
    }
}

bool
vlua_val_match_types (const vlua_val_t *values, u32 value_count,
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
vlua_val_is_string (const vlua_val_t *value, const char *fmt, ...)
{
  ASSERT (value && value->type == VLUA_T_STRING);
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
vlua_val_is_bool (const vlua_val_t *value, bool expected)
{
  ASSERT (value && value->type == VLUA_T_BOOL);
  return value->bool_value == expected;
}

bool
vlua_val_is_integer (const vlua_val_t *value, i64 expected)
{
  ASSERT (value && value->type == VLUA_T_INTEGER);
  return value->integer_value == expected;
}

bool
vlua_val_is_number (const vlua_val_t *value, double expected)
{
  ASSERT (value && value->type == VLUA_T_NUMBER);
  return value->number_value == expected;
}

bool
vlua_val_is_nil (const vlua_val_t *value)
{
  ASSERT (value);
  return value->type == VLUA_T_NIL;
}

bool
vlua_val_type_is_string (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_STRING;
}

bool
vlua_val_type_is_number (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_NUMBER;
}

bool
vlua_val_type_is_integer (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_INTEGER;
}

bool
vlua_val_type_is_bool (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_BOOL;
}

bool
vlua_val_type_is_nil (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_NIL;
}

bool
vlua_val_vec_type_is_string (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_string (vec + index);
}

bool
vlua_val_vec_type_is_number (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_number (vec + index);
}

bool
vlua_val_vec_type_is_integer (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_integer (vec + index);
}

bool
vlua_val_vec_type_is_bool (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_bool (vec + index);
}

bool
vlua_val_vec_type_is_nil (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_nil (vec + index);
}

const u8 *
vlua_val_get_string (const vlua_val_t *value, u32 *len)
{
  ASSERT (vlua_val_type_is_string (value));
  if (len)
    *len = vec_len (value->string_value);
  return value->string_value;
}

const u8 *
vlua_val_vec_get_string (const vlua_val_t *vec, u32 index, u32 *len)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_string (vec + index, len);
}

void
vlua_val_set_string (vlua_val_t *value, const char *fmt, ...)
{
  vlua_val_reset (value);
  value->type = VLUA_T_STRING;
  va_list va;
  va_start (va, fmt);
  value->string_value = va_format (0, fmt, &va);
  va_end (va);
}

double
vlua_val_get_number (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_number (value));
  return value->number_value;
}

double
vlua_val_vec_get_number (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_number (vec + index);
}

void
vlua_val_set_number (vlua_val_t *value, double number)
{
  vlua_val_reset (value);
  value->type = VLUA_T_NUMBER;
  value->number_value = number;
}

i64
vlua_val_get_integer (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_integer (value));
  return value->integer_value;
}

i64
vlua_val_vec_get_integer (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_integer (vec + index);
}

void
vlua_val_set_integer (vlua_val_t *value, i64 number)
{
  vlua_val_reset (value);
  value->type = VLUA_T_INTEGER;
  value->integer_value = number;
}

bool
vlua_val_get_bool (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_bool (value));
  return value->bool_value;
}

bool
vlua_val_vec_get_bool (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_bool (vec + index);
}

void
vlua_val_set_bool (vlua_val_t *value, bool flag)
{
  vlua_val_reset (value);
  value->type = VLUA_T_BOOL;
  value->bool_value = flag;
}

void
vlua_val_set_nil (vlua_val_t *value)
{
  vlua_val_reset (value);
  value->type = VLUA_T_NIL;
}
#include <stdarg.h>
