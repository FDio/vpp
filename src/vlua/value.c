/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <stdarg.h>
#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

#if LUA_VERSION_NUM < 502
static int
vlua_abs_index (lua_State *L, int idx)
{
  if (idx > 0 || idx <= LUA_REGISTRYINDEX)
    return idx;
  return lua_gettop (L) + idx + 1;
}
#else
#define vlua_abs_index lua_absindex
#endif

static void vlua_table_entries_free (vlua_table_entry_t **entries);
static vlua_table_entry_t *vlua_val_table_add_entry (vlua_val_t *table,
						     const char *key);

__clib_export void
vlua_val_vec_add_nil (vlua_val_t **vecp)
{
  vlua_val_t v = {
    .type = VLUA_T_NIL,
  };
  vec_add1 (*vecp, v);
}

__clib_export void
vlua_val_vec_add_bool (vlua_val_t **vecp, bool value)
{
  vlua_val_t v = {
    .type = VLUA_T_BOOL,
    .bool_value = value,
  };
  vec_add1 (*vecp, v);
}

__clib_export void
vlua_val_vec_add_number (vlua_val_t **vecp, i64 number)
{
  vlua_val_t v = {
    .type = VLUA_T_NUMBER,
    .number_value = (double) number,
  };
  vec_add1 (*vecp, v);
}

__clib_export void
vlua_val_vec_add_integer (vlua_val_t **vecp, i64 value)
{
  vlua_val_t v = {
    .type = VLUA_T_INTEGER,
    .integer_value = value,
  };
  vec_add1 (*vecp, v);
}

__clib_export void
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

__clib_export vlua_val_t *
vlua_val_vec_add_table (vlua_val_t **vecp)
{
  vlua_val_t v = {
    .type = VLUA_T_TABLE,
  };
  vec_add1 (*vecp, v);
  return &vec_end (*vecp)[-1];
}

__clib_export void
vlua_val_vec_free (vlua_val_t **vecp)
{
  vlua_val_t *vec = *vecp;
  vlua_val_t *value;
  if (!vec)
    return;
  /* Strings own heap memory; release them before dropping the vector. */
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
  else if (v->type == VLUA_T_TABLE && v->table_entries)
    vlua_table_entries_free (&v->table_entries);

  *v = (vlua_val_t){ 0 };
}

bool
vlua_val_from_lua (lua_State *L, int index, vlua_val_t *value)
{
  int abs_index = vlua_abs_index (L, index);
  vlua_val_reset (value);
  switch (lua_type (L, abs_index))
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
    case LUA_TTABLE:
      {
	vlua_table_entry_t *entries = 0;
	lua_pushnil (L);
	while (lua_next (L, abs_index) != 0)
	  {
	    size_t key_len;
	    const char *key;
	    vlua_val_t entry_value = { 0 };
	    vlua_table_entry_t *entry;

	    if (!lua_isstring (L, -2))
	      {
		lua_pop (L, 1);
		continue;
	      }
	    key = lua_tolstring (L, -2, &key_len);
	    if (!vlua_val_from_lua (L, -1, &entry_value))
	      {
		lua_pop (L, 1);
		continue;
	      }
	    vec_add2 (entries, entry, 1);
	    entry->key = 0;
	    vec_add (entry->key, key, key_len);
	    vec_add1 (entry->key, 0);
	    entry->value = entry_value;
	    lua_pop (L, 1);
	  }
	value->type = VLUA_T_TABLE;
	value->table_entries = entries;
	return true;
      }
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
    case VLUA_T_TABLE:
      {
	vlua_table_entry_t *entry;
	lua_createtable (
	  L, 0, value->table_entries ? vec_len (value->table_entries) : 0);
	vec_foreach (entry, value->table_entries)
	  {
	    lua_pushstring (L, (const char *) entry->key);
	    vlua_val_push (L, &entry->value);
	    lua_settable (L, -3);
	  }
	vlua_table_entries_free (&value->table_entries);
	break;
      }
    default:
      ASSERT (0);
      break;
    }
}

__clib_export u8 *
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

__clib_export bool
vlua_val_is_string (const vlua_val_t *value, const char *fmt, ...)
{
  bool result = false;
  va_list va;
  u8 *s;

  ASSERT (value && value->type == VLUA_T_STRING);
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (vec_len (s) == vec_len (value->string_value) &&
      memcmp (s, value->string_value, vec_len (s)) == 0)
    result = true;

  vec_free (s);
  return result;
}

__clib_export bool
vlua_val_is_bool (const vlua_val_t *value, bool expected)
{
  ASSERT (value && value->type == VLUA_T_BOOL);
  return value->bool_value == expected;
}

__clib_export bool
vlua_val_is_integer (const vlua_val_t *value, i64 expected)
{
  ASSERT (value && value->type == VLUA_T_INTEGER);
  return value->integer_value == expected;
}

__clib_export bool
vlua_val_is_number (const vlua_val_t *value, double expected)
{
  ASSERT (value && value->type == VLUA_T_NUMBER);
  return value->number_value == expected;
}

__clib_export bool
vlua_val_is_nil (const vlua_val_t *value)
{
  ASSERT (value);
  return value->type == VLUA_T_NIL;
}

__clib_export bool
vlua_val_type_is_string (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_STRING;
}

__clib_export bool
vlua_val_type_is_number (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_NUMBER;
}

__clib_export bool
vlua_val_type_is_integer (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_INTEGER;
}

__clib_export bool
vlua_val_type_is_bool (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_BOOL;
}

__clib_export bool
vlua_val_type_is_table (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_TABLE;
}

__clib_export bool
vlua_val_type_is_nil (const vlua_val_t *value)
{
  return value && value->type == VLUA_T_NIL;
}

static void
vlua_table_entries_free (vlua_table_entry_t **entries)
{
  vlua_table_entry_t *entry;

  if (!entries || !*entries)
    return;

  vec_foreach (entry, *entries)
    {
      vec_free (entry->key);
      vlua_val_reset (&entry->value);
    }
  vec_free (*entries);
  *entries = 0;
}

__clib_export bool
vlua_val_vec_type_is_string (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_string (vec + index);
}

__clib_export bool
vlua_val_vec_type_is_number (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_number (vec + index);
}

__clib_export bool
vlua_val_vec_type_is_integer (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_integer (vec + index);
}

__clib_export bool
vlua_val_vec_type_is_bool (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_bool (vec + index);
}

__clib_export bool
vlua_val_vec_type_is_table (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_table (vec + index);
}

__clib_export bool
vlua_val_vec_type_is_nil (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_type_is_nil (vec + index);
}

__clib_export const u8 *
vlua_val_get_string (const vlua_val_t *value, u32 *len)
{
  ASSERT (vlua_val_type_is_string (value));
  if (len)
    *len = vec_len (value->string_value);
  return value->string_value;
}

__clib_export const u8 *
vlua_val_vec_get_string (const vlua_val_t *vec, u32 index, u32 *len)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_string (vec + index, len);
}

__clib_export void
vlua_val_set_string (vlua_val_t *value, const char *fmt, ...)
{
  va_list va;

  vlua_val_reset (value);
  value->type = VLUA_T_STRING;
  va_start (va, fmt);
  value->string_value = va_format (0, fmt, &va);
  va_end (va);
}

__clib_export double
vlua_val_get_number (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_number (value));
  return value->number_value;
}

__clib_export double
vlua_val_vec_get_number (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_number (vec + index);
}

__clib_export void
vlua_val_set_number (vlua_val_t *value, double number)
{
  vlua_val_reset (value);
  value->type = VLUA_T_NUMBER;
  value->number_value = number;
}

__clib_export i64
vlua_val_get_integer (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_integer (value));
  return value->integer_value;
}

__clib_export i64
vlua_val_vec_get_integer (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_integer (vec + index);
}

__clib_export void
vlua_val_set_integer (vlua_val_t *value, i64 number)
{
  vlua_val_reset (value);
  value->type = VLUA_T_INTEGER;
  value->integer_value = number;
}

__clib_export bool
vlua_val_get_bool (const vlua_val_t *value)
{
  ASSERT (vlua_val_type_is_bool (value));
  return value->bool_value;
}

__clib_export bool
vlua_val_vec_get_bool (const vlua_val_t *vec, u32 index)
{
  ASSERT (vec && index < vec_len (vec));
  return vlua_val_get_bool (vec + index);
}

__clib_export void
vlua_val_set_bool (vlua_val_t *value, bool flag)
{
  vlua_val_reset (value);
  value->type = VLUA_T_BOOL;
  value->bool_value = flag;
}

__clib_export void
vlua_val_set_nil (vlua_val_t *value)
{
  vlua_val_reset (value);
  value->type = VLUA_T_NIL;
}

__clib_export void
vlua_val_table_add_string (vlua_val_t *table, const char *key, const char *fmt,
			   ...)
{
  vlua_table_entry_t *entry;
  va_list va;

  entry = vlua_val_table_add_entry (table, key);
  entry->value.type = VLUA_T_STRING;
  va_start (va, fmt);
  entry->value.string_value = va_format (0, fmt, &va);
  va_end (va);
}

__clib_export void
vlua_val_table_add_integer (vlua_val_t *table, const char *key, i64 value)
{
  vlua_table_entry_t *entry;

  entry = vlua_val_table_add_entry (table, key);
  entry->value.type = VLUA_T_INTEGER;
  entry->value.integer_value = value;
}

__clib_export void
vlua_val_table_add_number (vlua_val_t *table, const char *key, double value)
{
  vlua_table_entry_t *entry;

  entry = vlua_val_table_add_entry (table, key);
  entry->value.type = VLUA_T_NUMBER;
  entry->value.number_value = value;
}

__clib_export void
vlua_val_table_add_bool (vlua_val_t *table, const char *key, bool value)
{
  vlua_table_entry_t *entry;

  entry = vlua_val_table_add_entry (table, key);
  entry->value.type = VLUA_T_BOOL;
  entry->value.bool_value = value;
}

__clib_export void
vlua_val_table_add_nil (vlua_val_t *table, const char *key)
{
  vlua_table_entry_t *entry;

  entry = vlua_val_table_add_entry (table, key);
  entry->value.type = VLUA_T_NIL;
}

__clib_export const vlua_val_t *
vlua_val_table_get_entry (const vlua_val_t *table, const char *key)
{
  vlua_table_entry_t *entry;

  ASSERT (table && table->type == VLUA_T_TABLE && key);

  vec_foreach (entry, table->table_entries)
    {
      if (entry->key && strcmp ((const char *) entry->key, key) == 0)
	return &entry->value;
    }
  return 0;
}

static vlua_table_entry_t *
vlua_val_table_add_entry (vlua_val_t *table, const char *key)
{
  vlua_table_entry_t *entry;

  ASSERT (table && table->type == VLUA_T_TABLE);
  ASSERT (key);

  vec_add2 (table->table_entries, entry, 1);
  entry->key = format (0, "%s%c", key, 0);
  entry->value = (vlua_val_t){ 0 };
  return entry;
}
