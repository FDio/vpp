/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/pool.h>
#include <vppinfra/json.h>
#include <math.h>

typedef enum
{
  CLIB_JSON_PARENT_TEXT = 0,
  CLIB_JSON_PARENT_ARRAY,
  CLIB_JSON_PARENT_OBJECT
} clib_json_parent_type_t;

static clib_json_parent_type_t
clib_json_get_parent_type (clib_json_text_t *j)
{
  clib_json_value_t *v;
  if (j->current_value == -1)
    return CLIB_JSON_PARENT_TEXT;
  v = pool_elt_at_index (j->values, j->current_value);

  if (v->type == CLIB_JSON_VALUE_OBJECT)
    return CLIB_JSON_PARENT_OBJECT;
  ASSERT (v->type == CLIB_JSON_VALUE_ARRAY);
  return CLIB_JSON_PARENT_ARRAY;
}

static clib_json_value_t *
clib_json_get_current_value (clib_json_text_t *j)
{
  if (j->current_value == -1)
    return 0;
  return pool_elt_at_index (j->values, j->current_value);
}

/* Creates new value as a child of the current value, name is a vector
 * which is consumed (only object members have names). Returns index of the
 * new value or -1 if the value cannot be added at the current position. */
static int
clib_json_new_value (clib_json_text_t *j, clib_json_value_type_t type, u8 *name)
{
  clib_json_value_t *v, *p;
  clib_json_parent_type_t parent = clib_json_get_parent_type (j);
  int index;

  /* only object members have names, and they must have one */
  if ((parent == CLIB_JSON_PARENT_OBJECT) != (name != 0))
    goto error;

  /* the root value is the only one without a parent */
  if (parent == CLIB_JSON_PARENT_TEXT && j->root_value != -1)
    goto error;

  pool_get_zero (j->values, v);
  index = v - j->values;
  v->type = type;
  v->parent_value_index = j->current_value;

  if (parent == CLIB_JSON_PARENT_TEXT)
    {
      j->root_value = index;
      return index;
    }

  /* pool may grow */
  p = clib_json_get_current_value (j);

  if (parent == CLIB_JSON_PARENT_OBJECT)
    {
      clib_json_nvpair_t *nvp;
      pool_get_zero (p->nvpairs, nvp);
      nvp->name = name;
      nvp->value_index = index;
    }
  else
    vec_add1 (p->array_val_indices, index);

  return index;

error:
  vec_free (name);
  return -1;
}

static int
clib_json_new_value_va (clib_json_text_t *j, clib_json_value_type_t type, char *nfmt, va_list *va)
{
  return clib_json_new_value (j, type, nfmt ? va_format (0, nfmt, va) : 0);
}

__clib_export int
clib_json_add_null (clib_json_text_t *j, char *nfmt, ...)
{
  int index;
  va_list va;
  va_start (va, nfmt);
  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_NULL, nfmt, &va);
  va_end (va);
  return index;
}

__clib_export int
clib_json_add_true (clib_json_text_t *j, char *nfmt, ...)
{
  int index;
  va_list va;
  va_start (va, nfmt);
  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_TRUE, nfmt, &va);
  va_end (va);
  return index;
}

__clib_export int
clib_json_add_false (clib_json_text_t *j, char *nfmt, ...)
{
  int index;
  va_list va;
  va_start (va, nfmt);
  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_FALSE, nfmt, &va);
  va_end (va);
  return index;
}

__clib_export int
clib_json_add_string (clib_json_text_t *j, char *nfmt, char *sfmt, ...)
{
  int index;
  va_list va;
  va_start (va, sfmt);

  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_STRING, nfmt, &va);
  if (index >= 0)
    pool_elt_at_index (j->values, index)->string = va_format (0, sfmt, &va);

  va_end (va);
  return index;
}

__clib_export int
clib_json_add_number (clib_json_text_t *j, char *nfmt, f64 num, ...)
{
  int index;
  va_list va;
  va_start (va, num);

  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_NUMBER, nfmt, &va);
  if (index >= 0)
    pool_elt_at_index (j->values, index)->number = num;

  va_end (va);
  return index;
}

__clib_export int
clib_json_add_object (clib_json_text_t *j, char *nfmt, ...)
{
  int index;
  va_list va;
  va_start (va, nfmt);
  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_OBJECT, nfmt, &va);
  va_end (va);
  if (index >= 0)
    j->current_value = index;
  return index;
}

__clib_export int
clib_json_add_array (clib_json_text_t *j, char *nfmt, ...)
{
  int index;
  va_list va;
  va_start (va, nfmt);
  index = clib_json_new_value_va (j, CLIB_JSON_VALUE_ARRAY, nfmt, &va);
  va_end (va);
  if (index >= 0)
    j->current_value = index;
  return index;
}

__clib_export int
clib_json_get_top_value_index (clib_json_text_t *jt)
{
  return jt->root_value;
}

__clib_export int
clib_json_value_is_type (clib_json_text_t *jt, int value_index, clib_json_value_type_t type)
{
  clib_json_value_t *v;

  if (pool_is_free_index (jt->values, value_index))
    return 0;

  v = pool_elt_at_index (jt->values, value_index);
  if (v->type == type)
    return 1;
  return 0;
}

__clib_export int *
clib_json_get_array_value_indices (clib_json_text_t *j, int array_value_index)
{
  clib_json_value_t *v;

  if (!clib_json_value_is_array (j, array_value_index))
    return 0;

  v = pool_elt_at_index (j->values, array_value_index);
  return v->array_val_indices;
}

__clib_export int
clib_json_find_object_value_by_name (clib_json_text_t *j, int object_value_index, char *fmt, ...)
{
  clib_json_value_t *v;
  clib_json_nvpair_t *nvp;
  va_list va;
  u8 *name;
  int rv = CLIB_JSON_ERR_OBJECT_NAME_NOT_FOUND;

  if (!clib_json_value_is_object (j, object_value_index))
    return CLIB_JSON_ERR_INVALID_VALUE_TYPE;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  v = pool_elt_at_index (j->values, object_value_index);

  pool_foreach (nvp, v->nvpairs)
    if (vec_is_equal (name, nvp->name))
      {
	rv = nvp->value_index;
	break;
      }

  vec_free (name);

  return rv;
}

__clib_export uword
clib_json_unformat_string (clib_json_text_t *j, int value_index, char *fmt, ...)
{
  clib_json_value_t *v;
  unformat_input_t input;
  va_list va;
  uword result;

  if (!clib_json_value_is_string (j, value_index))
    return 0;

  v = pool_elt_at_index (j->values, value_index);

  unformat_init_string (&input, (char *) v->string, vec_len (v->string));

  va_start (va, fmt);
  result = va_unformat (&input, fmt, &va);
  va_end (va);

  unformat_free (&input);
  return result;
}

__clib_export void
clib_json_init (clib_json_text_t *j)
{
  clib_memset_u8 (j, 0, sizeof (j[0]));
  j->indent = 2;
  j->current_value = -1;
  j->root_value = -1;
}

static clib_error_t *
clib_json_parse (clib_json_text_t *j, unformat_input_t *input)
{
  clib_error_t *err = 0;
  clib_json_text_t tmp;

  clib_json_init (&tmp);

  if (!unformat (input, "%U", unformat_clib_json_value, &tmp))
    err = clib_error_return (0, "JSON parse error: %U", format_unformat_error, input);
  else if (tmp.root_value == -1 || tmp.current_value != -1)
    err = clib_error_return (0, "JSON parse error: incomplete text");

  if (err)
    clib_json_free (&tmp);
  else
    *j = tmp;

  unformat_free (input);
  return err;
}

__clib_export clib_error_t *
clib_json_init_from_file (clib_json_text_t *j, int fd)
{
  unformat_input_t input;

  unformat_init_clib_file (&input, fd);
  return clib_json_parse (j, &input);
}

__clib_export clib_error_t *
clib_json_init_from_string (clib_json_text_t *j, char *str, int len)
{
  unformat_input_t input;

  unformat_init_string (&input, str, len);
  return clib_json_parse (j, &input);
}

__clib_export void
clib_json_free (clib_json_text_t *j)
{
  clib_json_value_t *v;
  pool_foreach (v, j->values)
    {
      if (v->type == CLIB_JSON_VALUE_OBJECT)
	{
	  clib_json_nvpair_t *nvp;
	  pool_foreach (nvp, v->nvpairs)
	    vec_free (nvp->name);
	  pool_free (v->nvpairs);
	}
      else if (v->type == CLIB_JSON_VALUE_ARRAY)
	vec_free (v->array_val_indices);
      else if (v->type == CLIB_JSON_VALUE_STRING)
	vec_free (v->string);
    }
  pool_free (j->values);
}

static u8 *
format_json_string (u8 *s, va_list *args)
{
  u8 *str = va_arg (*args, u8 *);
  u32 i;

  vec_add1 (s, '"');
  vec_foreach_index (i, str)
    {
      u8 c = str[i];

      switch (c)
	{
	case '"':
	  s = format (s, "\\\"");
	  break;
	case '\\':
	  s = format (s, "\\\\");
	  break;
	case '\b':
	  s = format (s, "\\b");
	  break;
	case '\f':
	  s = format (s, "\\f");
	  break;
	case '\n':
	  s = format (s, "\\n");
	  break;
	case '\r':
	  s = format (s, "\\r");
	  break;
	case '\t':
	  s = format (s, "\\t");
	  break;
	default:
	  if (c < 0x20)
	    s = format (s, "\\u%04x", c);
	  else
	    vec_add1 (s, c);
	}
    }
  vec_add1 (s, '"');
  return s;
}

__clib_export u8 *
format_clib_json_value (u8 *s, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);
  u32 value_index = va_arg (*args, u32);
  clib_json_value_t *v = pool_elt_at_index (j->values, value_index);
  u32 i;

  switch (v->type)
    {
    case CLIB_JSON_VALUE_NULL:
      s = format (s, "null");
      break;
    case CLIB_JSON_VALUE_TRUE:
      s = format (s, "true");
      break;
    case CLIB_JSON_VALUE_FALSE:
      s = format (s, "false");
      break;
    case CLIB_JSON_VALUE_STRING:
      s = format (s, "%U", format_json_string, v->string);
      break;
    case CLIB_JSON_VALUE_NUMBER:
      if (isnan (v->number) || isinf (v->number))
	s = format (s, "null");
      else if (v->number == floor (v->number) && fabs (v->number) < 1e15)
	s = format (s, "%lld", (i64) v->number);
      else
	{
	  /* vppinfra %g is not JSON compatible (e.g. no leading zero),
	   * use the shortest precision which round trips */
	  char buf[32];

	  for (int prec = 15; prec <= 17; prec++)
	    {
	      snprintf (buf, sizeof (buf), "%.*g", prec, v->number);
	      if (strtod (buf, 0) == v->number)
		break;
	    }
	  s = format (s, "%s", buf);
	}
      break;
    case CLIB_JSON_VALUE_OBJECT:
      vec_add1 (s, '{');
      if (pool_elts (v->nvpairs))
	{
	  clib_json_nvpair_t *nvp;
	  j->current_indent += j->indent;
	  pool_foreach (nvp, v->nvpairs)
	    {
	      s = format (s, "\n%U", format_white_space, j->current_indent);
	      s = format (s, "%U: %U", format_json_string, nvp->name, format_clib_json_value, j,
			  nvp->value_index);
	      if (nvp != vec_end (v->nvpairs) - 1)
		s = format (s, ",");
	    }
	  j->current_indent -= j->indent;
	  s = format (s, "\n%U", format_white_space, j->current_indent);
	}
      vec_add1 (s, '}');
      break;
    case CLIB_JSON_VALUE_ARRAY:
      vec_add1 (s, '[');
      if (vec_len (v->array_val_indices))
	{
	  j->current_indent += j->indent;
	  vec_foreach_index (i, v->array_val_indices)
	    {
	      s = format (s, "\n%U", format_white_space, j->current_indent);
	      s = format (s, "%U", format_clib_json_value, j, v->array_val_indices[i]);
	      if (i != vec_len (v->array_val_indices) - 1)
		s = format (s, ",");
	    }
	  j->current_indent -= j->indent;
	  s = format (s, "\n%U", format_white_space, j->current_indent);
	}
      vec_add1 (s, ']');
      break;
    default:
      ASSERT (0);
      break;
    }
  return s;
}

__clib_export int
clib_json_parent (clib_json_text_t *j)
{
  clib_json_value_t *v;
  int rv;

  if (j->current_value == -1)
    return -1;

  v = pool_elt_at_index (j->values, j->current_value);
  rv = j->current_value;
  j->current_value = v->parent_value_index;
  return rv;
}

static int
clib_json_append_internal (clib_json_text_t *to, clib_json_text_t *from, u32 index, u8 *name)
{
  clib_json_value_t *fv, *tv;
  int to_index;
  u32 i;

  fv = pool_elt_at_index (from->values, index);
  to_index = clib_json_new_value (to, fv->type, name);

  if (to_index < 0)
    return to_index;
  tv = pool_elt_at_index (to->values, to_index);

  switch (tv->type)
    {
    case CLIB_JSON_VALUE_STRING:
      tv->string = vec_dup (fv->string);
      break;
    case CLIB_JSON_VALUE_NUMBER:
      tv->number = fv->number;
      break;
    case CLIB_JSON_VALUE_ARRAY:
      to->current_value = to_index;
      vec_foreach_index (i, fv->array_val_indices)
	clib_json_append_internal (to, from, fv->array_val_indices[i], 0);
      clib_json_parent (to);
      break;
    case CLIB_JSON_VALUE_OBJECT:
      to->current_value = to_index;
      for (i = 0; i < vec_len (fv->nvpairs); i++)
	clib_json_append_internal (to, from, fv->nvpairs[i].value_index,
				   vec_dup (fv->nvpairs[i].name));
      clib_json_parent (to);
      break;
    default:
      break;
    }
  return to_index;
}

__clib_export int
clib_json_append (clib_json_text_t *to, clib_json_text_t *from, char *nfmt, ...)
{
  u8 *name = 0;

  if (from->root_value == -1)
    return -1;

  if (nfmt)
    {
      va_list va;
      va_start (va, nfmt);
      name = va_format (0, nfmt, &va);
      va_end (va);
    }

  return clib_json_append_internal (to, from, from->root_value, name);
}

__clib_export u8 *
format_clib_json_text (u8 *s, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);

  j->current_indent = format_get_indent (s);
  s = format (s, "%U", format_clib_json_value, j, j->root_value);
  j->current_indent = 0;

  return s;
}

static int
clib_json_unformat_hex4 (unformat_input_t *i, u32 *result)
{
  u32 v = 0;

  for (int n = 0; n < 4; n++)
    {
      uword c = unformat_get_input (i);

      if (c >= '0' && c <= '9')
	v = (v << 4) | (c - '0');
      else if (c >= 'a' && c <= 'f')
	v = (v << 4) | (c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
	v = (v << 4) | (c - 'A' + 10);
      else
	return 0;
    }
  *result = v;
  return 1;
}

static u8 *
clib_json_add_utf8 (u8 *s, u32 cp)
{
  if (cp < 0x80)
    vec_add1 (s, cp);
  else if (cp < 0x800)
    {
      vec_add1 (s, 0xc0 | (cp >> 6));
      vec_add1 (s, 0x80 | (cp & 0x3f));
    }
  else if (cp < 0x10000)
    {
      vec_add1 (s, 0xe0 | (cp >> 12));
      vec_add1 (s, 0x80 | ((cp >> 6) & 0x3f));
      vec_add1 (s, 0x80 | (cp & 0x3f));
    }
  else
    {
      vec_add1 (s, 0xf0 | (cp >> 18));
      vec_add1 (s, 0x80 | ((cp >> 12) & 0x3f));
      vec_add1 (s, 0x80 | ((cp >> 6) & 0x3f));
      vec_add1 (s, 0x80 | (cp & 0x3f));
    }
  return s;
}

__clib_export uword
unformat_clib_json_string (unformat_input_t *i, va_list *args)
{
  u8 **string_return = va_arg (*args, u8 **);
  u8 *s = 0;
  uword c = unformat_get_input (i);

  if (c != '"')
    {
      unformat_put_input (i);
      return 0;
    }

  while ((c = unformat_get_input (i)) != UNFORMAT_END_OF_INPUT)
    {
      if (c == '"')
	{
	  *string_return = s;
	  return 1;
	}

      if (c < 0x20)
	break;

      if (c != '\\')
	{
	  vec_add1 (s, c);
	  continue;
	}

      c = unformat_get_input (i);
      switch (c)
	{
	case '"':
	case '\\':
	case '/':
	  vec_add1 (s, c);
	  break;
	case 'b':
	  vec_add1 (s, '\b');
	  break;
	case 'f':
	  vec_add1 (s, '\f');
	  break;
	case 'n':
	  vec_add1 (s, '\n');
	  break;
	case 'r':
	  vec_add1 (s, '\r');
	  break;
	case 't':
	  vec_add1 (s, '\t');
	  break;
	case 'u':
	  {
	    u32 cp, lo;

	    if (!clib_json_unformat_hex4 (i, &cp))
	      goto error;
	    /* UTF-16 surrogate pair */
	    if (cp >= 0xd800 && cp < 0xdc00)
	      {
		if (unformat_get_input (i) != '\\' || unformat_get_input (i) != 'u' ||
		    !clib_json_unformat_hex4 (i, &lo) || lo < 0xdc00 || lo > 0xdfff)
		  goto error;
		cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
	      }
	    else if (cp >= 0xdc00 && cp < 0xe000)
	      goto error;
	    s = clib_json_add_utf8 (s, cp);
	  }
	  break;
	default:
	  goto error;
	}
    }

error:
  vec_free (s);
  return 0;
}

/* Parses number token as defined in RFC 8259 */
static uword
clib_json_unformat_number (unformat_input_t *i, f64 *result)
{
  u8 *s = 0;
  uword c, rv = 0;
  char *end;

  while ((c = unformat_get_input (i)) != UNFORMAT_END_OF_INPUT)
    {
      if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E')
	vec_add1 (s, c);
      else
	{
	  unformat_put_input (i);
	  break;
	}
    }

  if (vec_len (s))
    {
      u8 *d = s, *e = vec_end (s);

      /* int = "-"? ("0" | [1-9][0-9]*), frac = "." [0-9]+,
       * exp = [eE] [+-]? [0-9]+ */
      if (d < e && *d == '-')
	d++;
      if (d < e && *d == '0')
	d++;
      else if (d < e && *d >= '1' && *d <= '9')
	while (d < e && *d >= '0' && *d <= '9')
	  d++;
      else
	goto done;

      if (d < e && *d == '.')
	{
	  u8 *start = ++d;

	  while (d < e && *d >= '0' && *d <= '9')
	    d++;
	  if (d == start)
	    goto done;
	}

      if (d < e && (*d == 'e' || *d == 'E'))
	{
	  u8 *start;

	  d++;
	  if (d < e && (*d == '+' || *d == '-'))
	    d++;
	  start = d;
	  while (d < e && *d >= '0' && *d <= '9')
	    d++;
	  if (d == start)
	    goto done;
	}

      if (d == e)
	{
	  vec_add1 (s, 0);
	  *result = strtod ((char *) s, &end);
	  rv = *end == 0;
	}
    }

done:
  vec_free (s);
  return rv;
}

static int
clib_json_new_container (clib_json_text_t *j, clib_json_value_type_t type, u8 **name)
{
  int index = clib_json_new_value (j, type, *name);

  *name = 0;
  if (index >= 0)
    j->current_value = index;
  return index;
}

__clib_export uword
unformat_clib_json_value (unformat_input_t *i, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);
  clib_json_parent_type_t parent;
  u8 *s = 0, *name = 0;
  uword c;

  enum
  {
    EXP_NONE = 0,
    EXP_VALUE = 1 << 0,
    EXP_COMMA = 1 << 1,
    EXP_COLON = 1 << 2,
    EXP_RIGHT_ANGLE_BKT = 1 << 3,
    EXP_RIGHT_CURLY_BKT = 1 << 4,
    EXP_STRING = 1 << 5,
  } expect = EXP_VALUE;

  parent = clib_json_get_parent_type (j);

  while ((c = unformat_get_input (i)) != UNFORMAT_END_OF_INPUT)
    {
      int token_is_value = 0, index;
      f64 number;

      if (is_white_space (c))
	continue;

      if (expect == EXP_NONE)
	goto error;

      unformat_put_input (i);
      switch (c)
	{
	case ',':
	  if ((expect & EXP_COMMA) == 0)
	    goto error;
	  unformat_get_input (i);
	  expect = (parent == CLIB_JSON_PARENT_OBJECT) ? EXP_STRING : EXP_VALUE;
	  break;

	case ':':
	  if ((expect & EXP_COLON) == 0)
	    goto error;
	  unformat_get_input (i);
	  expect = EXP_VALUE;
	  break;

	case '[':
	  if ((expect & EXP_VALUE) == 0 ||
	      clib_json_new_container (j, CLIB_JSON_VALUE_ARRAY, &name) < 0)
	    goto error;
	  unformat_get_input (i);
	  expect = EXP_VALUE | EXP_RIGHT_ANGLE_BKT;
	  parent = clib_json_get_parent_type (j);
	  break;

	case '{':
	  if ((expect & EXP_VALUE) == 0 ||
	      clib_json_new_container (j, CLIB_JSON_VALUE_OBJECT, &name) < 0)
	    goto error;
	  unformat_get_input (i);
	  expect = EXP_STRING | EXP_RIGHT_CURLY_BKT;
	  parent = clib_json_get_parent_type (j);
	  break;

	case ']':
	  if ((expect & EXP_RIGHT_ANGLE_BKT) == 0 || clib_json_parent (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  parent = clib_json_get_parent_type (j);
	  token_is_value = 1;
	  break;

	case '}':
	  if ((expect & EXP_RIGHT_CURLY_BKT) == 0 || clib_json_parent (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  parent = clib_json_get_parent_type (j);
	  token_is_value = 1;
	  break;

	case 'n':
	case 't':
	case 'f':
	  {
	    clib_json_value_type_t type = CLIB_JSON_VALUE_NULL;
	    char *lit = "null";

	    if (c == 't')
	      {
		type = CLIB_JSON_VALUE_TRUE;
		lit = "true";
	      }
	    else if (c == 'f')
	      {
		type = CLIB_JSON_VALUE_FALSE;
		lit = "false";
	      }

	    if ((expect & EXP_VALUE) == 0 || unformat (i, lit) == 0)
	      goto error;
	    index = clib_json_new_value (j, type, name);
	    name = 0;
	    if (index < 0)
	      goto error;
	    token_is_value = 1;
	  }
	  break;

	case '-':
	case '0' ... '9':
	  if ((expect & EXP_VALUE) == 0 || clib_json_unformat_number (i, &number) == 0)
	    goto error;
	  index = clib_json_new_value (j, CLIB_JSON_VALUE_NUMBER, name);
	  name = 0;
	  if (index < 0)
	    goto error;
	  pool_elt_at_index (j->values, index)->number = number;
	  token_is_value = 1;
	  break;

	case '"':
	  if ((expect & (EXP_VALUE | EXP_STRING)) == 0 ||
	      unformat (i, "%U", unformat_clib_json_string, &s) == 0)
	    goto error;

	  if (expect & EXP_VALUE)
	    {
	      index = clib_json_new_value (j, CLIB_JSON_VALUE_STRING, name);
	      name = 0;
	      if (index < 0)
		goto error;
	      pool_elt_at_index (j->values, index)->string = s;
	      s = 0;
	      token_is_value = 1;
	    }
	  else
	    {
	      ASSERT (parent == CLIB_JSON_PARENT_OBJECT);
	      name = s;
	      s = 0;
	      expect = EXP_COLON;
	    }
	  break;

	default:
	  goto error;
	}

      if (token_is_value)
	{
	  if (parent == CLIB_JSON_PARENT_ARRAY)
	    expect = EXP_RIGHT_ANGLE_BKT | EXP_COMMA;
	  else if (parent == CLIB_JSON_PARENT_OBJECT)
	    expect = EXP_RIGHT_CURLY_BKT | EXP_COMMA;
	  else
	    expect = EXP_NONE;
	}
    }

  vec_free (name);
  return 1;

error:
  vec_free (name);
  vec_free (s);
  return 0;
}
