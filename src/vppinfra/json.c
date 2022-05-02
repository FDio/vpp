/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/pool.h>
#include <vppinfra/json.h>

typedef enum
{
  CLIB_JSON_PARENT_TEXT = 0,
  CLIB_JSON_PARENT_ARRAY,
  CLIB_JSON_PARENT_OBJECT
} clib_json_parrent_type_t;

static clib_json_parrent_type_t
clib_json_get_parrent_type (clib_json_text_t *j)
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

__clib_export int
clib_json_new_value (clib_json_text_t *j, clib_json_value_type_t type)
{
  clib_json_value_t *v, *p;
  int index;

  /* parent must be array, object or root value */
  p = clib_json_get_current_value (j);
  if (p && p->type != CLIB_JSON_VALUE_ARRAY &&
      p->type != CLIB_JSON_VALUE_OBJECT)
    return -1;

  pool_get_zero (j->values, v);
  index = v - j->values;
  v->type = type;
  v->parent_value_index = j->current_value;

  if (j->root_value == -1)
    {
      j->root_value = index;
      return index;
    }

  /* pool may grow */
  p = clib_json_get_current_value (j);

  if (p->type == CLIB_JSON_VALUE_OBJECT)
    {
      clib_json_nvpair_t *nvp;
      pool_get_zero (p->nvpairs, nvp);
      nvp->name = j->next_nvpair_name;
      j->next_nvpair_name = 0;
      nvp->value_index = index;
    }
  else if (p->type == CLIB_JSON_VALUE_ARRAY)
    vec_add1 (p->array_val_indices, index);
  else
    ASSERT (0);

  return index;
}

__clib_export int
clib_json_add_null (clib_json_text_t *j)
{
  return clib_json_new_value (j, CLIB_JSON_VALUE_NULL);
}

__clib_export int
clib_json_add_true (clib_json_text_t *j)
{
  return clib_json_new_value (j, CLIB_JSON_VALUE_TRUE);
}

__clib_export int
clib_json_add_false (clib_json_text_t *j)
{
  return clib_json_new_value (j, CLIB_JSON_VALUE_FALSE);
}

__clib_export int
clib_json_add_string (clib_json_text_t *j, char *fmt, ...)
{
  int index = clib_json_new_value (j, CLIB_JSON_VALUE_STRING);
  clib_json_value_t *v;
  va_list va;

  if (index < 0)
    return index;

  v = pool_elt_at_index (j->values, index);

  va_start (va, fmt);
  v->string = va_format (0, fmt, &va);
  va_end (va);

  return index;
}

__clib_export int
clib_json_add_object (clib_json_text_t *j)
{
  int index = clib_json_new_value (j, CLIB_JSON_VALUE_OBJECT);
  j->current_value = index;
  return index;
}

__clib_export int
clib_json_add_array (clib_json_text_t *j)
{
  int index = clib_json_new_value (j, CLIB_JSON_VALUE_ARRAY);
  j->current_value = index;
  return index;
}

__clib_export void
clib_json_set_next_nvpair_name (clib_json_text_t *j, char *fmt, ...)
{
  va_list va;

  vec_reset_length (j->next_nvpair_name);
  va_start (va, fmt);
  j->next_nvpair_name = va_format (j->next_nvpair_name, fmt, &va);
  va_end (va);
}

__clib_export void
clib_json_init (clib_json_text_t *j)
{
  clib_memset_u8 (j, 0, sizeof (j[0]));
  j->indent = 4;
  j->current_value = -1;
  j->root_value = -1;
}

__clib_export clib_error_t *
clib_json_init_from_file (clib_json_text_t *j, int fd)
{
  clib_error_t *err = 0;
  clib_json_text_t tmp;
  unformat_input_t input;

  unformat_init_clib_file (&input, fd);
  clib_json_init (&tmp);

  if (!unformat (&input, "%U", unformat_clib_json_value, &tmp))
    err = clib_error_return (0, "JSON parse error: %U", format_unformat_error,
			     &input);

  if (err)
    clib_json_free (&tmp);
  else
    clib_memcpy (j, &tmp, sizeof (tmp));
  return err;
}

__clib_export clib_error_t *
clib_json_init_from_string (clib_json_text_t *j, char *str, int len)
{
  clib_error_t *err = 0;
  clib_json_text_t tmp;
  unformat_input_t input;

  unformat_init_string (&input, str, len);
  clib_json_init (&tmp);

  if (!unformat (&input, "%U", unformat_clib_json_value, &tmp))
    err = clib_error_return (0, "JSON parse error: %U", format_unformat_error,
			     &input);

  if (err)
    clib_json_free (&tmp);
  else
    clib_memcpy (j, &tmp, sizeof (tmp));
  return err;
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
	  vec_free (v->nvpairs);
	}
      else if (v->type == CLIB_JSON_VALUE_ARRAY)
	vec_free (v->array_val_indices);
      else if (v->type == CLIB_JSON_VALUE_STRING)
	vec_free (v->string);
    }
  pool_free (j->values);
  vec_free (j->next_nvpair_name);
}

static u8 *
format_clib_json_value (u8 *s, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);
  u32 value_index = va_arg (*args, u32);
  clib_json_value_t *v = pool_elt_at_index (j->values, value_index);
  clib_json_nvpair_t *nvp;
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
      s = format (s, "\"%v\"", v->string);
      break;
    case CLIB_JSON_VALUE_OBJECT:
      s = format (s, "{");
      j->current_indent += j->indent;
      pool_foreach (nvp, v->nvpairs)
	{
	  s = format (s, "\n%U", format_white_space, j->current_indent);
	  s = format (s, "\"%v\": %U", nvp->name, format_clib_json_value, j,
		      nvp->value_index);
	  if (nvp != vec_end (v->nvpairs) - 1)
	    s = format (s, ",");
	}
      j->current_indent -= j->indent;
      s = format (s, "\n%U}", format_white_space, j->current_indent);
      break;
    case CLIB_JSON_VALUE_ARRAY:
      s = format (s, "[");
      j->current_indent += j->indent;
      vec_foreach_index (i, v->array_val_indices)
	{
	  s = format (s, "\n%U", format_white_space, j->current_indent);
	  s = format (s, "%U", format_clib_json_value, j,
		      v->array_val_indices[i]);
	  if (i != vec_len (v->array_val_indices) - 1)
	    s = format (s, ",");
	}
      j->current_indent -= j->indent;
      s = format (s, "\n%U]", format_white_space, j->current_indent);
      break;
    default:
      s = format (s, "FIXME");
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
clib_json_append_internal (clib_json_text_t *to, clib_json_text_t *from,
			   u32 index)
{
  clib_json_value_t *fv, *tv;
  fv = pool_elt_at_index (from->values, index);
  int to_index = clib_json_new_value (to, fv->type);
  u32 i;

  if (to_index < 0)
    return to_index;
  tv = pool_elt_at_index (to->values, to_index);

  switch (tv->type)
    {
    case CLIB_JSON_VALUE_STRING:
      tv->string = vec_dup (fv->string);
      break;
    case CLIB_JSON_VALUE_ARRAY:
      to->current_value = to_index;
      vec_foreach_index (i, fv->array_val_indices)
	clib_json_append_internal (to, from, fv->array_val_indices[i]);
      clib_json_parent (to);
      break;
    case CLIB_JSON_VALUE_OBJECT:
      to->current_value = to_index;
      vec_foreach_index (i, fv->nvpairs)
	{
	  vec_free (to->next_nvpair_name);
	  to->next_nvpair_name = vec_dup (fv->nvpairs[i].name);
	  clib_json_append_internal (to, from, fv->nvpairs[i].value_index);
	}
      clib_json_parent (to);
      break;
    default:
      break;
    }
  return to_index;
}

__clib_export int
clib_json_append (clib_json_text_t *to, clib_json_text_t *from)
{

  if (vec_len (from->values) == 0)
    return -1;

  return clib_json_append_internal (to, from, from->root_value);
}

__clib_export u8 *
format_clib_json (u8 *s, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);

  j->current_indent = format_get_indent (s);
  s = format (s, "%U", format_clib_json_value, j, j->root_value);
  j->current_indent = 0;

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
      vec_add1 (s, c);
    }

  vec_free (s);
  return 0;
}

__clib_export uword
unformat_clib_json_value (unformat_input_t *i, va_list *args)
{
  clib_json_text_t *j = va_arg (*args, clib_json_text_t *);
  uword c;
  u8 *s = 0;
  clib_json_parrent_type_t parrent;

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

  parrent = clib_json_get_parrent_type (j);

  while ((c = unformat_get_input (i)) != UNFORMAT_END_OF_INPUT)
    {
      int token_is_value = 0;

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
	  expect =
	    (parrent == CLIB_JSON_PARENT_OBJECT) ? EXP_STRING : EXP_VALUE;
	  break;

	case ':':
	  if ((expect & EXP_COLON) == 0)
	    goto error;
	  unformat_get_input (i);
	  expect = EXP_VALUE;
	  break;

	case '[':
	  if ((expect & EXP_VALUE) == 0 || clib_json_add_array (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  expect = EXP_VALUE | EXP_RIGHT_ANGLE_BKT;
	  parrent = clib_json_get_parrent_type (j);
	  break;

	case '{':
	  if ((expect & EXP_VALUE) == 0 || clib_json_add_object (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  parrent = clib_json_get_parrent_type (j);
	  expect = EXP_STRING | EXP_RIGHT_CURLY_BKT;
	  break;

	case ']':
	  if ((expect & EXP_RIGHT_ANGLE_BKT) == 0 || clib_json_parent (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  parrent = clib_json_get_parrent_type (j);
	  token_is_value = 1;
	  break;

	case '}':
	  if ((expect & EXP_RIGHT_CURLY_BKT) == 0 || clib_json_parent (j) < 0)
	    goto error;
	  unformat_get_input (i);
	  parrent = clib_json_get_parrent_type (j);
	  token_is_value = 1;
	  break;

	case 'n':
	  if ((expect & EXP_VALUE) == 0 || unformat (i, "null") == 0 ||
	      clib_json_add_null (j) < 0)
	    goto error;
	  token_is_value = 1;
	  break;

	case 't':
	  if ((expect & EXP_VALUE) == 0 || unformat (i, "true") == 0 ||
	      clib_json_add_true (j) < 0)
	    goto error;
	  token_is_value = 1;
	  break;

	case 'f':
	  if ((expect & EXP_VALUE) == 0 || unformat (i, "false") == 0 ||
	      clib_json_add_false (j) < 0)
	    goto error;
	  token_is_value = 1;
	  break;

	case '"':
	  if ((expect & (EXP_VALUE | EXP_STRING)) == 0 ||
	      unformat (i, "%U", unformat_clib_json_string, &s) == 0)
	    goto error;

	  if (expect & EXP_VALUE)
	    {
	      int index = clib_json_new_value (j, CLIB_JSON_VALUE_STRING);
	      clib_json_value_t *v;

	      if (index < 0)
		{
		  vec_free (s);
		  goto error;
		}

	      v = pool_elt_at_index (j->values, index);
	      v->string = s;
	      token_is_value = 1;
	    }
	  else
	    {
	      ASSERT (parrent == CLIB_JSON_PARENT_OBJECT);
	      vec_free (j->next_nvpair_name);
	      j->next_nvpair_name = s;
	      expect = EXP_COLON;
	    }
	  break;
	default:
	  goto error;
	  break;
	}

      if (token_is_value)
	{
	  if (parrent == CLIB_JSON_PARENT_ARRAY)
	    expect = EXP_RIGHT_ANGLE_BKT | EXP_COMMA;
	  else if (parrent == CLIB_JSON_PARENT_OBJECT)
	    expect = EXP_RIGHT_CURLY_BKT | EXP_COMMA;
	  else
	    expect = EXP_NONE;
	}
    }

  return 1;

error:
  return 0;
}
