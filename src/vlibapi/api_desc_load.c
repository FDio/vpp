/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Creates API descriptors from the .api.json text of a file, which is what
 * get_api_json returns, for the programs which do not have the descriptors
 * compiled in. The layout (sizes and offsets of the packed C structures) is
 * calculated the same way vppapigen does it. */

#include <vlibapi/api_common.h>
#include <vlibapi/api_desc.h>
#include <vppinfra/pool.h>
#include <math.h>

typedef struct
{
  vl_api_desc_type_t *t; /* in the arrays of the file */
  /* what the type has, it is put in the arrays of the file when all are known */
  vl_api_desc_field_t *fields;
  vl_api_desc_enum_val_t *values;
  const vl_api_desc_option_t *options;
  int json; /* the definition in the JSON, 0 if none */
  u8 state; /* 0 new, 1 loading, 2 loaded */
} desc_ent_t;

typedef struct
{
  clib_json_text_t *j;
  /* everything which was allocated, to free it with the file */
  void **allocs;
  uword *types;	 /* name -> desc_ent_t */
  uword *consts; /* name of an enum value -> value */
  /* the descriptors of the types and of the messages */
  vl_api_desc_type_t *tarr, *marr;
  u32 nt, nm, n_tarr, n_marr;
  clib_error_t *err;
} desc_load_t;

typedef struct
{
  void **allocs;
  vl_api_desc_file_t file;
} desc_loaded_t;

static const struct
{
  const char *name;
  u8 kind;
  u8 size;
} desc_base[] = {
  { "u8", VL_API_DK_U8, 1 },	 { "i8", VL_API_DK_I8, 1 },   { "u16", VL_API_DK_U16, 2 },
  { "i16", VL_API_DK_I16, 2 },	 { "u32", VL_API_DK_U32, 4 }, { "i32", VL_API_DK_I32, 4 },
  { "u64", VL_API_DK_U64, 8 },	 { "i64", VL_API_DK_I64, 8 }, { "f64", VL_API_DK_F64, 8 },
  { "bool", VL_API_DK_BOOL, 1 },
};

/* the types which are printed by hand */
static const char *desc_manual_print[] = {
  "ip4_address",
  "ip6_address",
  "ip4_prefix",
  "ip6_prefix",
  "ip4_address_with_prefix",
  "ip6_address_with_prefix",
  "address",
  "prefix",
  "address_with_prefix",
  "mac_address",
};

static void *
l_alloc (desc_load_t *l, uword n)
{
  void *p = clib_mem_alloc (n);

  clib_memset (p, 0, n);
  vec_add1 (l->allocs, p);
  return p;
}

static const char *
l_copy (desc_load_t *l, u8 *s, u32 len)
{
  char *r = l_alloc (l, len + 1);

  if (len)
    clib_memcpy (r, s, len);
  return r;
}

static int
l_is (desc_load_t *l, int idx, clib_json_value_type_t type)
{
  return idx >= 0 && clib_json_value_is_type (l->j, idx, type);
}

static clib_json_value_t *
l_value (desc_load_t *l, int idx)
{
  return pool_elt_at_index (l->j->values, idx);
}

static const char *
l_string (desc_load_t *l, int idx)
{
  u8 *s;

  if (!l_is (l, idx, CLIB_JSON_VALUE_STRING))
    return 0;

  s = l_value (l, idx)->string;
  return l_copy (l, s, vec_len (s));
}

static int
l_member (desc_load_t *l, int obj, char *name)
{
  return l_is (l, obj, CLIB_JSON_VALUE_OBJECT) ?
	   clib_json_find_object_value_by_name (l->j, obj, "%s", name) :
	   -1;
}

static void l_default (desc_load_t *l, vl_api_desc_field_t *f, int x);

static clib_error_t *
l_fail (desc_load_t *l, char *fmt, ...)
{
  va_list va;

  if (!l->err)
    {
      u8 *msg;

      va_start (va, fmt);
      msg = va_format (0, fmt, &va);
      va_end (va);
      l->err = clib_error_return (0, "%v", msg);
      vec_free (msg);
    }
  return l->err;
}

/* vl_api_<name>_t and <name> */
static const char *
l_type_name (desc_load_t *l, const char *n)
{
  uword len = strlen (n);
  const char *r;

  if (len > 9 && !strncmp (n, "vl_api_", 7) && !strcmp (n + len - 2, "_t"))
    {
      char *c = l_alloc (l, len);

      clib_memcpy (c, n + 7, len - 9);
      r = c;
      return r;
    }

  return n;
}

static desc_ent_t *
l_find (desc_load_t *l, const char *n)
{
  uword *p = hash_get_mem (l->types, l_type_name (l, n));

  return p ? (desc_ent_t *) p[0] : 0;
}

static desc_ent_t *
l_new (desc_load_t *l, const char *name, u8 kind, int json)
{
  desc_ent_t *e = l_alloc (l, sizeof (*e));

  if (kind == VL_API_DT_MESSAGE ? l->nm >= l->n_marr : l->nt >= l->n_tarr)
    {
      l_fail (l, "too many definitions");
      e->t = l_alloc (l, sizeof (*e->t));
      return e;
    }

  e->t = kind == VL_API_DT_MESSAGE ? &l->marr[l->nm++] : &l->tarr[l->nt++];
  e->t->name = name;
  e->t->kind = kind;
  e->json = json;
  hash_set_mem (l->types, name, e);
  return e;
}

static int
l_base (const char *n)
{
  for (u32 i = 0; i < ARRAY_LEN (desc_base); i++)
    if (!strcmp (desc_base[i].name, n))
      return i;

  return -1;
}

static void l_load (desc_load_t *l, desc_ent_t *e);

/* the size of a type of a field, in the C structure */
static u32
l_size_of (desc_load_t *l, const char *n)
{
  desc_ent_t *e;
  int b = l_base (n);

  if (b >= 0)
    return desc_base[b].size;

  e = l_find (l, n);
  if (!e)
    {
      l_fail (l, "unknown type '%s'", n);
      return 0;
    }

  l_load (l, e);
  return e->t->size;
}

static void
l_field_kind (desc_load_t *l, const char *n, u8 *kind, u16 *ref)
{
  desc_ent_t *e;
  int b = l_base (n);

  *ref = 0;

  if (b >= 0)
    {
      *kind = desc_base[b].kind;
      return;
    }

  if (!strcmp (n, "string"))
    {
      *kind = VL_API_DK_STRING;
      return;
    }

  e = l_find (l, n);
  if (!e)
    {
      l_fail (l, "unknown type '%s'", n);
      *kind = VL_API_DK_U8;
      return;
    }

  *ref = e->t - l->tarr + 1;

  switch (e->t->kind)
    {
    case VL_API_DT_ENUM:
      *kind = VL_API_DK_ENUM;
      break;
    case VL_API_DT_ENUMFLAG:
      *kind = VL_API_DK_ENUMFLAG;
      break;
    case VL_API_DT_UNION:
      *kind = VL_API_DK_UNION;
      break;
    case VL_API_DT_ALIAS:
      b = l_base (e->t->alias_type);
      *kind = (!e->t->alias_length && b >= 0) ? desc_base[b].kind : VL_API_DK_NAMED;
      break;
    default:
      *kind = VL_API_DK_STRUCT;
      break;
    }
}

static int
l_field_index (const vl_api_desc_field_t *fields, u32 n, const char *name)
{
  for (u32 i = 0; i < n; i++)
    if (!strcmp (fields[i].name, name))
      return i;

  return -1;
}

static void
l_load_fields (desc_load_t *l, desc_ent_t *e)
{
  vl_api_desc_type_t *t = e->t;
  int *defs = clib_json_get_array_value_indices (l->j, e->json), *d;
  vl_api_desc_field_t *fields;
  const char **names;
  u32 n = 0, offset = 0, size = 0;

  /* the name, then the fields and, for a message or a type with a comment,
   * an object at the end */
  vec_foreach (d, defs)
    if (d > defs && l_is (l, *d, CLIB_JSON_VALUE_ARRAY))
      n++;

  fields = l_alloc (l, n * sizeof (*fields) + 1);
  names = l_alloc (l, n * sizeof (*names) + 1);
  e->fields = fields;
  t->n_fields = n;
  n = 0;

  vec_foreach (d, defs)
    {
      vl_api_desc_field_t *f;
      const char *type;
      u32 fsize;
      int *v, x;

      if (d == defs || !l_is (l, *d, CLIB_JSON_VALUE_ARRAY))
	continue;

      f = &fields[n];
      v = clib_json_get_array_value_indices (l->j, *d);

      if (vec_len (v) < 2 || !l_is (l, v[0], CLIB_JSON_VALUE_STRING) ||
	  !l_is (l, v[1], CLIB_JSON_VALUE_STRING))
	{
	  l_fail (l, "bad field in '%s'", t->name);
	  return;
	}

      type = l_string (l, v[0]);
      f->name = l_string (l, v[1]);
      l_field_kind (l, type, &f->kind, &f->ref);

      if (vec_len (v) > 2 && l_is (l, v[2], CLIB_JSON_VALUE_NUMBER))
	{
	  f->flags |= VL_API_DF_ARRAY;
	  f->length = l_value (l, v[2])->number;

	  if (!strcmp (type, "string"))
	    {
	      /* a fixed string is a nul terminated array of u8, a variable
	       * one is a vl_api_string_t */
	      if (f->length == 0)
		{
		  f->flags |= VL_API_DF_MODERN_VLA;
		  f->size = fsize = 4;
		}
	      else
		{
		  f->kind = VL_API_DK_FSTRING;
		  f->size = 1;
		  fsize = f->length;
		}
	    }
	  else
	    {
	      f->size = l_size_of (l, type);
	      fsize = f->size * f->length;
	    }

	  if (vec_len (v) > 3 && l_is (l, v[3], CLIB_JSON_VALUE_STRING))
	    {
	      /* the field which has the length */
	      names[n] = l_string (l, v[3]);
	      f->flags |= VL_API_DF_VLA;
	      fsize = 0;
	    }
	}
      else
	{
	  f->size = fsize = l_size_of (l, type);

	  if (vec_len (v) > 2 && l_is (l, v[2], CLIB_JSON_VALUE_OBJECT))
	    {
	      if ((x = l_member (l, v[2], "default")) >= 0)
		l_default (l, f, x);

	      if ((x = l_member (l, v[2], "discriminator")) >= 0)
		{
		  f->flags |= VL_API_DF_TAGGED;
		  names[n] = l_string (l, x);
		}

	      if ((x = l_member (l, v[2], "case")) >= 0)
		{
		  const char *c = l_string (l, x);
		  uword *p = c ? hash_get_mem (l->consts, c) : 0;

		  f->flags |= VL_API_DF_CASE;
		  f->case_name = c;
		  if (p)
		    f->case_value = (i64) p[0];
		  else if (l_is (l, x, CLIB_JSON_VALUE_NUMBER))
		    f->case_value = l_value (l, x)->number;
		  else
		    {
		      l_fail (l, "unknown case '%s' in '%s'", c ? c : "", t->name);
		      return;
		    }
		}
	    }
	}

      if (t->kind == VL_API_DT_UNION)
	{
	  f->offset = 0;
	  size = size > fsize ? size : fsize;
	}
      else
	{
	  f->offset = offset;
	  offset += fsize;
	  size = offset;
	}

      if (!strcmp (f->name, "client_index") && !(f->flags & VL_API_DF_ARRAY))
	f->flags |= VL_API_DF_NO_ENDIAN;

      if (l->err)
	return;

      n++;
    }

  /* the fields which refer to others */
  for (u32 i = 0; i < t->n_fields; i++)
    {
      vl_api_desc_field_t *f = &fields[i];
      const char *rel = (f->flags & (VL_API_DF_VLA | VL_API_DF_TAGGED)) ? names[i] : 0;
      int k;

      if (!rel)
	continue;

      k = l_field_index (fields, t->n_fields, rel);
      if (k < 0)
	{
	  l_fail (l, "no field '%s' in '%s'", rel, t->name);
	  return;
	}

      f->related = k;
      if (f->flags & VL_API_DF_VLA)
	fields[k].flags |= VL_API_DF_LENGTH;
    }

  t->size = size;

  /* a variable length part is the last field, or what the last field is */
  if (t->n_fields)
    {
      const vl_api_desc_field_t *f = &fields[t->n_fields - 1];

      if ((f->flags & (VL_API_DF_VLA | VL_API_DF_MODERN_VLA)) ||
	  (f->ref && (l->tarr[f->ref - 1].flags & VL_API_DTF_VLA)))
	t->flags |= VL_API_DTF_VLA;
    }
}

static void
l_load (desc_load_t *l, desc_ent_t *e)
{
  if (e->state == 2 || l->err)
    return;

  if (e->state == 1)
    {
      l_fail (l, "type '%s' contains itself", e->t->name);
      return;
    }

  e->state = 1;

  switch (e->t->kind)
    {
    case VL_API_DT_ENUM:
    case VL_API_DT_ENUMFLAG:
      break;
    case VL_API_DT_ALIAS:
      e->t->size = l_size_of (l, e->t->alias_type) * (e->t->alias_length ? e->t->alias_length : 1);
      break;
    default:
      l_load_fields (l, e);
      break;
    }

  e->state = 2;
}

static const char *
l_def_name (desc_load_t *l, int def)
{
  int *v = clib_json_get_array_value_indices (l->j, def);

  return vec_len (v) ? l_string (l, v[0]) : 0;
}

/* [name, [id, value]..., {"enumtype": T}] */
static void
l_enum (desc_load_t *l, int def, u8 kind, desc_ent_t ***list)
{
  int *v = clib_json_get_array_value_indices (l->j, def), *d;
  const char *name = l_def_name (l, def);
  desc_ent_t *e;
  vl_api_desc_enum_val_t *values;
  u32 n = 0;

  if (!name)
    {
      l_fail (l, "bad enum");
      return;
    }

  e = l_new (l, name, kind, def);
  vec_add1 (*list, e);
  e->state = 2;
  e->t->base = VL_API_DK_U32;

  vec_foreach (d, v)
    if (d > v && l_is (l, *d, CLIB_JSON_VALUE_ARRAY))
      n++;

  values = l_alloc (l, n * sizeof (*values) + 1);
  e->values = values;
  e->t->n_fields = n;
  n = 0;

  vec_foreach (d, v)
    {
      int x, *p;

      if (d == v)
	continue;

      if (l_is (l, *d, CLIB_JSON_VALUE_OBJECT))
	{
	  x = l_member (l, *d, "enumtype");
	  if (x >= 0 && l_is (l, x, CLIB_JSON_VALUE_STRING))
	    {
	      int b = l_base (l_string (l, x));

	      if (b >= 0)
		e->t->base = desc_base[b].kind;
	    }
	  continue;
	}

      p = clib_json_get_array_value_indices (l->j, *d);
      if (vec_len (p) < 2 || !l_is (l, p[0], CLIB_JSON_VALUE_STRING) ||
	  !l_is (l, p[1], CLIB_JSON_VALUE_NUMBER))
	{
	  l_fail (l, "bad value in enum '%s'", name);
	  return;
	}

      values[n].name = l_string (l, p[0]);
      values[n].value = l_value (l, p[1])->number;
      hash_set_mem (l->consts, values[n].name, (uword) values[n].value);
      n++;
    }

  e->t->size = e->t->base < ARRAY_LEN (desc_base) ? desc_base[e->t->base].size : 4;
}

/* the number of the elements of an array or of the members of an object */
static u32
l_length (desc_load_t *l, int idx)
{
  if (l_is (l, idx, CLIB_JSON_VALUE_ARRAY))
    return vec_len (l_value (l, idx)->array_val_indices);

  if (l_is (l, idx, CLIB_JSON_VALUE_OBJECT))
    return pool_elts (l_value (l, idx)->nvpairs);

  return 0;
}

/* the members of an object whose values are strings or null */
static const vl_api_desc_option_t *
l_options (desc_load_t *l, int obj, u32 *n)
{
  clib_json_nvpair_t *nv;
  vl_api_desc_option_t *o;
  u32 count = 0;

  *n = 0;
  if (!l_is (l, obj, CLIB_JSON_VALUE_OBJECT))
    return 0;

  pool_foreach (nv, l_value (l, obj)->nvpairs)
    count++;

  o = l_alloc (l, (count + 1) * sizeof (*o));
  count = 0;

  pool_foreach (nv, l_value (l, obj)->nvpairs)
    {
      o[count].name = l_copy (l, nv->name, vec_len (nv->name));

      if (l_is (l, nv->value_index, CLIB_JSON_VALUE_STRING))
	o[count].value = l_string (l, nv->value_index);
      else if (!l_is (l, nv->value_index, CLIB_JSON_VALUE_NULL))
	l_fail (l, "the option '%s' is not a string", o[count].name);

      count++;
    }

  *n = count;
  return o;
}

static void
l_default (desc_load_t *l, vl_api_desc_field_t *f, int x)
{
  clib_json_value_t *v = l_value (l, x);

  switch (v->type)
    {
    case CLIB_JSON_VALUE_TRUE:
    case CLIB_JSON_VALUE_FALSE:
      f->default_kind = VL_API_DD_BOOL;
      f->default_value.i = v->type == CLIB_JSON_VALUE_TRUE;
      break;
    case CLIB_JSON_VALUE_NUMBER:
      /* 1 and 1.0 are the same in JSON, the type of the field tells */
      if (f->kind != VL_API_DK_F64 && v->number == floor (v->number) && fabs (v->number) < 9.2e18)
	{
	  f->default_kind = VL_API_DD_INT;
	  f->default_value.i = (i64) v->number;
	}
      else
	{
	  f->default_kind = VL_API_DD_FLOAT;
	  f->default_value.f = v->number;
	}
      break;
    case CLIB_JSON_VALUE_STRING:
      f->default_kind = VL_API_DD_STRING;
      f->default_value.s = l_string (l, x);
      break;
    default:
      l_fail (l, "bad default value of '%s'", f->name);
      break;
    }
}

/* the requests and the messages which answer them, they are messages of the file */
static void
l_services (desc_load_t *l, int obj)
{
  clib_json_nvpair_t *nv;

  if (!l_is (l, obj, CLIB_JSON_VALUE_OBJECT))
    return;

  pool_foreach (nv, l_value (l, obj)->nvpairs)
    {
      u8 *name = format (0, "%v%c", nv->name, 0);
      desc_ent_t *e = l_find (l, (char *) name);
      int o = nv->value_index, x;
      const char *r;

      vec_free (name);

      if (!e || e->t->kind != VL_API_DT_MESSAGE)
	continue;

      e->t->flags |= VL_API_DTF_SERVICE;

      r = l_string (l, l_member (l, o, "reply"));
      if (r && strcmp (r, "null"))
	{
	  desc_ent_t *re = l_find (l, r);

	  if (re && re->t->kind == VL_API_DT_MESSAGE)
	    e->t->reply = re->t - l->marr + 1;
	  else
	    l_fail (l, "the reply '%s' of '%s' is not a message", r, e->t->name);
	}

      x = l_member (l, o, "stream");
      if (x >= 0 && l_is (l, x, CLIB_JSON_VALUE_TRUE))
	e->t->flags |= VL_API_DTF_STREAM;

      r = l_string (l, l_member (l, o, "stream_msg"));
      if (r)
	{
	  desc_ent_t *de = l_find (l, r);

	  if (de && de->t->kind == VL_API_DT_MESSAGE)
	    e->t->details = de->t - l->marr + 1;
	  else
	    l_fail (l, "the details '%s' of '%s' are not a message", r, e->t->name);
	}
    }
}

clib_error_t *
vl_api_desc_file_from_json (clib_json_text_t *j, int value_index, const vl_api_desc_file_t **file)
{
  desc_load_t _l = { .j = j }, *l = &_l;
  desc_loaded_t *loaded;
  vl_api_desc_file_t *f;
  desc_ent_t **types = 0, **msgs = 0, *e;
  int x, *d, root = value_index;
  const char *name;
  clib_error_t *err;

  *file = 0;

  if (!l_is (l, root, CLIB_JSON_VALUE_OBJECT))
    return clib_error_return (0, "the JSON is not an object");

  l->types = hash_create_string (0, sizeof (uword));
  l->consts = hash_create_string (0, sizeof (uword));

  /* the descriptors of the file are in two arrays, count them */
  {
    static char *type_groups[] = { "enums", "enumflags", "types", "unions" };

    for (u32 g = 0; g < ARRAY_LEN (type_groups); g++)
      l->n_tarr += l_length (l, l_member (l, root, type_groups[g]));
    l->n_tarr += l_length (l, l_member (l, root, "aliases"));
    l->n_marr = l_length (l, l_member (l, root, "messages"));
    l->tarr = l_alloc (l, (l->n_tarr + 1) * sizeof (*l->tarr));
    l->marr = l_alloc (l, (l->n_marr + 1) * sizeof (*l->marr));
  }

  /* the enums first, the case of a union arm is the name of a value */
  x = l_member (l, root, "enums");
  if (l_is (l, x, CLIB_JSON_VALUE_ARRAY))
    vec_foreach (d, clib_json_get_array_value_indices (j, x))
      l_enum (l, *d, VL_API_DT_ENUM, &types);

  x = l_member (l, root, "enumflags");
  if (l_is (l, x, CLIB_JSON_VALUE_ARRAY))
    vec_foreach (d, clib_json_get_array_value_indices (j, x))
      l_enum (l, *d, VL_API_DT_ENUMFLAG, &types);

  /* the aliases, then the types which have fields */
  x = l_member (l, root, "aliases");
  if (l_is (l, x, CLIB_JSON_VALUE_OBJECT))
    {
      clib_json_nvpair_t *nv;

      pool_foreach (nv, l_value (l, x)->nvpairs)
	{
	  int t = nv->value_index, len;

	  e = l_new (l, l_copy (l, nv->name, vec_len (nv->name)), VL_API_DT_ALIAS, 0);
	  e->t->alias_type = l_string (l, l_member (l, t, "type"));
	  len = l_member (l, t, "length");
	  if (len >= 0)
	    e->t->alias_length = l_value (l, len)->number;
	  if (!e->t->alias_type)
	    l_fail (l, "bad alias '%s'", e->t->name);
	  vec_add1 (types, e);
	}
    }

  static const struct
  {
    char *key;
    u8 kind;
  } groups[] = {
    { "types", VL_API_DT_TYPEDEF },
    { "unions", VL_API_DT_UNION },
    { "messages", VL_API_DT_MESSAGE },
  };

  for (u32 g = 0; g < ARRAY_LEN (groups); g++)
    {
      x = l_member (l, root, groups[g].key);
      if (!l_is (l, x, CLIB_JSON_VALUE_ARRAY))
	continue;

      vec_foreach (d, clib_json_get_array_value_indices (j, x))
	{
	  name = l_def_name (l, *d);
	  if (!name)
	    {
	      l_fail (l, "bad definition in '%s'", groups[g].key);
	      break;
	    }

	  e = l_new (l, name, groups[g].kind, *d);

	  if (groups[g].kind == VL_API_DT_MESSAGE)
	    {
	      e->t->id = vec_len (msgs);
	      vec_add1 (msgs, e);
	    }
	  else
	    vec_add1 (types, e);
	}
    }

  /* every type, in the order of the file: the layout of a type needs the
   * types it uses */
  vec_foreach_index (x, types)
    l_load (l, types[x]);
  vec_foreach_index (x, msgs)
    l_load (l, msgs[x]);

  /* the meta data of the definitions, the object at the end of the array */
  for (u32 g = 0; g < 2 && !l->err; g++)
    vec_foreach_index (x, g ? msgs : types)
      {
	e = (g ? msgs : types)[x];

	if (e->json && (e->t->kind == VL_API_DT_TYPEDEF || e->t->kind == VL_API_DT_MESSAGE ||
			e->t->kind == VL_API_DT_UNION))
	  {
	    int *v = clib_json_get_array_value_indices (j, e->json);
	    int meta = vec_len (v) > 1 ? v[vec_len (v) - 1] : -1;

	    if (l_is (l, meta, CLIB_JSON_VALUE_OBJECT))
	      {
		int c = l_member (l, meta, "crc"), o = l_member (l, meta, "options");

		if (c >= 0 && l_is (l, c, CLIB_JSON_VALUE_STRING))
		  e->t->crc = strtoul ((char *) l_string (l, c), 0, 0);
		if (o >= 0)
		  {
		    u32 n;

		    e->options = l_options (l, o, &n);
		    e->t->n_options = n;
		  }
	      }
	  }

	for (u32 i = 0; i < ARRAY_LEN (desc_manual_print); i++)
	  if (e->t->kind != VL_API_DT_MESSAGE && !strcmp (e->t->name, desc_manual_print[i]))
	    e->t->flags |= VL_API_DTF_MANUAL_PRINT;
      }

  l_services (l, l_member (l, root, "services"));

  if (l->err)
    {
      err = l->err;
      goto done;
    }

  loaded = clib_mem_alloc (sizeof (*loaded));
  clib_memset (loaded, 0, sizeof (*loaded));
  f = &loaded->file;
  f->module = l_string (l, l_member (l, root, "module"));
  x = l_member (l, root, "vl_api_version");
  if (x >= 0 && l_is (l, x, CLIB_JSON_VALUE_STRING))
    {
      const char *crc = l_string (l, x);

      f->file_crc = strtoul (crc, 0, 0);
    }

  /* the fields, the values and the options of all the types in one array each,
   * the options of the file are the first */
  {
    u32 nf = 0, nv = 0, no = 0, n_file;
    const vl_api_desc_option_t *file_opts = l_options (l, l_member (l, root, "options"), &n_file);
    vl_api_desc_field_t *fa;
    vl_api_desc_enum_val_t *va;
    vl_api_desc_option_t *oa;

    for (u32 i = 0; i < l->nt + l->nm; i++)
      {
	vl_api_desc_type_t *t = i < l->nt ? &l->tarr[i] : &l->marr[i - l->nt];

	if (t->kind == VL_API_DT_ENUM || t->kind == VL_API_DT_ENUMFLAG)
	  nv += t->n_fields;
	else if (t->kind != VL_API_DT_ALIAS)
	  nf += t->n_fields;
      }

    for (u32 i = 0; i < vec_len (types) + vec_len (msgs); i++)
      {
	e = i < vec_len (types) ? types[i] : msgs[i - vec_len (types)];
	no += e->t->n_options;
      }

    fa = l_alloc (l, (nf + 1) * sizeof (*fa));
    va = l_alloc (l, (nv + 1) * sizeof (*va));
    oa = l_alloc (l, (n_file + no + 1) * sizeof (*oa));

    for (u32 i = 0; i < n_file; i++)
      oa[i] = file_opts[i];

    nf = nv = 0;
    no = n_file;

    for (u32 i = 0; i < vec_len (types) + vec_len (msgs); i++)
      {
	e = i < vec_len (types) ? types[i] : msgs[i - vec_len (types)];

	if (e->values)
	  {
	    e->t->first = nv;
	    for (u32 k = 0; k < e->t->n_fields; k++)
	      va[nv++] = e->values[k];
	  }
	else if (e->fields)
	  {
	    e->t->first = nf;
	    for (u32 k = 0; k < e->t->n_fields; k++)
	      fa[nf++] = e->fields[k];
	  }

	if (e->options)
	  {
	    e->t->first_option = no;
	    for (u32 k = 0; k < e->t->n_options; k++)
	      oa[no++] = e->options[k];
	  }
      }

    f->fields = fa;
    f->values = va;
    f->options = oa;
    f->n_options = n_file;
  }
  f->types = l->tarr;
  f->n_types = l->nt;
  f->msgs = l->marr;
  f->n_msgs = l->nm;

  if (!f->module || x < 0)
    {
      err = clib_error_return (0, "no module or vl_api_version");
      clib_mem_free (loaded);
      goto done;
    }

  loaded->allocs = l->allocs;
  l->allocs = 0;
  *file = f;
  err = 0;

done:
  for (u32 i = 0; i < vec_len (l->allocs); i++)
    clib_mem_free (l->allocs[i]);
  vec_free (l->allocs);
  vec_free (types);
  vec_free (msgs);
  hash_free (l->types);
  hash_free (l->consts);
  return err;
}

void
vl_api_desc_file_free (const vl_api_desc_file_t *f)
{
  desc_loaded_t *loaded = (desc_loaded_t *) ((u8 *) f - offsetof (desc_loaded_t, file));

  for (u32 i = 0; i < vec_len (loaded->allocs); i++)
    clib_mem_free (loaded->allocs[i]);
  vec_free (loaded->allocs);
  clib_mem_free (loaded);
}
