/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

/* Tests the API descriptors which are created from the .api.json text of a
 * file, as vat2 does, against the ones vppapigen compiles in, and converts
 * messages from and to JSON with them. */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <vlibapi/api.h>
#include "vat2/test/vat2_test.api_types.h"
#include <vlibapi/api_desc.h>

/* the API descriptors of the file */
#include "vat2/test/vat2_test.api_desc.c"

#define CHECK(c, fmt, ...)                                                                         \
  do                                                                                               \
    {                                                                                              \
      if (!(c))                                                                                    \
	{                                                                                          \
	  fformat (stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__);                 \
	  exit (1);                                                                                \
	}                                                                                          \
    }                                                                                              \
  while (0)

struct tests
{
  char *s;
  bool should_fail;
};

struct tests tests[] = {
  { .s = "{\"_msgname\": \"test_prefix\", \"pref\": \"2001:db8::/64\"}" },
  { .s = "{\"_msgname\": \"test_prefix\", \"pref\": \"192.168.10.0/24\"}" },
  { .s = "{\"_msgname\": \"test_enum\", \"flags\": [\"RED\", \"BLUE\"]}" },
  { .s = "{\"_msgname\": \"test_enum\", \"flags\": [\"BLACK\", \"BLUE\"]}",
    .should_fail = 1 },
  { .s = "{\"_msgname\": \"test_string\", \"str\": {\"str\": \"Test string "
	 "type\"}}" },
  { .s =
      "{\"_msgname\": \"test_string2\", \"str\": \"Test string toplevel\"}" },
  { .s = "{\"_msgname\": \"test_vla\", \"count\": 5, \"vla\": [1,2,3,4,5]}" },
  { .s = "{\"_msgname\": \"test_vla2\", \"count\": 5, \"vla\": "
	 "\"0xaabbccddee\"}" },
  { .s = "{\"_msgname\": \"test_vla3\", \"count\": 2, \"vla\": [{\"data\": 1} "
	 ", {\"data\": 2} ] }" },
  { .s = "{\"_msgname\": \"test_vla4\", \"data\": { \"count\": 5, \"vla\": "
	 "[1,2,3,4,5] }}" },
  { .s = "{\"_msgname\": \"test_vla5\", \"data\": { \"count\": 5, \"vla\": "
	 "\"0xaabbccddee\" }}" },
  { .s = "{\"_msgname\": \"test_addresses\", \"a\": \"1.2.3.4\" }" },
  { .s = "{\"_msgname\": \"test_addresses\", \"a\": \"2001:db8::23\" }" },
  { .s = "{\"_msgname\": \"test_addresses2\", \"a\": [\"2001:db8::23\", "
	 "\"2001:db8::23\"] }" },
  { .s = "{\"_msgname\": \"test_addresses3\", \"n\": 2, \"a\": "
	 "[\"2001:db8::23\", \"2001:db8::23\"] }" },
  { .s = "{\"_msgname\": \"test_empty\"}" },
  { .s = "{\"_msgname\": \"test_interface\", \"sw_if_index\": 100 }" },
  { .s = "{\"_msgname\": \"test_interface\", \"sw_if_index\": 4294967295 }" },
};

static const vl_api_desc_file_t *loaded;

/* The descriptors of a type, and of the types of its fields, are the same */
static void
check_type (const vl_api_desc_file_t *cf, const vl_api_desc_type_t *c, const vl_api_desc_file_t *lf,
	    const vl_api_desc_type_t *l)
{
  /* the JSON does not tell which messages use autoendian */
  u8 mask = ~VL_API_DTF_AUTOENDIAN;

  CHECK (!strcmp (c->name, l->name), "name %s, %s", c->name, l->name);
  CHECK (c->kind == l->kind, "%s: kind %u, %u", c->name, c->kind, l->kind);
  CHECK (c->size == l->size, "%s: size %u, %u", c->name, c->size, l->size);
  CHECK ((c->flags & mask) == (l->flags & mask), "%s: flags 0x%x, 0x%x", c->name, c->flags,
	 l->flags);
  CHECK (c->crc == l->crc, "%s: crc 0x%x, 0x%x", c->name, c->crc, l->crc);
  CHECK (c->id == l->id, "%s: id %u, %u", c->name, c->id, l->id);
  CHECK (c->base == l->base, "%s: base %u, %u", c->name, c->base, l->base);
  CHECK (c->alias_length == l->alias_length, "%s: alias length", c->name);
  CHECK (c->n_fields == l->n_fields, "%s: %u fields, %u", c->name, c->n_fields, l->n_fields);

  if (c->kind == VL_API_DT_ENUM || c->kind == VL_API_DT_ENUMFLAG)
    {
      for (u32 i = 0; i < c->n_fields; i++)
	{
	  const vl_api_desc_enum_val_t *cv = cf->values + c->first + i;
	  const vl_api_desc_enum_val_t *lv = lf->values + l->first + i;

	  CHECK (!strcmp (cv->name, lv->name) && cv->value == lv->value, "%s: value %s", c->name,
		 cv->name);
	}
      return;
    }

  if (c->kind == VL_API_DT_ALIAS)
    return;

  for (u32 i = 0; i < c->n_fields; i++)
    {
      const vl_api_desc_field_t *a = vl_api_desc_fields (cf, c) + i;
      const vl_api_desc_field_t *b = vl_api_desc_fields (lf, l) + i;

      CHECK (!strcmp (a->name, b->name), "%s: field %s, %s", c->name, a->name, b->name);
      CHECK (a->kind == b->kind, "%s.%s: kind %u, %u", c->name, a->name, a->kind, b->kind);
      CHECK (a->flags == b->flags, "%s.%s: flags 0x%x, 0x%x", c->name, a->name, a->flags, b->flags);
      CHECK (a->offset == b->offset, "%s.%s: offset", c->name, a->name);
      CHECK (a->size == b->size, "%s.%s: size", c->name, a->name);
      CHECK (a->length == b->length, "%s.%s: length", c->name, a->name);
      CHECK (a->related == b->related, "%s.%s: related", c->name, a->name);
      CHECK (a->case_value == b->case_value, "%s.%s: case", c->name, a->name);
      CHECK (!a->ref == !b->ref, "%s.%s: type", c->name, a->name);

      if (a->ref)
	check_type (cf, cf->types + a->ref - 1, lf, lf->types + b->ref - 1);
    }
}

static void
check_file (const vl_api_desc_file_t *c, const vl_api_desc_file_t *l)
{
  CHECK (!strcmp (c->module, l->module), "module %s, %s", c->module, l->module);
  CHECK (c->file_crc == l->file_crc, "file crc 0x%x, 0x%x", c->file_crc, l->file_crc);
  CHECK (c->n_msgs == l->n_msgs, "%u messages, %u", c->n_msgs, l->n_msgs);

  for (u32 i = 0; i < c->n_msgs; i++)
    check_type (c, &c->msgs[i], l, &l->msgs[i]);
}

/* Whether two JSON values are the same, the order of the members of an object
 * does not matter. The _crc of a message is not compared. */
static int
json_equal (clib_json_text_t *a, int ai, clib_json_text_t *b, int bi)
{
  clib_json_value_t *av = pool_elt_at_index (a->values, ai);
  clib_json_value_t *bv = pool_elt_at_index (b->values, bi);
  clib_json_nvpair_t *nv;

  if (av->type != bv->type)
    return 0;

  switch (av->type)
    {
    case CLIB_JSON_VALUE_NUMBER:
      return av->number == bv->number;
    case CLIB_JSON_VALUE_STRING:
      return vec_is_equal (av->string, bv->string);
    case CLIB_JSON_VALUE_ARRAY:
      if (vec_len (av->array_val_indices) != vec_len (bv->array_val_indices))
	return 0;
      for (u32 i = 0; i < vec_len (av->array_val_indices); i++)
	if (!json_equal (a, av->array_val_indices[i], b, bv->array_val_indices[i]))
	  return 0;
      return 1;
    case CLIB_JSON_VALUE_OBJECT:
      {
	u32 na = 0, nb = 0;

	pool_foreach (nv, bv->nvpairs)
	  nb += !(vec_len (nv->name) == 4 && !memcmp (nv->name, "_crc", 4));

	pool_foreach (nv, av->nvpairs)
	  {
	    int v;

	    if (vec_len (nv->name) == 4 && !memcmp (nv->name, "_crc", 4))
	      continue;
	    na++;
	    v = clib_json_find_object_value_by_name (b, bi, "%v", nv->name);
	    if (v < 0 || !json_equal (a, nv->value_index, b, v))
	      return 0;
	  }
	return na == nb;
      }
    default:
      return 1;
    }
}

static void
runtest (char *s, bool should_fail)
{
  clib_json_text_t in, out;
  vl_api_desc_msg_t cm, lm;
  clib_error_t *err;
  u8 *name = 0, *msg, *cmsg, *net;
  int v;

  err = clib_json_init_from_string (&in, s, strlen (s));
  CHECK (!err, "%s: %U", s, format_clib_error, err);

  v = clib_json_find_object_value_by_name (&in, in.root_value, "_msgname");
  CHECK (v >= 0, "%s: no _msgname", s);
  name = format (0, "%v%c", pool_elt_at_index (in.values, v)->string, 0);
  printf ("Message name: %s\n", name);

  CHECK (vl_api_desc_file_find (loaded, (char *) name, &lm), "%s: not loaded", name);
  CHECK (vl_api_desc_file_find (&vat2_test_api_desc, (char *) name, &cm), "%s: not compiled in",
	 name);

  /* JSON to the message, the same with both descriptors */
  msg = vl_api_desc_msg_from_json (&lm, &in, in.root_value);
  cmsg = vl_api_desc_msg_from_json (&cm, &in, in.root_value);
  CHECK (msg && cmsg, "%s: cannot convert from JSON", name);
  CHECK (vec_is_equal (msg, cmsg), "%s: the messages differ", name);

  /* to network byte order, as it is sent, and back */
  net = vec_dup (msg);
  vl_api_desc_msg_endian (&lm, net, 1);
  CHECK (vl_api_desc_msg_calc_size (&lm, net) == vec_len (net), "%s: size %lu, %u", name,
	 vl_api_desc_msg_calc_size (&lm, net), vec_len (net));
  vl_api_desc_msg_endian (&lm, net, 0);
  CHECK (vec_is_equal (msg, net), "%s: byte order round trip", name);

  /* the message to JSON */
  CHECK (!vl_api_desc_msg_to_json (&lm, net, &out), "%s: cannot convert to JSON", name);
  CHECK (json_equal (&in, in.root_value, &out, out.root_value) == !should_fail, "%s: %s\n%U", name,
	 s, format_clib_json_text, &out);

  clib_json_free (&in);
  clib_json_free (&out);
  vec_free (name);
  vec_free (msg);
  vec_free (cmsg);
  vec_free (net);
}

int main (int argc, char **argv)
{
  clib_json_text_t j;
  clib_error_t *err;
  int fd;

  clib_mem_init (0, 64 << 20);

  fd = open (VAT2_TEST_API_JSON, O_RDONLY);
  CHECK (fd >= 0, "cannot open %s", VAT2_TEST_API_JSON);
  err = clib_json_init_from_file (&j, fd);
  CHECK (!err, "%U", format_clib_error, err);
  close (fd);

  err = vl_api_desc_file_from_json (&j, j.root_value, &loaded);
  CHECK (!err, "%U", format_clib_error, err);
  clib_json_free (&j);

  check_file (&vat2_test_api_desc, loaded);

  int i, n;
  n = sizeof(tests)/sizeof(tests[0]);
  for (i = 0; i < n; i++) {
    runtest(tests[i].s, tests[i].should_fail);
  }

  vl_api_desc_file_free (loaded);
}
