/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* binary-api: calls the binary API from the CLI. The messages and their fields are
 * known from the API descriptors, so there is nothing per plugin. The
 * message is given as JSON or as "field value" pairs, the fields which are
 * not given get a default value. */

#include <ctype.h>
#include <vlib/vlib.h>
#include <vlib/cli_decl.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ethernet/cli_types.h>
#include <vlibapi/api.h>
#include <vlibapi/api_desc.h>
#include <vlibmemory/api.h>
#include <vlibmemory/memclnt.api_types.h>
#include <vpp/app/version.h>

#define BAPI_TIMEOUT 5.0

typedef struct
{
  u16 id;
  void *handler;
} bapi_saved_handler_t;

typedef struct
{
  /* handle of the in-process client, ~0 until it is created */
  u32 client_index;
  u32 context;

  /* request in progress */
  u8 active;
  u8 done;
  u8 is_dump;
  u16 reply_id;
  u16 ping_reply_id;
  clib_json_text_t replies;
  u32 n_replies;
  bapi_saved_handler_t *saved;
  /* what the arguments of the commands are, by the pointer of the argument */
  uword *info_by_arg;
  /* the messages which have a command, by name */
  uword *registered;
  u32 n_registered;
} bapi_test_main_t;

static bapi_test_main_t bapi_test_main = {
  .client_index = ~0,
};

static int
bapi_is_header_field (const char *name)
{
  return !strcmp (name, "_vl_msg_id") || !strcmp (name, "client_index") ||
	 !strcmp (name, "context");
}

static const vl_api_desc_field_t *
bapi_field (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t, const char *name)
{
  for (u32 i = 0; i < t->n_fields; i++)
    if (!strcmp (vl_api_desc_fields (df, t)[i].name, name))
      return &vl_api_desc_fields (df, t)[i];

  return 0;
}

static const vl_api_desc_msg_t *
bapi_find_msg (api_main_t *am, const char *name, u32 *id)
{
  for (u32 i = 0; i < vec_len (am->desc_by_msg_id); i++)
    {
      const vl_api_desc_msg_t *d = &am->desc_by_msg_id[i];

      if (d->type && !strcmp (d->type->name, name))
	{
	  *id = i;
	  return d;
	}
    }

  return 0;
}

/* ---- default values of the fields which are not given */

static u8 *
bapi_default_manual (u8 *s, const vl_api_desc_type_t *t)
{
  const char *n = t->name;

  if (!strcmp (n, "ip6_address"))
    return format (s, "\"::\"");

  if (!strcmp (n, "ip6_prefix") || !strcmp (n, "ip6_address_with_prefix"))
    return format (s, "\"::/0\"");

  if (!strcmp (n, "mac_address"))
    return format (s, "\"00:00:00:00:00:00\"");

  if (!strcmp (n, "ip4_prefix") || !strcmp (n, "ip4_address_with_prefix") ||
      !strcmp (n, "prefix") || !strcmp (n, "address_with_prefix"))
    return format (s, "\"0.0.0.0/0\"");

  return format (s, "\"0.0.0.0\"");
}

static u8 *bapi_default_fields (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_type_t *t);

static u8 *
bapi_default_value (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_field_t *f, int in_array)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);

  switch (f->kind)
    {
    case VL_API_DK_BOOL:
      return format (s, "false");
    case VL_API_DK_ENUM:
      for (u32 i = 0; i < r->n_fields; i++)
	if (vl_api_desc_values (df, r)[i].value == 0)
	  return format (s, "\"%s\"", vl_api_desc_values (df, r)[i].name);

      return format (s, "\"%s\"", r->n_fields ? vl_api_desc_values (df, r)[0].name : "");
    case VL_API_DK_ENUMFLAG:
      return format (s, "[]");
    case VL_API_DK_STRUCT:
      if (r->flags & VL_API_DTF_MANUAL_PRINT)
	return bapi_default_manual (s, r);

      return bapi_default_fields (df, s, r);
    case VL_API_DK_UNION:
      return format (s, "{}");
    case VL_API_DK_NAMED:
      return bapi_default_manual (s, r);
    default:
      return format (s, "0");
    }
}

/* the JSON text of a string */
static u8 *
bapi_quote_cstring (u8 *s, const char *str)
{
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_string (&j, 0, "%s", str);
  s = format (s, "%U", format_clib_json_text, &j);
  clib_json_free (&j);
  return s;
}

static u8 *
bapi_default_field (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_field_t *f)
{
  if (!(f->flags & VL_API_DF_ARRAY))
    {
      switch (f->default_kind)
	{
	case VL_API_DD_INT:
	  return format (s, "%lld", (long long) f->default_value.i);
	case VL_API_DD_BOOL:
	  return format (s, f->default_value.i ? "true" : "false");
	case VL_API_DD_FLOAT:
	  return format (s, "%.15g", f->default_value.f);
	case VL_API_DD_STRING:
	  return bapi_quote_cstring (s, f->default_value.s);
	}

      return bapi_default_value (df, s, f, 0);
    }

  if ((f->flags & VL_API_DF_MODERN_VLA) || f->kind == VL_API_DK_FSTRING)
    return format (s, "\"\"");

  if (vl_api_desc_field_is_u8 (f))
    {
      s = format (s, "\"0x");

      for (u32 i = 0; i < f->length; i++)
	s = format (s, "00");

      return format (s, "\"");
    }

  s = format (s, "[");

  if (!(f->flags & VL_API_DF_VLA))
    for (u32 i = 0; i < f->length; i++)
      {
	if (i)
	  s = format (s, ", ");

	s = bapi_default_value (df, s, f, 1);
      }

  return format (s, "]");
}

static u8 *
bapi_default_fields (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_type_t *t)
{
  u32 n = 0;

  s = format (s, "{");

  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];

      if (t->kind == VL_API_DT_UNION || (f->flags & VL_API_DF_LENGTH) ||
	  (t->kind == VL_API_DT_MESSAGE && bapi_is_header_field (f->name)))
	continue;

      s = format (s, "%s\"%s\": ", n++ ? ", " : "", f->name);
      s = bapi_default_field (df, s, f);
    }

  return format (s, "}");
}

static u8 *bapi_complete_object (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_type_t *t,
				 clib_json_text_t *user, int obj, u8 **error);

/* the value the user gave for a field, with the defaults for the fields of
 * the types inside it */
static u8 *
bapi_complete_value (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_field_t *f,
		     clib_json_text_t *user, int idx, u8 **error)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);
  int is_struct = r && (f->kind == VL_API_DK_STRUCT || f->kind == VL_API_DK_UNION) &&
		  !(r->flags & VL_API_DTF_MANUAL_PRINT);

  if (is_struct && !(f->flags & VL_API_DF_ARRAY) && clib_json_value_is_object (user, idx))
    return bapi_complete_object (df, s, r, user, idx, error);

  if (is_struct && (f->flags & VL_API_DF_ARRAY) && clib_json_value_is_array (user, idx))
    {
      int *e, n = 0;

      s = format (s, "[");
      vec_foreach (e, pool_elt_at_index (user->values, idx)->array_val_indices)
	{
	  if (n++)
	    s = format (s, ", ");

	  if (clib_json_value_is_object (user, *e))
	    s = bapi_complete_object (df, s, r, user, *e, error);
	  else
	    s = format (s, "%U", format_clib_json_value, user, *e);
	}
      return format (s, "]");
    }

  return format (s, "%U", format_clib_json_value, user, idx);
}

/* An object of a message or of a type, with all the fields: the ones the
 * user gave and the defaults for the others. The arms of an union are only
 * the ones the user gave. */
static u8 *
bapi_complete_object (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_type_t *t,
		      clib_json_text_t *user, int obj, u8 **error)
{
  clib_json_nvpair_t *nv;
  int is_msg = t->kind == VL_API_DT_MESSAGE;
  u32 n = 0;

  /* what is not a field is a mistake */
  pool_foreach (nv, pool_elt_at_index (user->values, obj)->nvpairs)
    {
      u8 *name = format (0, "%v%c", nv->name, 0);
      const vl_api_desc_field_t *f = bapi_field (df, t, (char *) name);
      /* the length of an array is in the JSON of a message, it is ignored */
      int ok = (f && !(is_msg && bapi_is_header_field (f->name))) ||
	       (is_msg && (!strcmp ((char *) name, "_msgname") || !strcmp ((char *) name, "_crc")));

      vec_free (name);

      if (!ok)
	{
	  *error = format (0, "'%v' is not a field of %s", nv->name, t->name);
	  return s;
	}
    }

  s = format (s, "{");

  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];
      int idx;

      if ((f->flags & VL_API_DF_LENGTH) || (is_msg && bapi_is_header_field (f->name)))
	continue;

      idx = clib_json_find_object_value_by_name (user, obj, "%s", f->name);
      if (idx < 0 && t->kind == VL_API_DT_UNION)
	continue;

      s = format (s, "%s\"%s\": ", n++ ? ", " : "", f->name);

      if (idx >= 0)
	s = bapi_complete_value (df, s, f, user, idx, error);
      else
	s = bapi_default_field (df, s, f);
    }

  return format (s, "}");
}

static u8 *
bapi_complete_json (const vl_api_desc_file_t *df, const vl_api_desc_type_t *d,
		    clib_json_text_t *user, u8 **error)
{
  u8 *s = 0;

  if (!clib_json_value_is_object (user, user->root_value))
    {
      *error = format (0, "the message must be a JSON object");
      return 0;
    }

  s = bapi_complete_object (df, s, d, user, user->root_value, error);

  if (*error)
    vec_free (s);

  return s;
}

/* ---- the in-process client */

static void
bapi_register_client (api_main_t *am, bapi_test_main_t *bm)
{
  vl_api_registration_t **regpp, *regp;
  void *oldheap;

  if (bm->client_index != ~0)
    return;

  pool_get (am->vl_clients, regpp);
  oldheap = vl_msg_push_heap ();
  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));
  regp = *regpp;
  clib_memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;
  regp->vlib_rp = am->vlib_rp;
  regp->shmem_hdr = am->shmem_hdr;
  /* the replies are sent to the queue of VPP, where they are handled */
  regp->vl_input_queue = am->shmem_hdr->vl_input_queue;
  regp->name = format (0, "binary-api");
  vec_add1 (regp->name, 0);
  vl_msg_pop_heap (oldheap);

  bm->client_index = vl_msg_api_handle_from_index_and_epoch (regp->vl_api_registration_pool_index,
							     am->shmem_hdr->application_restarts);
}

static void
bapi_reply_handler (void *mp)
{
  bapi_test_main_t *bm = &bapi_test_main;
  api_main_t *am = vlibapi_get_main ();
  u16 raw = *(u16 *) mp, id = clib_net_to_host_u16 (raw);
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);
  const vl_api_desc_msg_t *d;
  const vl_api_desc_field_t *cf;
  clib_json_text_t j;
  u8 *copy = 0;

  /* messages which are converted to host byte order before the handler
   * have the message id in host byte order */
  if (!m || m->is_autoendian)
    {
      id = raw;
      m = vl_api_get_msg_data (am, id);
    }

  if (bm->active && bm->is_dump && m && id == bm->ping_reply_id)
    {
      u32 ctx = ((vl_api_control_ping_reply_t *) mp)->context;

      if (!m->is_autoendian)
	ctx = clib_net_to_host_u32 (ctx);

      if (ctx == bm->context)
	bm->done = 1;

      return;
    }

  d = vl_api_desc_find_msg (am, id);
  if (!bm->active || !m || !d)
    return;

  vec_add (copy, mp, vl_msg_api_get_msg_length (mp));

  if (!m->is_autoendian)
    vl_api_msg_endian (am, id, copy, 0 /* to host */);

  cf = bapi_field (d->file, d->type, "context");
  if (cf)
    {
      u32 ctx;

      memcpy (&ctx, copy + cf->offset, sizeof (ctx));

      if (ctx != bm->context)
	{
	  vec_free (copy);
	  return;
	}
    }

  if (vl_api_desc_msg_to_json (d, copy, &j) == 0)
    {
      clib_json_append (&bm->replies, &j, 0);
      clib_json_free (&j);
      bm->n_replies++;

      if (id == bm->reply_id && !bm->is_dump)
	bm->done = 1;
    }

  vec_free (copy);
}

static void
bapi_hook (api_main_t *am, bapi_test_main_t *bm, u16 id)
{
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);
  bapi_saved_handler_t s = {
    .id = id,
  };

  if (!m)
    return;

  s.handler = m->handler;
  vec_add1 (bm->saved, s);
  m->handler = bapi_reply_handler;
}

static void
bapi_unhook (api_main_t *am, bapi_test_main_t *bm)
{
  bapi_saved_handler_t *s;

  vec_foreach (s, bm->saved)
    {
      vl_api_msg_data_t *m = vl_api_get_msg_data (am, s->id);

      if (m)
	m->handler = s->handler;
    }
  vec_reset_length (bm->saved);
}

/* sends a message, msg is in host byte order */
static void
bapi_send (api_main_t *am, bapi_test_main_t *bm, u16 id, u8 *msg, const vl_api_desc_msg_t *d)
{
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);
  const vl_api_desc_field_t *f;
  void *mp;

  f = bapi_field (d->file, d->type, "_vl_msg_id");
  memcpy (msg + f->offset, &id, sizeof (id));

  f = bapi_field (d->file, d->type, "client_index");
  if (f)
    memcpy (msg + f->offset, &bm->client_index, sizeof (bm->client_index));

  f = bapi_field (d->file, d->type, "context");
  if (f)
    memcpy (msg + f->offset, &bm->context, sizeof (bm->context));

  mp = vl_msg_api_alloc_as_if_client (vec_len (msg));
  clib_memcpy (mp, msg, vec_len (msg));

  if (m)
    vl_api_msg_endian (am, id, mp, 1 /* to network */);

  vl_msg_api_send_shmem (am->shmem_hdr->vl_input_queue, (u8 *) &mp);
}

static void
bapi_send_ping (api_main_t *am, bapi_test_main_t *bm, u16 id)
{
  vl_api_control_ping_t *mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (id);
  mp->client_index = bm->client_index;
  mp->context = clib_host_to_net_u32 (bm->context);
  vl_msg_api_send_shmem (am->shmem_hdr->vl_input_queue, (u8 *) &mp);
}

/* ---- list and help */

static void
bapi_list (vlib_main_t *vm, api_main_t *am, char *filter)
{
  u32 n = 0;

  for (u32 i = 0; i < vec_len (am->desc_files); i++)
    {
      const vl_api_desc_file_t *f = am->desc_files[i];

      for (u32 k = 0; k < f->n_msgs; k++)
	{
	  const char *name = f->msgs[k].name;

	  if (!(f->msgs[k].flags & VL_API_DTF_SERVICE) || (filter && !strstr (name, filter)))
	    continue;

	  vlib_cli_output (vm, "%-40s %s", name, f->module);
	  n++;
	}
    }

  vlib_cli_output (vm, "%u messages", n);
}

static void
bapi_help (vlib_main_t *vm, api_main_t *am, char *name)
{
  const vl_api_desc_msg_t *dm;
  const vl_api_desc_file_t *df;
  const vl_api_desc_type_t *d;
  u32 id;

  dm = bapi_find_msg (am, name, &id);
  if (!dm)
    {
      vlib_cli_output (vm, "unknown message '%s'", name);
      return;
    }

  df = dm->file;
  d = dm->type;

  {
    if (d->flags & VL_API_DTF_SERVICE)
      vlib_cli_output (
	vm, "%s: reply %s%s%s%s", d->name, d->reply ? vl_api_desc_reply (df, d)->name : "null",
	(d->flags & VL_API_DTF_STREAM) ? ", dump" : "", d->details ? ", details " : "",
	d->details ? vl_api_desc_details (df, d)->name : "");
    else
      vlib_cli_output (vm, "%s: not a request", d->name);
  }

  if (d->brief)
    vlib_cli_output (vm, "%s", d->brief);

  for (u32 i = 0; i < d->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, d)[i];

      if (bapi_is_header_field (f->name) || (f->flags & VL_API_DF_LENGTH))
	continue;

      vlib_cli_output (vm, "  %-28s %U%s%s%s%s%s", f->name, format_vl_api_desc_field_type, f,
		       (f->flags & VL_API_DF_VLA) ? " [vla, length " : "",
		       (f->flags & VL_API_DF_VLA) ? vl_api_desc_len_field_name (df, d, f) : "",
		       (f->flags & VL_API_DF_VLA) ? "]" : "", f->description ? " - " : "",
		       f->description ? f->description : "");
    }
}

/* ---- the commands, one per request message, from the descriptors */

typedef struct bapi_arg_info
{
  const vl_api_desc_file_t *df;
  const vl_api_desc_field_t *f;
  /* the group of the field of a type, 0 at the top */
  const struct bapi_arg_info *parent;
  u8 is_group;
  u8 is_json;
} bapi_arg_info_t;

static u8 *
bapi_parse_text (const cli_arg_t *a __clib_unused, u8 *tok, cli_value_t *v)
{
  v->str = vec_dup (tok);
  return 0;
}

static cli_type_t bapi_type_text = {
  .name = "text",
  .help = "the text of an address, a prefix",
  .owns_str = 1,
  .parse = bapi_parse_text,
};

static u8 *
bapi_json_quote (u8 *s, u8 *text)
{
  u32 i;

  vec_add1 (s, '"');

  vec_foreach_index (i, text)
    {
      u8 c = text[i];

      if (c == '"' || c == '\\')
	s = format (s, "\\%c", c);
      else if (c == '\n')
	s = format (s, "\\n");
      else if (c == '\t')
	s = format (s, "\\t");
      else if (c < 0x20)
	s = format (s, "\\u%04x", c);
      else
	vec_add1 (s, c);
    }

  vec_add1 (s, '"');
  return s;
}

/* A field which is a keyword with a value, and not a group or a JSON text */
static int
bapi_is_simple (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);

  if (f->flags & VL_API_DF_ARRAY)
    return (f->flags & VL_API_DF_MODERN_VLA) || f->kind == VL_API_DK_FSTRING ||
	   vl_api_desc_field_is_u8 (f);

  switch (f->kind)
    {
    case VL_API_DK_STRUCT:
      return r->flags & VL_API_DTF_MANUAL_PRINT;
    case VL_API_DK_UNION:
      return 0;
    case VL_API_DK_NAMED:
      return r->flags & VL_API_DTF_MANUAL_PRINT;
    default:
      return 1;
    }
}

static int
bapi_is_mac (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f)
{
  return f->ref && !strcmp (vl_api_desc_ref (df, f)->name, "mac_address");
}

static const cli_choice_t *
bapi_choices (const vl_api_desc_file_t *df, const vl_api_desc_type_t *r)
{
  cli_choice_t *c = clib_mem_alloc ((r->n_fields + 1) * sizeof (*c));

  clib_memset (c, 0, (r->n_fields + 1) * sizeof (*c));

  for (u32 i = 0; i < r->n_fields; i++)
    {
      c[i].name = vl_api_desc_values (df, r)[i].name;
      c[i].value = vl_api_desc_values (df, r)[i].value;
    }

  return c;
}

/* the help of an argument: what the comment of the message says about the
 * field, and its type */
static char *
bapi_field_help (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f)
{
  u8 *s = 0;

  if (f->description)
    s = format (s, "%s (%U)", f->description, format_vl_api_desc_field_type, df, f);
  else
    s = format (s, "%U", format_vl_api_desc_field_type, df, f);

  vec_add1 (s, 0);
  return (char *) s;
}

static void
bapi_make_keyword (const vl_api_desc_file_t *df, bapi_test_main_t *bm, cli_arg_t *a,
		   const vl_api_desc_field_t *f, const bapi_arg_info_t *parent)
{
  bapi_arg_info_t *info = clib_mem_alloc (sizeof (*info));
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);

  *info = (bapi_arg_info_t) {
    .df = df,
    .f = f,
    .parent = parent,
  };
  *a = (cli_arg_t) {
    .kind = CLI_K_KEYWORD,
    .name = f->name,
    .flags = CLI_F_OPTIONAL,
    .help = bapi_field_help (df, f),
  };

  if (f->flags & VL_API_DF_ARRAY)
    {
      if (vl_api_desc_field_is_u8 (f))
	{
	  a->type = &cli_type_hex;
	  a->max = f->length;
	}
      else
	a->type = &cli_type_string;
    }
  else
    switch (f->kind)
      {
      case VL_API_DK_U8:
	a->type = &cli_type_u32;
	a->max = 0xff;
	break;
      case VL_API_DK_U16:
	a->type = &cli_type_u32;
	a->max = 0xffff;
	break;
      case VL_API_DK_U32:
	a->type = &cli_type_u32;

	if ((f->ref && !strcmp (vl_api_desc_ref (df, f)->name, "interface_index")))
	  a->type = &cli_type_sw_interface;

	break;
      case VL_API_DK_U64:
	a->type = &cli_type_u64;
	break;
      case VL_API_DK_F64:
	a->type = &cli_type_f64;
	break;
      case VL_API_DK_BOOL:
	a->type = &cli_type_bool;
	break;
      case VL_API_DK_ENUM:
	a->type = &cli_type_enum;
	a->choices = bapi_choices (df, r);
	break;
      case VL_API_DK_ENUMFLAG:
	a->type = &cli_type_flags;
	a->choices = bapi_choices (df, r);
	break;
      case VL_API_DK_STRUCT:
      case VL_API_DK_NAMED:
	a->type = bapi_is_mac (df, f) ? &cli_type_mac_address : &bapi_type_text;
	break;
      default:
	/* the signed integers are numbers in the text */
	a->type = &cli_type_string;
	break;
      }

  hash_set (bm->info_by_arg, a, info);
}

static cli_arg_t *
bapi_build_args (const vl_api_desc_file_t *df, bapi_test_main_t *bm, const vl_api_desc_type_t *d)
{
  /* the hidden argument which tells the message, the JSON, the fields */
  u32 n_max = 2 + d->n_fields, n = 0;
  cli_arg_t *a = clib_mem_alloc ((n_max + 1) * sizeof (*a));
  bapi_arg_info_t *info;

  clib_memset (a, 0, (n_max + 1) * sizeof (*a));

  a[n++] = (cli_arg_t) {
    .kind = CLI_K_KEYWORD,
    .name = "_msg",
    .type = &cli_type_string,
    .flags = CLI_F_OPTIONAL | CLI_F_HIDDEN,
    .def = (char *) format (0, "%s%c", d->name, 0),
  };

  info = clib_mem_alloc (sizeof (*info));
  *info = (bapi_arg_info_t) {
    .is_json = 1,
  };
  a[n] = (cli_arg_t) {
    .kind = CLI_K_KEYWORD,
    .name = "json",
    .type = &cli_type_rest,
    .flags = CLI_F_OPTIONAL,
    .help = "fields as JSON, for the ones which have no argument",
  };
  hash_set (bm->info_by_arg, &a[n], info);
  n++;

  for (u32 i = 0; i < d->n_fields && n < 64; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, d)[i];
      const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);

      if ((f->flags & VL_API_DF_LENGTH) || bapi_is_header_field (f->name))
	continue;

      if (bapi_is_simple (df, f))
	{
	  bapi_make_keyword (df, bm, &a[n++], f, 0);
	  continue;
	}

      /* a type of simple fields is a group, everything else is in the JSON */
      if (f->kind == VL_API_DK_STRUCT && !(f->flags & VL_API_DF_ARRAY))
	{
	  u32 nc = 0;
	  cli_arg_t *c = clib_mem_alloc ((r->n_fields + 1) * sizeof (*c));

	  clib_memset (c, 0, (r->n_fields + 1) * sizeof (*c));

	  info = clib_mem_alloc (sizeof (*info));
	  *info = (bapi_arg_info_t) {
	    .f = f,
	    .is_group = 1,
	  };

	  for (u32 k = 0; k < r->n_fields && nc < 64; k++)
	    if (!(vl_api_desc_fields (df, r)[k].flags & VL_API_DF_LENGTH) &&
		bapi_is_simple (df, &vl_api_desc_fields (df, r)[k]))
	      bapi_make_keyword (df, bm, &c[nc++], &vl_api_desc_fields (df, r)[k], info);

	  a[n] = (cli_arg_t) {
	    .kind = CLI_K_GROUP,
	    .name = f->name,
	    .help = bapi_field_help (df, f),
	    .flags = CLI_F_OPTIONAL,
	    .children = c,
	  };
	  hash_set (bm->info_by_arg, &a[n], info);
	  n++;
	}
    }

  return a;
}

/* The JSON text of the value of an argument */
static u8 *
bapi_value_json (const vl_api_desc_file_t *df, u8 *s, const vl_api_desc_field_t *f,
		 const cli_value_t *v)
{
  const vl_api_desc_type_t *r = vl_api_desc_ref (df, f);
  char buf[32];

  if (f->flags & VL_API_DF_ARRAY)
    {
      if (vl_api_desc_field_is_u8 (f))
	return format (s, "\"0x%U\"", format_hex_bytes_no_wrap, v->str, vec_len (v->str));

      return bapi_json_quote (s, v->str);
    }

  switch (f->kind)
    {
    case VL_API_DK_U8:
    case VL_API_DK_U16:
    case VL_API_DK_U64:
      return format (s, "%llu", v->u64);
    case VL_API_DK_U32:
      if ((f->ref && !strcmp (vl_api_desc_ref (df, f)->name, "interface_index")))
	return format (s, "%u", v->index);

      return format (s, "%llu", v->u64);
    case VL_API_DK_F64:
      snprintf (buf, sizeof (buf), "%.17g", v->f64);
      return format (s, "%s", buf);
    case VL_API_DK_BOOL:
      return format (s, v->index ? "true" : "false");
    case VL_API_DK_ENUM:
      for (u32 i = 0; i < r->n_fields; i++)
	if (vl_api_desc_values (df, r)[i].value == v->index)
	  return format (s, "\"%s\"", vl_api_desc_values (df, r)[i].name);

      return format (s, "\"\"");
    case VL_API_DK_ENUMFLAG:
      {
	u32 n = 0;

	s = format (s, "[");

	for (u32 i = 0; i < r->n_fields; i++)
	  if (vl_api_desc_values (df, r)[i].value && (v->u64 & vl_api_desc_values (df, r)[i].value))
	    s = format (s, "%s\"%s\"", n++ ? ", " : "", vl_api_desc_values (df, r)[i].name);

	return format (s, "]");
      }
    case VL_API_DK_STRUCT:
    case VL_API_DK_NAMED:
      if (bapi_is_mac (df, f))
	return format (s, "\"%02x:%02x:%02x:%02x:%02x:%02x\"", v->prefix.addr[0], v->prefix.addr[1],
		       v->prefix.addr[2], v->prefix.addr[3], v->prefix.addr[4], v->prefix.addr[5]);

      return bapi_json_quote (s, v->str);
    default:
      /* the signed integers, a number if it is one */
      if (vec_len (v->str) && (isdigit (v->str[0]) || v->str[0] == '-'))
	return format (s, "%v", v->str);

      return bapi_json_quote (s, v->str);
    }
}

/* The JSON object of the arguments the user typed, and of the json argument:
 * its members replace the ones of the typed arguments. */
static u8 *
bapi_args_to_json (bapi_test_main_t *bm, cli_ctx_t *ctx, u8 **error)
{
  struct
  {
    const bapi_arg_info_t *group;
    u8 *members;
  } *groups = 0, *g;
  u8 *top = 0, *json = 0, *text = 0;
  clib_json_text_t typed, given;
  cli_value_t *v;
  u32 n = 0;

  vec_foreach (v, ctx->values)
    {
      uword *p = hash_get (bm->info_by_arg, v->arg);
      const bapi_arg_info_t *info = p ? (bapi_arg_info_t *) p[0] : 0;
      u8 **members = &top;

      if (!info)
	continue;

      if (info->is_json)
	{
	  json = v->str;
	  continue;
	}

      /* the group of the argument, a group is there even without arguments */
      if (info->is_group || info->parent)
	{
	  const bapi_arg_info_t *gi = info->is_group ? info : info->parent;

	  vec_foreach (g, groups)
	    if (g->group == gi)
	      break;

	  if (g == vec_end (groups))
	    {
	      vec_add2 (groups, g, 1);
	      g->group = gi;
	      g->members = 0;
	    }

	  if (info->is_group)
	    continue;

	  members = &g->members;
	}

      *members = format (*members, "%s\"%s\": ", vec_len (*members) ? ", " : "", info->f->name);
      *members = bapi_value_json (info->df, *members, info->f, v);
    }

  text = format (0, "{%v", top);

  vec_foreach (g, groups)
    {
      text = format (text, "%s\"%s\": {%v}", vec_len (text) > 1 ? ", " : "", g->group->f->name,
		     g->members);
      vec_free (g->members);
    }

  text = format (text, "}");
  vec_free (top);
  vec_free (groups);

  if (!json)
    return text;

  /* the json argument replaces what the typed arguments gave */
  if (clib_json_init_from_string (&typed, (char *) text, vec_len (text)) ||
      clib_json_init_from_string (&given, (char *) json, vec_len (json)))
    {
      *error = format (0, "the json argument is not a JSON object");
      vec_free (text);
      return 0;
    }

  vec_free (text);
  text = format (0, "{");

  if (clib_json_value_is_object (&given, given.root_value))
    {
      clib_json_nvpair_t *nv;

      pool_foreach (nv, pool_elt_at_index (typed.values, typed.root_value)->nvpairs)
	if (clib_json_find_object_value_by_name (&given, given.root_value, "%v", nv->name) < 0)
	  text = format (text, "%s\"%v\": %U", n++ ? ", " : "", nv->name, format_clib_json_value,
			 &typed, nv->value_index);

      pool_foreach (nv, pool_elt_at_index (given.values, given.root_value)->nvpairs)
	text = format (text, "%s\"%v\": %U", n++ ? ", " : "", nv->name, format_clib_json_value,
		       &given, nv->value_index);

      text = format (text, "}");
    }
  else
    {
      *error = format (0, "the json argument is not a JSON object");
      vec_free (text);
      text = 0;
    }

  clib_json_free (&typed);
  clib_json_free (&given);
  return text;
}

/* The replies, as the table or the JSON the user asked for with a pipe, or as
 * the JSON text. */
static clib_error_t *
bapi_show_replies (vlib_main_t *vm, cli_ctx_t *ctx, bapi_test_main_t *bm, int single)
{
  clib_json_text_t *r = &bm->replies;
  cli_column_t *cols = 0, *col;

  if (ctx && cli_is_structured (ctx))
    {
      int first = bm->n_replies ? clib_json_get_array_value_indices (r, r->root_value)[0] : -1;

      /* the members which are not objects or arrays are the columns */
      if (first >= 0 && clib_json_value_is_object (r, first))
	{
	  clib_json_nvpair_t *nv;

	  pool_foreach (nv, pool_elt_at_index (r->values, first)->nvpairs)
	    if (!clib_json_value_is_object (r, nv->value_index) &&
		!clib_json_value_is_array (r, nv->value_index))
	      {
		vec_add2 (cols, col, 1);
		col->key = col->header = (char *) format (0, "%v%c", nv->name, 0);
	      }
	}

      vec_add2 (cols, col, 1);
      clib_memset (col, 0, sizeof (*col));
      return cli_emit_table (ctx, r, cols);
    }

  if (single)
    {
      int first = clib_json_get_array_value_indices (r, r->root_value)[0];

      vlib_cli_output (vm, "%U", format_clib_json_value, r, first);
    }
  else
    vlib_cli_output (vm, "%U", format_clib_json_text, r);

  clib_json_free (r);
  return 0;
}

static clib_error_t *
bapi_execute (vlib_main_t *vm, cli_ctx_t *ctx, const char *name, clib_json_text_t *user)
{
  bapi_test_main_t *bm = &bapi_test_main;
  api_main_t *am = vlibapi_get_main ();
  const vl_api_desc_msg_t *dm;
  const vl_api_desc_file_t *df;
  const vl_api_desc_type_t *d;
  const vl_api_desc_type_t *reply, *stream_msg;
  clib_error_t *err = 0;
  u32 id, ping_id, ping_reply_id, base;
  u8 *error = 0, *full = 0, *msg = 0;
  int is_stream;
  f64 deadline;

  if (!am->shmem_hdr)
    return clib_error_return (0, "the shared memory API is not enabled");

  if (bm->active)
    return clib_error_return (0, "a request is in progress");

  dm = bapi_find_msg (am, name, &id);
  if (!dm || dm->type->kind != VL_API_DT_MESSAGE)
    return clib_error_return (0, "unknown message '%s', see 'binary-api list'", name);

  df = dm->file;
  d = dm->type;
  base = id - d->id;

  if (!(d->flags & VL_API_DTF_SERVICE))
    return clib_error_return (0, "'%s' is not a request", name);

  reply = vl_api_desc_reply (df, d);
  stream_msg = vl_api_desc_details (df, d);
  is_stream = !!(d->flags & VL_API_DTF_STREAM);

  full = bapi_complete_json (df, d, user, &error);
  if (!full)
    {
      err = clib_error_return (0, "%v", error);
      goto done;
    }

  {
    clib_json_text_t j;

    if (clib_json_init_from_string (&j, (char *) full, vec_len (full)))
      {
	err = clib_error_return (0, "the message is not valid JSON");
	goto done;
      }

    msg = vl_api_desc_msg_from_json (dm, &j, j.root_value);
    clib_json_free (&j);
  }

  if (!msg)
    {
      err = clib_error_return (
	0, "the arguments do not match the message, see 'binary-api help %s'", name);
      goto done;
    }

  /* what ends the request */
  {
    u32 rid;

    if (!reply || !bapi_find_msg (am, reply->name, &rid))
      {
	err = clib_error_return (0, "'%s' has no reply", name);
	goto done;
      }

    bm->reply_id = rid;
  }
  bm->is_dump = is_stream && !stream_msg;
  ping_id = vl_msg_api_get_msg_index ((u8 *) VL_API_CONTROL_PING_CRC);
  ping_reply_id = vl_msg_api_get_msg_index ((u8 *) VL_API_CONTROL_PING_REPLY_CRC);
  if (bm->is_dump && (ping_id == (u16) ~0 || ping_reply_id == (u16) ~0))
    {
      err = clib_error_return (0, "control_ping is not available");
      goto done;
    }

  bm->ping_reply_id = bm->is_dump ? ping_reply_id : ~0;

  bapi_register_client (am, bm);
  bm->context++;
  clib_json_init (&bm->replies);
  clib_json_add_array (&bm->replies, 0);
  bm->n_replies = 0;
  bm->done = 0;
  bm->active = 1;

  bapi_hook (am, bm, bm->reply_id);

  if (stream_msg)
    {
      u32 sid;

      if (bapi_find_msg (am, stream_msg->name, &sid))
	bapi_hook (am, bm, sid);
    }

  /* the details messages of a dump are the reply of the service, the end
   * is the reply of the control ping */
  if (bm->is_dump)
    bapi_hook (am, bm, ping_reply_id);

  bapi_send (am, bm, base + d->id, msg, dm);

  if (bm->is_dump)
    bapi_send_ping (am, bm, ping_id);

  deadline = vlib_time_now (vm) + BAPI_TIMEOUT;
  while (!bm->done && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 1e-3);

  bapi_unhook (am, bm);
  bm->active = 0;

  if (!bm->done)
    vlib_cli_output (vm, "no reply in %.0f seconds", BAPI_TIMEOUT);

  err = bapi_show_replies (vm, ctx, bm, bm->n_replies == 1 && !bm->is_dump && !stream_msg);

done:
  vec_free (error);
  vec_free (full);
  vec_free (msg);
  return err;
}

static clib_error_t *
bapi_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  bapi_test_main_t *bm = &bapi_test_main;
  cli_value_t *m = cli_get (ctx, "_msg");
  clib_json_text_t user;
  clib_error_t *err;
  u8 *error = 0, *text, *name;

  text = bapi_args_to_json (bm, ctx, &error);
  if (!text)
    {
      err = clib_error_return (0, "%v", error);
      vec_free (error);
      return err;
    }

  if (clib_json_init_from_string (&user, (char *) text, vec_len (text)))
    {
      vec_free (text);
      return clib_error_return (0, "the arguments are not valid JSON");
    }

  name = format (0, "%v%c", m->str, 0);
  err = bapi_execute (vm, ctx, (char *) name, &user);

  clib_json_free (&user);
  vec_free (name);
  vec_free (text);
  return err;
}

/* One command for each request message, they are there when all the plugins
 * have registered their descriptors. */
static clib_error_t *
bapi_register_commands (vlib_main_t *vm)
{
  bapi_test_main_t *bm = &bapi_test_main;
  api_main_t *am = vlibapi_get_main ();

  if (!bm->info_by_arg)
    {
      bm->info_by_arg = hash_create (0, sizeof (uword));
      bm->registered = hash_create_string (0, sizeof (uword));
    }

  for (u32 i = 0; i < vec_len (am->desc_files); i++)
    {
      const vl_api_desc_file_t *f = am->desc_files[i];

      for (u32 si = 0; si < f->n_msgs; si++)
	{
	  vlib_cli_command_t *c;
	  const vl_api_desc_type_t *d = &f->msgs[si];
	  const vl_api_desc_file_t *df = f;
	  u8 *name;
	  clib_error_t *err;
	  int keep = 0;

	  if (!(d->flags & VL_API_DTF_SERVICE))
	    continue;

	  name = format (0, "%s%c", d->name, 0);

	  if (!hash_get_mem (bm->registered, (char *) name))
	    {
	      c = clib_mem_alloc (sizeof (*c));
	      clib_memset (c, 0, sizeof (*c));
	      c->path = (char *) format (0, "binary-api %s%c", name, 0);
	      c->short_help =
		(char *) format (0, "binary-api %s [<field> <value> ...] [json {...}]%c", name, 0);
	      c->args = bapi_build_args (df, bm, d);
	      c->handler = bapi_command_fn;
	      c->function = cli_dispatch;
	      c->function_arg = (uword) c;
	      c->is_mp_safe = 1;

	      err = vlib_cli_register (vm, c);
	      if (err)
		clib_error_free (err);
	      else
		{
		  /* the hash keeps the name */
		  hash_set_mem (bm->registered, (char *) name, 1);
		  bm->n_registered++;
		  keep = 1;
		}
	    }

	  if (!keep)
	    vec_free (name);
	}
    }

  return 0;
}

/* The descriptors of some of the files are registered when the API process
 * starts, which is after the main loop is entered. */
static uword
bapi_register_process (vlib_main_t *vm, vlib_node_runtime_t *rt __clib_unused,
		       vlib_frame_t *f __clib_unused)
{
  vlib_process_suspend (vm, 0.5);
  bapi_register_commands (vm);
  return 0;
}

VLIB_REGISTER_NODE (bapi_register_node) = {
  .function = bapi_register_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "bapi-register",
};

VLIB_MAIN_LOOP_ENTER_FUNCTION (bapi_register_commands);

/* "binary-api <message>" before all the commands exist, they are made and the line
 * is run again. */
static clib_error_t *
bapi_parent_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd __clib_unused)
{
  bapi_test_main_t *bm = &bapi_test_main;
  unformat_input_t again;
  u32 before = bm->n_registered;
  u8 *line = 0;
  uword c;

  bapi_register_commands (vm);

  if (bm->n_registered == before)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  line = format (0, "binary-api ");

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    vec_add1 (line, c);

  unformat_init_vector (&again, line);
  vlib_cli_input (vm, &again, 0, 0);
  unformat_free (&again);
  return 0;
}

VLIB_CLI_COMMAND (bapi_parent_command, static) = {
  .path = "binary-api",
  .short_help = "binary-api <message> [<field> <value> ...] [json {...}]",
  .function = bapi_parent_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
bapi_list_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd __clib_unused)
{
  char *filter = 0;

  unformat (input, "%s", &filter);
  bapi_list (vm, vlibapi_get_main (), filter);
  vec_free (filter);
  return 0;
}

VLIB_CLI_COMMAND (bapi_list_command, static) = {
  .path = "binary-api list",
  .short_help = "binary-api list [<filter>]",
  .function = bapi_list_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
bapi_help_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd __clib_unused)
{
  char *name = 0;

  if (!unformat (input, "%s", &name))
    return clib_error_return (0, "binary-api help <message>");

  bapi_help (vm, vlibapi_get_main (), name);
  vec_free (name);
  return 0;
}

VLIB_CLI_COMMAND (bapi_help_command, static) = {
  .path = "binary-api help",
  .short_help = "binary-api help <message>",
  .function = bapi_help_command_fn,
  .is_mp_safe = 1,
};
