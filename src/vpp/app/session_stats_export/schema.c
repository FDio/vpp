/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "internal.h"

STATIC_ASSERT_SIZEOF (sfdp_session_stats_ring_entry_t, SESSION_STATS_ENTRY_SIZE);

const schema_field_def_t schema_field_defs[] = {
#define _(id, name, type, member) { name, FIELD_##id, type },
  foreach_session_stats_export_field (_)
#undef _
};

STATIC_ASSERT (ARRAY_LEN (schema_field_defs) == FIELD_MAX,
	       "schema_field_defs must match schema_field_id_t");

typedef struct
{
  schema_field_id_t id;
  schema_field_type_t type;
  u32 member_offset;
  u32 member_size;
} decode_field_map_t;

static const decode_field_map_t decode_field_map[] = {
#define _(field_id, field_name, field_type, field_member)                                          \
  {                                                                                                \
    .id = FIELD_##field_id,                                                                        \
    .type = field_type,                                                                            \
    .member_offset = (u32) offsetof (sfdp_session_stats_ring_entry_t, field_member),               \
    .member_size = (u32) sizeof (((sfdp_session_stats_ring_entry_t *) 0)->field_member),           \
  },
  foreach_session_stats_export_field (_)
#undef _
};

STATIC_ASSERT (ARRAY_LEN (decode_field_map) == FIELD_MAX,
	       "decode_field_map must match schema_field_id_t");

static void
init_cjson_hooks_once (void)
{
  static int initialized = 0;

  if (initialized)
    return;

  /* configure cJSON to use vpp memory alloc functions */
  cJSON_Hooks hooks = {
    .malloc_fn = clib_mem_alloc,
    .free_fn = clib_mem_free,
    .realloc_fn = clib_mem_realloc,
  };
  cJSON_InitHooks (&hooks);
  initialized = 1;
}

static int
schema_type_from_string (const char *type_str, const cJSON *field_obj,
			 schema_field_type_t *out_type, u32 *out_size)
{
  /* decode provided type in schema fields, and return associated type / size */
  if (!type_str || !out_type || !out_size)
    return -1;

  if (strcmp (type_str, "u8") == 0)
    {
      *out_type = FIELD_TYPE_U8;
      *out_size = 1;
      return 0;
    }
  if (strcmp (type_str, "u16") == 0)
    {
      *out_type = FIELD_TYPE_U16;
      *out_size = 2;
      return 0;
    }
  if (strcmp (type_str, "u32") == 0)
    {
      *out_type = FIELD_TYPE_U32;
      *out_size = 4;
      return 0;
    }
  if (strcmp (type_str, "u64") == 0)
    {
      *out_type = FIELD_TYPE_U64;
      *out_size = 8;
      return 0;
    }
  if (strcmp (type_str, "f64") == 0)
    {
      *out_type = FIELD_TYPE_F64;
      *out_size = 8;
      return 0;
    }
  /* ip4/ip6 format */
  if (strcmp (type_str, "ip") == 0)
    {
      *out_type = FIELD_TYPE_IP;
      *out_size = 16;
      return 0;
    }
  /* for bytes format, look at explicit 'size' field */
  if (strcmp (type_str, "bytes") == 0)
    {
      cJSON *size = cJSON_GetObjectItemCaseSensitive ((cJSON *) field_obj, "size");
      if (cJSON_IsNumber (size) && size->valuedouble >= 0)
	{
	  *out_type = FIELD_TYPE_BYTES;
	  *out_size = (u32) size->valuedouble;
	  return 0;
	}
    }

  return -1;
}

static const schema_field_def_t *
schema_field_def_lookup (const char *name)
{
  /* lookup field corresponding to provided name */
  if (!name)
    return 0;

  for (u32 i = 0; i < ARRAY_LEN (schema_field_defs); i++)
    {
      if (strcmp (schema_field_defs[i].name, name) == 0)
	return &schema_field_defs[i];
    }

  return 0;
}

void
schema_reset (ring_schema_t *schema)
{
  /* clear schema */
  clib_memset (schema, 0, sizeof (*schema));
}

static void
schema_set_field (ring_schema_t *schema, schema_field_id_t id, u32 offset, u32 size)
{
  /* if entry is found in schema, set as valid with size and offset properties */
  if (offset + size > schema->entry_size)
    return;

  schema->fields[id].offset = offset;
  schema->fields[id].size = size;
  schema->fields[id].valid = 1;
}

static void
schema_finalize (ring_schema_t *schema)
{
  /* check schema fields properties */
  /* having a core labels is at least expected */
  schema->has_opaque_label = schema->fields[FIELD_OPAQUE].valid;
  schema->has_core_labels =
    schema->fields[FIELD_SESSION_ID].valid && schema->fields[FIELD_TENANT_ID].valid &&
    schema->fields[FIELD_PROTO].valid && schema->fields[FIELD_IS_IP4].valid &&
    schema->fields[FIELD_SRC_IP].valid && schema->fields[FIELD_DST_IP].valid &&
    schema->fields[FIELD_SRC_PORT].valid && schema->fields[FIELD_DST_PORT].valid;
}

static int
schema_parse_json (session_exporter_main_t *em, const char *schema_buf, size_t schema_len,
		   const vlib_stats_ring_config_t *config,
		   const vlib_stats_ring_metadata_t *metadata)
{
  /* parse provided JSON schema */
  ring_schema_t *schema = &em->schema;

  schema_reset (schema);
  schema->entry_size = config->entry_size;
  schema->schema_version = metadata->schema_version;
  schema->schema_size = metadata->schema_size;
  schema->schema_offset = metadata->schema_offset;

  /* initialize cjson hooks if needed */
  init_cjson_hooks_once ();
  cJSON *root = cJSON_ParseWithLength (schema_buf, schema_len);
  if (!root)
    return -1;

  /* TODO - is adding/checking the entry size within the schema necessary ? */
  cJSON *schema_entry_size = cJSON_GetObjectItemCaseSensitive (root, "entry_size");
  if (cJSON_IsNumber (schema_entry_size))
    {
      u32 json_entry_size = (u32) schema_entry_size->valuedouble;
      if (json_entry_size != config->entry_size)
	fprintf (stderr, "Schema entry_size mismatch (schema=%u, ring=%u); using ring config\n",
		 json_entry_size, config->entry_size);
    }

  /* get fields of json schema containing information on stored data */

  cJSON *fields = cJSON_GetObjectItemCaseSensitive (root, "fields");
  if (!cJSON_IsArray (fields))
    {
      cJSON_Delete (root);
      return -1;
    }

  /* iterate over schema fields, and verify they confirm to corresponding fields in
   * internal schema  */
  cJSON *field = 0;
  cJSON_ArrayForEach (field, fields)
  {
    cJSON *name = cJSON_GetObjectItemCaseSensitive (field, "name");
    cJSON *type = cJSON_GetObjectItemCaseSensitive (field, "type");
    cJSON *offset = cJSON_GetObjectItemCaseSensitive (field, "offset");

    if (!cJSON_IsString (name) || !cJSON_IsString (type) || !cJSON_IsNumber (offset))
      continue;

    const schema_field_def_t *def = schema_field_def_lookup (name->valuestring);
    if (!def)
      continue;

    schema_field_type_t schema_type;
    u32 size = 0;
    if (schema_type_from_string (type->valuestring, field, &schema_type, &size) < 0)
      continue;

    if (schema_type != def->type)
      continue;

    /* if schema field matches conformity criteria, set as valid */
    schema_set_field (schema, def->id, (u32) offset->valuedouble, size);
  }

  cJSON_Delete (root);

  schema->parsed = 1;
  schema->valid = 1;
  schema_finalize (schema);
  return 0;
}

int
ensure_schema_loaded (session_exporter_main_t *em, stat_client_main_t *shm, vlib_stats_entry_t *ep,
		      const vlib_stats_ring_config_t *config,
		      const vlib_stats_ring_metadata_t *metadata, int *schema_changed)
{
  /* load schema & identify potential conflicts with ring buffer metadata and config */
  if (schema_changed)
    *schema_changed = 0;

  if (config->entry_size == 0)
    return -1;

  /* check if provided schema matches the existing one in the exporter main */
  if (em->schema.parsed && em->schema.schema_version == metadata->schema_version &&
      em->schema.schema_size == metadata->schema_size &&
      em->schema.schema_offset == metadata->schema_offset &&
      em->schema.entry_size == config->entry_size)
    return 0;

  if (schema_changed)
    *schema_changed = 1;

  if (metadata->schema_size == 0)
    {
      fprintf (stderr, "no schema found in ring buffer; cannot identify information to export\n");
      return -1;
    }

  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    return -1;

  u8 *schema_ptr = ring_ptr + metadata->schema_offset;
  u32 schema_size = metadata->schema_size;

  /* copy ring buffer schema information */
  char *schema_buf = clib_mem_alloc (schema_size + 1);
  if (!schema_buf)
    return -1;

  clib_memcpy (schema_buf, schema_ptr, schema_size);
  schema_buf[schema_size] = '\0';

  /* parse ring buffer schema to identify which information can be exported */
  int rv = schema_parse_json (em, schema_buf, schema_size, config, metadata);
  if (rv < 0)
    {
      fprintf (stderr, "Failed to parse ring schema in strict mode\n");
      clib_mem_free (schema_buf);
      return -1;
    }

  clib_mem_free (schema_buf);
  return 0;
}

static inline u8
read_field_u8 (const u8 *entry, const schema_field_t *field)
{
  u8 v = 0;
  clib_memcpy (&v, entry + field->offset, sizeof (v));
  return v;
}

static inline u16
read_field_u16 (const u8 *entry, const schema_field_t *field)
{
  u16 v = 0;
  clib_memcpy (&v, entry + field->offset, sizeof (v));
  return v;
}

static inline u32
read_field_u32 (const u8 *entry, const schema_field_t *field)
{
  u32 v = 0;
  clib_memcpy (&v, entry + field->offset, sizeof (v));
  return v;
}

static inline u64
read_field_u64 (const u8 *entry, const schema_field_t *field)
{
  u64 v = 0;
  clib_memcpy (&v, entry + field->offset, sizeof (v));
  return v;
}

static inline f64
read_field_f64 (const u8 *entry, const schema_field_t *field)
{
  f64 v = 0;
  clib_memcpy (&v, entry + field->offset, sizeof (v));
  return v;
}

void
decode_entry (const session_exporter_main_t *em, const u8 *entry,
	      sfdp_session_stats_ring_entry_t *out)
{
  /* decode ring buffer entry */
  const ring_schema_t *schema = &em->schema;

  clib_memset (out, 0, sizeof (*out));

  /* iterate over internal decode field map */
  /* use offset and size read from schema to read each field from ring buffer entry */
  for (u32 i = 0; i < ARRAY_LEN (decode_field_map); i++)
    {
      const decode_field_map_t *m = &decode_field_map[i];
      const schema_field_t *field = &schema->fields[m->id];
      if (!field->valid)
	continue;

      u8 *dest = (u8 *) out + m->member_offset;
      switch (m->type)
	{
	case FIELD_TYPE_U8:
	  {
	    u8 v = read_field_u8 (entry, field);
	    clib_memcpy (dest, &v, sizeof (v));
	    break;
	  }
	case FIELD_TYPE_U16:
	  {
	    u16 v = read_field_u16 (entry, field);
	    clib_memcpy (dest, &v, sizeof (v));
	    break;
	  }
	case FIELD_TYPE_U32:
	  {
	    u32 v = read_field_u32 (entry, field);
	    clib_memcpy (dest, &v, sizeof (v));
	    break;
	  }
	case FIELD_TYPE_U64:
	  {
	    u64 v = read_field_u64 (entry, field);
	    clib_memcpy (dest, &v, sizeof (v));
	    break;
	  }
	case FIELD_TYPE_F64:
	  {
	    f64 v = read_field_f64 (entry, field);
	    clib_memcpy (dest, &v, sizeof (v));
	    break;
	  }
	case FIELD_TYPE_IP:
	case FIELD_TYPE_BYTES:
	  {
	    u32 copy_size = clib_min (field->size, m->member_size);
	    clib_memcpy (dest, entry + field->offset, copy_size);
	    break;
	  }
	default:
	  break;
	}
    }
}
