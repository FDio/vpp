/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <stddef.h>
#include <stdio.h>
#include "internal.h"

#define vl_endianfun
#include <plugins/sfdp_services/session_stats/session_stats.api.h>
#undef vl_endianfun

void
schema_reset (ring_schema_t *schema)
{
  clib_memset (schema, 0, sizeof (*schema));
}

int
ensure_schema_loaded (session_exporter_main_t *em, stat_client_main_t *shm, vlib_stats_entry_t *ep,
		      const vlib_stats_ring_config_t *config,
		      const vlib_stats_ring_metadata_t *metadata, int *schema_changed)
{
  /* load schema & identify potential conflicts with ring buffer metadata and config */
  if (schema_changed)
    *schema_changed = 0;

  /* check if entry has expected size */
  if (config->entry_size != sizeof (vl_api_sfdp_session_stats_ring_entry_t))
    {
      fprintf (stderr, "unsupported ring entry_size=%u expected=%u\n", config->entry_size,
	       (u32) sizeof (vl_api_sfdp_session_stats_ring_entry_t));
      return -1;
    }

  if (metadata->schema_size == 0)
    {
      fprintf (stderr, "no ring ABI identifier found in ring metadata\n");
      return -1;
    }

  if (em->schema.parsed && em->schema.schema_version == metadata->schema_version &&
      em->schema.schema_size == metadata->schema_size &&
      em->schema.schema_offset == metadata->schema_offset &&
      em->schema.entry_size == config->entry_size)
    return 0;

  if (schema_changed)
    *schema_changed = 1;

  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    return -1;

  u8 *schema_ptr = ring_ptr + metadata->schema_offset;
  u32 schema_size = metadata->schema_size;
  char *schema_buf = clib_mem_alloc (schema_size + 1);
  if (!schema_buf)
    return -1;

  clib_memcpy (schema_buf, schema_ptr, schema_size);
  schema_buf[schema_size] = '\0';

  /* check if version / abi id for session stats ring entries has expected value */
  if (clib_strcmp (schema_buf, VL_API_SFDP_SESSION_STATS_RING_ENTRY_ABI_ID_CRC) != 0)
    {
      fprintf (stderr, "unsupported/unknown ring ABI ID '%s' (expected '%s')\n", schema_buf,
	       VL_API_SFDP_SESSION_STATS_RING_ENTRY_ABI_ID_CRC);
      clib_mem_free (schema_buf);
      return -1;
    }

  /* if metadata schema is valid, proceed to copy to exporter main */
  schema_reset (&em->schema);
  em->schema.entry_size = config->entry_size;
  em->schema.schema_version = metadata->schema_version;
  em->schema.schema_size = metadata->schema_size;
  em->schema.schema_offset = metadata->schema_offset;
  em->schema.parsed = 1;

  clib_mem_free (schema_buf);
  return 0;
}

void
decode_entry (const session_exporter_main_t *em, const u8 *entry,
	      vl_api_sfdp_session_stats_ring_entry_t *out)
{
  /* Ring payload is API wire format; convert to host order after copy. */
  clib_memcpy_fast (out, entry, sizeof (*out));
  vl_api_sfdp_session_stats_ring_entry_t_endian (out, /* to_net */ 0);
}
