/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#ifndef included_vpp_session_stats_export_internal_h
#define included_vpp_session_stats_export_internal_h

#include <vpp-api/client/stat_client.h>
#include <vlib/stats/shared.h>
#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vppinfra/time.h>
#include <plugins/sfdp_services/session_stats/session_stats.h>
#include <plugins/sfdp_services/session_stats/session_stats.api_types.h>

/* ring-entry type comes from the API-generated session stats typedef
 * shared by VPP session stats service and application */

/* Default port - follow existing exporter behavior */
#define SERVER_PORT 9482

/* Ring buffer name for SFDP session stats */
#define SFDP_SESSION_STATS_RING "/sfdp/session/stats"

/* Maximum sessions to track for Prometheus (to limit memory) */
#define MAX_TRACKED_SESSIONS 10000

/* Default Prometheus label name for opaque ring field */
#define OPAQUE_LABEL_DEFAULT_NAME "opaque"

typedef struct
{
  u32 entry_size;
  u32 schema_version;
  u32 schema_size;
  u32 schema_offset;
  u8 parsed;
} ring_schema_t;

typedef struct
{
  vl_api_sfdp_session_stats_ring_entry_t stats;
  u64 session_id;
  f64 last_update;
} tracked_session_t;

typedef struct
{
  u32 local_tail;
  u64 last_sequence;
  u8 initialized;
} thread_consumer_state_t;

/*
 * Global exporter state.
 * `session_silence_timeout`: stale threshold in seconds; stale sessions remain
 * in cache but are skipped during metrics emission.
 */
typedef struct
{
  tracked_session_t *sessions;
  uword *session_index_by_id;
  thread_consumer_state_t *thread_states;
  u8 *instance;
  u8 *opaque_label;
  ring_schema_t schema;
  f64 session_silence_timeout;
} session_exporter_main_t;

typedef enum
{
  CONSUME_OK = 0,
  CONSUME_ERR_NO_RING = -1,
  CONSUME_ERR_CONFIG = -2,
  CONSUME_ERR_SCHEMA = -3,
} consume_result_t;

extern session_exporter_main_t exporter_main;

void schema_reset (ring_schema_t *schema);
int ensure_schema_loaded (session_exporter_main_t *em, stat_client_main_t *shm,
			  vlib_stats_entry_t *ep, const vlib_stats_ring_config_t *config,
			  const vlib_stats_ring_metadata_t *metadata, int *schema_changed);
void decode_entry (const session_exporter_main_t *em, const u8 *entry,
		   vl_api_sfdp_session_stats_ring_entry_t *out);

consume_result_t consume_ring_buffer_entries (stat_client_main_t *shm);
void dump_session_metrics (FILE *stream, stat_client_main_t *shm);

#endif /* included_vpp_session_stats_export_internal_h */
