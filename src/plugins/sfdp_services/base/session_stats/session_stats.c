/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vppinfra/byte_order.h"
#include <sfdp_services/base/session_stats/session_stats.h>
#include <vlib/stats/stats.h>

sfdp_session_stats_main_t sfdp_session_stats_main;

static u8 *
format_sfdp_session_stats_export_reason_internal (u8 *s, va_list *args)
{
  u8 reason = va_arg (*args, u32);
  switch (reason)
    {
#define _(name, val, str)                                                     \
  case SFDP_SESSION_STATS_EXPORT_##name:                                      \
    s = format (s, str);                                                      \
    break;
      foreach_sfdp_session_stats_export_reason
#undef _
	default : s = format (s, "unknown(%d)", reason);
      break;
    }
  return s;
}

u8 *
format_sfdp_session_stats_export_reason (u8 *s, va_list *args)
{
  return format_sfdp_session_stats_export_reason_internal (s, args);
}

u8 *
format_sfdp_session_stats (u8 *s, va_list *args)
{
  sfdp_session_stats_entry_t *stats =
    va_arg (*args, sfdp_session_stats_entry_t *);

  s = format (s, "pkts: [fwd: %llu, rev: %llu], bytes: [fwd: %llu, rev: %llu]",
	      stats->packets[SFDP_FLOW_FORWARD],
	      stats->packets[SFDP_FLOW_REVERSE],
	      stats->bytes[SFDP_FLOW_FORWARD], stats->bytes[SFDP_FLOW_REVERSE]);

  if (stats->first_seen > 0)
    s = format (s, ", first: %.4f, last: %.4f, duration: %.4fs",
		stats->first_seen, stats->last_seen,
		stats->last_seen - stats->first_seen);

  return s;
}

u32
sfdp_table_format_insert_session_stats (table_t *t, u32 n, sfdp_main_t *sfdp,
					u32 session_index,
					sfdp_session_t *session,
					sfdp_session_stats_entry_t *stats)
{
  table_format_cell (t, n, 0, "%u", session_index);
  table_format_cell (t, n, 1, "%llu", stats->packets[SFDP_FLOW_FORWARD]);
  table_format_cell (t, n, 2, "%llu", stats->packets[SFDP_FLOW_REVERSE]);
  table_format_cell (t, n, 3, "%llu", stats->bytes[SFDP_FLOW_FORWARD]);
  table_format_cell (t, n, 4, "%llu", stats->bytes[SFDP_FLOW_REVERSE]);
  if (stats->first_seen > 0)
    {
      table_format_cell (t, n, 5, "%.4f", stats->last_seen - stats->first_seen);
    }
  else
    {
      table_format_cell (t, n, 5, "-");
    }
  return n + 1;
}

/*
 * Initialize the ring buffer for session stats export
 */
int
sfdp_session_stats_ring_init (vlib_main_t *vm, u32 ring_size)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (ssm->ring_buffer_enabled)
    return 0;

  /* Schema describing the ring buffer entry format (JSON-like)
   * Offsets are for __clib_packed struct (no alignment padding):
   *   0: session_id (u64), 8: session_index (u32), 12: tenant_id (u32),
   *   16: proto (u8), 17: session_type (u8), 18: export_reason (u8), 19: pad (u8),
   *   20: packets_forward (u64), 28: packets_reverse (u64),
   *   36: bytes_forward (u64), 44: bytes_reverse (u64),
   *   52: first_seen (f64), 60: last_seen (f64), 68: export_time (f64),
   *   76: src_ip (16 bytes), 92: dst_ip (16 bytes),
   *   108: src_port (u16), 110: dst_port (u16), 112: is_ip4 (u8),
   *   113: reserved (15 bytes) -> total 128 bytes
   */
  static const char schema_string[] =
    "{"
    "\"version\":1,"
    "\"fields\":["
    "{\"name\":\"session_id\",\"type\":\"u64\",\"offset\":0},"
    "{\"name\":\"session_index\",\"type\":\"u32\",\"offset\":8},"
    "{\"name\":\"tenant_id\",\"type\":\"u32\",\"offset\":12},"
    "{\"name\":\"proto\",\"type\":\"u8\",\"offset\":16},"
    "{\"name\":\"session_type\",\"type\":\"u8\",\"offset\":17},"
    "{\"name\":\"export_reason\",\"type\":\"u8\",\"offset\":18},"
    "{\"name\":\"packets_forward\",\"type\":\"u64\",\"offset\":20},"
    "{\"name\":\"packets_reverse\",\"type\":\"u64\",\"offset\":28},"
    "{\"name\":\"bytes_forward\",\"type\":\"u64\",\"offset\":36},"
    "{\"name\":\"bytes_reverse\",\"type\":\"u64\",\"offset\":44},"
    "{\"name\":\"first_seen\",\"type\":\"f64\",\"offset\":52},"
    "{\"name\":\"last_seen\",\"type\":\"f64\",\"offset\":60},"
    "{\"name\":\"export_time\",\"type\":\"f64\",\"offset\":68},"
    "{\"name\":\"src_ip\",\"type\":\"ip\",\"offset\":76},"
    "{\"name\":\"dst_ip\",\"type\":\"ip\",\"offset\":92},"
    "{\"name\":\"src_port\",\"type\":\"u16\",\"offset\":108},"
    "{\"name\":\"dst_port\",\"type\":\"u16\",\"offset\":110},"
    "{\"name\":\"is_ip4\",\"type\":\"u8\",\"offset\":112}"
    "]}";

  vlib_stats_ring_config_t config = {
    .entry_size = sizeof (sfdp_session_stats_ring_entry_t),
    .ring_size = ring_size,
    .n_threads = vlib_get_n_threads (),
    .schema_size = strlen (schema_string), // FIXME - initially sizeof.. this is not accurate!
    .schema_version = 1
  };

  ssm->ring_buffer_index = vlib_stats_add_ring_buffer (
    &config, (const void *) schema_string, "/sfdp/session/stats");

  if (ssm->ring_buffer_index == CLIB_U32_MAX)
    {
      clib_warning ("Failed to create SFDP session stats ring buffer");
      return -1;
    }

  ssm->ring_buffer_size = ring_size;
  ssm->ring_buffer_enabled = 1;

  return 0;
}

/*
 * Export a single session's stats to the ring buffer
 */
void
sfdp_session_stats_export_session (vlib_main_t *vm, u32 session_index,
				   sfdp_session_stats_export_reason_t reason)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_stats_ring_entry_t *entry;
  sfdp_session_stats_entry_t *stats;
  sfdp_session_t *session;
  sfdp_tenant_t *tenant;
  u32 thread_index;

  if (!ssm->ring_buffer_enabled)
    return;

  if (session_index >= vec_len (ssm->stats))
    return;

  stats = vec_elt_at_index (ssm->stats, session_index);
  session = sfdp_session_at_index (session_index);

  /* Validate session version */
  if (stats->version != session->session_version)
    return;

  thread_index = vlib_get_thread_index ();

  /* Reserve a slot in the ring buffer */
  entry = vlib_stats_ring_reserve_slot (ssm->ring_buffer_index, thread_index);
  if (!entry)
    return;

  /* Fill in the entry */
  clib_memset (entry, 0, sizeof (*entry));

  entry->session_id = session->session_id;
  entry->session_index = session_index;
  entry->proto = session->proto;
  entry->session_type = session->type;
  entry->export_reason = reason;

  /* Get tenant ID */
  tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
  entry->tenant_id = tenant ? tenant->tenant_id : 0;

  /* Copy stats */
  entry->packets_forward = stats->packets[SFDP_FLOW_FORWARD];
  entry->packets_reverse = stats->packets[SFDP_FLOW_REVERSE];
  entry->bytes_forward = stats->bytes[SFDP_FLOW_FORWARD];
  entry->bytes_reverse = stats->bytes[SFDP_FLOW_REVERSE];
  entry->first_seen = stats->first_seen;
  entry->last_seen = stats->last_seen;
  entry->export_time = vlib_time_now (vm);

  /* Extract key information */
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      sfdp_session_ip4_key_t *key4 = &session->keys[0].key4;
      entry->is_ip4 = 1;
      clib_memcpy (entry->src_ip, &key4->ip4_key.ip_addr_lo, 4);
      clib_memcpy (entry->dst_ip, &key4->ip4_key.ip_addr_hi, 4);
      // entry->dst_port = key4->ip4_key.port_hi;
      // entry->src_port = key4->ip4_key.port_lo;
      entry->src_port = clib_net_to_host_u16(key4->ip4_key.port_lo);
      entry->dst_port = clib_net_to_host_u16(key4->ip4_key.port_hi);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      sfdp_session_ip6_key_t *key6 = &session->keys[0].key6;
      entry->is_ip4 = 0;
      clib_memcpy (entry->src_ip, &key6->ip6_key.ip6_addr_lo, 16);
      clib_memcpy (entry->dst_ip, &key6->ip6_key.ip6_addr_hi, 16);
      entry->src_port = clib_net_to_host_u16(key6->ip6_key.port_lo);
      entry->dst_port = clib_net_to_host_u16(key6->ip6_key.port_hi);
    }

  /* Commit the slot */
  vlib_stats_ring_commit_slot (ssm->ring_buffer_index, thread_index);

  /* Update export counter */
  ssm->total_exports++;
}

/*
 * Export all sessions to the ring buffer
 */
void
sfdp_session_stats_export_all_sessions (vlib_main_t *vm,
					sfdp_session_stats_export_reason_t reason)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_t *session;
  uword session_index;

  if (!ssm->ring_buffer_enabled)
    return;

  sfdp_foreach_session (sfdp, session_index, session)
  {
    sfdp_session_stats_entry_t *stats;

    if (session_index >= vec_len (ssm->stats))
      continue;

    stats = vec_elt_at_index (ssm->stats, session_index);

    /* Only export sessions that have seen traffic */
    if (stats->packets[SFDP_FLOW_FORWARD] == 0 &&
	stats->packets[SFDP_FLOW_REVERSE] == 0)
      continue;

    sfdp_session_stats_export_session (vm, session_index, reason);
  }
}

/*
 * Callback for session deletion - export stats before session is removed
 */
static u32
sfdp_session_stats_notify_deleted_sessions (const u32 *deleted_sessions,
					    u32 len)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vlib_main_t *vm = vlib_get_main ();

  for (u32 i = 0; i < len; i++)
    {
      u32 session_index = deleted_sessions[i];

      /* Export stats before clearing if ring buffer is enabled */
      if (ssm->export_on_expiry && ssm->ring_buffer_enabled)
	{
	  sfdp_session_stats_export_session (vm, session_index,
					     SFDP_SESSION_STATS_EXPORT_EXPIRY);
	}

      /* Clear the stats entry to avoid stale data */
      if (session_index < vec_len (ssm->stats))
	{
	  sfdp_session_stats_entry_t *stats =
	    vec_elt_at_index (ssm->stats, session_index);
	  clib_memset (stats, 0, sizeof (*stats));
	}
    }

  return 0;
}

/*
 * Callback for new session creation - initialize stats entry
 */
static u32
sfdp_session_stats_notify_new_sessions (const u32 *new_sessions, u32 len)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_entry_t *stats;
  sfdp_session_t *session;

  for (u32 i = 0; i < len; i++)
    {
      u32 session_index = new_sessions[i];

      vec_validate (ssm->stats, session_index);
      stats = vec_elt_at_index (ssm->stats, session_index);

      /* Initialize stats entry */
      clib_memset (stats, 0, sizeof (*stats));

      session = sfdp_session_at_index (session_index);
      stats->version = session->session_version;
      stats->first_seen = 0; /* Will be set on first packet */
    }

  return 0;
}

SFDP_REGISTER_CALLBACK (sfdp_notify_new_sessions_cb_t, head_notify_new_sessions,
			session_stats_new) = {
  .fun = sfdp_session_stats_notify_new_sessions,
};

SFDP_REGISTER_CALLBACK (sfdp_notify_deleted_sessions_cb_t,
			head_notify_deleted_sessions,
			session_stats_deleted) = {
  .fun = sfdp_session_stats_notify_deleted_sessions,
};

static clib_error_t *
sfdp_session_stats_init (vlib_main_t *vm)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  vec_validate (ssm->stats, sfdp_num_sessions ());
  vec_validate (ssm->per_thread, vlib_get_n_threads () - 1);

  ssm->ring_buffer_index = CLIB_U32_MAX;
  ssm->ring_buffer_enabled = 0;
  ssm->ring_buffer_size = 0;
  ssm->export_interval = 60.0;	     /* Default: export every 60 seconds */
  ssm->export_on_expiry = 1;	     /* Default: export on session expiry */
  ssm->periodic_export_enabled = 0;  /* Default: periodic export disabled */
  ssm->total_exports = 0;

  return 0;
}

VLIB_INIT_FUNCTION (sfdp_session_stats_init);
