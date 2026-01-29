/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vppinfra/byte_order.h"
#include <sfdp_services/session_stats/session_stats.h>
#include <vlib/stats/stats.h>

sfdp_session_stats_main_t sfdp_session_stats_main;

int
sfdp_session_stats_ring_init (vlib_main_t *vm, u32 ring_size)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  /* check if ring buffer is not already enabled */
  if (ssm->ring_buffer_enabled)
    return 0;

  // TODO - Schema string is in JSON format today - could another format be used per-see ?
  /* Build schema string dynamically to include custom_api_data_name if set */
  u8 *schema_string = 0;

  /* Start with base schema */
  schema_string = format (schema_string, "{"
					 "\"version\":1,"
					 "\"entry_size\":384,");

  /* Add custom_api_data_name - use default 'custom_api_data' if not set */
  if (ssm->custom_api_data_name[0])
    {
      schema_string =
	format (schema_string, "\"custom_api_data_name\":\"%s\",", ssm->custom_api_data_name);
    }
  else
    {
      schema_string = format (schema_string, "\"custom_api_data_name\":\"custom_api_data\",");
    }

  /* Add fields array */
  schema_string = format (
    schema_string, "\"fields\":["
		   "{\"name\":\"session_id\",\"type\":\"u64\",\"offset\":0},"
		   "{\"name\":\"session_index\",\"type\":\"u32\",\"offset\":8},"
		   "{\"name\":\"tenant_id\",\"type\":\"u32\",\"offset\":12},"
		   "{\"name\":\"proto\",\"type\":\"u8\",\"offset\":16},"
		   "{\"name\":\"session_type\",\"type\":\"u8\",\"offset\":17},"
		   "{\"name\":\"export_reason\",\"type\":\"u8\",\"offset\":18},"
		   "{\"name\":\"is_ip4\",\"type\":\"u8\",\"offset\":19},"
		   "{\"name\":\"packets_forward\",\"type\":\"u64\",\"offset\":20},"
		   "{\"name\":\"packets_reverse\",\"type\":\"u64\",\"offset\":28},"
		   "{\"name\":\"bytes_forward\",\"type\":\"u64\",\"offset\":36},"
		   "{\"name\":\"bytes_reverse\",\"type\":\"u64\",\"offset\":44},"
		   "{\"name\":\"first_seen\",\"type\":\"f64\",\"offset\":52},"
		   "{\"name\":\"last_seen\",\"type\":\"f64\",\"offset\":60},"
		   "{\"name\":\"export_time\",\"type\":\"f64\",\"offset\":68},"
		   "{\"name\":\"duration\",\"type\":\"f64\",\"offset\":76},"
		   "{\"name\":\"fwd_src_ip\",\"type\":\"ip\",\"offset\":84},"
		   "{\"name\":\"fwd_dst_ip\",\"type\":\"ip\",\"offset\":100},"
		   "{\"name\":\"fwd_src_port\",\"type\":\"u16\",\"offset\":116},"
		   "{\"name\":\"fwd_dst_port\",\"type\":\"u16\",\"offset\":118},"
		   "{\"name\":\"rev_src_ip\",\"type\":\"ip\",\"offset\":120},"
		   "{\"name\":\"rev_dst_ip\",\"type\":\"ip\",\"offset\":136},"
		   "{\"name\":\"rev_src_port\",\"type\":\"u16\",\"offset\":152},"
		   "{\"name\":\"rev_dst_port\",\"type\":\"u16\",\"offset\":154},"
		   "{\"name\":\"ttl_min_forward\",\"type\":\"u8\",\"offset\":156},"
		   "{\"name\":\"ttl_max_forward\",\"type\":\"u8\",\"offset\":157},"
		   "{\"name\":\"ttl_min_reverse\",\"type\":\"u8\",\"offset\":158},"
		   "{\"name\":\"ttl_max_reverse\",\"type\":\"u8\",\"offset\":159},"
		   "{\"name\":\"ttl_mean_forward\",\"type\":\"f64\",\"offset\":160},"
		   "{\"name\":\"ttl_mean_reverse\",\"type\":\"f64\",\"offset\":168},"
		   "{\"name\":\"ttl_stddev_forward\",\"type\":\"f64\",\"offset\":176},"
		   "{\"name\":\"ttl_stddev_reverse\",\"type\":\"f64\",\"offset\":184},"
		   "{\"name\":\"rtt_mean_forward\",\"type\":\"f64\",\"offset\":192},"
		   "{\"name\":\"rtt_mean_reverse\",\"type\":\"f64\",\"offset\":200},"
		   "{\"name\":\"rtt_stddev_forward\",\"type\":\"f64\",\"offset\":208},"
		   "{\"name\":\"rtt_stddev_reverse\",\"type\":\"f64\",\"offset\":216},"
		   "{\"name\":\"tcp_mss\",\"type\":\"u16\",\"offset\":224},"
		   "{\"name\":\"tcp_handshake_complete\",\"type\":\"u8\",\"offset\":226},"
		   "{\"name\":\"tcp_syn_packets\",\"type\":\"u32\",\"offset\":228},"
		   "{\"name\":\"tcp_fin_packets\",\"type\":\"u32\",\"offset\":232},"
		   "{\"name\":\"tcp_rst_packets\",\"type\":\"u32\",\"offset\":236},"
		   "{\"name\":\"tcp_ecn_ect_packets\",\"type\":\"u32\",\"offset\":240},"
		   "{\"name\":\"tcp_ecn_ce_packets\",\"type\":\"u32\",\"offset\":244},"
		   "{\"name\":\"tcp_ece_packets\",\"type\":\"u32\",\"offset\":248},"
		   "{\"name\":\"tcp_cwr_packets\",\"type\":\"u32\",\"offset\":252},"
		   "{\"name\":\"tcp_retransmissions_fwd\",\"type\":\"u32\",\"offset\":256},"
		   "{\"name\":\"tcp_retransmissions_rev\",\"type\":\"u32\",\"offset\":260},"
		   "{\"name\":\"tcp_zero_window_events_fwd\",\"type\":\"u32\",\"offset\":264},"
		   "{\"name\":\"tcp_zero_window_events_rev\",\"type\":\"u32\",\"offset\":268},"
		   "{\"name\":\"tcp_dupack_events_fwd\",\"type\":\"u32\",\"offset\":272},"
		   "{\"name\":\"tcp_dupack_events_rev\",\"type\":\"u32\",\"offset\":276},"
		   "{\"name\":\"tcp_partial_overlap_events_fwd\",\"type\":\"u32\",\"offset\":280},"
		   "{\"name\":\"tcp_partial_overlap_events_rev\",\"type\":\"u32\",\"offset\":284},"
		   "{\"name\":\"tcp_out_of_order_events_fwd\",\"type\":\"u32\",\"offset\":288},"
		   "{\"name\":\"tcp_out_of_order_events_rev\",\"type\":\"u32\",\"offset\":292},"
		   "{\"name\":\"tcp_last_seq_forward\",\"type\":\"u32\",\"offset\":296},"
		   "{\"name\":\"tcp_last_ack_forward\",\"type\":\"u32\",\"offset\":300},"
		   "{\"name\":\"tcp_last_seq_reverse\",\"type\":\"u32\",\"offset\":304},"
		   "{\"name\":\"tcp_last_ack_reverse\",\"type\":\"u32\",\"offset\":308},"
		   "{\"name\":\"custom_data_flags\",\"type\":\"u8\",\"offset\":312},"
		   "{\"name\":\"custom_api_data\",\"type\":\"u64\",\"offset\":320}"
		   "]}");

  /* Null-terminate the string for strlen */
  vec_add1 (schema_string, 0);

  vlib_stats_ring_config_t config = { .entry_size = sizeof (sfdp_session_stats_ring_entry_t),
				      .ring_size = ring_size,
				      .n_threads = vlib_get_n_threads (),
				      .schema_size = vec_len (schema_string) - 1,
				      .schema_version = 1 };

  ssm->ring_buffer_index =
    vlib_stats_add_ring_buffer (&config, (const void *) schema_string, "/sfdp/session/stats");

  vec_free (schema_string);

  if (ssm->ring_buffer_index == CLIB_U32_MAX)
    {
      clib_warning ("Failed to create SFDP session stats ring buffer");
      return -1;
    }

  ssm->ring_buffer_size = ring_size;
  ssm->ring_buffer_enabled = 1;

  return 0;
}

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

  /* Extract forward and reverse five-tuple from session keys */
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      sfdp_session_ip4_key_t *key4 = &session->keys[0].key4;
      entry->is_ip4 = 1;

      /* Forward five-tuple: src -> dst */
      clib_memcpy (entry->fwd_src_ip, &key4->ip4_key.ip_addr_lo, 4);
      clib_memcpy (entry->fwd_dst_ip, &key4->ip4_key.ip_addr_hi, 4);
      entry->fwd_src_port = clib_net_to_host_u16 (key4->ip4_key.port_lo);
      entry->fwd_dst_port = clib_net_to_host_u16 (key4->ip4_key.port_hi);

      /* Reverse five-tuple: dst -> src (swapped) */
      clib_memcpy (entry->rev_src_ip, &key4->ip4_key.ip_addr_hi, 4);
      clib_memcpy (entry->rev_dst_ip, &key4->ip4_key.ip_addr_lo, 4);
      entry->rev_src_port = clib_net_to_host_u16 (key4->ip4_key.port_hi);
      entry->rev_dst_port = clib_net_to_host_u16 (key4->ip4_key.port_lo);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      sfdp_session_ip6_key_t *key6 = &session->keys[0].key6;
      entry->is_ip4 = 0;

      /* Forward five-tuple: src -> dst */
      clib_memcpy (entry->fwd_src_ip, &key6->ip6_key.ip6_addr_lo, 16);
      clib_memcpy (entry->fwd_dst_ip, &key6->ip6_key.ip6_addr_hi, 16);
      entry->fwd_src_port = clib_net_to_host_u16 (key6->ip6_key.port_lo);
      entry->fwd_dst_port = clib_net_to_host_u16 (key6->ip6_key.port_hi);

      /* Reverse five-tuple: dst -> src (swapped) */
      clib_memcpy (entry->rev_src_ip, &key6->ip6_key.ip6_addr_hi, 16);
      clib_memcpy (entry->rev_dst_ip, &key6->ip6_key.ip6_addr_lo, 16);
      entry->rev_src_port = clib_net_to_host_u16 (key6->ip6_key.port_hi);
      entry->rev_dst_port = clib_net_to_host_u16 (key6->ip6_key.port_lo);
    }

  /* Duration */
  entry->duration =
    (stats->last_seen > stats->first_seen) ? (stats->last_seen - stats->first_seen) : 0.0;

  /* TTL statistics */
  entry->ttl_min_forward = stats->ttl[SFDP_FLOW_FORWARD].min_ttl;
  entry->ttl_max_forward = stats->ttl[SFDP_FLOW_FORWARD].max_ttl;
  entry->ttl_min_reverse = stats->ttl[SFDP_FLOW_REVERSE].min_ttl;
  entry->ttl_max_reverse = stats->ttl[SFDP_FLOW_REVERSE].max_ttl;
  entry->ttl_mean_forward = stats->ttl[SFDP_FLOW_FORWARD].mean;
  entry->ttl_mean_reverse = stats->ttl[SFDP_FLOW_REVERSE].mean;
  entry->ttl_stddev_forward = sfdp_session_stats_compute_stddev (
    stats->ttl[SFDP_FLOW_FORWARD].m2, stats->ttl[SFDP_FLOW_FORWARD].count);
  entry->ttl_stddev_reverse = sfdp_session_stats_compute_stddev (
    stats->ttl[SFDP_FLOW_REVERSE].m2, stats->ttl[SFDP_FLOW_REVERSE].count);

  /* RTT statistics */
  entry->rtt_mean_forward = stats->rtt[SFDP_FLOW_FORWARD].mean;
  entry->rtt_mean_reverse = stats->rtt[SFDP_FLOW_REVERSE].mean;
  entry->rtt_stddev_forward = sfdp_session_stats_compute_stddev (
    stats->rtt[SFDP_FLOW_FORWARD].m2, stats->rtt[SFDP_FLOW_FORWARD].count);
  entry->rtt_stddev_reverse = sfdp_session_stats_compute_stddev (
    stats->rtt[SFDP_FLOW_REVERSE].m2, stats->rtt[SFDP_FLOW_REVERSE].count);

  /* TCP-specific statistics (only valid for TCP sessions) */
  if (session->proto == IP_PROTOCOL_TCP)
    {
      entry->tcp_mss = stats->tcp.mss;
      entry->tcp_handshake_complete = stats->tcp.handshake_complete;
      entry->tcp_syn_packets = stats->tcp.syn_packets;
      entry->tcp_fin_packets = stats->tcp.fin_packets;
      entry->tcp_rst_packets = stats->tcp.rst_packets;
      /* ECN/CWR metrics */
      entry->tcp_ecn_ect_packets = stats->tcp.ecn_ect_packets;
      entry->tcp_ecn_ce_packets = stats->tcp.ecn_ce_packets;
      entry->tcp_ece_packets = stats->tcp.ece_packets;
      entry->tcp_cwr_packets = stats->tcp.cwr_packets;
      entry->tcp_retransmissions_fwd = stats->tcp.retransmissions[SFDP_FLOW_FORWARD];
      entry->tcp_retransmissions_rev = stats->tcp.retransmissions[SFDP_FLOW_REVERSE];
      entry->tcp_zero_window_events_fwd = stats->tcp.zero_window_events[SFDP_FLOW_FORWARD];
      entry->tcp_zero_window_events_rev = stats->tcp.zero_window_events[SFDP_FLOW_REVERSE];
      entry->tcp_dupack_events_fwd = stats->tcp.dupack_like[SFDP_FLOW_FORWARD];
      entry->tcp_dupack_events_rev = stats->tcp.dupack_like[SFDP_FLOW_REVERSE];
      entry->tcp_partial_overlap_events_fwd = stats->tcp.partial_overlaps[SFDP_FLOW_FORWARD];
      entry->tcp_partial_overlap_events_rev = stats->tcp.partial_overlaps[SFDP_FLOW_REVERSE];
      entry->tcp_out_of_order_events_fwd = stats->tcp.out_of_order[SFDP_FLOW_FORWARD];
      entry->tcp_out_of_order_events_rev = stats->tcp.out_of_order[SFDP_FLOW_REVERSE];
      entry->tcp_last_seq_forward = stats->tcp.last_seq[SFDP_FLOW_FORWARD];
      entry->tcp_last_ack_forward = stats->tcp.last_ack[SFDP_FLOW_FORWARD];
      entry->tcp_last_seq_reverse = stats->tcp.last_seq[SFDP_FLOW_REVERSE];
      entry->tcp_last_ack_reverse = stats->tcp.last_ack[SFDP_FLOW_REVERSE];
    }

  /* Populate custom data if configured */
  entry->custom_data_flags = 0;
  entry->custom_data.api_data = SFDP_SESSION_STATS_CUSTOM_API_DATA_INVALID;
  entry->custom_data.reserved = 0;

  if (pool_elts (ssm->custom_data_entries) > 0 && tenant)
    {
      /* Set per-tenant API custom data (first 64 bits) */
      u8 has_tenant_data = 0;
      u64 tenant_api_data =
	sfdp_session_stats_get_custom_api_data (tenant->tenant_id, &has_tenant_data);
      if (has_tenant_data)
	{
	  entry->custom_data.api_data = tenant_api_data;
	  entry->custom_data_flags |= SFDP_SESSION_STATS_CUSTOM_FLAG_API_DATA;
	}
    }

  /* Commit the slot */
  vlib_stats_ring_commit_slot (ssm->ring_buffer_index, thread_index);

  /* Update export counter */
  ssm->total_exports++;
}

void
sfdp_session_stats_export_all_sessions (vlib_main_t *vm, sfdp_session_stats_export_reason_t reason)
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
    if (stats->packets[SFDP_FLOW_FORWARD] == 0 && stats->packets[SFDP_FLOW_REVERSE] == 0)
      continue;

    sfdp_session_stats_export_session (vm, session_index, reason);
  }
}

/*
 * Callback for session deletion - export stats before session is removed
 */
static u32
sfdp_session_stats_notify_deleted_sessions (const u32 *deleted_sessions, u32 len)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vlib_main_t *vm = vlib_get_main ();

  for (u32 i = 0; i < len; i++)
    {
      u32 session_index = deleted_sessions[i];

      /* Export stats before clearing if ring buffer is enabled */
      if (ssm->export_on_expiry && ssm->ring_buffer_enabled)
	{
	  sfdp_session_stats_export_session (vm, session_index, SFDP_SESSION_STATS_EXPORT_EXPIRY);
	}

      /* Clear the stats entry to avoid stale data */
      if (session_index < vec_len (ssm->stats))
	{
	  sfdp_session_stats_entry_t *stats = vec_elt_at_index (ssm->stats, session_index);
	  clib_memset (stats, 0, sizeof (*stats));
	}
    }

  return 0;
}

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

SFDP_REGISTER_CALLBACK (sfdp_notify_deleted_sessions_cb_t, head_notify_deleted_sessions,
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
  ssm->export_interval = 30.0;	    /* Default: export every 30 seconds */
  ssm->export_on_expiry = 1;	    /* Default: export on session expiry */
  ssm->periodic_export_enabled = 0; /* Default: periodic export disabled */
  ssm->total_exports = 0;

  /* Custom API data name - empty by default */
  clib_memset (ssm->custom_api_data_name, 0, sizeof (ssm->custom_api_data_name));

  /* Per-tenant custom data hash table, allocated on demand */
  clib_bihash_init_8_8 (&ssm->custom_data_by_tenant, "custom_data_by_tenant", 64,
			(uword) 64 * 1024);
  ssm->custom_data_entries = NULL;

  return 0;
}

/*
 * Set custom API data value for a tenant (first 64 bits of custom data)
 */
int
sfdp_session_stats_set_custom_api_data (u32 tenant_id, u64 value)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (tenant_id == SFDP_SESSION_STATS_ALL_TENANTS)
    return -1; /* Cannot set data for "all tenants" - must specify a valid tenant */

  /* Create key from tenant_id */
  u64 key_value = sfdp_session_stats_make_custom_data_key (tenant_id);
  clib_bihash_kv_8_8_t kv, result;
  kv.key = key_value;

  /* Check if entry already exists */
  if (clib_bihash_search_8_8 (&ssm->custom_data_by_tenant, &kv, &result) == 0)
    {
      /* Entry exists, update it */
      sfdp_session_stats_custom_data_entry_t *entry =
	pool_elt_at_index (ssm->custom_data_entries, result.value);
      entry->value = value;
      entry->has_value = 1;
    }
  else
    {
      /* Create new entry */
      sfdp_session_stats_custom_data_entry_t *entry;
      pool_get_zero (ssm->custom_data_entries, entry);
      entry->value = value;
      entry->has_value = 1;
      kv.value = entry - ssm->custom_data_entries;
      clib_bihash_add_del_8_8 (&ssm->custom_data_by_tenant, &kv, 1);
    }

  return 0;
}

/*
 * Clear custom API data for a tenant or all tenants
 * If tenant_id == SFDP_SESSION_STATS_ALL_TENANTS, clear all tenants
 */
int
sfdp_session_stats_clear_custom_api_data (u32 tenant_id)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (tenant_id == SFDP_SESSION_STATS_ALL_TENANTS)
    {
      /* Clear all entries - reset the hash table and pool */
      sfdp_session_stats_custom_data_entry_t *entry;

      /* Clear all pool entries */
      pool_foreach (entry, ssm->custom_data_entries)
	{
	  entry->value = 0;
	  entry->has_value = 0;
	}

      /* Free the pool and reinitialize the hash table */
      pool_free (ssm->custom_data_entries);
      ssm->custom_data_entries = NULL;

      clib_bihash_free_8_8 (&ssm->custom_data_by_tenant);
      clib_bihash_init_8_8 (&ssm->custom_data_by_tenant, "custom_data_by_tenant", 64,
			    (uword) 64 * 1024);
    }
  else
    {
      /* Clear specific tenant */
      u64 key_value = sfdp_session_stats_make_custom_data_key (tenant_id);
      clib_bihash_kv_8_8_t kv, result;
      kv.key = key_value;

      if (clib_bihash_search_8_8 (&ssm->custom_data_by_tenant, &kv, &result) == 0)
	{
	  /* Entry exists, clear it */
	  sfdp_session_stats_custom_data_entry_t *entry =
	    pool_elt_at_index (ssm->custom_data_entries, result.value);
	  entry->value = 0;
	  entry->has_value = 0;

	  /* Remove from hash table and free pool entry */
	  clib_bihash_add_del_8_8 (&ssm->custom_data_by_tenant, &kv, 0);
	  pool_put (ssm->custom_data_entries, entry);
	}
    }

  return 0;
}

u64
sfdp_session_stats_get_custom_api_data (u32 tenant_id, u8 *has_value)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  u64 key_value = sfdp_session_stats_make_custom_data_key (tenant_id);
  clib_bihash_kv_8_8_t kv, result;
  kv.key = key_value;

  if (clib_bihash_search_8_8 (&ssm->custom_data_by_tenant, &kv, &result) == 0)
    {
      sfdp_session_stats_custom_data_entry_t *entry =
	pool_elt_at_index (ssm->custom_data_entries, result.value);
      if (entry->has_value)
	{
	  if (has_value)
	    *has_value = 1;
	  return entry->value;
	}
    }

  /* No value set for this tenant - return invalid marker */
  if (has_value)
    *has_value = 0;
  return SFDP_SESSION_STATS_CUSTOM_API_DATA_INVALID;
}

int
sfdp_session_stats_set_custom_api_data_name (const u8 *name, u32 name_len)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  /* Validate name length */
  if (name_len > SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN)
    return -1;

  /* Cannot change name while ring buffer is enabled */
  if (ssm->ring_buffer_enabled)
    return -2;

  /* Copy the name */
  if (name && name_len > 0)
    {
      clib_memcpy_fast (ssm->custom_api_data_name, name, name_len);
      ssm->custom_api_data_name[name_len] = '\0';
    }
  else
    {
      /* Clear the name if NULL or empty */
      clib_memset (ssm->custom_api_data_name, 0, sizeof (ssm->custom_api_data_name));
    }

  return 0;
}

int
sfdp_session_stats_get_custom_api_data_name (u8 *name, u32 *name_len)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (!name || !name_len)
    return -1;

  u32 actual_len = clib_strnlen ((char *) ssm->custom_api_data_name,
				 SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN);
  u32 copy_len = clib_min (actual_len, *name_len);
  clib_memcpy_fast (name, ssm->custom_api_data_name, copy_len);
  if (copy_len < *name_len)
    name[copy_len] = '\0';
  *name_len = actual_len;

  return 0;
}

VLIB_INIT_FUNCTION (sfdp_session_stats_init);
