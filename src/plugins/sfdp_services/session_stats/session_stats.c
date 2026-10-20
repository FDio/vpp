/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <stddef.h>
#include <errno.h>
#include <sys/random.h>
#include <unistd.h>
#include <sfdp_services/session_stats/session_stats.h>
#include <sfdp_services/session_stats/session_stats.api_types.h>
#include <vlib/stats/stats.h>
#include <vlib/threads.h>
#include <vppinfra/time.h>
#include <vppinfra/xxhash.h>

#define vl_endianfun
#include <sfdp_services/session_stats/session_stats.api.h>
#undef vl_endianfun

STATIC_ASSERT (sizeof (vl_api_sfdp_session_stats_ring_entry_v2_t) == 304,
	       "sfdp_session_stats_ring_entry_v2_t size changed");
STATIC_ASSERT (sizeof (vl_api_sfdp_session_stats_ring_entry_v3_t) == 306,
	       "sfdp_session_stats_ring_entry_v3_t size changed, "
	       "update consumers and bump API version");
STATIC_ASSERT (offsetof (vl_api_sfdp_session_stats_ring_entry_v3_t, update_sequence) == 304,
	       "update sequence offset changed, update consumers and bump API version");
STATIC_ASSERT (SFDP_SESSION_STATS_UPDATE_SEQUENCE_NEXT (65534) == 65535,
	       "update sequence must advance from 65534 to 65535");
STATIC_ASSERT (SFDP_SESSION_STATS_UPDATE_SEQUENCE_NEXT (65535) == 0,
	       "update sequence must wrap from 65535 to 0");
STATIC_ASSERT (SFDP_SESSION_STATS_UPDATE_SEQUENCE_NEXT (0) == 1,
	       "update sequence must advance from 0 to 1");

/* Keep the process marker exactly representable in GoVPP's float64 gauge. */
#define SFDP_SESSION_STATS_PROCESS_EPOCH_MAX ((1ULL << 53) - 1)

sfdp_session_stats_main_t sfdp_session_stats_main;

int
sfdp_session_stats_ring_init (vlib_main_t *vm, u32 ring_size)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_entry_t *stats;

  /* Copy the ABI ID associated with the version 3 ring entry. */
  const char *schema_id = VL_API_SFDP_SESSION_STATS_RING_ENTRY_V3_ABI_ID_CRC;
  u32 schema_size = clib_strnlen (schema_id, 128);

  clib_spinlock_lock (&ssm->ring_config_lock);

  /* check if ring buffer is not already enabled */
  if (ssm->ring_buffer_enabled)
    {
      clib_spinlock_unlock (&ssm->ring_config_lock);
      return 0;
    }

  /* Worker threads can be configured after plugin initialization. */
  vec_validate_aligned (ssm->per_thread, vlib_get_n_threads () - 1, CLIB_CACHE_LINE_BYTES);

  vlib_stats_ring_config_t config = { .entry_size =
					sizeof (vl_api_sfdp_session_stats_ring_entry_v3_t),
				      .ring_size = ring_size,
				      .n_threads = vlib_get_n_threads (),
				      .schema_size = schema_size,
				      .schema_version = 3 };

  ssm->ring_buffer_index =
    vlib_stats_add_ring_buffer (&config, (const void *) schema_id, "/sfdp/session/stats");

  if (ssm->ring_buffer_index == CLIB_U32_MAX)
    {
      clib_warning ("Failed to create SFDP session stats ring buffer");
      clib_spinlock_unlock (&ssm->ring_config_lock);
      return -1;
    }

  for (u32 i = 0; i < vec_len (ssm->per_thread); i++)
    clib_atomic_store_relax_n (&ssm->per_thread[i].ring_write_sequence, 0);
  ssm->ring_buffer_size = ring_size;
  vec_foreach (stats, ssm->stats)
    stats->create_exported = 0;
  ssm->ring_config_generation++;
  ssm->ring_buffer_enabled = 1;
  clib_spinlock_unlock (&ssm->ring_config_lock);

  return 0;
}

__clib_export int
sfdp_session_stats_ring_health_get_v1 (u32 worker_index, u32 abi_version, u32 output_size,
				       sfdp_session_stats_ring_health_v1_t *output)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_ring_health_v1_t health = { 0 };
  vlib_stats_ring_buffer_t *ring;
  vlib_stats_ring_metadata_t *metadata;
  const char *schema_id = VL_API_SFDP_SESSION_STATS_RING_ENTRY_V3_ABI_ID_CRC;
  u32 schema_id_len;

  if (!output || abi_version != SFDP_SESSION_STATS_RING_HEALTH_ABI_V1 ||
      output_size != sizeof (*output))
    return SFDP_SESSION_STATS_RING_HEALTH_ABI_MISMATCH;
  schema_id_len = clib_strnlen (schema_id, 128);
  if (schema_id_len < sizeof (health.ring_abi))
    return SFDP_SESSION_STATS_RING_HEALTH_UNAVAILABLE;

  clib_spinlock_lock (&ssm->ring_config_lock);
  if (!ssm->ring_buffer_enabled || worker_index >= vec_len (ssm->per_thread))
    {
      clib_spinlock_unlock (&ssm->ring_config_lock);
      return SFDP_SESSION_STATS_RING_HEALTH_UNAVAILABLE;
    }

  ring = vlib_stats_get_entry_data_pointer (ssm->ring_buffer_index);
  if (!ring || worker_index >= ring->config.n_threads || ring->config.ring_size == 0)
    {
      clib_spinlock_unlock (&ssm->ring_config_lock);
      return SFDP_SESSION_STATS_RING_HEALTH_UNAVAILABLE;
    }
  metadata = (vlib_stats_ring_metadata_t *) ((u8 *) ring + ring->metadata_offset +
					     worker_index * sizeof (vlib_stats_ring_metadata_t));

  health.worker_index = worker_index;
  health.schema_version = metadata->schema_version;
  health.entry_size = ring->config.entry_size;
  health.capacity = ring->config.ring_size;
  health.producer_sequence = __atomic_load_n (&metadata->sequence, __ATOMIC_ACQUIRE);
  /* Sequence identifies committed entries in this ring lifetime. The export
   * counter remains monotonic across ring recreation within the VPP process. */
  health.records_produced =
    __atomic_load_n (&ssm->per_thread[worker_index].total_exports, __ATOMIC_RELAXED);
  health.config_generation = ssm->ring_config_generation;
  clib_memcpy_fast (health.ring_abi, schema_id + schema_id_len - sizeof (health.ring_abi),
		    sizeof (health.ring_abi));
  clib_spinlock_unlock (&ssm->ring_config_lock);

  *output = health;
  return SFDP_SESSION_STATS_RING_HEALTH_OK;
}

static int
sfdp_session_stats_export_session_snapshot (vlib_main_t *vm, u32 session_index,
					    sfdp_session_stats_export_reason_t reason)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  vl_api_sfdp_session_stats_ring_entry_v3_t *entry;
  sfdp_session_stats_entry_t *stats;
  sfdp_session_stats_update_sequence_t *sequence_state = 0;
  sfdp_session_t *session;
  sfdp_tenant_t *tenant;
  u32 thread_index;
  u16 update_sequence = SFDP_SESSION_STATS_UPDATE_SEQUENCE_FIRST;
  u8 is_create = reason == SFDP_SESSION_STATS_EXPORT_CREATE;
  u8 is_update =
    reason == SFDP_SESSION_STATS_EXPORT_PERIODIC || reason == SFDP_SESSION_STATS_EXPORT_API_REQUEST;
  u8 swap_endpoints;

  if (!ssm->ring_buffer_enabled)
    return 0;

  if (session_index >= vec_len (ssm->stats))
    return 0;

  stats = vec_elt_at_index (ssm->stats, session_index);

  /* Skip entries with no traffic */
  if (stats->packets[SFDP_FLOW_FORWARD] == 0 && stats->packets[SFDP_FLOW_REVERSE] == 0)
    return 0;

  session = sfdp_session_at_index_if_valid (session_index);
  if (!session)
    return 0;

  /* Validate session version */
  if (stats->version != session->session_version)
    return 0;

  /* Skip sessions without a valid session ID */
  if (PREDICT_FALSE (session->session_id == 0))
    return 0;

  thread_index = vlib_get_thread_index ();
  ASSERT (!is_update || (thread_index == 0 && vlib_worker_thread_barrier_held ()));

  if (is_update)
    {
      if (PREDICT_FALSE (stats->first_seen == 0))
	return 0;
      sequence_state = vec_elt_at_index (ssm->update_sequences, session_index);
      if (sequence_state->session_version == session->session_version &&
	  sequence_state->session_id == session->session_id &&
	  sequence_state->first_seen == stats->first_seen)
	{
	  update_sequence = sequence_state->next_update_sequence;
	}
    }

  /* Reserve a slot in the ring buffer */
  entry = vlib_stats_ring_reserve_slot (ssm->ring_buffer_index, thread_index);
  if (!entry)
    {
      __atomic_fetch_add (&ssm->ring_reservation_failures, 1, __ATOMIC_RELAXED);
      return 0;
    }

  vlib_stats_ring_buffer_t *ring = vlib_stats_get_entry_data_pointer (ssm->ring_buffer_index);
  vlib_stats_ring_metadata_t *meta =
    (void *) ((u8 *) ring + ring->metadata_offset + thread_index * sizeof (*meta));
  sfdp_session_stats_per_thread_t *pt = &ssm->per_thread[thread_index];
  /* Publish before touching the slot, including writes that later abort. */
  clib_atomic_store_relax_n (&pt->ring_write_sequence, meta->sequence + 1);
  clib_atomic_fence_rel ();

  /* Fill in the entry */
  clib_memset (entry, 0, sizeof (*entry));

  if (reason == SFDP_SESSION_STATS_EXPORT_EXPIRY)
    entry->event_type = SFDP_SESSION_STATS_EVENT_TYPE_CLOSED;
  else if (is_create)
    entry->event_type = SFDP_SESSION_STATS_EVENT_TYPE_CREATED;
  else
    entry->event_type = SFDP_SESSION_STATS_EVENT_TYPE_UPDATED;

  if (is_update)
    entry->update_sequence = update_sequence;

  entry->session_id = session->session_id;
  entry->session_index = session_index;
  entry->proto = session->proto;
  entry->session_type = session->type;
  entry->session_state = session->state;
  entry->forward_service_bitmap = session->bitmaps[SFDP_FLOW_FORWARD];
  entry->reverse_service_bitmap = session->bitmaps[SFDP_FLOW_REVERSE];
  entry->exported_at_unix_micros = ssm->unix_time_offset_us + (i64) (vlib_time_now (vm) * 1e6);
  entry->first_packet_time_unix_micros = ssm->unix_time_offset_us + (i64) (stats->first_seen * 1e6);
  if (entry->event_type == SFDP_SESSION_STATS_EVENT_TYPE_CLOSED)
    entry->last_packet_time_unix_micros = ssm->unix_time_offset_us + (i64) (stats->last_seen * 1e6);

  /* Get tenant ID */
  tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
  entry->tenant_id = tenant ? tenant->tenant_id : 0;
  entry->context_id = tenant ? tenant->context_id : 0;

  /* Copy stats */
  entry->packets_forward = stats->packets[SFDP_FLOW_FORWARD];
  entry->packets_reverse = stats->packets[SFDP_FLOW_REVERSE];
  entry->bytes_forward = stats->bytes[SFDP_FLOW_FORWARD];
  entry->bytes_reverse = stats->bytes[SFDP_FLOW_REVERSE];

  /* Restore the initiator/responder orientation of the first packet. */
  swap_endpoints = session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY];
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      sfdp_session_ip4_key_t *key4 = &session->keys[0].key4;
      entry->is_ip4 = 1;

      clib_memcpy (entry->src_ip,
		   swap_endpoints ? &key4->ip4_key.ip_addr_hi : &key4->ip4_key.ip_addr_lo, 4);
      clib_memcpy (entry->dst_ip,
		   swap_endpoints ? &key4->ip4_key.ip_addr_lo : &key4->ip4_key.ip_addr_hi, 4);
      entry->src_port =
	clib_net_to_host_u16 (swap_endpoints ? key4->ip4_key.port_hi : key4->ip4_key.port_lo);
      entry->dst_port =
	clib_net_to_host_u16 (swap_endpoints ? key4->ip4_key.port_lo : key4->ip4_key.port_hi);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      sfdp_session_ip6_key_t *key6 = &session->keys[0].key6;
      entry->is_ip4 = 0;

      clib_memcpy (entry->src_ip,
		   swap_endpoints ? &key6->ip6_key.ip6_addr_hi : &key6->ip6_key.ip6_addr_lo, 16);
      clib_memcpy (entry->dst_ip,
		   swap_endpoints ? &key6->ip6_key.ip6_addr_lo : &key6->ip6_key.ip6_addr_hi, 16);
      entry->src_port =
	clib_net_to_host_u16 (swap_endpoints ? key6->ip6_key.port_hi : key6->ip6_key.port_lo);
      entry->dst_port =
	clib_net_to_host_u16 (swap_endpoints ? key6->ip6_key.port_lo : key6->ip6_key.port_hi);
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

  /* Populate opaque data - always present in exported entries. */
  entry->opaque = SFDP_SESSION_STATS_OPAQUE_DATA_DEFAULT;

  if (tenant && session->tenant_idx < vec_len (ssm->custom_data_entries))
    {
      sfdp_session_stats_custom_data_entry_t *custom_data =
	&ssm->custom_data_entries[session->tenant_idx];

      /* Validate ownership in case SFDP reused a deleted tenant's pool slot. */
      if (custom_data->has_value && custom_data->tenant_id == tenant->tenant_id)
	entry->opaque = custom_data->value;
    }

  entry->opaque = (entry->opaque & ~stats->session_opaque_mask) |
		  (stats->session_opaque & stats->session_opaque_mask);

  /* ring entries are stored in network-byte order for decoding compatibility in consumers */
  /* TODO - for performance, it would be change this to avoid encoding/decoding to network-byte
  order and directly copy entries to the ring buffer for consumption by an external consumer  */
  vl_api_sfdp_session_stats_ring_entry_v3_t_endian (entry, /* to_net */ 1);

  /* Commit the slot */
  if (PREDICT_FALSE (vlib_stats_ring_commit_slot (ssm->ring_buffer_index, thread_index) != 0))
    {
      vlib_stats_ring_abort_slot (ssm->ring_buffer_index, thread_index);
      __atomic_fetch_add (&ssm->ring_commit_failures, 1, __ATOMIC_RELAXED);
      return 0;
    }

  /* Single writer; relaxed atomics support concurrent health reads. */
  u64 total_exports = clib_atomic_load_relax_n (&pt->total_exports);
  clib_atomic_store_relax_n (&pt->total_exports, total_exports + 1);
  if (is_create)
    stats->create_exported = 1;
  if (is_update)
    {
      sequence_state->session_version = session->session_version;
      sequence_state->session_id = session->session_id;
      sequence_state->first_seen = stats->first_seen;
      sequence_state->next_update_sequence =
	SFDP_SESSION_STATS_UPDATE_SEQUENCE_NEXT (update_sequence);
      ssm->update_sequence_allocations++;
      if (update_sequence == CLIB_U16_MAX)
	ssm->update_sequence_wraps++;
    }

  return 1;
}

/* UPDATE snapshots hold the worker barrier through commit and sequence advance. */
int
sfdp_session_stats_export_session (vlib_main_t *vm, u32 session_index,
				   sfdp_session_stats_export_reason_t reason)
{
  u8 is_update =
    reason == SFDP_SESSION_STATS_EXPORT_PERIODIC || reason == SFDP_SESSION_STATS_EXPORT_API_REQUEST;
  u8 acquired_barrier = 0;
  int exported;

  if (is_update)
    {
      if (PREDICT_FALSE (vlib_get_thread_index () != 0 ||
			 !sfdp_session_stats_main.ring_buffer_enabled))
	return 0;
      if (!vlib_worker_thread_barrier_held ())
	{
	  vlib_worker_thread_barrier_sync (vm);
	  acquired_barrier = 1;
	}
    }
  exported = sfdp_session_stats_export_session_snapshot (vm, session_index, reason);
  if (acquired_barrier)
    vlib_worker_thread_barrier_release (vm);
  return exported;
}

/* Atomic bitmap is a hint; read session data only under the worker barrier. */
static u32
sfdp_session_stats_collect_active (sfdp_session_stats_main_t *ssm, u32 *cursor, u32 *candidates,
				   u32 capacity)
{
  uword word_index = *cursor / BITS (uword);
  uword bit_index = *cursor % BITS (uword);
  u32 count = 0;

  ASSERT (capacity > 0);
  while (word_index < vec_len (ssm->active_sessions))
    {
      uword bits = clib_atomic_load_relax_n (&ssm->active_sessions[word_index]);
      bits &= ~((uword) 0) << bit_index;
      while (bits)
	{
	  u32 index = word_index * BITS (uword) + count_trailing_zeros (bits);
	  if (index >= vec_len (ssm->stats))
	    goto done;
	  candidates[count++] = index;
	  bits &= bits - 1;
	  if (count == capacity)
	    {
	      *cursor = index + 1;
	      return count;
	    }
	}
      word_index++;
      bit_index = 0;
    }
done:
  *cursor = vec_len (ssm->stats);
  return count;
}

/* Bound candidates per worker pause; scan empty ranges without a barrier. */
#define SFDP_SESSION_STATS_SNAPSHOT_CHUNK	   256
#define SFDP_SESSION_STATS_SNAPSHOT_BUDGET_SECONDS 50e-6

u32
sfdp_session_stats_export_batch (vlib_main_t *vm, sfdp_session_stats_export_reason_t reason,
				 u32 start_index, u32 max_entries, f64 active_since)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u32 index = start_index, exported = 0;

  if (PREDICT_FALSE (vlib_get_thread_index () != 0 ||
		     (reason != SFDP_SESSION_STATS_EXPORT_PERIODIC &&
		      reason != SFDP_SESSION_STATS_EXPORT_API_REQUEST)))
    return 0;
  if (!ssm->ring_buffer_enabled)
    return 0;

  u64 config_generation = ssm->ring_config_generation;
  u8 can_yield = vlib_in_process_context (vm) &&
		 (vlib_get_n_threads () < 2 || !vlib_worker_thread_barrier_held ());

  while (index < vec_len (ssm->stats))
    {
      u32 candidates[SFDP_SESSION_STATS_SNAPSHOT_CHUNK];
      u32 capacity = ARRAY_LEN (candidates);
      if (max_entries > 0)
	capacity = clib_min (capacity, max_entries - exported);
      u32 n_candidates = sfdp_session_stats_collect_active (ssm, &index, candidates, capacity);
      if (n_candidates == 0)
	break;

      u8 acquired_barrier = !vlib_worker_thread_barrier_held ();
      if (acquired_barrier)
	vlib_worker_thread_barrier_sync (vm);
      f64 deadline = vlib_time_now (vm) + SFDP_SESSION_STATS_SNAPSHOT_BUDGET_SECONDS;
      for (u32 i = 0; i < n_candidates; i++)
	{
	  u32 session_index = candidates[i];
	  sfdp_session_stats_entry_t *stats = vec_elt_at_index (ssm->stats, session_index);
	  if (stats->last_seen >= active_since &&
	      sfdp_session_stats_export_session_snapshot (vm, session_index, reason))
	    exported++;
	  if ((max_entries > 0 && exported >= max_entries) ||
	      (((i + 1) & 15) == 0 && vlib_time_now (vm) >= deadline))
	    {
	      /* Resume after the last processed candidate. */
	      index = session_index + 1;
	      break;
	    }
	}
      if (acquired_barrier)
	vlib_worker_thread_barrier_release (vm);
      if ((max_entries > 0 && exported >= max_entries) ||
	  (!acquired_barrier && vlib_get_n_threads () > 1))
	return index < vec_len (ssm->stats) ? index : 0;
      if (can_yield && index < vec_len (ssm->stats))
	{
	  vlib_process_yield (vm);
	  if (!ssm->ring_buffer_enabled || ssm->ring_config_generation != config_generation)
	    return 0;
	}
    }
  return 0;
}

void
sfdp_session_stats_export_all_sessions (vlib_main_t *vm, sfdp_session_stats_export_reason_t reason)
{
  if (PREDICT_FALSE (vlib_get_thread_index () != 0))
    return;
  if (!vlib_in_process_context (vm) ||
      (vlib_get_n_threads () > 1 && vlib_worker_thread_barrier_held ()))
    {
      sfdp_session_stats_export_now (vm);
      return;
    }
  (void) sfdp_session_stats_export_batch (vm, reason, 0, 0, 0);
}

int
sfdp_session_stats_clear_sessions (u64 session_id)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (session_id == 0)
    {
      /* clear all sessions counters */
      /* while preserving session version and validity  */
      for (u32 i = 0; i < vec_len (ssm->stats); i++)
	{
	  sfdp_session_stats_entry_t *stats = vec_elt_at_index (ssm->stats, i);
	  session_version_t v = stats->version;
	  f64 first_seen = stats->first_seen;
	  u64 session_opaque = stats->session_opaque;
	  u64 session_opaque_mask = stats->session_opaque_mask;
	  u8 create_exported = stats->create_exported;
	  clib_memset (stats, 0, sizeof (sfdp_session_stats_entry_t));
	  stats->version = v;
	  stats->first_seen = first_seen;
	  stats->session_opaque = session_opaque;
	  stats->session_opaque_mask = session_opaque_mask;
	  stats->create_exported = create_exported;
	}
    }
  else
    {
      /* Clear a specific session by session_id */
      sfdp_main_t *sfdp = &sfdp_main;
      sfdp_session_t *session;
      bool session_found = 0;
      uword session_index;

      sfdp_foreach_session (sfdp, session_index, session)
      {
	if (session->session_id == session_id && session_index < vec_len (ssm->stats))
	  {
	    sfdp_session_stats_entry_t *stats = vec_elt_at_index (ssm->stats, session_index);
	    session_version_t v = stats->version;
	    f64 first_seen = stats->first_seen;
	    u64 session_opaque = stats->session_opaque;
	    u64 session_opaque_mask = stats->session_opaque_mask;
	    u8 create_exported = stats->create_exported;
	    session_found = 1;
	    clib_memset (stats, 0, sizeof (sfdp_session_stats_entry_t));
	    stats->version = v;
	    stats->first_seen = first_seen;
	    stats->session_opaque = session_opaque;
	    stats->session_opaque_mask = session_opaque_mask;
	    stats->create_exported = create_exported;
	    break;
	  }
      }
      /* return error code if session was not found */
      if (!session_found)
	return -1;
    }

  return 0;
}

__clib_export int
sfdp_session_stats_update_session_opaque (u32 session_index, u64 value, u64 mask)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_entry_t *stats;
  sfdp_session_t *session;

  if (session_index >= vec_len (ssm->stats))
    return -1;

  session = sfdp_session_at_index_if_valid (session_index);
  if (!session)
    return -1;

  stats = vec_elt_at_index (ssm->stats, session_index);
  if (stats->version != session->session_version)
    return -1;

  stats->session_opaque = (stats->session_opaque & ~mask) | (value & mask);
  stats->session_opaque_mask |= mask;
  return 0;
}

__clib_export int
sfdp_session_stats_set_session_opaque_once (u32 session_index, u64 value, u64 mask)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_entry_t *stats;
  sfdp_session_t *session;

  if (session_index >= vec_len (ssm->stats))
    return -1;

  session = sfdp_session_at_index_if_valid (session_index);
  if (!session)
    return -1;

  stats = vec_elt_at_index (ssm->stats, session_index);
  if (stats->version != session->session_version)
    return -1;

  if (stats->session_opaque_mask & mask)
    return 0;

  stats->session_opaque = (stats->session_opaque & ~mask) | (value & mask);
  stats->session_opaque_mask |= mask;
  return 0;
}

static u32
sfdp_session_stats_notify_deleted_sessions (const u32 *deleted_sessions, u32 len)
{
  /* upon session deletion, export session stats to ring buffer */
  /* this export can be triggered from worker threads */
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u32 thread_index = vlib_get_thread_index ();
  vlib_main_t *vm = vlib_get_main_by_index (thread_index);

  for (u32 i = 0; i < len; i++)
    {
      u32 session_index = deleted_sessions[i];

      /* Export stats before clearing if ring buffer is enabled */
      if (ssm->export_on_expiry && ssm->ring_buffer_enabled)
	{
	  sfdp_session_stats_export_session (vm, session_index, SFDP_SESSION_STATS_EXPORT_EXPIRY);
	  vlib_log_debug (ssm->log_class, "worker %u: exported session %u on expiry (total: %lu)",
			  thread_index, session_index, ssm->per_thread[thread_index].total_exports);
	}

      /* Clear the stats entry to avoid stale data */
      if (session_index < vec_len (ssm->stats))
	{
	  sfdp_session_stats_entry_t *stats = vec_elt_at_index (ssm->stats, session_index);
	  clib_memset (stats, 0, sizeof (*stats));
	  __atomic_fetch_and (&ssm->active_sessions[session_index / BITS (uword)],
			      ~((uword) 1 << (session_index % BITS (uword))), __ATOMIC_RELAXED);
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

      /* should always be true, we initialize ssm->stats to have size of total number of sessions */
      ASSERT (session_index < vec_len (ssm->stats));
      stats = vec_elt_at_index (ssm->stats, session_index);

      /* Initialize stats entry */
      clib_memset (stats, 0, sizeof (*stats));

      session = sfdp_session_at_index (session_index);
      stats->version = session->session_version; /* set session version */
      stats->first_seen = 0;			 /* Will be set on first packet */
      __atomic_fetch_or (&ssm->active_sessions[session_index / BITS (uword)],
			 (uword) 1 << (session_index % BITS (uword)), __ATOMIC_RELAXED);
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
  vec_validate (ssm->update_sequences, sfdp_num_sessions ());
  vec_validate (ssm->active_sessions, (vec_len (ssm->stats) - 1) / BITS (uword));
  vec_validate_aligned (ssm->per_thread, vlib_get_n_threads () - 1, CLIB_CACHE_LINE_BYTES);

  /* Publish the process marker in both API replies and the mapped stats segment. */
  ssize_t n;
  do
    n = getrandom (&ssm->process_epoch, sizeof (ssm->process_epoch), GRND_NONBLOCK);
  while (n < 0 && errno == EINTR);
  ssm->process_epoch &= SFDP_SESSION_STATS_PROCESS_EPOCH_MAX;
  if (n != (ssize_t) sizeof (ssm->process_epoch) || ssm->process_epoch == 0)
    {
      ssm->process_epoch =
	clib_xxhash (unix_time_now_nsec () ^ clib_cpu_time_now () ^ ((u64) getpid () << 32)) &
	SFDP_SESSION_STATS_PROCESS_EPOCH_MAX;
      if (ssm->process_epoch == 0)
	ssm->process_epoch = 1;
    }
  u32 instance_index = vlib_stats_add_gauge ("/sfdp/session/stats-instance");
  if (instance_index == CLIB_U32_MAX)
    return clib_error_return (0, "failed to publish session stats process instance");
  vlib_stats_set_gauge (instance_index, ssm->process_epoch);

  ssm->ring_buffer_index = CLIB_U32_MAX;
  clib_spinlock_init (&ssm->ring_config_lock);
  ssm->ring_buffer_enabled = 0;
  ssm->ring_buffer_size = 0;
  ssm->export_interval = SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL;
  ssm->export_batch_interval = SFDP_SESSION_STATS_DEFAULT_BATCH_EXPORT_INTERVAL;
  ssm->export_on_expiry = 1;	    /* Default: export on session expiry */
  ssm->periodic_export_enabled = 0; /* Default: periodic export disabled */
  ssm->unix_time_offset_us =
    (i64) (unix_time_now_nsec () / 1000) - (i64) (vlib_time_now (vm) * 1e6);

  /* Per-tenant custom data vec */
  ssm->custom_data_entries = NULL;

  ssm->log_class = vlib_log_register_class ("sfdp-services", "session-stats");

  return 0;
}

/*
 * Set tenant custom data value for a tenant.
 */
int
sfdp_session_stats_set_tenant_custom_data (u32 tenant_id, u64 value)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id };
  u32 tenant_idx;

  if (tenant_id == SFDP_SESSION_STATS_ALL_TENANTS)
    return -1; /* Cannot set data for "all tenants" - must specify a valid tenant */

  if (!sfdp->tenants || clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return -1; /* Tenant must exist before custom data can be attached. */

  tenant_idx = kv.value;

  /* Store by compact pool index, not by the potentially sparse tenant ID. */
  sfdp_session_stats_custom_data_entry_t entry_init = { 0 };
  vec_validate_init_empty (ssm->custom_data_entries, tenant_idx, entry_init);
  ssm->custom_data_entries[tenant_idx].value = value;
  ssm->custom_data_entries[tenant_idx].tenant_id = tenant_id;
  ssm->custom_data_entries[tenant_idx].has_value = 1;

  return 0;
}

/*
 * Clear tenant custom data for a tenant or all tenants
 * If tenant_id == SFDP_SESSION_STATS_ALL_TENANTS, clear all tenants
 */
int
sfdp_session_stats_clear_tenant_custom_data (u32 tenant_id)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id };

  if (tenant_id == SFDP_SESSION_STATS_ALL_TENANTS)
    {
      vec_free (ssm->custom_data_entries);
    }
  else
    {
      /* Resolve the external tenant ID to its compact SFDP pool index. */
      if (sfdp->tenants && !clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv) &&
	  kv.value < vec_len (ssm->custom_data_entries) &&
	  ssm->custom_data_entries[kv.value].tenant_id == tenant_id)
	{
	  ssm->custom_data_entries[kv.value].value = 0;
	  ssm->custom_data_entries[kv.value].tenant_id = 0;
	  ssm->custom_data_entries[kv.value].has_value = 0;
	}
    }

  return 0;
}

u64
sfdp_session_stats_get_tenant_custom_data (u32 tenant_id, u8 *has_value)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id };

  if (sfdp->tenants && !clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv) &&
      kv.value < vec_len (ssm->custom_data_entries) &&
      ssm->custom_data_entries[kv.value].tenant_id == tenant_id &&
      ssm->custom_data_entries[kv.value].has_value)
    {
      if (has_value)
	*has_value = 1;
      return ssm->custom_data_entries[kv.value].value;
    }

  /* No value set for this tenant - return default opaque value */
  if (has_value)
    *has_value = 0;
  return SFDP_SESSION_STATS_OPAQUE_DATA_DEFAULT;
}

VLIB_INIT_FUNCTION (sfdp_session_stats_init);
