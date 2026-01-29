/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "internal.h"

static vlib_stats_entry_t *
find_ring_buffer_entry (stat_client_main_t *shm, const char *name)
{
  /* find ring buffer entry associated with session monitoring service */
  vlib_stats_entry_t *entries = shm->directory_vector;

  for (u32 i = 0; i < vec_len (entries); i++)
    {
      vlib_stats_entry_t *ep = &entries[i];
      if (ep->type == STAT_DIR_TYPE_RING_BUFFER && strcmp (ep->name, name) == 0)
	return ep;
    }

  return 0;
}

static void
read_ring_layout (stat_client_main_t *shm, vlib_stats_entry_t *ep, vlib_stats_ring_buffer_t *ring)
{
  /* get ring buffer layout, from vpp internal vlib_stats_ring_buffer_t struct */
  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      clib_memset (ring, 0, sizeof (*ring));
      return;
    }

  clib_memcpy (ring, ring_ptr, sizeof (*ring));
}

static void
read_ring_metadata (stat_client_main_t *shm, vlib_stats_entry_t *ep,
		    const vlib_stats_ring_buffer_t *ring, u32 thread_index,
		    vlib_stats_ring_metadata_t *metadata)
{
  /* get ring buffer metadata, from vpp internal vlib_stats_ring_metadata_t struct */
  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      clib_memset (metadata, 0, sizeof (*metadata));
      return;
    }

  u8 *metadata_ptr = ring_ptr + ring->metadata_offset + (thread_index * CLIB_CACHE_LINE_BYTES);
  clib_memcpy (metadata, metadata_ptr, sizeof (*metadata));
}

static void
reset_session_tracking (session_exporter_main_t *em)
{
  vec_reset_length (em->sessions);
  if (em->session_index_by_id)
    hash_free (em->session_index_by_id);
  em->session_index_by_id = hash_create (0, sizeof (uword));
}

static int
ensure_thread_states (session_exporter_main_t *em, u32 n_threads)
{
  /* setup / ensure consistent thread state */
  /* which is required as ring-buffer in vpp can be defined over multiple threads */
  if (n_threads == 0)
    return -1;

  if (vec_len (em->thread_states) == n_threads)
    return 0;

  vec_free (em->thread_states);
  em->thread_states = 0;
  vec_validate (em->thread_states, n_threads - 1);
  clib_memset (em->thread_states, 0, vec_len (em->thread_states) * sizeof (*em->thread_states));
  return 0;
}

static void
upsert_session (session_exporter_main_t *em, const vl_api_sfdp_session_stats_ring_entry_t *decoded,
		f64 now)
{
  uword *p = hash_get (em->session_index_by_id, decoded->session_id);
  if (p)
    {
      u32 idx = p[0];
      if (idx < vec_len (em->sessions))
	{
	  em->sessions[idx].stats = *decoded;
	  em->sessions[idx].last_update = now;
	}
      return;
    }

  if (em->max_tracked_sessions == 0)
    {
      fprintf (stderr, "WARNING: max_tracked_sessions is 0; forcing to 1\n");
      em->max_tracked_sessions = 1;
    }

  /* check if the cache size is full */
  /* if true, start evicting entry with oldest timestamp */
  if (vec_len (em->sessions) < em->max_tracked_sessions)
    {
      tracked_session_t ts = {
	.session_id = decoded->session_id,
	.stats = *decoded,
	.last_update = now,
      };
      u32 idx = vec_len (em->sessions);
      vec_add1 (em->sessions, ts);
      hash_set (em->session_index_by_id, decoded->session_id, idx);
      return;
    }

  /* evict oldest cached session entry to add new entry */
  u32 oldest_idx = 0;
  f64 oldest_ts = em->sessions[0].last_update;
  for (u32 i = 1; i < vec_len (em->sessions); i++)
    {
      if (em->sessions[i].last_update < oldest_ts)
	{
	  oldest_ts = em->sessions[i].last_update;
	  oldest_idx = i;
	}
    }

  hash_unset (em->session_index_by_id, em->sessions[oldest_idx].session_id);
  em->sessions[oldest_idx].session_id = decoded->session_id;
  em->sessions[oldest_idx].stats = *decoded;
  em->sessions[oldest_idx].last_update = now;
  hash_set (em->session_index_by_id, decoded->session_id, oldest_idx);
}

consume_result_t
consume_ring_buffer_entries (stat_client_main_t *shm)
{
  session_exporter_main_t *em = &exporter_main;
  stat_segment_access_t sa;

  /* connect to vpp stats-segment and lookup ring buffer entry */
  if (stat_segment_access_start (&sa, shm))
    return CONSUME_ERR_NO_RING;

  vlib_stats_entry_t *ep = find_ring_buffer_entry (shm, SFDP_SESSION_STATS_RING);
  if (!ep)
    {
      stat_segment_access_end (&sa, shm);
      return CONSUME_ERR_NO_RING;
    }

  /* copy ring buffer information */
  vlib_stats_ring_buffer_t ring;
  read_ring_layout (shm, ep, &ring);
  if (ring.config.entry_size == 0 || ring.config.ring_size == 0 || ring.config.n_threads == 0)
    {
      stat_segment_access_end (&sa, shm);
      return CONSUME_ERR_CONFIG;
    }

  /* verify consistent thread configuration */
  if (ensure_thread_states (em, ring.config.n_threads) < 0)
    {
      stat_segment_access_end (&sa, shm);
      return CONSUME_ERR_CONFIG;
    }

  /* copy ring buffer metadata */
  vlib_stats_ring_metadata_t thread0_metadata;
  read_ring_metadata (shm, ep, &ring, 0, &thread0_metadata);

  /* read schema from ring buffer */
  int schema_changed = 0;
  if (ensure_schema_loaded (em, shm, ep, &ring.config, &thread0_metadata, &schema_changed) < 0)
    {
      stat_segment_access_end (&sa, shm);
      return CONSUME_ERR_SCHEMA;
    }

  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      stat_segment_access_end (&sa, shm);
      return CONSUME_ERR_CONFIG;
    }
  u8 *data_ptr = ring_ptr + ring.data_offset;

  /* schema change is detected at initialization or if it occurs at runtime */
  /* in this scenario, initialize tail pointers from current head and skip old data */
  if (schema_changed)
    {
      reset_session_tracking (em);

      /* initialize per-thread metadata for the ring-buffer */
      for (u32 thread_index = 0; thread_index < ring.config.n_threads; thread_index++)
	{
	  vlib_stats_ring_metadata_t metadata;
	  read_ring_metadata (shm, ep, &ring, thread_index, &metadata);
	  em->thread_states[thread_index].local_tail = metadata.head;
	  em->thread_states[thread_index].last_sequence = metadata.sequence;
	  em->thread_states[thread_index].initialized = 1;
	}
      stat_segment_access_end (&sa, shm);
      return CONSUME_OK;
    }

  /* for each thread, iterate over ring buffer entries */
  for (u32 thread_index = 0; thread_index < ring.config.n_threads; thread_index++)
    {
      vlib_stats_ring_metadata_t metadata;
      read_ring_metadata (shm, ep, &ring, thread_index, &metadata);
      thread_consumer_state_t *state = &em->thread_states[thread_index];

      /* initialize thread state if needed */
      if (!state->initialized)
	{
	  state->local_tail = metadata.head;
	  state->last_sequence = metadata.sequence;
	  state->initialized = 1;
	  continue;
	}

      /* reset consumer if we detect from sequence number that the ring buffer has wrapped-around */
      /* TODO - should we be more resilient in this scenario ? */
      u64 delta = metadata.sequence - state->last_sequence;
      if (delta > ring.config.ring_size)
	{
	  u64 missed = delta - ring.config.ring_size;
	  em->missed_entries_total += missed;
	  fprintf (stderr,
		   "WARNING: ring consumer may have missed %" PRIu64
		   " entries on thread %u (delta=%" PRIu64 ", ring_size=%u, total_missed=%" PRIu64
		   "); resetting consumer pointer\n",
		   missed, thread_index, delta, ring.config.ring_size, em->missed_entries_total);
	  state->local_tail = metadata.head;
	  state->last_sequence = metadata.sequence;
	  continue;
	}

      /* iterte over valid ring buffer entries for current thread */
      while (state->local_tail != metadata.head)
	{
	  uword slot_index = (uword) thread_index * ring.config.ring_size + state->local_tail;
	  uword offset = slot_index * ring.config.entry_size;
	  const u8 *entry = data_ptr + offset;

	  /* decode entry and store in exporter main for export to prometheus */
	  vl_api_sfdp_session_stats_ring_entry_t decoded;
	  decode_entry (em, entry, &decoded);
	  upsert_session (em, &decoded, unix_time_now ());
	  state->local_tail = (state->local_tail + 1) % ring.config.ring_size;
	}

      state->last_sequence = metadata.sequence;
    }

  stat_segment_access_end (&sa, shm);
  return CONSUME_OK;
}
