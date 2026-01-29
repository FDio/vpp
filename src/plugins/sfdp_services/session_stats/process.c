/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/session_stats/session_stats.h>

/* Debug log used for export process */
#define SFDP_SESSION_STATS_DBG(...) vlib_log_debug (ssm->log_class, __VA_ARGS__);

typedef enum
{
  SFDP_SESSION_STATS_PROCESS_EVENT_START = 1,
  SFDP_SESSION_STATS_PROCESS_EVENT_STOP,
  SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW,
} sfdp_session_stats_process_event_t;

static inline f64
sfdp_session_stats_get_export_interval (void)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  return ssm->export_interval > 0 ? ssm->export_interval :
				    SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL;
}

static inline f64
sfdp_session_stats_get_batch_export_interval (void)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  return ssm->export_batch_interval > 0 ? ssm->export_batch_interval :
					  SFDP_SESSION_STATS_DEFAULT_BATCH_EXPORT_INTERVAL;
}

/* This process node runs as a background task and periodically
 * exports active session statistics to the ring buffer in batches.
 *
 * Each periodic cycle exports at most ring_buffer_size entries per batch,
 * sleeping 'batch_interval' seconds between batches until all qualifying
 * entries have been exported.
 *
 * Note: the next periodic export timer starts from the end of the batch
 * cycle, not from the original periodic export time. This means the
 * cadence drifts forward by the total batch cycle duration. This is
 * acceptable since batch cycles are expected to be short relative to
 * the export interval.
 *
 * NB: Worker thread ring buffer slots can still be populated by non-process export paths
 * (e.g. expiry callbacks executing on worker threads).*
 */

/* TODO: optimize periodic export to leverage multi-thread aspect of
 * ring-buffer. Currently, sfdp_session_stats_process_node is a process node
 * which is only expected to run on the main thread, and only populate the main
 * thread data of the ring buffer. */
static uword
sfdp_session_stats_process_fn (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u32 ti = vlib_get_thread_index ();
  f64 timeout;
  uword event_type;
  uword *event_data = 0;

  /* Batch state — persists across loop iterations */
  u8 batch_in_progress = 0;
  u32 batch_next_index = 0;
  u32 batch_cycle_index = 0; /* used for debugging logs */
  f64 batch_start_time = 0;
  f64 batch_active_since = 0;

  while (1)
    {
      /* select next interval to use */
      /* if a batch write to ring buffer is in progress, use batch interval */
      if (batch_in_progress)
	timeout = sfdp_session_stats_get_batch_export_interval ();
      else
	timeout = sfdp_session_stats_get_export_interval ();

      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case SFDP_SESSION_STATS_PROCESS_EVENT_START:
	  SFDP_SESSION_STATS_DBG ("periodic export started (interval=%.1fs, "
				  "batch_interval=%.1fs)",
				  ssm->export_interval, ssm->export_batch_interval);
	  ssm->periodic_export_enabled = 1;
	  batch_in_progress = 0;
	  break;

	case SFDP_SESSION_STATS_PROCESS_EVENT_STOP:
	  SFDP_SESSION_STATS_DBG ("periodic export stopped");
	  ssm->periodic_export_enabled = 0;
	  batch_in_progress = 0;
	  break;

	  /* TODO - api-triggered export does not currently support batching */
	  /* batching should be implemented to avoid iterating over all session entries */
	  /* in a single call & if there are more sessions than ring-buffer entries, overlap */
	  /* will occur */
	case SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW:
	  SFDP_SESSION_STATS_DBG ("export-now requested (ring_buffer=%s)",
				  ssm->ring_buffer_enabled ? "enabled" : "disabled");
	  /* Force immediate unbatched export */
	  if (ssm->ring_buffer_enabled)
	    {
	      sfdp_session_stats_export_all_sessions (vm, SFDP_SESSION_STATS_EXPORT_API_REQUEST);
	      ssm->per_thread[ti].last_export_time = vlib_time_now (vm);
	    }
	  batch_in_progress = 0;
	  break;

	case ~0: /* Timeout — periodic or batch continuation */
	  if (ssm->periodic_export_enabled && ssm->ring_buffer_enabled)
	    {
	      /* if no batch is active, start new batch cycle */
	      if (!batch_in_progress)
		{
		  SFDP_SESSION_STATS_DBG ("starting batch export cycle");
		  /* fixed threshold for entire batch cycle — only export sessions
		   * with last_seen >= last_export_time */
		  batch_start_time = vlib_time_now (vm);
		  batch_active_since = ssm->per_thread[ti].last_export_time;
		  batch_cycle_index = 0;
		  batch_next_index = 0;
		  batch_in_progress = 1;
		}

	      /* abort if batch cycles run for too long, and exceed threshold with export interval
	       */
	      if (vlib_time_now (vm) - batch_start_time >=
		  sfdp_session_stats_get_export_interval () /
		    SFDP_SESSION_STATS_BATCH_CYCLE_MAX_RATIO)
		{
		  clib_warning ("batch export exceeded ratio over main interval, "
				"aborting at batch #%u, stats index %u",
				batch_cycle_index, batch_next_index);
		  batch_in_progress = 0;
		  batch_cycle_index = 0;
		  break;
		}
	      /* export batch to fill current ring buffer, and return non-zero batch_next_index if
	       * more batches are needed */
	      u64 exports_before = ssm->per_thread[ti].total_exports;
	      batch_next_index = sfdp_session_stats_export_batch (
		vm, SFDP_SESSION_STATS_EXPORT_PERIODIC, batch_next_index, ssm->ring_buffer_size,
		batch_active_since);
	      batch_cycle_index++;

	      SFDP_SESSION_STATS_DBG (
		"batch #%u: exported %u entries (next_index=%u)", batch_cycle_index,
		(u32) (ssm->per_thread[ti].total_exports - exports_before), batch_next_index);

	      /* No additional batches required / all entries exported */
	      if (batch_next_index == 0)
		{
		  SFDP_SESSION_STATS_DBG ("batch export cycle complete after %u batches "
					  "(duration=%.3fs)",
					  batch_cycle_index, vlib_time_now (vm) - batch_start_time);
		  ssm->per_thread[ti].last_export_time = vlib_time_now (vm);
		  batch_in_progress = 0;
		  batch_cycle_index = 0;
		}
	    }
	  break;

	default:
	  break;
	}

      vec_reset_length (event_data);
    }

  return 0;
}

VLIB_REGISTER_NODE (sfdp_session_stats_process_node) = {
  .function = sfdp_session_stats_process_fn,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "sfdp-session-stats-process",
};

int
sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval, f64 batch_interval)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  /* use default values if intervals are invalid */
  if (interval <= 0)
    interval = SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL;

  if (batch_interval <= 0)
    batch_interval = SFDP_SESSION_STATS_DEFAULT_BATCH_EXPORT_INTERVAL;

  /* Reject batch_interval if it is greater than specified ratio of main export interval */
  if (batch_interval >= interval / SFDP_SESSION_STATS_BATCH_CYCLE_MAX_RATIO)
    return -1;

  ssm->export_interval = interval;
  ssm->export_batch_interval = batch_interval;

  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_START, 0);
  return 0;
}

void
sfdp_session_stats_periodic_export_disable (vlib_main_t *vm)
{
  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_STOP, 0);
}

void
sfdp_session_stats_export_now (vlib_main_t *vm)
{
  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW, 0);
}
