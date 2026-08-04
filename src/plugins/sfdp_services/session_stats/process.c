/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <sfdp_services/session_stats/session_stats.h>

static vlib_node_registration_t sfdp_session_stats_export_node;

/* Only the owning worker changes its cursor, counters and sequence state. */
static uword
sfdp_session_stats_export_worker (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_stats_per_thread_t *pt = &ssm->per_thread[vm->thread_index];
  f64 now = vlib_time_now (vm);
  if (!ssm->ring_buffer_enabled)
    {
      pt->export_reason = 0;
      clib_atomic_swap_acq_n (&pt->export_requested, 0);
      return 0;
    }
  if (pt->ring_generation != ssm->ring_config_generation)
    {
      pt->ring_generation = ssm->ring_config_generation;
      pt->export_reason = 0;
      pt->last_export_time = 0;
      pt->next_export_time = now + ssm->export_interval;
    }
  if (pt->config_generation != ssm->export_config_generation)
    {
      pt->config_generation = ssm->export_config_generation;
      if (pt->export_reason == SFDP_SESSION_STATS_EXPORT_PERIODIC)
	pt->export_reason = 0;
      pt->next_export_time = now + ssm->export_interval;
    }

  if (pt->export_reason != SFDP_SESSION_STATS_EXPORT_API_REQUEST &&
      clib_atomic_load_relax_n (&pt->export_requested) &&
      clib_atomic_swap_acq_n (&pt->export_requested, 0))
    {
      pt->export_reason = SFDP_SESSION_STATS_EXPORT_API_REQUEST;
      pt->next_session = pt->batch_exports = 0;
      pt->cycle_started_at = now;
      pt->active_since = 0;
    }
  if (!pt->export_reason)
    {
      if (!ssm->periodic_export_enabled)
	return 0;
      if (now < pt->next_export_time)
	{
	  vlib_node_schedule (vm, node->node_index, pt->next_export_time - now);
	  return 0;
	}
      pt->export_reason = SFDP_SESSION_STATS_EXPORT_PERIODIC;
      pt->next_session = pt->batch_exports = 0;
      pt->cycle_started_at = now;
      pt->active_since = pt->last_export_time;
    }

  u8 periodic = pt->export_reason == SFDP_SESSION_STATS_EXPORT_PERIODIC;
  u32 remaining = periodic ? ssm->ring_buffer_size - pt->batch_exports : 0;
  u64 before = pt->total_exports;
  pt->next_session = pt->active_count ?
		       sfdp_session_stats_export_batch (vm, pt->export_reason, pt->next_session,
							remaining, pt->active_since) :
		       0;
  pt->batch_exports += pt->total_exports - before;

  if (!pt->next_session)
    {
      /* Include traffic arriving during this cycle in the next cycle. */
      pt->last_export_time = pt->cycle_started_at;
      pt->next_export_time = vlib_time_now (vm) + ssm->export_interval;
      pt->export_reason = 0;
      if (clib_atomic_load_relax_n (&pt->export_requested))
	vlib_node_schedule (vm, node->node_index, 0);
      else if (ssm->periodic_export_enabled)
	vlib_node_schedule (vm, node->node_index, ssm->export_interval);
    }
  else
    {
      f64 delay = 0;
      if (periodic && pt->batch_exports >= ssm->ring_buffer_size)
	{
	  pt->batch_exports = 0;
	  delay = ssm->export_batch_interval;
	}
      vlib_node_schedule (vm, node->node_index, delay);
    }
  return 0;
}

VLIB_REGISTER_NODE (sfdp_session_stats_export_node, static) = {
  .function = sfdp_session_stats_export_worker,
  .name = "sfdp-session-stats-export",
  .type = VLIB_NODE_TYPE_SCHED,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

void
sfdp_session_stats_wake_workers (u8 export_now)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  ASSERT (vlib_get_thread_index () == 0);
  for (u32 i = 0; i < vlib_get_n_threads (); i++)
    {
      if (export_now)
	clib_atomic_store_rel_n (&ssm->per_thread[i].export_requested, 1);
      vlib_node_set_interrupt_pending (vlib_get_main_by_index (i),
				       sfdp_session_stats_export_node.index);
    }
}

int
sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval, f64 batch_interval)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  if (interval <= 0)
    interval = SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL;
  if (batch_interval <= 0)
    batch_interval = SFDP_SESSION_STATS_DEFAULT_BATCH_EXPORT_INTERVAL;
  if (batch_interval >= interval / SFDP_SESSION_STATS_BATCH_CYCLE_MAX_RATIO)
    return -1;

  ssm->export_interval = interval;
  ssm->export_batch_interval = batch_interval;
  ssm->periodic_export_enabled = 1;
  ssm->export_config_generation++;
  sfdp_session_stats_wake_workers (0);
  return 0;
}

void
sfdp_session_stats_periodic_export_disable (vlib_main_t *vm)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  ssm->periodic_export_enabled = 0;
  ssm->export_config_generation++;
  sfdp_session_stats_wake_workers (0);
}

void
sfdp_session_stats_export_now (vlib_main_t *vm)
{
  sfdp_session_stats_wake_workers (1);
}
