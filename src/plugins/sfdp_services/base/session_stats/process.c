/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 *
 * SFDP Session Stats - Process Node for Periodic Export
 */

#include "plugins/sfdp_services/base/session_stats/session_stats.h"
#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/session_stats/session_stats.h>

#define SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL 10.0 /* seconds */

/**
 * @brief Process node state
 */
typedef enum
{
  SFDP_SESSION_STATS_PROCESS_EVENT_START = 1,
  SFDP_SESSION_STATS_PROCESS_EVENT_STOP,
  SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW,
} sfdp_session_stats_process_event_t;

/**
 * @brief Get the export interval
 */
static inline f64
sfdp_session_stats_get_export_interval (void)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  return ssm->export_interval > 0 ? ssm->export_interval
				  : SFDP_SESSION_STATS_DEFAULT_EXPORT_INTERVAL;
}

/**
 * @brief Process node function for periodic stats export
 *
 * This process node runs as a background task and periodically
 * exports all active session statistics to the ring buffer.
 */
static uword
sfdp_session_stats_process_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
			       vlib_frame_t *f)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  f64 export_interval;
  uword event_type;
  uword *event_data = 0;

  while (1)
    {
      export_interval = sfdp_session_stats_get_export_interval ();

      /* Wait for event or timeout */
      vlib_process_wait_for_event_or_clock (vm, export_interval);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case SFDP_SESSION_STATS_PROCESS_EVENT_START:
	  ssm->periodic_export_enabled = 1;
	  break;

	case SFDP_SESSION_STATS_PROCESS_EVENT_STOP:
	  ssm->periodic_export_enabled = 0;
	  break;

	case SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW:
	  /* Force immediate export */
	  if (ssm->ring_buffer_enabled)
	    sfdp_session_stats_export_all_sessions (
	      vm, SFDP_SESSION_STATS_EXPORT_API_REQUEST);
	  break;

	case ~0: /* Timeout - periodic export */
	  if (ssm->periodic_export_enabled && ssm->ring_buffer_enabled)
	    {
	      sfdp_session_stats_export_all_sessions (
		vm, SFDP_SESSION_STATS_EXPORT_PERIODIC);
	    }
	  break;

	default:
	  /* Unknown event */
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

/**
 * @brief Enable periodic export
 */
void
sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (interval > 0)
    ssm->export_interval = interval;

  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_START, 0);
}

/**
 * @brief Disable periodic export
 */
void
sfdp_session_stats_periodic_export_disable (vlib_main_t *vm)
{
  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_STOP, 0);
}

/**
 * @brief Trigger immediate export of all sessions
 */
void
sfdp_session_stats_export_now (vlib_main_t *vm)
{
  vlib_process_signal_event (vm, sfdp_session_stats_process_node.index,
			     SFDP_SESSION_STATS_PROCESS_EVENT_EXPORT_NOW, 0);
}
