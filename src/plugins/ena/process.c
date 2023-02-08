/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>
#include "ena/ena_defs.h"

VLIB_REGISTER_LOG_CLASS (ena_proc_log, static) = {
  .class_name = "ena",
  .subclass_name = "process",
};

#define log_debug(...) vlib_log_debug (ena_proc_log.class, __VA_ARGS__)
#define log_err(...)   vlib_log_err (ena_proc_log.class, __VA_ARGS__)

static uword
ena_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword *event_data = 0, event_type;
  int started = 0;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;

  while (1)
    {
      if (started)
	vlib_process_wait_for_event_or_clock (vm, 5.0 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
	  last_periodic_time = vlib_time_now (vm);
	  break;
	case ENA_PROCESS_EVENT_START:
	  started = 1;
	  log_debug ("process started");
	  break;

	default:
	  ASSERT (0);
	}

      vec_reset_length (event_data);

      if (started == 0)
	continue;

      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

VLIB_REGISTER_NODE (ena_process_node)  = {
  .function = ena_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ena-process",
};

