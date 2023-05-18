/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>
#include "ena/ena_defs.h"

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "process",
};

static ena_aenq_entry_t *
ena_get_next_aenq_entry (ena_device_t *ed)
{
  u16 index = ed->aenq_head & pow2_mask (ENA_ASYNC_QUEUE_LOG2_DEPTH);
  u16 phase = 1 & (ed->aenq_head >> ENA_ASYNC_QUEUE_LOG2_DEPTH);
  ena_aenq_entry_t *e = ed->aenq_entries + index;

  if (e->phase != phase)
    return 0;

  ed->aenq_head++;

  return e;
}

static void
ena_process_one_device (vlib_main_t *vm, ena_device_t *ed)
{
  ena_aenq_entry_t *ae;
  u16 aenq_head = ed->aenq_head;
  if (!ed->initialized)
    return;

  while ((ae = ena_get_next_aenq_entry (ed)))
    {
      ena_log_debug (ed, "aenq: group %u syndrome %u phase %u timestamp %lu",
		     ae->group, ae->syndrome, ae->phase, ae->timestamp);

      switch (ae->group)
	{
	case ENA_AENQ_GROUP_LINK_CHANGE:
	  ena_log_debug (ed, "link_change: status %u",
			 ae->link_change.link_status);
	  break;
	case ENA_AENQ_GROUP_KEEP_ALIVE:
	  ena_log_debug (ed, "keep_alive: rx_drops %lu tx_drops %lu",
			 ae->keep_alive.rx_drops, ae->keep_alive.tx_drops);
	  break;
	default:
	  ena_log_debug (ed, "aenq %U", format_hexdump, ae, 32);
	};
    }

  if (aenq_head != ed->aenq_head)
    ena_reg_write (ed, ENA_REG_AENQ_HEAD_DB, &(u32){ ed->aenq_head });

  // ena_log_debug(ed, "debug %U", format_hexdump, ed->debug_area, 32);
}

static uword
ena_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  ena_main_t *em = &ena_main;
  uword *event_data = 0, event_type;
  int started = 0;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;
  ena_device_t **dev_pointers = 0;
  u32 i;

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
	  vlib_log_debug (ena_log.class, "process started");
	  break;
	case ENA_PROCESS_EVENT_STOP:
	  started = 0;
	  vlib_log_debug (ena_log.class, "process stopped");
	  break;

	default:
	  ASSERT (0);
	}

      vec_reset_length (event_data);

      if (started == 0)
	continue;

      vec_reset_length (dev_pointers);
      pool_foreach_index (i, em->devices)
	vec_add1 (dev_pointers, ena_get_device (i));

      vec_foreach_index (i, dev_pointers)
	ena_process_one_device (vm, dev_pointers[i]);

      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

VLIB_REGISTER_NODE (ena_process_node) = {
  .function = ena_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ena-process",
};
