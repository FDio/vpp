/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>

static_always_inline u32
vlib_handoff_queue_slot_n_buffers (vlib_handoff_queue_slot_t *slot)
{
  u32 i;

  for (i = 0; i < VLIB_HANDOFF_QUEUE_SLOT_SIZE; i++)
    if (slot->buffer_indices[i] == VLIB_BUFFER_INVALID_INDEX)
      break;

  return i;
}

static clib_error_t *
show_handoff_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_handoff_queue_main_t *hqm;
  u32 index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &index))
	;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (vec_len (vm->handoff_queue_mains) == 0)
    {
      vlib_cli_output (vm, "No handoff queues exist");
      return 0;
    }

  vec_foreach (hqm, vm->handoff_queue_mains)
    {
      u32 hqm_index = hqm - vm->handoff_queue_mains;
      vlib_handoff_queue_t *hq;
      u32 thread_index;

      if (index != ~0 && index != hqm_index)
	continue;

      vlib_cli_output (vm, "Handoff queue index %u (next node '%U'):", hqm_index,
		       format_vlib_node_name, vm, hqm->node_index);
      vlib_cli_output (vm, "  size %u slots, slot-size %u buffers", hqm->size,
		       VLIB_HANDOFF_QUEUE_SLOT_SIZE);
      vlib_cli_output (vm, "  thread             head         tail     slots  buffers");

      vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
	{
	  vlib_handoff_queue_slot_t *slots;
	  u64 head, tail;
	  u32 buffers = 0;
	  u64 slots_ready = 0;
	  u32 slot_index;
	  u64 i;

	  hq = hqm->vlib_handoff_queues[thread_index];
	  slots = vlib_handoff_queue_buffer_index_slots (hq);
	  head = __atomic_load_n (&hq->head, __ATOMIC_ACQUIRE);
	  tail = __atomic_load_n (&hq->tail, __ATOMIC_ACQUIRE);

	  for (i = head; i < tail; i++)
	    {
	      slot_index = i & (hq->size - 1);
	      if (__atomic_load_n (&slots[slot_index].buffer_indices[0], __ATOMIC_ACQUIRE) ==
		  VLIB_BUFFER_INVALID_INDEX)
		break;
	      slots_ready++;
	      buffers += vlib_handoff_queue_slot_n_buffers (slots + slot_index);
	    }

	  vlib_cli_output (vm, "  %-12v %12llu %12llu %9llu %8u",
			   vlib_worker_threads[thread_index].name, head, tail, slots_ready,
			   buffers);
	}
    }

  if (index != ~0 && index >= vec_len (vm->handoff_queue_mains))
    return clib_error_return (0, "expecting valid handoff queue index");

  return 0;
}

VLIB_CLI_COMMAND (show_handoff_command, static) = {
  .path = "show handoff",
  .short_help = "show handoff [index <index>]",
  .function = show_handoff_fn,
};
