/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vppinfra/format_table.h>

static_always_inline u32
vlib_handoff_queue_slot_n_buffers (vlib_handoff_queue_slot_t *slot)
{
  u32 i;

  for (i = 0; i < VLIB_HANDOFF_QUEUE_SLOT_N_ELTS; i++)
    if (slot->buffer_indices[i] == VLIB_BUFFER_INVALID_INDEX)
      break;

  return i;
}

static clib_error_t *
show_handoff_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_handoff_queue_main_t *hqm;
  table_t table = {};
  u32 index = ~0;
  u32 row = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &index))
	;
      else if (unformat (input, "all"))
	index = ~0;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (vec_len (vm->handoff_queue_mains) == 0)
    {
      vlib_cli_output (vm, "No handoff queues exist");
      return 0;
    }

  if (index == ~0)
    {
      table_add_hdr_row (&table, 5, "index", "node name", "size", "vectors", "drops");

      vec_foreach (hqm, vm->handoff_queue_mains)
	{
	  u64 n_vectors = 0, n_dropped = 0;
	  u32 hqm_index = hqm - vm->handoff_queue_mains;
	  u32 thread_index;

	  vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
	    {
	      vlib_handoff_queue_t *hq = hqm->vlib_handoff_queues[thread_index];

	      n_vectors += __atomic_load_n (&hq->n_vectors, __ATOMIC_RELAXED);
	      n_dropped += __atomic_load_n (&hq->n_dropped, __ATOMIC_RELAXED);
	    }

	  table_format_cell (&table, row, 0, "%u", hqm_index);
	  table_format_cell (&table, row, 1, "%U", format_vlib_node_name, vm, hqm->node_index);
	  table_set_cell_align (&table, row, 1, TTAA_LEFT);
	  table_format_cell (&table, row, 2, "%u", hqm->size * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);
	  table_format_cell (&table, row, 3, "%llu", n_vectors);
	  table_format_cell (&table, row, 4, "%llu", n_dropped);
	  row++;
	}

      vlib_cli_output (vm, "%U", format_table, &table);
      table_free (&table);
      return 0;
    }

  if (index >= vec_len (vm->handoff_queue_mains))
    return clib_error_return (0, "expecting valid handoff queue index");

  vec_foreach (hqm, vm->handoff_queue_mains)
    {
      u32 hqm_index = hqm - vm->handoff_queue_mains;
      vlib_handoff_queue_t *hq;
      u32 thread_index;

      if (index != hqm_index)
	continue;

      table_format_title (&table, "%U (%u)", format_vlib_node_name, vm, hqm->node_index, hqm_index);
      table_add_hdr_row (&table, 8, "thread", "size", "head", "tail", "slots", "buffers", "vectors",
			 "drops");
      table_set_cell_align (&table, -1, 0, TTAA_LEFT);
      row = 0;

      vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
	{
	  vlib_handoff_queue_slot_t *slots;
	  u64 head, tail, n_vectors, n_dropped;
	  u32 buffers = 0;
	  u64 slots_ready = 0;
	  u32 slot_index;
	  u64 i;

	  hq = hqm->vlib_handoff_queues[thread_index];
	  slots = vlib_handoff_queue_buffer_index_slots (hq);
	  head = __atomic_load_n (&hq->head, __ATOMIC_ACQUIRE);
	  tail = __atomic_load_n (&hq->tail, __ATOMIC_ACQUIRE);
	  n_vectors = __atomic_load_n (&hq->n_vectors, __ATOMIC_RELAXED);
	  n_dropped = __atomic_load_n (&hq->n_dropped, __ATOMIC_RELAXED);

	  for (i = head; i < tail; i++)
	    {
	      slot_index = i & (hq->size - 1);
	      if (__atomic_load_n (&slots[slot_index].buffer_indices[0], __ATOMIC_ACQUIRE) ==
		  VLIB_BUFFER_INVALID_INDEX)
		break;
	      slots_ready++;
	      buffers += vlib_handoff_queue_slot_n_buffers (slots + slot_index);
	    }

	  table_format_cell (&table, row, 0, "%v", vlib_worker_threads[thread_index].name);
	  table_set_cell_align (&table, row, 0, TTAA_LEFT);
	  table_format_cell (&table, row, 1, "%u", hqm->size * VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);
	  table_format_cell (&table, row, 2, "%llu", head);
	  table_format_cell (&table, row, 3, "%llu", tail);
	  table_format_cell (&table, row, 4, "%llu", slots_ready);
	  table_format_cell (&table, row, 5, "%u", buffers);
	  table_format_cell (&table, row, 6, "%llu", n_vectors);
	  table_format_cell (&table, row, 7, "%llu", n_dropped);
	  row++;
	}

      vlib_cli_output (vm, "%U", format_table, &table);
      table_free (&table);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_handoff_command, static) = {
  .path = "show handoff",
  .short_help = "show handoff [index <index>]",
  .function = show_handoff_fn,
};

static clib_error_t *
clear_handoff_counters_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_handoff_queue_main_t *hqm;
  u32 index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &index))
	;
      else if (unformat (input, "all"))
	index = ~0;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (index != ~0 && index >= vec_len (vm->handoff_queue_mains))
    return clib_error_return (0, "expecting valid handoff queue index");

  vec_foreach (hqm, vm->handoff_queue_mains)
    {
      u32 hqm_index = hqm - vm->handoff_queue_mains;
      u32 thread_index;

      if (index != ~0 && index != hqm_index)
	continue;

      vec_foreach_index (thread_index, hqm->vlib_handoff_queues)
	{
	  vlib_handoff_queue_t *hq = hqm->vlib_handoff_queues[thread_index];

	  __atomic_store_n (&hq->n_vectors, 0, __ATOMIC_RELAXED);
	  __atomic_store_n (&hq->n_dropped, 0, __ATOMIC_RELAXED);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (clear_handoff_counters_command, static) = {
  .path = "clear handoff counters",
  .short_help = "clear handoff counters [all | index <index>]",
  .function = clear_handoff_counters_fn,
};

static clib_error_t *
set_handoff_queue_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 index = ~0;
  u32 size = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &index))
	;
      else if (unformat (input, "size %u", &size))
	;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (index == ~0)
    return clib_error_return (0, "missing index");

  if (size == 0)
    return clib_error_return (0, "missing size");

  if (size < VLIB_HANDOFF_QUEUE_SLOT_N_ELTS || (size & (size - 1)))
    return clib_error_return (0, "size must be a power of 2 and at least %u",
			      VLIB_HANDOFF_QUEUE_SLOT_N_ELTS);

  return vlib_handoff_queue_resize (index, size);
}

VLIB_CLI_COMMAND (set_handoff_queue_command, static) = {
  .path = "set handoff queue",
  .short_help = "set handoff queue index <index> size <size>",
  .function = set_handoff_queue_fn,
};
