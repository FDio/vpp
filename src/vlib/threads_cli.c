/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE

#include <vppinfra/bitmap.h>
#include <vppinfra/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/format_table.h>
#include <vlib/vlib.h>

#include <vlib/threads.h>
#include <vlib/unix/unix.h>

static u8 *
format_sched_policy_and_priority (u8 * s, va_list * args)
{
  long i = va_arg (*args, long);
  struct sched_param sched_param;
  u8 *t = 0;

  switch (sched_getscheduler (i))
    {
#define _(v,f,str) case SCHED_POLICY_##f: t = (u8 *) str; break;
      foreach_sched_policy
#undef _
    }
  if (sched_getparam (i, &sched_param) == 0)
    return format (s, "%s (%d)", t, sched_param.sched_priority);
  else
    return format (s, "%s (n/a)", t);
}

static clib_error_t *
show_threads_fn (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_main_t *thread_vm;
  vlib_worker_thread_t *w;
  table_t table = {};
  int col;
  int i;

  table_add_hdr_row (&table, 11, "ID", "Name", "LWP", "CPU", "Sched", "Loops", "Epolls", "Sleeps",
		     "FdWakeups", "WakeReq", "Wakeups");

#if !defined(__powerpc64__)
  for (i = 0; i < vec_len (vlib_worker_threads); i++)
    {
      w = vlib_worker_threads + i;
      thread_vm = vlib_get_main_by_index (i);

      col = 0;
      table_format_cell (&table, i, col++, "%d", i);
      table_format_cell (&table, i, col, "%s", w->name ? w->name : (u8 *) "");
      table_set_cell_align (&table, i, col++, TTAA_LEFT);
      table_format_cell (&table, i, col++, "%d", w->lwp);
      table_format_cell (&table, i, col++, "%d", w->cpu_id);
      table_format_cell (&table, i, col, "%U", format_sched_policy_and_priority, w->lwp);
      table_set_cell_align (&table, i, col++, TTAA_LEFT);
      table_format_cell (&table, i, col++, "%u", thread_vm->main_loop_count);
      table_format_cell (&table, i, col++, "%llu", thread_vm->epoll_waits);
      table_format_cell (&table, i, col++, "%llu", thread_vm->sleep_count);
      table_format_cell (&table, i, col++, "%llu", thread_vm->sleep_fd_event_count);
      table_format_cell (&table, i, col++, "%llu", thread_vm->wakeup_request_count);
      table_format_cell (&table, i, col++, "%llu", thread_vm->wakeup_count);
    }
#endif

  vlib_cli_output (vm, "%U", format_table, &table);
  table_free (&table);

  return 0;
}

VLIB_CLI_COMMAND (show_threads_command, static) = {
  .path = "show threads",
  .short_help = "Show threads",
  .function = show_threads_fn,
};
