/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE

#include <vppinfra/bitmap.h>
#include <vppinfra/unix.h>
#include <vppinfra/format.h>
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
  const vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_worker_thread_t *w;
  int i;
  u8 *line = NULL;

  line = format (line, "%-7s%-20s%-12s%-8s%-25s%-7s%-7s%-7s%-10s", "ID",
		 "Name", "Type", "LWP", "Sched Policy (Priority)", "lcore",
		 "Core", "Socket", "State");
  if (tm->cpu_translate)
    line = format (line, "%-15s", "Relative Core");
  vlib_cli_output (vm, "%v", line);
  vec_free (line);

#if !defined(__powerpc64__)
  for (i = 0; i < vec_len (vlib_worker_threads); i++)
    {
      w = vlib_worker_threads + i;

      line = format (line, "%-7d%-20s%-12s%-8d",
		     i,
		     w->name ? w->name : (u8 *) "",
		     w->registration ? w->registration->name : "", w->lwp);

      line = format (line, "%-25U", format_sched_policy_and_priority, w->lwp);

      int cpu_id = w->cpu_id;
      if (cpu_id > -1 && tm->main_lcore != ~0)
	{
	  int core_id = w->core_id;
	  int numa_id = w->numa_id;
	  line = format (line, "%-7u%-7u%-17u%", cpu_id, core_id, numa_id);
	  if (tm->cpu_translate)
	    {
	      int cpu_translate_core_id =
		os_translate_cpu_from_affinity_bitmap (cpu_id);
	      line = format (line, "%-7u", cpu_translate_core_id);
	    }
	}
      else
	{
	  line = format (line, "%-7s%-7s%-7s%", "n/a", "n/a", "n/a");
	}

      vlib_cli_output (vm, "%v", line);
      vec_free (line);
    }
#endif

  return 0;
}

VLIB_CLI_COMMAND (show_threads_command, static) = {
  .path = "show threads",
  .short_help = "Show threads",
  .function = show_threads_fn,
};
