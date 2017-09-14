/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE

#include <vppinfra/format.h>
#include <vppinfra/linux/sysfs.h>
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
  vlib_worker_thread_t *w;
  int i;

  vlib_cli_output (vm, "%-7s%-20s%-12s%-8s%-25s%-7s%-7s%-7s%-10s",
		   "ID", "Name", "Type", "LWP", "Sched Policy (Priority)",
		   "lcore", "Core", "Socket", "State");

#if !defined(__powerpc64__)
  for (i = 0; i < vec_len (vlib_worker_threads); i++)
    {
      w = vlib_worker_threads + i;
      u8 *line = NULL;

      line = format (line, "%-7d%-20s%-12s%-8d",
		     i,
		     w->name ? w->name : (u8 *) "",
		     w->registration ? w->registration->name : "", w->lwp);

      line = format (line, "%-25U", format_sched_policy_and_priority, w->lwp);

      int lcore = -1;
      cpu_set_t cpuset;
      CPU_ZERO (&cpuset);
      int ret = -1;

      ret =
	pthread_getaffinity_np (w->thread_id, sizeof (cpu_set_t), &cpuset);
      if (!ret)
	{
	  int c;
	  for (c = 0; c < CPU_SETSIZE; c++)
	    if (CPU_ISSET (c, &cpuset))
	      {
		if (lcore > -1)
		  {
		    lcore = -2;
		    break;
		  }
		lcore = c;
	      }
	}
      else
	{
	  lcore = w->lcore_id;
	}

      if (lcore > -1)
	{
	  const char *sys_cpu_path = "/sys/devices/system/cpu/cpu";
	  int socket_id = -1;
	  int core_id = -1;
	  u8 *p = 0;

	  p = format (p, "%s%u/topology/core_id%c", sys_cpu_path, lcore, 0);
	  clib_sysfs_read ((char *) p, "%d", &core_id);

	  vec_reset_length (p);
	  p =
	    format (p,
		    "%s%u/topology/physical_package_id%c",
		    sys_cpu_path, lcore, 0);
	  clib_sysfs_read ((char *) p, "%d", &socket_id);
	  vec_free (p);

	  line = format (line, "%-7u%-7u%-7u%", lcore, core_id, socket_id);
	}
      else
	{
	  line =
	    format (line, "%-7s%-7s%-7s%", (lcore == -2) ? "M" : "n/a", "n/a",
		    "n/a");
	}

      vlib_cli_output (vm, "%v", line);
      vec_free (line);
    }
#endif

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_threads_command, static) = {
  .path = "show threads",
  .short_help = "Show threads",
  .function = show_threads_fn,
};
/* *INDENT-ON* */

/*
 * Trigger threads to grab frame queue trace data
 */
static clib_error_t *
trace_frame_queue (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  frame_queue_trace_t *fqt;
  frame_queue_nelt_counter_t *fqh;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  u32 num_fq;
  u32 fqix;
  u32 enable = 2;
  u32 index = ~(u32) 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	enable = 1;
      else if (unformat (line_input, "off"))
	enable = 0;
      else if (unformat (line_input, "index %u", &index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (enable > 1)
    {
      error = clib_error_return (0, "expecting on or off");
      goto done;
    }

  if (vec_len (tm->frame_queue_mains) == 0)
    {
      error = clib_error_return (0, "no worker handoffs exist");
      goto done;
    }

  if (index > vec_len (tm->frame_queue_mains) - 1)
    {
      error = clib_error_return (0,
				 "expecting valid worker handoff queue index");
      goto done;
    }

  fqm = vec_elt_at_index (tm->frame_queue_mains, index);

  num_fq = vec_len (fqm->vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output (vm, "No frame queues exist\n");
      goto done;
    }

  // Allocate storage for trace if necessary
  vec_validate_aligned (fqm->frame_queue_traces, num_fq - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (fqm->frame_queue_histogram, num_fq - 1,
			CLIB_CACHE_LINE_BYTES);

  for (fqix = 0; fqix < num_fq; fqix++)
    {
      fqt = &fqm->frame_queue_traces[fqix];
      fqh = &fqm->frame_queue_histogram[fqix];

      memset (fqt->n_vectors, 0xff, sizeof (fqt->n_vectors));
      fqt->written = 0;
      memset (fqh, 0, sizeof (*fqh));
      fqm->vlib_frame_queues[fqix]->trace = enable;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_trace_frame_queue,static) = {
    .path = "trace frame-queue",
    .short_help = "trace frame-queue (on|off)",
    .function = trace_frame_queue,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */


/*
 * Adding two counters and compute percent of total
 * Round up, e.g. 0.000001 => 1%
 */
static u32
compute_percent (u64 * two_counters, u64 total)
{
  if (total == 0)
    {
      return 0;
    }
  else
    {
      return (((two_counters[0] + two_counters[1]) * 100) +
	      (total - 1)) / total;
    }
}

/*
 * Display frame queue trace data gathered by threads.
 */
static clib_error_t *
show_frame_queue_internal (vlib_main_t * vm,
			   vlib_frame_queue_main_t * fqm, u32 histogram)
{
  clib_error_t *error = NULL;
  frame_queue_trace_t *fqt;
  frame_queue_nelt_counter_t *fqh;
  u32 num_fq;
  u32 fqix;

  num_fq = vec_len (fqm->frame_queue_traces);
  if (num_fq == 0)
    {
      vlib_cli_output (vm, "No trace data for frame queues\n");
      return error;
    }

  if (histogram)
    {
      vlib_cli_output (vm, "0-1   2-3   4-5   6-7   8-9   10-11 12-13 14-15 "
		       "16-17 18-19 20-21 22-23 24-25 26-27 28-29 30-31\n");
    }

  for (fqix = 0; fqix < num_fq; fqix++)
    {
      fqt = &(fqm->frame_queue_traces[fqix]);

      vlib_cli_output (vm, "Thread %d %v\n", fqix,
		       vlib_worker_threads[fqix].name);

      if (fqt->written == 0)
	{
	  vlib_cli_output (vm, "  no trace data\n");
	  continue;
	}

      if (histogram)
	{
	  fqh = &(fqm->frame_queue_histogram[fqix]);
	  u32 nelt;
	  u64 total = 0;

	  for (nelt = 0; nelt < FRAME_QUEUE_MAX_NELTS; nelt++)
	    {
	      total += fqh->count[nelt];
	    }

	  /*
	   * Print in pairs to condense the output.
	   * Allow entries with 0 counts to be clearly identified, by rounding up.
	   * Any non-zero value will be displayed as at least one percent. This
	   * also means the sum of percentages can be > 100, but that is fine. The
	   * histogram is counted from the last time "trace frame on" was issued.
	   */
	  vlib_cli_output (vm,
			   "%3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  "
			   "%3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%\n",
			   compute_percent (&fqh->count[0], total),
			   compute_percent (&fqh->count[2], total),
			   compute_percent (&fqh->count[4], total),
			   compute_percent (&fqh->count[6], total),
			   compute_percent (&fqh->count[8], total),
			   compute_percent (&fqh->count[10], total),
			   compute_percent (&fqh->count[12], total),
			   compute_percent (&fqh->count[14], total),
			   compute_percent (&fqh->count[16], total),
			   compute_percent (&fqh->count[18], total),
			   compute_percent (&fqh->count[20], total),
			   compute_percent (&fqh->count[22], total),
			   compute_percent (&fqh->count[24], total),
			   compute_percent (&fqh->count[26], total),
			   compute_percent (&fqh->count[28], total),
			   compute_percent (&fqh->count[30], total));
	}
      else
	{
	  vlib_cli_output (vm,
			   "  vector-threshold %d  ring size %d  in use %d\n",
			   fqt->threshold, fqt->nelts, fqt->n_in_use);
	  vlib_cli_output (vm, "  head %12d  head_hint %12d  tail %12d\n",
			   fqt->head, fqt->head_hint, fqt->tail);
	  vlib_cli_output (vm,
			   "  %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d\n",
			   fqt->n_vectors[0], fqt->n_vectors[1],
			   fqt->n_vectors[2], fqt->n_vectors[3],
			   fqt->n_vectors[4], fqt->n_vectors[5],
			   fqt->n_vectors[6], fqt->n_vectors[7],
			   fqt->n_vectors[8], fqt->n_vectors[9],
			   fqt->n_vectors[10], fqt->n_vectors[11],
			   fqt->n_vectors[12], fqt->n_vectors[13],
			   fqt->n_vectors[14], fqt->n_vectors[15]);

	  if (fqt->nelts > 16)
	    {
	      vlib_cli_output (vm,
			       "  %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d\n",
			       fqt->n_vectors[16], fqt->n_vectors[17],
			       fqt->n_vectors[18], fqt->n_vectors[19],
			       fqt->n_vectors[20], fqt->n_vectors[21],
			       fqt->n_vectors[22], fqt->n_vectors[23],
			       fqt->n_vectors[24], fqt->n_vectors[25],
			       fqt->n_vectors[26], fqt->n_vectors[27],
			       fqt->n_vectors[28], fqt->n_vectors[29],
			       fqt->n_vectors[30], fqt->n_vectors[31]);
	    }
	}

    }
  return error;
}

static clib_error_t *
show_frame_queue_trace (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  clib_error_t *error;

  vec_foreach (fqm, tm->frame_queue_mains)
  {
    vlib_cli_output (vm, "Worker handoff queue index %u (next node '%U'):",
		     fqm - tm->frame_queue_mains,
		     format_vlib_node_name, vm, fqm->node_index);
    error = show_frame_queue_internal (vm, fqm, 0);
    if (error)
      return error;
  }
  return 0;
}

static clib_error_t *
show_frame_queue_histogram (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  clib_error_t *error;

  vec_foreach (fqm, tm->frame_queue_mains)
  {
    vlib_cli_output (vm, "Worker handoff queue index %u (next node '%U'):",
		     fqm - tm->frame_queue_mains,
		     format_vlib_node_name, vm, fqm->node_index);
    error = show_frame_queue_internal (vm, fqm, 1);
    if (error)
      return error;
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_frame_queue_trace,static) = {
    .path = "show frame-queue",
    .short_help = "show frame-queue trace",
    .function = show_frame_queue_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_frame_queue_histogram,static) = {
    .path = "show frame-queue histogram",
    .short_help = "show frame-queue histogram",
    .function = show_frame_queue_histogram,
};
/* *INDENT-ON* */


/*
 * Modify the number of elements on the frame_queues
 */
static clib_error_t *
test_frame_queue_nelts (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  clib_error_t *error = NULL;
  u32 num_fq;
  u32 fqix;
  u32 nelts = 0;
  u32 index = ~(u32) 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "nelts %u", &nelts))
	;
      else if (unformat (line_input, "index %u", &index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (index > vec_len (tm->frame_queue_mains) - 1)
    {
      error = clib_error_return (0,
				 "expecting valid worker handoff queue index");
      goto done;
    }

  fqm = vec_elt_at_index (tm->frame_queue_mains, index);

  if ((nelts != 4) && (nelts != 8) && (nelts != 16) && (nelts != 32))
    {
      error = clib_error_return (0, "expecting 4,8,16,32");
      goto done;
    }

  num_fq = vec_len (fqm->vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output (vm, "No frame queues exist\n");
      goto done;
    }

  for (fqix = 0; fqix < num_fq; fqix++)
    {
      fqm->vlib_frame_queues[fqix]->nelts = nelts;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_frame_queue_nelts,static) = {
    .path = "test frame-queue nelts",
    .short_help = "test frame-queue nelts (4,8,16,32)",
    .function = test_frame_queue_nelts,
};
/* *INDENT-ON* */


/*
 * Modify the max number of packets pulled off the frame queues
 */
static clib_error_t *
test_frame_queue_threshold (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  clib_error_t *error = NULL;
  u32 num_fq;
  u32 fqix;
  u32 threshold = ~(u32) 0;
  u32 index = ~(u32) 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "threshold %u", &threshold))
	;
      else if (unformat (line_input, "index %u", &index))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (index > vec_len (tm->frame_queue_mains) - 1)
    {
      error = clib_error_return (0,
				 "expecting valid worker handoff queue index");
      goto done;
    }

  fqm = vec_elt_at_index (tm->frame_queue_mains, index);


  if (threshold == ~(u32) 0)
    {
      vlib_cli_output (vm, "expecting threshold value\n");
      goto done;
    }

  if (threshold == 0)
    threshold = ~0;

  num_fq = vec_len (fqm->vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output (vm, "No frame queues exist\n");
      goto done;
    }

  for (fqix = 0; fqix < num_fq; fqix++)
    {
      fqm->vlib_frame_queues[fqix]->vector_threshold = threshold;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_frame_queue_threshold,static) = {
    .path = "test frame-queue threshold",
    .short_help = "test frame-queue threshold N (0=no limit)",
    .function = test_frame_queue_threshold,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
