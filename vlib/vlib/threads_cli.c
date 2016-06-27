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

#include <vppinfra/format.h>
#include <vlib/vlib.h>

#include <vlib/threads.h>

static clib_error_t *
show_threads_fn (vlib_main_t * vm,
       unformat_input_t * input,
       vlib_cli_command_t * cmd)
{
  vlib_worker_thread_t * w;
  int i;

  vlib_cli_output (vm, "%-7s%-20s%-12s%-8s%-7s%-7s%-7s%-10s",
                   "ID", "Name", "Type", "LWP",
                   "lcore", "Core", "Socket", "State");

#if !defined(__powerpc64__)
  for (i = 0; i < vec_len(vlib_worker_threads); i++)
    {
      w = vlib_worker_threads + i;
      u8 * line = NULL;

      line = format(line, "%-7d%-20s%-12s%-8d",
                    i,
                    w->name ? w->name : (u8 *) "",
                    w->registration ? w->registration->name : "",
                    w->lwp);

#if DPDK==1
      int lcore = w->dpdk_lcore_id;
      if (lcore > -1)
        {
          line = format(line, "%-7u%-7u%-7u",
                        lcore,
                        lcore_config[lcore].core_id,
                        lcore_config[lcore].socket_id);

          switch(lcore_config[lcore].state)
            {
              case WAIT:
                line = format(line, "wait");
                break;
              case RUNNING:
                line = format(line, "running");
                break;
              case FINISHED:
                line = format(line, "finished");
                break;
              default:
                line = format(line, "unknown");
            }
        }
#endif
      vlib_cli_output(vm, "%v", line);
      vec_free(line);
    }
#endif

  return 0;
}


VLIB_CLI_COMMAND (show_threads_command, static) = {
  .path = "show threads",
  .short_help = "Show threads",
  .function = show_threads_fn,
};

/*
 * Trigger threads to grab frame queue trace data
 */
static clib_error_t *
trace_frame_queue (vlib_main_t *vm, unformat_input_t *input,
                  vlib_cli_command_t *cmd)
{
  clib_error_t * error = NULL;
  frame_queue_trace_t *fqt;
  frame_queue_nelt_counter_t *fqh;
  vlib_thread_main_t *tm = vlib_get_thread_main();
  u32 num_fq;
  u32 fqix;
  u32 enable = 0;

  if (unformat(input, "on")) {
    enable = 1;
  } else if (unformat(input, "off")) {
    enable = 0;
  } else {
      return clib_error_return(0, "expecting on or off");
  }

  num_fq = vec_len(vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output(vm, "No frame queues exist\n");
      return error;
    }

  // Allocate storage for trace if necessary
  vec_validate_aligned(tm->frame_queue_traces, num_fq-1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned(tm->frame_queue_histogram, num_fq-1, CLIB_CACHE_LINE_BYTES);

  for (fqix=0; fqix<num_fq; fqix++) {
    fqt = &tm->frame_queue_traces[fqix];
    fqh = &tm->frame_queue_histogram[fqix];

    memset(fqt->n_vectors, 0xff, sizeof(fqt->n_vectors));
    fqt->written = 0;
    memset(fqh, 0, sizeof(*fqh));
    vlib_frame_queues[fqix]->trace = enable;
  }
  return error;
}

VLIB_CLI_COMMAND (cmd_trace_frame_queue,static) = {
    .path = "trace frame-queue",
    .short_help = "trace frame-queue (on|off)",
    .function = trace_frame_queue,
    .is_mp_safe = 1,
};


/*
 * Adding two counters and compute percent of total
 * Round up, e.g. 0.000001 => 1%
 */
static u32
compute_percent (u64 *two_counters, u64 total)
{
    if (total == 0)
      {
        return 0;
      }
    else
      {
        return (((two_counters[0] + two_counters[1]) * 100) + (total-1)) / total;
      }
}

/*
 * Display frame queue trace data gathered by threads.
 */
static clib_error_t *
show_frame_queue_internal (vlib_main_t *vm,
                           u32          histogram)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  clib_error_t * error = NULL;
  frame_queue_trace_t *fqt;
  frame_queue_nelt_counter_t *fqh;
  u32 num_fq;
  u32 fqix;

  num_fq = vec_len(tm->frame_queue_traces);
  if (num_fq == 0)
    {
      vlib_cli_output(vm, "No trace data for frame queues\n");
      return error;
    }

  if (histogram)
    {
      vlib_cli_output(vm, "0-1   2-3   4-5   6-7   8-9   10-11 12-13 14-15 "
                          "16-17 18-19 20-21 22-23 24-25 26-27 28-29 30-31\n");
    }

  for (fqix=0; fqix<num_fq; fqix++) {
    fqt = &(tm->frame_queue_traces[fqix]);

    vlib_cli_output(vm, "Thread %d %v\n", fqix, vlib_worker_threads[fqix].name);

    if (fqt->written == 0)
      {
        vlib_cli_output(vm, "  no trace data\n");
        continue;
      }

    if (histogram)
      {
        fqh = &(tm->frame_queue_histogram[fqix]);
        u32 nelt;
        u64 total = 0;

        for (nelt=0; nelt<FRAME_QUEUE_MAX_NELTS; nelt++) {
            total += fqh->count[nelt];
        }

        /*
         * Print in pairs to condense the output.
         * Allow entries with 0 counts to be clearly identified, by rounding up.
         * Any non-zero value will be displayed as at least one percent. This
         * also means the sum of percentages can be > 100, but that is fine. The
         * histogram is counted from the last time "trace frame on" was issued.
         */
        vlib_cli_output(vm,
                        "%3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  "
                        "%3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%  %3d%%\n",
                        compute_percent(&fqh->count[ 0], total),
                        compute_percent(&fqh->count[ 2], total),
                        compute_percent(&fqh->count[ 4], total),
                        compute_percent(&fqh->count[ 6], total),
                        compute_percent(&fqh->count[ 8], total),
                        compute_percent(&fqh->count[10], total),
                        compute_percent(&fqh->count[12], total),
                        compute_percent(&fqh->count[14], total),
                        compute_percent(&fqh->count[16], total),
                        compute_percent(&fqh->count[18], total),
                        compute_percent(&fqh->count[20], total),
                        compute_percent(&fqh->count[22], total),
                        compute_percent(&fqh->count[24], total),
                        compute_percent(&fqh->count[26], total),
                        compute_percent(&fqh->count[28], total),
                        compute_percent(&fqh->count[30], total));
      }
    else
      {
        vlib_cli_output(vm, "  vector-threshold %d  ring size %d  in use %d\n",
                        fqt->threshold, fqt->nelts, fqt->n_in_use);
        vlib_cli_output(vm, "  head %12d  head_hint %12d  tail %12d\n",
                        fqt->head, fqt->head_hint, fqt->tail);
        vlib_cli_output(vm, "  %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d\n",
                        fqt->n_vectors[0], fqt->n_vectors[1], fqt->n_vectors[2], fqt->n_vectors[3],
                        fqt->n_vectors[4], fqt->n_vectors[5], fqt->n_vectors[6], fqt->n_vectors[7],
                        fqt->n_vectors[8], fqt->n_vectors[9], fqt->n_vectors[10], fqt->n_vectors[11],
                        fqt->n_vectors[12], fqt->n_vectors[13], fqt->n_vectors[14], fqt->n_vectors[15]);

        if (fqt->nelts > 16)
          {
            vlib_cli_output(vm, "  %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d %3d\n",
                            fqt->n_vectors[16], fqt->n_vectors[17], fqt->n_vectors[18], fqt->n_vectors[19],
                            fqt->n_vectors[20], fqt->n_vectors[21], fqt->n_vectors[22], fqt->n_vectors[23],
                            fqt->n_vectors[24], fqt->n_vectors[25], fqt->n_vectors[26], fqt->n_vectors[27],
                            fqt->n_vectors[28], fqt->n_vectors[29], fqt->n_vectors[30], fqt->n_vectors[31]);
          }
      }

   }
  return error;
}

static clib_error_t *
show_frame_queue_trace (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *cmd)
{
  return show_frame_queue_internal (vm, 0);
}

static clib_error_t *
show_frame_queue_histogram (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  return show_frame_queue_internal (vm, 1);
}

VLIB_CLI_COMMAND (cmd_show_frame_queue_trace,static) = {
    .path = "show frame-queue",
    .short_help = "show frame-queue trace",
    .function = show_frame_queue_trace,
};

VLIB_CLI_COMMAND (cmd_show_frame_queue_histogram,static) = {
    .path = "show frame-queue histogram",
    .short_help = "show frame-queue histogram",
    .function = show_frame_queue_histogram,
};


/*
 * Modify the number of elements on the frame_queues
 */
static clib_error_t *
test_frame_queue_nelts (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *cmd)
{
  clib_error_t * error = NULL;
  u32 num_fq;
  u32 fqix;
  u32 nelts = 0;

  unformat(input, "%d", &nelts);
  if ((nelts != 4) && (nelts != 8) && (nelts != 16) && (nelts != 32)) {
      return clib_error_return(0, "expecting 4,8,16,32");
  }

  num_fq = vec_len(vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output(vm, "No frame queues exist\n");
      return error;
    }

  for (fqix=0; fqix<num_fq; fqix++) {
    vlib_frame_queues[fqix]->nelts = nelts;
  }

  return error;
}

VLIB_CLI_COMMAND (cmd_test_frame_queue_nelts,static) = {
    .path = "test frame-queue nelts",
    .short_help = "test frame-queue nelts (4,8,16,32)",
    .function = test_frame_queue_nelts,
};


/*
 * Modify the max number of packets pulled off the frame queues
 */
static clib_error_t *
test_frame_queue_threshold (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  clib_error_t * error = NULL;
  u32 num_fq;
  u32 fqix;
  u32 threshold = 0;

  if (unformat(input, "%d", &threshold)) {
  } else {
      vlib_cli_output(vm, "expecting threshold value\n");
      return error;
  }

  if (threshold == 0)
    threshold = ~0;

  num_fq = vec_len(vlib_frame_queues);
  if (num_fq == 0)
    {
      vlib_cli_output(vm, "No frame queues exist\n");
      return error;
    }

  for (fqix=0; fqix<num_fq; fqix++) {
    vlib_frame_queues[fqix]->vector_threshold = threshold;
  }

  return error;
}

VLIB_CLI_COMMAND (cmd_test_frame_queue_threshold,static) = {
    .path = "test frame-queue threshold",
    .short_help = "test frame-queue threshold N (0=no limit)",
    .function = test_frame_queue_threshold,
};

