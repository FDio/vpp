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
/*
 * main.h: VLIB main data structure
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_main_h
#define included_vlib_main_h

#include <vppinfra/elog.h>
#include <vppinfra/format.h>
#include <vppinfra/longjmp.h>
#include <vppinfra/pool.h>
#include <vppinfra/random_buffer.h>
#include <vppinfra/time.h>
#include <vppinfra/pmc.h>
#include <vppinfra/pcap.h>

#include <pthread.h>


/* By default turn off node/error event logging.
   Override with -DVLIB_ELOG_MAIN_LOOP */
#ifndef VLIB_ELOG_MAIN_LOOP
#define VLIB_ELOG_MAIN_LOOP 0
#endif

typedef struct vlib_main_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Instruction level timing state. */
  clib_time_t clib_time;

  /* Time stamp of last node dispatch. */
  u64 cpu_time_last_node_dispatch;

  /* Time stamp when main loop was entered (time 0). */
  u64 cpu_time_main_loop_start;

  /* Incremented once for each main loop. */
  u32 main_loop_count;

  /* Count of vectors processed this main loop. */
  u32 main_loop_vectors_processed;
  u32 main_loop_nodes_processed;

  /* Circular buffer of input node vector counts.
     Indexed by low bits of
     (main_loop_count >> VLIB_LOG2_INPUT_VECTORS_PER_MAIN_LOOP). */
  u32 vector_counts_per_main_loop[2];
  u32 node_counts_per_main_loop[2];

  /* Main loop hw / sw performance counters */
    u64 (*vlib_node_runtime_perf_counter_cb) (struct vlib_main_t *);
  int perf_counter_id;
  int perf_counter_fd;

  /* Every so often we switch to the next counter. */
#define VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE 7

  /* Jump target to exit main loop with given code. */
  u32 main_loop_exit_set;
  /* Set e.g. in the SIGTERM signal handler, checked in a safe place... */
  volatile u32 main_loop_exit_now;
  clib_longjmp_t main_loop_exit;
#define VLIB_MAIN_LOOP_EXIT_NONE 0
#define VLIB_MAIN_LOOP_EXIT_PANIC 1
  /* Exit via CLI. */
#define VLIB_MAIN_LOOP_EXIT_CLI 2

  /* Error marker to use when exiting main loop. */
  clib_error_t *main_loop_error;

  /* Name for e.g. syslog. */
  char *name;

  /* Start of the heap. */
  void *heap_base;

  /* Truncated version, to create frame indices */
  void *heap_aligned_base;

  /* Size of the heap */
  uword heap_size;

  /* buffer main structure. */
  vlib_buffer_main_t *buffer_main;

  /* physical memory main structure. */
  vlib_physmem_main_t physmem_main;

  /* Node graph main structure. */
  vlib_node_main_t node_main;

  /* Command line interface. */
  vlib_cli_main_t cli_main;

  /* Packet trace buffer. */
  vlib_trace_main_t trace_main;

  /* Pcap dispatch trace main */
  pcap_main_t dispatch_pcap_main;
  uword dispatch_pcap_enable;
  u8 *pcap_buffer;

  /* Error handling. */
  vlib_error_main_t error_main;

  /* Punt packets to underlying operating system for when fast switching
     code does not know what to do. */
  void (*os_punt_frame) (struct vlib_main_t * vm,
			 struct vlib_node_runtime_t * node,
			 vlib_frame_t * frame);

  /* Stream index to use for distribution when MC is enabled. */
  u32 mc_stream_index;

  vlib_one_time_waiting_process_t *procs_waiting_for_mc_stream_join;

  /* Event logger. */
  elog_main_t elog_main;

  /* Event logger trace flags */
  int elog_trace_api_messages;
  int elog_trace_cli_commands;

  /* Node call and return event types. */
  elog_event_type_t *node_call_elog_event_types;
  elog_event_type_t *node_return_elog_event_types;

  elog_event_type_t *error_elog_event_types;

  /* Seed for random number generator. */
  uword random_seed;

  /* Buffer of random data for various uses. */
  clib_random_buffer_t random_buffer;

  /* Hash table to record which init functions have been called. */
  uword *init_functions_called;

  /* thread, cpu and numa_node indices */
  u32 thread_index;
  u32 cpu_index;
  u32 numa_node;

  /* List of init functions to call, setup by constructors */
  _vlib_init_function_list_elt_t *init_function_registrations;
  _vlib_init_function_list_elt_t *worker_init_function_registrations;
  _vlib_init_function_list_elt_t *main_loop_enter_function_registrations;
  _vlib_init_function_list_elt_t *main_loop_exit_function_registrations;
  _vlib_init_function_list_elt_t *api_init_function_registrations;
  vlib_config_function_runtime_t *config_function_registrations;

  /* control-plane API queue signal pending, length indication */
  volatile u32 queue_signal_pending;
  volatile u32 api_queue_nonempty;
  void (*queue_signal_callback) (struct vlib_main_t *);
  u8 **argv;

  /* Top of (worker) dispatch loop callback */
  volatile void (*worker_thread_main_loop_callback) (struct vlib_main_t *);

  /* debugging */
  volatile int parked_at_barrier;

  /* Attempt to do a post-mortem elog dump */
  int elog_post_mortem_dump;

  /*
   * Need to call vlib_worker_thread_node_runtime_update before
   * releasing worker thread barrier. Only valid in vlib_global_main.
   */
  int need_vlib_worker_thread_node_runtime_update;

  /*
   * Barrier epoch - Set to current time, each time barrier_sync or
   * barrier_release is called with zero recursion.
   */
  f64 barrier_epoch;

  /* Earliest barrier can be closed again */
  f64 barrier_no_close_before;

  /* RPC requests, main thread only */
  uword *pending_rpc_requests;
  uword *processing_rpc_requests;
  clib_spinlock_t pending_rpc_lock;

} vlib_main_t;

/* Global main structure. */
extern vlib_main_t vlib_global_main;

void vlib_worker_loop (vlib_main_t * vm);

always_inline f64
vlib_time_now (vlib_main_t * vm)
{
  return clib_time_now (&vm->clib_time);
}

always_inline f64
vlib_time_now_ticks (vlib_main_t * vm, u64 n)
{
  return clib_time_now_internal (&vm->clib_time, n);
}

/* Busy wait for specified time. */
always_inline void
vlib_time_wait (vlib_main_t * vm, f64 wait)
{
  f64 t = vlib_time_now (vm);
  f64 limit = t + wait;
  while (t < limit)
    t = vlib_time_now (vm);
}

/* Time a piece of code. */
#define vlib_time_code(vm,body)			\
do {						\
    f64 _t[2];					\
    _t[0] = vlib_time_now (vm);			\
    do { body; } while (0);			\
    _t[1] = vlib_time_now (vm);			\
    clib_warning ("%.7e", _t[1] - _t[0]);	\
} while (0)

#define vlib_wait_with_timeout(vm,suspend_time,timeout_time,test)	\
({									\
    uword __vlib_wait_with_timeout = 0;					\
    f64 __vlib_wait_time = 0;						\
    while (! (__vlib_wait_with_timeout = (test))			\
	   && __vlib_wait_time < (timeout_time))			\
      {									\
	vlib_process_suspend (vm, suspend_time);			\
	__vlib_wait_time += suspend_time;				\
      }									\
    __vlib_wait_with_timeout;						\
})

always_inline void
vlib_panic_with_error (vlib_main_t * vm, clib_error_t * error)
{
  vm->main_loop_error = error;
  clib_longjmp (&vm->main_loop_exit, VLIB_MAIN_LOOP_EXIT_PANIC);
}

#define vlib_panic_with_msg(vm,args...) \
  vlib_panic_with_error (vm, clib_error_return (0, args))

always_inline void
vlib_panic (vlib_main_t * vm)
{
  vlib_panic_with_error (vm, 0);
}

always_inline u32
vlib_vector_input_stats_index (vlib_main_t * vm, word delta)
{
  u32 i;
  i = vm->main_loop_count >> VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE;
  ASSERT (is_pow2 (ARRAY_LEN (vm->vector_counts_per_main_loop)));
  return (i + delta) & (ARRAY_LEN (vm->vector_counts_per_main_loop) - 1);
}

/* Estimate input rate based on previous
   2^VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE
   samples. */
always_inline u32
vlib_last_vectors_per_main_loop (vlib_main_t * vm)
{
  u32 i = vlib_vector_input_stats_index (vm, -1);
  u32 n = vm->vector_counts_per_main_loop[i];
  return n >> VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE;
}

/* Total ave vector count per iteration of main loop. */
always_inline f64
vlib_last_vectors_per_main_loop_as_f64 (vlib_main_t * vm)
{
  u32 i = vlib_vector_input_stats_index (vm, -1);
  u32 v = vm->vector_counts_per_main_loop[i];
  return (f64) v / (f64) (1 << VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE);
}

/* Total ave vectors/node count per iteration of main loop. */
always_inline f64
vlib_last_vector_length_per_node (vlib_main_t * vm)
{
  u32 i = vlib_vector_input_stats_index (vm, -1);
  u32 v = vm->vector_counts_per_main_loop[i];
  u32 n = vm->node_counts_per_main_loop[i];
  return n == 0 ? 0 : (f64) v / (f64) n;
}

extern u32 wraps;

always_inline void
vlib_increment_main_loop_counter (vlib_main_t * vm)
{
  u32 i, c, n, v, is_wrap;

  c = vm->main_loop_count++;

  is_wrap = (c & pow2_mask (VLIB_LOG2_MAIN_LOOPS_PER_STATS_UPDATE)) == 0;

  if (is_wrap)
    wraps++;

  i = vlib_vector_input_stats_index (vm, /* delta */ is_wrap);

  v = is_wrap ? 0 : vm->vector_counts_per_main_loop[i];
  n = is_wrap ? 0 : vm->node_counts_per_main_loop[i];

  v += vm->main_loop_vectors_processed;
  n += vm->main_loop_nodes_processed;
  vm->main_loop_vectors_processed = 0;
  vm->main_loop_nodes_processed = 0;
  vm->vector_counts_per_main_loop[i] = v;
  vm->node_counts_per_main_loop[i] = n;

  if (PREDICT_FALSE (vm->main_loop_exit_now))
    clib_longjmp (&vm->main_loop_exit, VLIB_MAIN_LOOP_EXIT_CLI);
}

always_inline void vlib_set_queue_signal_callback
  (vlib_main_t * vm, void (*fp) (vlib_main_t *))
{
  vm->queue_signal_callback = fp;
}

/* Main routine. */
int vlib_main (vlib_main_t * vm, unformat_input_t * input);

/* Thread stacks, for os_get_thread_index */
extern u8 **vlib_thread_stacks;

/* Number of thread stacks that the application needs */
u32 vlib_app_num_thread_stacks_needed (void) __attribute__ ((weak));

extern void vlib_node_sync_stats (vlib_main_t * vm, vlib_node_t * n);

#define VLIB_PCAP_MAJOR_VERSION 1
#define VLIB_PCAP_MINOR_VERSION 0

#endif /* included_vlib_main_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
