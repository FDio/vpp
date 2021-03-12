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

#include <vppinfra/callback_data.h>
#include <vppinfra/elog.h>
#include <vppinfra/format.h>
#include <vppinfra/longjmp.h>
#include <vppinfra/pool.h>
#include <vppinfra/random_buffer.h>
#include <vppinfra/time.h>

#include <pthread.h>


/* By default turn off node/error event logging.
   Override with -DVLIB_ELOG_MAIN_LOOP */
#ifndef VLIB_ELOG_MAIN_LOOP
#define VLIB_ELOG_MAIN_LOOP 0
#endif

typedef struct
{
  u8 trace_filter_enable;
  u32 classify_table_index;
} vlib_trace_filter_t;

typedef enum
{
  VLIB_NODE_RUNTIME_PERF_BEFORE,
  VLIB_NODE_RUNTIME_PERF_AFTER,
  VLIB_NODE_RUNTIME_PERF_RESET,
} vlib_node_runtime_perf_call_type_t;

typedef struct
{
  struct vlib_main_t *vm;
  vlib_node_runtime_t *node;
  vlib_frame_t *frame;
  uword packets;
  u64 cpu_time_now;
  vlib_node_runtime_perf_call_type_t call_type;
} vlib_node_runtime_perf_callback_args_t;

struct vlib_node_runtime_perf_callback_data_t;

typedef void (*vlib_node_runtime_perf_callback_fp_t)
  (struct vlib_node_runtime_perf_callback_data_t * data,
   vlib_node_runtime_perf_callback_args_t * args);

typedef struct vlib_node_runtime_perf_callback_data_t
{
  vlib_node_runtime_perf_callback_fp_t fp;
  union
  {
    void *v;
    u64 u;
  } u[3];
} vlib_node_runtime_perf_callback_data_t;

clib_callback_data_typedef (vlib_node_runtime_perf_callback_set_t,
			    vlib_node_runtime_perf_callback_data_t);

typedef struct vlib_main_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Instruction level timing state. */
  clib_time_t clib_time;
  /* Offset from main thread time */
  f64 time_offset;
  f64 time_last_barrier_release;

  /* Time stamp of last node dispatch. */
  u64 cpu_time_last_node_dispatch;

  /* Time stamp when main loop was entered (time 0). */
  u64 cpu_time_main_loop_start;

  /* Incremented once for each main loop. */
  volatile u32 main_loop_count;

  /* Count of vectors processed this main loop. */
  u32 main_loop_vectors_processed;
  u32 main_loop_nodes_processed;

  /* Internal node vectors, calls */
  u64 internal_node_vectors;
  u64 internal_node_calls;
  u64 internal_node_vectors_last_clear;
  u64 internal_node_calls_last_clear;

  /* Instantaneous vector rate */
  u32 internal_node_last_vectors_per_main_loop;

  /* Main loop hw / sw performance counters */
  vlib_node_runtime_perf_callback_set_t vlib_node_runtime_perf_callbacks;

  /* dispatch wrapper function */
  vlib_node_function_t *dispatch_wrapper_fn;

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

  /* Packet trace capture filter */
  vlib_trace_filter_t trace_filter;

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
  u32 configured_elog_ring_size;

  /* Event logger trace flags */
  int elog_trace_api_messages;
  int elog_trace_cli_commands;
  int elog_trace_graph_dispatch;
  int elog_trace_graph_circuit;
  u32 elog_trace_graph_circuit_node_index;

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
  u32 cpu_id;
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
  void (**volatile worker_thread_main_loop_callbacks)
    (struct vlib_main_t *, u64 t);
  void (**volatile worker_thread_main_loop_callback_tmp)
    (struct vlib_main_t *, u64 t);
  clib_spinlock_t worker_thread_main_loop_callback_lock;

  /* debugging */
  volatile int parked_at_barrier;

  /* post-mortem callbacks */
  void (**post_mortem_callbacks) (void);

  /*
   * Need to call vlib_worker_thread_node_runtime_update before
   * releasing worker thread barrier. Only valid in vlib_global_main.
   */
  int need_vlib_worker_thread_node_runtime_update;

  /* Dispatch loop time accounting */
  u64 loops_this_reporting_interval;
  f64 loop_interval_end;
  f64 loop_interval_start;
  f64 loops_per_second;
  f64 seconds_per_loop;
  f64 damping_constant;

  /*
   * Barrier epoch - Set to current time, each time barrier_sync or
   * barrier_release is called with zero recursion.
   */
  f64 barrier_epoch;

  /* Earliest barrier can be closed again */
  f64 barrier_no_close_before;

  /* Barrier counter callback */
  void (**volatile barrier_perf_callbacks)
    (struct vlib_main_t *, u64 t, int leave);
  void (**volatile barrier_perf_callbacks_tmp)
    (struct vlib_main_t *, u64 t, int leave);

  /* Need to check the frame queues */
  volatile uword check_frame_queues;

  /* RPC requests, main thread only */
  uword *pending_rpc_requests;
  uword *processing_rpc_requests;
  clib_spinlock_t pending_rpc_lock;

  /* buffer fault injector */
  u32 buffer_alloc_success_seed;
  f64 buffer_alloc_success_rate;

#ifdef CLIB_SANITIZE_ADDR
  /* address sanitizer stack save */
  void *asan_stack_save;
#endif
  int magic_marker;
} vlib_main_t;

/* Global main structure. */
extern vlib_main_t vlib_global_main;

void vlib_worker_loop (vlib_main_t * vm);

always_inline f64
vlib_time_now (vlib_main_t * vm)
{
#if CLIB_DEBUG > 0
  extern __thread uword __os_thread_index;
#endif
  /*
   * Make sure folks don't pass &vlib_global_main from a worker thread.
   */
  ASSERT (vm->thread_index == __os_thread_index);
  return clib_time_now (&vm->clib_time) + vm->time_offset;
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


always_inline f64
vlib_internal_node_vector_rate (vlib_main_t * vm)
{
  u64 vectors;
  u64 calls;

  calls = vm->internal_node_calls - vm->internal_node_calls_last_clear;

  if (PREDICT_FALSE (calls == 0))
    return 0.0;

  vectors = vm->internal_node_vectors - vm->internal_node_vectors_last_clear;

  return (f64) vectors / (f64) calls;
}

always_inline void
vlib_clear_internal_node_vector_rate (vlib_main_t * vm)
{
  vm->internal_node_calls_last_clear = vm->internal_node_calls;
  vm->internal_node_vectors_last_clear = vm->internal_node_vectors;
}

always_inline void
vlib_increment_main_loop_counter (vlib_main_t * vm)
{
  vm->main_loop_count++;
  vm->internal_node_last_vectors_per_main_loop = 0;

  if (PREDICT_FALSE (vm->main_loop_exit_now))
    clib_longjmp (&vm->main_loop_exit, VLIB_MAIN_LOOP_EXIT_CLI);
}

always_inline u32
vlib_last_vectors_per_main_loop (vlib_main_t * vm)
{
  return vm->internal_node_last_vectors_per_main_loop;
}

always_inline void
vlib_node_runtime_perf_counter (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame, uword n, u64 t,
				vlib_node_runtime_perf_call_type_t call_type)
{
  vlib_node_runtime_perf_callback_data_t *v =
    clib_callback_data_check_and_get (&vm->vlib_node_runtime_perf_callbacks);
  if (vec_len (v))
    {
      vlib_node_runtime_perf_callback_args_t args = {
	.vm = vm,
	.node = node,
	.frame = frame,
	.packets = n,
	.cpu_time_now = t,
	.call_type = call_type,
      };
      clib_callback_data_call_vec (v, &args);
    }
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
void vlib_add_del_post_mortem_callback (void *cb, int is_add);

vlib_main_t *vlib_get_main_not_inline (void);
elog_main_t *vlib_get_elog_main_not_inline ();

#endif /* included_vlib_main_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
