/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_vlib_threads_h
#define included_vlib_threads_h

#include <vlib/main.h>
#include <vppinfra/callback.h>
#ifdef __linux__
#include <linux/sched.h>
#elif __FreeBSD__
#include <sys/sched.h>
#endif /* __linux__ */

void vlib_set_thread_name (char *name);

/* arg is actually a vlib__thread_t * */
typedef void (vlib_thread_function_t) (void *arg);

typedef struct vlib_thread_registration_
{
  /* constructor generated list of thread registrations */
  struct vlib_thread_registration_ *next;

  /* config parameters */
  char *name;
  char *short_name;
  vlib_thread_function_t *function;
  uword mheap_size;
  int fixed_count;
  u32 count;
  int no_data_structure_clone;
  u32 frame_queue_nelts;

  /* All threads of this type run on pthreads */
  int use_pthreads;
  u32 first_index;
  uword *coremask;
} vlib_thread_registration_t;

#define VLIB_LOG2_THREAD_STACK_SIZE (21)
#define VLIB_THREAD_STACK_SIZE (1<<VLIB_LOG2_THREAD_STACK_SIZE)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 valid;
  u32 maybe_trace : 1;
  u32 n_vectors;
  u32 offset;
  STRUCT_MARK (end_of_reset);

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 buffer_index[VLIB_FRAME_SIZE];
  u32 aux_data[VLIB_FRAME_SIZE];
}
vlib_frame_queue_elt_t;

typedef struct
{
  /* First cache line */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *wait_at_barrier;
  volatile u32 *workers_at_barrier;

  /* Second Cache Line */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  void *thread_mheap;
  u8 *thread_stack;
  void (*thread_function) (void *);
  void *thread_function_arg;
  i64 recursion_level;
  elog_track_t elog_track;
  u32 instance_id;
  vlib_thread_registration_t *registration;
  u8 *name;
  u64 barrier_sync_count;
  u8 barrier_elog_enabled;
  const char *barrier_caller;
  const char *barrier_context;
  volatile u32 *node_reforks_required;
  volatile u32 wait_before_barrier;
  volatile u32 workers_before_barrier;
  volatile u32 done_work_before_barrier;

  long lwp;
  int cpu_id;
  int core_id;
  int numa_id;
  pthread_t thread_id;
} vlib_worker_thread_t;

extern vlib_worker_thread_t *vlib_worker_threads;

typedef struct
{
  /* static data */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_frame_queue_elt_t *elts;
  u64 vector_threshold;
  u64 trace;
  u32 nelts;

  /* modified by enqueue side  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  volatile u64 tail;

  /* modified by dequeue side  */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  volatile u64 head;
}
vlib_frame_queue_t;

struct vlib_frame_queue_main_t_;
typedef u32 (vlib_frame_queue_dequeue_fn_t) (
  vlib_main_t *vm, struct vlib_frame_queue_main_t_ *fqm);
typedef struct vlib_frame_queue_main_t_
{
  u32 node_index;
  u32 frame_queue_nelts;

  vlib_frame_queue_t **vlib_frame_queues;

  /* for frame queue tracing */
  frame_queue_trace_t *frame_queue_traces;
  frame_queue_nelt_counter_t *frame_queue_histogram;
  vlib_frame_queue_dequeue_fn_t *frame_queue_dequeue_fn;
} vlib_frame_queue_main_t;

typedef struct
{
  uword node_index;
  uword type_opaque;
  uword data;
} vlib_process_signal_event_mt_args_t;

/* Called early, in thread 0's context */
clib_error_t *vlib_thread_init (vlib_main_t * vm);

void vlib_worker_thread_node_runtime_update (void);

void vlib_create_worker_threads (vlib_main_t * vm, int n,
				 void (*thread_function) (void *));

void vlib_worker_thread_init (vlib_worker_thread_t * w);
u32 vlib_frame_queue_main_init (u32 node_index, u32 frame_queue_nelts);

/* Check for a barrier sync request every 30ms */
#define BARRIER_SYNC_DELAY (0.030000)

#if CLIB_DEBUG > 0
/* long barrier timeout, for gdb... */
#define BARRIER_SYNC_TIMEOUT (600.1)
#else
#define BARRIER_SYNC_TIMEOUT (1.0)
#endif

#define vlib_worker_thread_barrier_sync(X)                                    \
  {                                                                           \
    vlib_worker_thread_barrier_sync_int (X, __func__);                        \
  }

void vlib_worker_thread_barrier_sync_int (vlib_main_t * vm,
					  const char *func_name);
void vlib_worker_thread_barrier_release (vlib_main_t * vm);
u8 vlib_worker_thread_barrier_held (void);
void vlib_worker_thread_initial_barrier_sync_and_release (vlib_main_t * vm);
void vlib_worker_thread_node_refork (void);
/**
 * Wait until each of the workers has been once around the track
 */
void vlib_worker_wait_one_loop (void);
/**
 * Flush worker's pending rpc requests to main thread's rpc queue
 */
void vlib_worker_flush_pending_rpc_requests (vlib_main_t *vm);

static_always_inline clib_thread_index_t
vlib_get_thread_index (void)
{
  return __os_thread_index;
}

always_inline void
vlib_smp_unsafe_warning (void)
{
  if (CLIB_DEBUG > 0)
    {
      if (vlib_get_thread_index ())
	fformat (stderr, "%s: SMP unsafe warning...\n", __func__);
    }
}

always_inline int
__foreach_vlib_main_helper (vlib_main_t *ii, vlib_main_t **p, int checks)
{
  vlib_main_t *vm;
  u32 index = ii - (vlib_main_t *) 0;

  if (index >= vec_len (vlib_global_main.vlib_mains))
    return 0;

  *p = vm = vlib_global_main.vlib_mains[index];
  ASSERT (!checks || index == 0 || vm->parked_at_barrier == 1);
  return 1;
}

#define foreach_vlib_main__(checks)                                           \
  for (vlib_main_t *ii = 0, *this_vlib_main;                                  \
       __foreach_vlib_main_helper (ii, &this_vlib_main, checks); ii++)        \
    if (this_vlib_main)

#define foreach_vlib_main() foreach_vlib_main__ (1)

#define foreach_sched_policy_posix                                            \
  _ (SCHED_OTHER, OTHER, "other")                                             \
  _ (SCHED_FIFO, FIFO, "fifo")                                                \
  _ (SCHED_RR, RR, "rr")
#define foreach_sched_policy_linux                                            \
  _ (SCHED_BATCH, BATCH, "batch")                                             \
  _ (SCHED_IDLE, IDLE, "idle")

#ifdef __linux__
#define foreach_sched_policy                                                  \
  foreach_sched_policy_posix foreach_sched_policy_linux
#else
#define foreach_sched_policy foreach_sched_policy_posix
#endif /* __linux__ */

typedef enum
{
#define _(v,f,s) SCHED_POLICY_##f = v,
  foreach_sched_policy
#undef _
    SCHED_POLICY_N,
} sched_policy_t;

typedef struct
{
  /* Link list of registrations, built by constructors */
  vlib_thread_registration_t *next;

  /* Vector of registrations, w/ non-data-structure clones at the top */
  vlib_thread_registration_t **registrations;

  uword *thread_registrations_by_name;

  vlib_worker_thread_t *worker_threads;

  int use_pthreads;

  /* Translate requested cpu configuration to vpp affinity mask */
  int cpu_translate;

  /* Number of vlib_main / vnet_main clones */
  u32 n_vlib_mains;

  /* Number of thread stacks to create */
  u32 n_thread_stacks;

  /* Number of pthreads */
  u32 n_pthreads;

  /* Number of threads */
  u32 n_threads;

  /* Number of cores to skip, must match the core mask */
  u32 skip_cores;

  /* Thread prefix name */
  u8 *thread_prefix;

  /* main thread lcore */
  u32 main_lcore;

  /* Bitmap of available CPU cores */
  uword *cpu_core_bitmap;

  /* Bitmap of available CPU sockets (NUMA nodes) */
  uword *cpu_socket_bitmap;

  /* Worker handoff queues */
  vlib_frame_queue_main_t *frame_queue_mains;

  /* worker thread initialization barrier */
  volatile u32 worker_thread_release;

  /* scheduling policy */
  u32 sched_policy;

  /* scheduling policy priority */
  u32 sched_priority;

  /* NUMA-bound heap size */
  uword numa_heap_size;

} vlib_thread_main_t;

extern vlib_thread_main_t vlib_thread_main;

#include <vlib/global_funcs.h>

#define VLIB_REGISTER_THREAD(x,...)                     \
  __VA_ARGS__ vlib_thread_registration_t x;             \
static void __vlib_add_thread_registration_##x (void)   \
  __attribute__((__constructor__)) ;                    \
static void __vlib_add_thread_registration_##x (void)   \
{                                                       \
  vlib_thread_main_t * tm = &vlib_thread_main;          \
  x.next = tm->next;                                    \
  tm->next = &x;                                        \
}                                                       \
static void __vlib_rm_thread_registration_##x (void)    \
  __attribute__((__destructor__)) ;                     \
static void __vlib_rm_thread_registration_##x (void)    \
{                                                       \
  vlib_thread_main_t * tm = &vlib_thread_main;          \
  VLIB_REMOVE_FROM_LINKED_LIST (tm->next, &x, next);    \
}                                                       \
__VA_ARGS__ vlib_thread_registration_t x

always_inline u32
vlib_num_workers ()
{
  return vlib_thread_main.n_vlib_mains - 1;
}

always_inline u32
vlib_get_worker_thread_index (u32 worker_index)
{
  return worker_index + 1;
}

always_inline u32
vlib_get_worker_index (clib_thread_index_t thread_index)
{
  return thread_index - 1;
}

always_inline u32
vlib_get_current_worker_index ()
{
  return vlib_get_thread_index () - 1;
}

static inline void
vlib_worker_thread_barrier_check (void)
{
  if (PREDICT_FALSE (*vlib_worker_threads->wait_at_barrier))
    {
      vlib_global_main_t *vgm = vlib_get_global_main ();
      vlib_main_t *vm = vlib_get_main ();
      clib_thread_index_t thread_index = vm->thread_index;
      f64 t = vlib_time_now (vm);

      if (PREDICT_FALSE (vec_len (vm->barrier_perf_callbacks) != 0))
	clib_call_callbacks (vm->barrier_perf_callbacks, vm,
			     vm->clib_time.last_cpu_time, 0 /* enter */ );

      if (PREDICT_FALSE (vlib_worker_threads->barrier_elog_enabled))
	{
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
	  ELOG_TYPE_DECLARE (e) = {
	    .format = "barrier-wait-thread-%d",
	    .format_args = "i4",
	  };

	  struct
	  {
	    clib_thread_index_t thread_index;
	  } __clib_packed *ed;

	  ed = ELOG_TRACK_DATA (vlib_get_elog_main (), e, w->elog_track);
	  ed->thread_index = thread_index;
	}

      if (CLIB_DEBUG > 0)
	{
	  vm = vlib_get_main ();
	  vm->parked_at_barrier = 1;
	}
      clib_atomic_fetch_add (vlib_worker_threads->workers_at_barrier, 1);
      while (*vlib_worker_threads->wait_at_barrier)
	;

      /*
       * Recompute the offset from thread-0 time.
       * Note that vlib_time_now adds vm->time_offset, so
       * clear it first. Save the resulting idea of "now", to
       * see how well we're doing. See show_clock_command_fn(...)
       */
      {
	f64 now;
	f64 new_offset;
	vm->time_offset = 0.0;
	now = vlib_time_now (vm);
	new_offset = vgm->vlib_mains[0]->time_last_barrier_release - now;
	/*
	 * Ensure monotonicity: time must never go backwards.
	 * If new offset would cause time to decrease below pre-barrier
	 * value (t), clamp it to maintain monotonicity.
	 */
	if (PREDICT_FALSE (now + new_offset < t))
	  new_offset = t - now;
	vm->time_offset = new_offset;
	vm->time_last_barrier_release = vlib_time_now (vm);
      }

      if (CLIB_DEBUG > 0)
	vm->parked_at_barrier = 0;
      clib_atomic_fetch_add (vlib_worker_threads->workers_at_barrier, -1);

      if (PREDICT_FALSE (*vlib_worker_threads->node_reforks_required))
	{
	  if (PREDICT_FALSE (vlib_worker_threads->barrier_elog_enabled))
	    {
	      t = vlib_time_now (vm) - t;
	      vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
              ELOG_TYPE_DECLARE (e) = {
                .format = "barrier-refork-thread-%d",
                .format_args = "i4",
              };

	      struct
	      {
		clib_thread_index_t thread_index;
	      } __clib_packed *ed;

	      ed = ELOG_TRACK_DATA (vlib_get_elog_main (), e, w->elog_track);
	      ed->thread_index = thread_index;
	    }

	  vlib_worker_thread_node_refork ();
	  clib_atomic_fetch_add (vlib_worker_threads->node_reforks_required,
				 -1);
	  while (*vlib_worker_threads->node_reforks_required)
	    ;
	}
      if (PREDICT_FALSE (vlib_worker_threads->barrier_elog_enabled))
	{
	  t = vlib_time_now (vm) - t;
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;
	  ELOG_TYPE_DECLARE (e) = {
	    .format = "barrier-released-thread-%d: %dus",
	    .format_args = "i4i4",
	  };

	  struct
	  {
	    clib_thread_index_t thread_index;
	    u32 duration;
	  } __clib_packed *ed;

	  ed = ELOG_TRACK_DATA (vlib_get_elog_main (), e, w->elog_track);
	  ed->thread_index = thread_index;
	  ed->duration = (int) (1000000.0 * t);
	}

      if (PREDICT_FALSE (vec_len (vm->barrier_perf_callbacks) != 0))
	clib_call_callbacks (vm->barrier_perf_callbacks, vm,
			     vm->clib_time.last_cpu_time, 1 /* leave */ );
    }
}

always_inline vlib_main_t *
vlib_get_worker_vlib_main (u32 worker_index)
{
  vlib_main_t *vm;
  vlib_thread_main_t *tm = &vlib_thread_main;
  ASSERT (worker_index < tm->n_vlib_mains - 1);
  vm = vlib_get_main_by_index (worker_index + 1);
  ASSERT (vm);
  return vm;
}

static inline u8
vlib_thread_is_main_w_barrier (void)
{
  return (!vlib_num_workers ()
	  || ((vlib_get_thread_index () == 0
	       && vlib_worker_threads->wait_at_barrier[0])));
}

u8 *vlib_thread_stack_init (uword thread_index);

void
vlib_process_signal_event_mt_helper (vlib_process_signal_event_mt_args_t *
				     args);
void vlib_rpc_call_main_thread (void *function, u8 * args, u32 size);
void vlib_force_rpc_call_main_thread (void *function, u8 *args, u32 size);
void vlib_rpc_call_main_thread_process (vlib_main_t *vm);
void vlib_get_thread_core_numa (vlib_worker_thread_t * w, unsigned cpu_id);
vlib_thread_main_t *vlib_get_thread_main_not_inline (void);

/**
 * Force workers sync from within worker
 *
 * Must be paired with @ref vlib_workers_continue
 */
void vlib_workers_sync (void);
/**
 * Release barrier after workers sync
 */
void vlib_workers_continue (void);
static_always_inline void
vlib_thread_wakeup (clib_thread_index_t thread_index)
{
  vlib_main_t *vm = vlib_get_main_by_index (thread_index);
  ssize_t __clib_unused rv;
  u64 val = 1;

  if (__atomic_load_n (&vm->thread_sleeps, __ATOMIC_RELAXED))
    if (__atomic_exchange_n (&vm->wakeup_pending, 1, __ATOMIC_RELAXED) == 0)
      rv = write (vm->wakeup_fd, &val, sizeof (u64));
}

#endif /* included_vlib_threads_h */
