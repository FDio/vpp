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
#ifndef included_vlib_threads_h
#define included_vlib_threads_h

#include <vlib/main.h>
#include <linux/sched.h>

/*
 * To enable detailed tracing of barrier usage, including call stacks and
 * timings, define BARRIER_TRACING here or in relevant TAGS.  If also used
 * with CLIB_DEBUG, timing will _not_ be representative of normal code
 * execution.
 *
 */

// #define BARRIER_TRACING 1

extern vlib_main_t **vlib_mains;

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

/*
 * Frames have their cpu / vlib_main_t index in the low-order N bits
 * Make VLIB_MAX_CPUS a power-of-two, please...
 */

#ifndef VLIB_MAX_CPUS
#define VLIB_MAX_CPUS 256
#endif

#if VLIB_MAX_CPUS > CLIB_MAX_MHEAPS
#error Please increase number of per-cpu mheaps
#endif

#define VLIB_CPU_MASK (VLIB_MAX_CPUS - 1)	/* 0x3f, max */
#define VLIB_OFFSET_MASK (~VLIB_CPU_MASK)

#define VLIB_LOG2_THREAD_STACK_SIZE (21)
#define VLIB_THREAD_STACK_SIZE (1<<VLIB_LOG2_THREAD_STACK_SIZE)

typedef enum
{
  VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME,
} vlib_frame_queue_msg_type_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 valid;
  u32 msg_type;
  u32 n_vectors;
  u32 last_n_vectors;

  /* 256 * 4 = 1024 bytes, even mult of cache line size */
  u32 buffer_index[VLIB_FRAME_SIZE];
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
#ifdef BARRIER_TRACING
  const char *barrier_caller;
  const char *barrier_context;
#endif
  volatile u32 *node_reforks_required;

  long lwp;
  int lcore_id;
  pthread_t thread_id;
} vlib_worker_thread_t;

extern vlib_worker_thread_t *vlib_worker_threads;

typedef struct
{
  /* enqueue side */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u64 tail;
  u64 enqueues;
  u64 enqueue_ticks;
  u64 enqueue_vectors;
  u32 enqueue_full_events;

  /* dequeue side */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  volatile u64 head;
  u64 dequeues;
  u64 dequeue_ticks;
  u64 dequeue_vectors;
  u64 trace;
  u64 vector_threshold;

  /* dequeue hint to enqueue side */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  volatile u64 head_hint;

  /* read-only, constant, shared */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline3);
  vlib_frame_queue_elt_t *elts;
  u32 nelts;
}
vlib_frame_queue_t;

typedef struct
{
  u32 node_index;
  vlib_frame_queue_t **vlib_frame_queues;

  /* for frame queue tracing */
  frame_queue_trace_t *frame_queue_traces;
  frame_queue_nelt_counter_t *frame_queue_histogram;
} vlib_frame_queue_main_t;

/* Called early, in thread 0's context */
clib_error_t *vlib_thread_init (vlib_main_t * vm);

int vlib_frame_queue_enqueue (vlib_main_t * vm, u32 node_runtime_index,
			      u32 frame_queue_index, vlib_frame_t * frame,
			      vlib_frame_queue_msg_type_t type);

int
vlib_frame_queue_dequeue (vlib_main_t * vm, vlib_frame_queue_main_t * fqm);

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

#ifdef BARRIER_TRACING
#define vlib_worker_thread_barrier_sync(X) {vlib_worker_threads[0].barrier_caller=__FUNCTION__;vlib_worker_thread_barrier_sync_int(X);}
#else
#define vlib_worker_thread_barrier_sync(X) vlib_worker_thread_barrier_sync_int(X)
#endif


void vlib_worker_thread_barrier_sync_int (vlib_main_t * vm);
void vlib_worker_thread_barrier_release (vlib_main_t * vm);
void vlib_worker_thread_node_refork (void);

static_always_inline uword
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
	fformat (stderr, "%s: SMP unsafe warning...\n", __FUNCTION__);
    }
}

typedef enum
{
  VLIB_WORKER_THREAD_FORK_FIXUP_ILLEGAL = 0,
  VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX,
} vlib_fork_fixup_t;

void vlib_worker_thread_fork_fixup (vlib_fork_fixup_t which);

#define foreach_vlib_main(body)                         \
do {                                                    \
  vlib_main_t ** __vlib_mains = 0, *this_vlib_main;     \
  int ii;                                               \
                                                        \
  for (ii = 0; ii < vec_len (vlib_mains); ii++)         \
    {                                                   \
      this_vlib_main = vlib_mains[ii];                  \
      ASSERT (ii == 0 ||                                \
	      this_vlib_main->parked_at_barrier == 1);  \
      if (this_vlib_main)                               \
        vec_add1 (__vlib_mains, this_vlib_main);        \
    }                                                   \
                                                        \
  for (ii = 0; ii < vec_len (__vlib_mains); ii++)       \
    {                                                   \
      this_vlib_main = __vlib_mains[ii];                \
      /* body uses this_vlib_main... */                 \
      (body);                                           \
    }                                                   \
  vec_free (__vlib_mains);                              \
} while (0);

#define foreach_sched_policy \
  _(SCHED_OTHER, OTHER, "other") \
  _(SCHED_BATCH, BATCH, "batch") \
  _(SCHED_IDLE, IDLE, "idle")   \
  _(SCHED_FIFO, FIFO, "fifo")   \
  _(SCHED_RR, RR, "rr")

typedef enum
{
#define _(v,f,s) SCHED_POLICY_##f = v,
  foreach_sched_policy
#undef _
    SCHED_POLICY_N,
} sched_policy_t;

typedef struct
{
  clib_error_t *(*vlib_launch_thread_cb) (void *fp, vlib_worker_thread_t * w,
					  unsigned lcore_id);
  clib_error_t *(*vlib_thread_set_lcore_cb) (u32 thread, u16 lcore);
} vlib_thread_callbacks_t;

typedef struct
{
  /* Link list of registrations, built by constructors */
  vlib_thread_registration_t *next;

  /* Vector of registrations, w/ non-data-structure clones at the top */
  vlib_thread_registration_t **registrations;

  uword *thread_registrations_by_name;

  vlib_worker_thread_t *worker_threads;

  /*
   * Launch all threads as pthreads,
   * not eal_rte_launch (strict affinity) threads
   */
  int use_pthreads;

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
  u8 main_lcore;

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

  /* callbacks */
  vlib_thread_callbacks_t cb;
  int extern_thread_mgmt;
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
vlib_get_worker_index (u32 thread_index)
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
      vlib_main_t *vm;
      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, 1);
      if (CLIB_DEBUG > 0)
	{
	  vm = vlib_get_main ();
	  vm->parked_at_barrier = 1;
	}
      while (*vlib_worker_threads->wait_at_barrier)
	;
      if (CLIB_DEBUG > 0)
	vm->parked_at_barrier = 0;
      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, -1);

      if (PREDICT_FALSE (*vlib_worker_threads->node_reforks_required))
	{
	  vlib_worker_thread_node_refork ();
	  clib_smp_atomic_add (vlib_worker_threads->node_reforks_required,
			       -1);
	  while (*vlib_worker_threads->node_reforks_required)
	    ;
	}
    }
}

always_inline vlib_main_t *
vlib_get_worker_vlib_main (u32 worker_index)
{
  vlib_main_t *vm;
  vlib_thread_main_t *tm = &vlib_thread_main;
  ASSERT (worker_index < tm->n_vlib_mains - 1);
  vm = vlib_mains[worker_index + 1];
  ASSERT (vm);
  return vm;
}

static inline void
vlib_put_frame_queue_elt (vlib_frame_queue_elt_t * hf)
{
  CLIB_MEMORY_BARRIER ();
  hf->valid = 1;
}

static inline vlib_frame_queue_elt_t *
vlib_get_frame_queue_elt (u32 frame_queue_index, u32 index)
{
  vlib_frame_queue_t *fq;
  vlib_frame_queue_elt_t *elt;
  vlib_thread_main_t *tm = &vlib_thread_main;
  vlib_frame_queue_main_t *fqm =
    vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);
  u64 new_tail;

  fq = fqm->vlib_frame_queues[index];
  ASSERT (fq);

  new_tail = __sync_add_and_fetch (&fq->tail, 1);

  /* Wait until a ring slot is available */
  while (new_tail >= fq->head_hint + fq->nelts)
    vlib_worker_thread_barrier_check ();

  elt = fq->elts + (new_tail & (fq->nelts - 1));

  /* this would be very bad... */
  while (elt->valid)
    ;

  elt->msg_type = VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME;
  elt->last_n_vectors = elt->n_vectors = 0;

  return elt;
}

static inline vlib_frame_queue_t *
is_vlib_frame_queue_congested (u32 frame_queue_index,
			       u32 index,
			       u32 queue_hi_thresh,
			       vlib_frame_queue_t **
			       handoff_queue_by_worker_index)
{
  vlib_frame_queue_t *fq;
  vlib_thread_main_t *tm = &vlib_thread_main;
  vlib_frame_queue_main_t *fqm =
    vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);

  fq = handoff_queue_by_worker_index[index];
  if (fq != (vlib_frame_queue_t *) (~0))
    return fq;

  fq = fqm->vlib_frame_queues[index];
  ASSERT (fq);

  if (PREDICT_FALSE (fq->tail >= (fq->head_hint + queue_hi_thresh)))
    {
      /* a valid entry in the array will indicate the queue has reached
       * the specified threshold and is congested
       */
      handoff_queue_by_worker_index[index] = fq;
      fq->enqueue_full_events++;
      return fq;
    }

  return NULL;
}

static inline vlib_frame_queue_elt_t *
vlib_get_worker_handoff_queue_elt (u32 frame_queue_index,
				   u32 vlib_worker_index,
				   vlib_frame_queue_elt_t **
				   handoff_queue_elt_by_worker_index)
{
  vlib_frame_queue_elt_t *elt;

  if (handoff_queue_elt_by_worker_index[vlib_worker_index])
    return handoff_queue_elt_by_worker_index[vlib_worker_index];

  elt = vlib_get_frame_queue_elt (frame_queue_index, vlib_worker_index);

  handoff_queue_elt_by_worker_index[vlib_worker_index] = elt;

  return elt;
}

u8 *vlib_thread_stack_init (uword thread_index);

int vlib_thread_cb_register (struct vlib_main_t *vm,
			     vlib_thread_callbacks_t * cb);

#endif /* included_vlib_threads_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
