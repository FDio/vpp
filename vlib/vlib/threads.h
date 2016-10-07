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

vlib_main_t **vlib_mains;

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

#define VLIB_LOG2_THREAD_STACK_SIZE (20)
#define VLIB_THREAD_STACK_SIZE (1<<VLIB_LOG2_THREAD_STACK_SIZE)

typedef enum
{
  VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME,
} vlib_frame_queue_msg_type_t;

typedef struct
{
  volatile u32 valid;
  u32 msg_type;
  u32 n_vectors;
  u32 last_n_vectors;

  /* 256 * 4 = 1024 bytes, even mult of cache line size */
  u32 buffer_index[VLIB_FRAME_SIZE];

  /* Pad to a cache line boundary */
  u8 pad[CLIB_CACHE_LINE_BYTES - 4 * sizeof (u32)];
}
vlib_frame_queue_elt_t;

typedef struct
{
  /* First cache line */
  volatile u32 *wait_at_barrier;
  volatile u32 *workers_at_barrier;
  u8 pad0[CLIB_CACHE_LINE_BYTES - (2 * sizeof (u32 *))];

  /* Second Cache Line */
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

  long lwp;
  int lcore_id;
  pthread_t thread_id;
} vlib_worker_thread_t;

vlib_worker_thread_t *vlib_worker_threads;

typedef struct
{
  /* enqueue side */
  volatile u64 tail;
  u64 enqueues;
  u64 enqueue_ticks;
  u64 enqueue_vectors;
  u32 enqueue_full_events;
  u32 enqueue_efd_discards;
  u8 pad2[CLIB_CACHE_LINE_BYTES - (2 * sizeof (u32)) - (4 * sizeof (u64))];

  /* dequeue side */
  volatile u64 head;
  u64 dequeues;
  u64 dequeue_ticks;
  u64 dequeue_vectors;
  u64 trace;
  u64 vector_threshold;
  u8 pad4[CLIB_CACHE_LINE_BYTES - (6 * sizeof (u64))];

  /* dequeue hint to enqueue side */
  volatile u64 head_hint;
  u8 pad5[CLIB_CACHE_LINE_BYTES - sizeof (u64)];

  /* read-only, constant, shared */
  vlib_frame_queue_elt_t *elts;
  u32 nelts;
}
vlib_frame_queue_t;

vlib_frame_queue_t **vlib_frame_queues;

/* Called early, in thread 0's context */
clib_error_t *vlib_thread_init (vlib_main_t * vm);

vlib_worker_thread_t *vlib_alloc_thread (vlib_main_t * vm);

int vlib_frame_queue_enqueue (vlib_main_t * vm, u32 node_runtime_index,
			      u32 frame_queue_index, vlib_frame_t * frame,
			      vlib_frame_queue_msg_type_t type);

int vlib_frame_queue_dequeue (int thread_id,
			      vlib_main_t * vm, vlib_node_main_t * nm);

u64 dispatch_node (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_node_type_t type,
		   vlib_node_state_t dispatch_state,
		   vlib_frame_t * frame, u64 last_time_stamp);

u64 dispatch_pending_node (vlib_main_t * vm,
			   vlib_pending_frame_t * p, u64 last_time_stamp);

void vlib_worker_thread_node_runtime_update (void);

void vlib_create_worker_threads (vlib_main_t * vm, int n,
				 void (*thread_function) (void *));

void vlib_worker_thread_init (vlib_worker_thread_t * w);

/* Check for a barrier sync request every 30ms */
#define BARRIER_SYNC_DELAY (0.030000)

#if CLIB_DEBUG > 0
/* long barrier timeout, for gdb... */
#define BARRIER_SYNC_TIMEOUT (600.1)
#else
#define BARRIER_SYNC_TIMEOUT (1.0)
#endif

void vlib_worker_thread_barrier_sync (vlib_main_t * vm);
void vlib_worker_thread_barrier_release (vlib_main_t * vm);

always_inline void
vlib_smp_unsafe_warning (void)
{
  if (CLIB_DEBUG > 0)
    {
      if (os_get_cpu_number ())
	fformat (stderr, "%s: SMP unsafe warning...\n", __FUNCTION__);
    }
}

typedef enum
{
  VLIB_WORKER_THREAD_FORK_FIXUP_ILLEGAL = 0,
  VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX,
} vlib_fork_fixup_t;

void vlib_worker_thread_fork_fixup (vlib_fork_fixup_t which);

static inline void
vlib_worker_thread_barrier_check (void)
{
  if (PREDICT_FALSE (*vlib_worker_threads->wait_at_barrier))
    {
      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, 1);
      while (*vlib_worker_threads->wait_at_barrier)
	;
      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, -1);
    }
}

#define foreach_vlib_main(body)			                        \
do {                                                                    \
    vlib_main_t ** __vlib_mains = 0, *this_vlib_main;                   \
    int ii;                                                             \
                                                                        \
    if (vec_len (vlib_mains) == 0)                                      \
        vec_add1 (__vlib_mains, &vlib_global_main);                     \
    else                                                                \
    {                                                                   \
        for (ii = 0; ii < vec_len (vlib_mains); ii++)                   \
        {                                                               \
            this_vlib_main = vlib_mains[ii];                            \
            if (this_vlib_main)                                         \
                vec_add1 (__vlib_mains, this_vlib_main);                \
        }                                                               \
    }                                                                   \
                                                                        \
    for (ii = 0; ii < vec_len (__vlib_mains); ii++)                     \
    {                                                                   \
        this_vlib_main = __vlib_mains[ii];                              \
        /* body uses this_vlib_main... */                               \
        (body);                                                         \
    }                                                                   \
    vec_free (__vlib_mains);                                            \
} while (0);


/* Early-Fast-Discard (EFD) */
#define VLIB_EFD_DISABLED                   0
#define VLIB_EFD_DISCARD_ENABLED            (1 << 0)
#define VLIB_EFD_MONITOR_ENABLED            (1 << 1)

#define VLIB_EFD_DEF_WORKER_HI_THRESH_PCT   90

/* EFD worker thread settings */
typedef struct vlib_efd_t
{
  u16 enabled;
  u16 queue_hi_thresh;
  u8 ip_prec_bitmap;
  u8 mpls_exp_bitmap;
  u8 vlan_cos_bitmap;
  u8 pad;
} vlib_efd_t;

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

  /* Number of DPDK eal threads */
  u32 n_eal_threads;

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

  vlib_efd_t efd;

  /* handoff node index */
  u32 handoff_dispatch_node_index;

  /* for frame queue tracing */
  frame_queue_trace_t *frame_queue_traces;
  frame_queue_nelt_counter_t *frame_queue_histogram;

  /* worker thread initialization barrier */
  volatile u32 worker_thread_release;

  /* scheduling policy */
  u32 sched_policy;

  /* scheduling policy priority */
  u32 sched_priority;

} vlib_thread_main_t;

vlib_thread_main_t vlib_thread_main;

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

#endif /* included_vlib_threads_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
