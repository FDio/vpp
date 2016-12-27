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
 * node.h: VLIB processing nodes
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

#ifndef included_vlib_node_h
#define included_vlib_node_h

#include <vppinfra/cpu.h>
#include <vppinfra/longjmp.h>
#include <vppinfra/timing_wheel.h>
#include <vlib/trace.h>		/* for vlib_trace_filter_t */

/* Forward declaration. */
struct vlib_node_runtime_t;
struct vlib_frame_t;

/* Internal nodes (including output nodes) move data from node to
   node (or out of the graph for output nodes). */
typedef uword (vlib_node_function_t) (struct vlib_main_t * vm,
				      struct vlib_node_runtime_t * node,
				      struct vlib_frame_t * frame);

typedef enum
{
  /* An internal node on the call graph (could be output). */
  VLIB_NODE_TYPE_INTERNAL,

  /* Nodes which input data into the processing graph.
     Input nodes are called for each iteration of main loop. */
  VLIB_NODE_TYPE_INPUT,

  /* Nodes to be called before all input nodes.
     Used, for example, to clean out driver TX rings before
     processing input. */
  VLIB_NODE_TYPE_PRE_INPUT,

  /* "Process" nodes which can be suspended and later resumed. */
  VLIB_NODE_TYPE_PROCESS,

  VLIB_N_NODE_TYPE,
} vlib_node_type_t;

typedef struct _vlib_node_registration
{
  /* Vector processing function for this node. */
  vlib_node_function_t *function;

  /* Node name. */
  char *name;

  /* Name of sibling (if applicable). */
  char *sibling_of;

  /* Node index filled in by registration. */
  u32 index;

  /* Type of this node. */
  vlib_node_type_t type;

  /* Error strings indexed by error code for this node. */
  char **error_strings;

  /* Buffer format/unformat for this node. */
  format_function_t *format_buffer;
  unformat_function_t *unformat_buffer;

  /* Trace format/unformat for this node. */
  format_function_t *format_trace;
  unformat_function_t *unformat_trace;

  /* Function to validate incoming frames. */
  u8 *(*validate_frame) (struct vlib_main_t * vm,
			 struct vlib_node_runtime_t *,
			 struct vlib_frame_t * f);

  /* Per-node runtime data. */
  void *runtime_data;

  /* Process stack size. */
  u16 process_log2_n_stack_bytes;

  /* Number of bytes of per-node run time data. */
  u8 runtime_data_bytes;

  /* State for input nodes. */
  u8 state;

  /* Node flags. */
  u16 flags;

  /* Size of scalar and vector arguments in bytes. */
  u16 scalar_size, vector_size;

  /* Number of error codes used by this node. */
  u16 n_errors;

  /* Number of next node names that follow. */
  u16 n_next_nodes;

  /* Constructor link-list, don't ask... */
  struct _vlib_node_registration *next_registration;

  /* Names of next nodes which this node feeds into. */
  char *next_nodes[];

} vlib_node_registration_t;

#define VLIB_REGISTER_NODE(x,...)                                       \
    __VA_ARGS__ vlib_node_registration_t x;                             \
static void __vlib_add_node_registration_##x (void)                     \
    __attribute__((__constructor__)) ;                                  \
static void __vlib_add_node_registration_##x (void)                     \
{                                                                       \
    vlib_main_t * vm = vlib_get_main();                                 \
    x.next_registration = vm->node_main.node_registrations;             \
    vm->node_main.node_registrations = &x;                              \
}                                                                       \
__VA_ARGS__ vlib_node_registration_t x

#if CLIB_DEBUG > 0
#define VLIB_NODE_FUNCTION_CLONE_TEMPLATE(arch, fn)
#define VLIB_NODE_FUNCTION_MULTIARCH_CLONE(fn)
#define VLIB_NODE_FUNCTION_MULTIARCH(node, fn)
#else
#define VLIB_NODE_FUNCTION_CLONE_TEMPLATE(arch, fn, tgt)		\
  uword									\
  __attribute__ ((flatten))						\
  __attribute__ ((target (tgt)))					\
  CLIB_CPU_OPTIMIZED							\
  fn ## _ ## arch ( struct vlib_main_t * vm,				\
                   struct vlib_node_runtime_t * node,			\
                   struct vlib_frame_t * frame)				\
  { return fn (vm, node, frame); }

#define VLIB_NODE_FUNCTION_MULTIARCH_CLONE(fn)				\
  foreach_march_variant(VLIB_NODE_FUNCTION_CLONE_TEMPLATE, fn)

#define VLIB_NODE_FUNCTION_MULTIARCH(node, fn)				\
  VLIB_NODE_FUNCTION_MULTIARCH_CLONE(fn)				\
  CLIB_MULTIARCH_SELECT_FN(fn, static inline)				\
  static void __attribute__((__constructor__))				\
  __vlib_node_function_multiarch_select_##node (void)			\
  { node.function = fn ## _multiarch_select(); }
#endif

always_inline vlib_node_registration_t *
vlib_node_next_registered (vlib_node_registration_t * c)
{
  c =
    clib_elf_section_data_next (c,
				c->n_next_nodes * sizeof (c->next_nodes[0]));
  return c;
}

typedef struct
{
  /* Total calls, clock ticks and vector elements processed for this node. */
  u64 calls, vectors, clocks, suspends;
  u64 max_clock;
  u64 max_clock_n;
} vlib_node_stats_t;

#define foreach_vlib_node_state					\
  /* Input node is called each iteration of main loop.		\
     This is the default (zero). */				\
  _ (POLLING)							\
  /* Input node is called when device signals an interrupt. */	\
  _ (INTERRUPT)							\
  /* Input node is never called. */				\
  _ (DISABLED)

typedef enum
{
#define _(f) VLIB_NODE_STATE_##f,
  foreach_vlib_node_state
#undef _
    VLIB_N_NODE_STATE,
} vlib_node_state_t;

typedef struct vlib_node_t
{
  /* Vector processing function for this node. */
  vlib_node_function_t *function;

  /* Node name. */
  u8 *name;

  /* Node name index in elog string table. */
  u32 name_elog_string;

  /* Total statistics for this node. */
  vlib_node_stats_t stats_total;

  /* Saved values as of last clear (or zero if never cleared).
     Current values are always stats_total - stats_last_clear. */
  vlib_node_stats_t stats_last_clear;

  /* Type of this node. */
  vlib_node_type_t type;

  /* Node index. */
  u32 index;

  /* Index of corresponding node runtime. */
  u32 runtime_index;

  /* Runtime data for this node. */
  void *runtime_data;

  /* Node flags. */
  u16 flags;

  /* Processing function keeps frame.  Tells node dispatching code not
     to free frame after dispatch is done.  */
#define VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH (1 << 0)

  /* Node counts as output/drop/punt node for stats purposes. */
#define VLIB_NODE_FLAG_IS_OUTPUT (1 << 1)
#define VLIB_NODE_FLAG_IS_DROP (1 << 2)
#define VLIB_NODE_FLAG_IS_PUNT (1 << 3)
#define VLIB_NODE_FLAG_IS_HANDOFF (1 << 4)

  /* Set if current node runtime has traced vectors. */
#define VLIB_NODE_FLAG_TRACE (1 << 5)

#define VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE (1 << 6)
#define VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE (1 << 7)

  /* State for input nodes. */
  u8 state;

  /* Number of bytes of run time data. */
  u8 runtime_data_bytes;

  /* Number of error codes used by this node. */
  u16 n_errors;

  /* Size of scalar and vector arguments in bytes. */
  u16 scalar_size, vector_size;

  /* Handle/index in error heap for this node. */
  u32 error_heap_handle;
  u32 error_heap_index;

  /* Error strings indexed by error code for this node. */
  char **error_strings;

  /* Vector of next node names.
     Only used before next_nodes array is initialized. */
  char **next_node_names;

  /* Next node indices for this node. */
  u32 *next_nodes;

  /* Name of node that we are sibling of. */
  char *sibling_of;

  /* Bitmap of all of this node's siblings. */
  uword *sibling_bitmap;

  /* Total number of vectors sent to each next node. */
  u64 *n_vectors_by_next_node;

  /* Hash table mapping next node index into slot in
     next_nodes vector.  Quickly determines whether this node
     is connected to given next node and, if so, with which slot. */
  uword *next_slot_by_node;

  /* Bitmap of node indices which feed this node. */
  uword *prev_node_bitmap;

  /* Node/next-index which own enqueue rights with to this node. */
  u32 owner_node_index, owner_next_index;

  /* Buffer format/unformat for this node. */
  format_function_t *format_buffer;
  unformat_function_t *unformat_buffer;

  /* Trace buffer format/unformat for this node. */
  format_function_t *format_trace;

  /* Function to validate incoming frames. */
  u8 *(*validate_frame) (struct vlib_main_t * vm,
			 struct vlib_node_runtime_t *,
			 struct vlib_frame_t * f);
  /* for pretty-printing, not typically valid */
  u8 *state_string;
} vlib_node_t;

#define VLIB_INVALID_NODE_INDEX ((u32) ~0)

/* Max number of vector elements to process at once per node. */
#define VLIB_FRAME_SIZE 256
#define VLIB_FRAME_ALIGN VLIB_MAX_CPUS

/* Calling frame (think stack frame) for a node. */
typedef struct vlib_frame_t
{
  /* Frame flags. */
  u16 flags;

  /* Number of scalar bytes in arguments. */
  u8 scalar_size;

  /* Number of bytes per vector argument. */
  u8 vector_size;

  /* Number of vector elements currently in frame. */
  u16 n_vectors;

  /* Owner cpuid / heap id */
  u16 cpu_index;

  /* Scalar and vector arguments to next node. */
  u8 arguments[0];
} vlib_frame_t;

typedef struct
{
  /* Frame index. */
  u32 frame_index;

  /* Node runtime for this next. */
  u32 node_runtime_index;

  /* Next frame flags. */
  u32 flags;

  /* Reflects node frame-used flag for this next. */
#define VLIB_FRAME_NO_FREE_AFTER_DISPATCH \
  VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH

  /* This next frame owns enqueue to node
     corresponding to node_runtime_index. */
#define VLIB_FRAME_OWNER (1 << 15)

  /* Set when frame has been allocated for this next. */
#define VLIB_FRAME_IS_ALLOCATED	VLIB_NODE_FLAG_IS_OUTPUT

  /* Set when frame has been added to pending vector. */
#define VLIB_FRAME_PENDING VLIB_NODE_FLAG_IS_DROP

  /* Set when frame is to be freed after dispatch. */
#define VLIB_FRAME_FREE_AFTER_DISPATCH VLIB_NODE_FLAG_IS_PUNT

  /* Set when frame has traced packets. */
#define VLIB_FRAME_TRACE VLIB_NODE_FLAG_TRACE

  /* Number of vectors enqueue to this next since last overflow. */
  u32 vectors_since_last_overflow;
} vlib_next_frame_t;

always_inline void
vlib_next_frame_init (vlib_next_frame_t * nf)
{
  memset (nf, 0, sizeof (nf[0]));
  nf->frame_index = ~0;
  nf->node_runtime_index = ~0;
}

/* A frame pending dispatch by main loop. */
typedef struct
{
  /* Node and runtime for this frame. */
  u32 node_runtime_index;

  /* Frame index (in the heap). */
  u32 frame_index;

  /* Start of next frames for this node. */
  u32 next_frame_index;

  /* Special value for next_frame_index when there is no next frame. */
#define VLIB_PENDING_FRAME_NO_NEXT_FRAME ((u32) ~0)
} vlib_pending_frame_t;

typedef struct vlib_node_runtime_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* Node function to call. */
  vlib_node_function_t *function;

  /* Vector of errors for this node. */
  vlib_error_t *errors;

  /* Number of clock cycles. */
  u32 clocks_since_last_overflow;

  /* Maximum clock cycle for an invocation. */
  u32 max_clock;

  /* Number of vectors in the recorded max_clock. */
  u32 max_clock_n;

  /* Number of calls. */
  u32 calls_since_last_overflow;

  /* Number of vector elements processed by this node. */
  u32 vectors_since_last_overflow;

  /* Start of next frames for this node. */
  u32 next_frame_index;

  /* Node index. */
  u32 node_index;

  /* For input nodes: decremented on each main loop interation until it reaches zero
     and function is called.  Allows some input nodes to be called
     more than others. */
  u32 input_main_loops_per_call;

  /* Saved main loop counter of last dispatch of this node. */
  u32 main_loop_count_last_dispatch;

  u32 main_loop_vector_stats[2];

  /* Copy of main node flags. */
  u16 flags;

  /* Input node state. */
  u16 state;

  u16 n_next_nodes;

  /* Next frame index that vector arguments were last enqueued to
     last time this node ran.  Set to zero before first run
     of this node. */
  u16 cached_next_index;

  /* CPU this node runs on */
  u16 cpu_index;

  /* Function dependent node-runtime. */
  u8 runtime_data[0];
}
vlib_node_runtime_t;

typedef struct
{
  /* Number of allocated frames for this scalar/vector size. */
  u32 n_alloc_frames;

  /* Vector of free frame indices for this scalar/vector size. */
  u32 *free_frame_indices;
} vlib_frame_size_t;

typedef struct
{
  /* Users opaque value for event type. */
  uword opaque;
} vlib_process_event_type_t;

typedef struct
{
  /* Node runtime for this process. */
  vlib_node_runtime_t node_runtime;

  /* Where to longjmp when process is done. */
  clib_longjmp_t return_longjmp;

#define VLIB_PROCESS_RETURN_LONGJMP_RETURN ((uword) ~0 - 0)
#define VLIB_PROCESS_RETURN_LONGJMP_SUSPEND ((uword) ~0 - 1)

  /* Where to longjmp to resume node after suspend. */
  clib_longjmp_t resume_longjmp;
#define VLIB_PROCESS_RESUME_LONGJMP_SUSPEND 0
#define VLIB_PROCESS_RESUME_LONGJMP_RESUME  1

  u16 flags;
#define VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_CLOCK (1 << 0)
#define VLIB_PROCESS_IS_SUSPENDED_WAITING_FOR_EVENT (1 << 1)
  /* Set to indicate that this process has been added to resume vector. */
#define VLIB_PROCESS_RESUME_PENDING (1 << 2)

  /* Process function is currently running. */
#define VLIB_PROCESS_IS_RUNNING (1 << 3)

  /* Size of process stack. */
  u16 log2_n_stack_bytes;

  u32 suspended_process_frame_index;

  /* Number of times this process was suspended. */
  u32 n_suspends;

  /* Vectors of pending event data indexed by event type index. */
  void **pending_event_data_by_type_index;

  /* Bitmap of event type-indices with non-empty vectors. */
  uword *non_empty_event_type_bitmap;

  /* Bitmap of event type-indices which are one time events. */
  uword *one_time_event_type_bitmap;

  /* Type is opaque pointer -- typically a pointer to an event handler
     function.  Hash table to map opaque to a type index. */
  uword *event_type_index_by_type_opaque;

  /* Pool of currently valid event types. */
  vlib_process_event_type_t *event_type_pool;

  /* When suspending saves cpu cycle counter when process is to be resumed. */
  u64 resume_cpu_time;

  /* Default output function and its argument for any CLI outputs
     within the process. */
  vlib_cli_output_function_t *output_function;
  uword output_function_arg;

#ifdef CLIB_UNIX
  /* Pad to a multiple of the page size so we can mprotect process stacks */
#define PAGE_SIZE_MULTIPLE 0x1000
#define ALIGN_ON_MULTIPLE_PAGE_BOUNDARY_FOR_MPROTECT  __attribute__ ((aligned (PAGE_SIZE_MULTIPLE)))
#else
#define ALIGN_ON_MULTIPLE_PAGE_BOUNDARY_FOR_MPROTECT
#endif

  /* Process stack.  Starts here and extends 2^log2_n_stack_bytes
     bytes. */

#define VLIB_PROCESS_STACK_MAGIC (0xdead7ead)
  u32 stack[0] ALIGN_ON_MULTIPLE_PAGE_BOUNDARY_FOR_MPROTECT;
} vlib_process_t __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)));

#ifdef CLIB_UNIX
  /* Ensure that the stack is aligned on the multiple of the page size */
typedef char
  assert_process_stack_must_be_aligned_exactly_to_page_size_multiple[(sizeof
								      (vlib_process_t)
								      -
								      PAGE_SIZE_MULTIPLE)
								     ==
								     0 ? 0 :
								     -1];
#endif

typedef struct
{
  u32 node_index;

  u32 one_time_event;
} vlib_one_time_waiting_process_t;

typedef struct
{
  u16 n_data_elts;

  u16 n_data_elt_bytes;

  /* n_data_elts * n_data_elt_bytes */
  u32 n_data_bytes;

  /* Process node & event type to be used to signal event. */
  u32 process_node_index;

  u32 event_type_index;

  union
  {
    u8 inline_event_data[64 - 3 * sizeof (u32) - 2 * sizeof (u16)];

    /* Vector of event data used only when data does not fit inline. */
    u8 *event_data_as_vector;
  };
}
vlib_signal_timed_event_data_t;

always_inline uword
vlib_timing_wheel_data_is_timed_event (u32 d)
{
  return d & 1;
}

always_inline u32
vlib_timing_wheel_data_set_suspended_process (u32 i)
{
  return 0 + 2 * i;
}

always_inline u32
vlib_timing_wheel_data_set_timed_event (u32 i)
{
  return 1 + 2 * i;
}

always_inline uword
vlib_timing_wheel_data_get_index (u32 d)
{
  return d / 2;
}

typedef struct
{
  /* Public nodes. */
  vlib_node_t **nodes;

  /* Node index hashed by node name. */
  uword *node_by_name;

  u32 flags;
#define VLIB_NODE_MAIN_RUNTIME_STARTED (1 << 0)

  /* Nodes segregated by type for cache locality.
     Does not apply to nodes of type VLIB_NODE_TYPE_INTERNAL. */
  vlib_node_runtime_t *nodes_by_type[VLIB_N_NODE_TYPE];

  /* Node runtime indices for input nodes with pending interrupts. */
  u32 *pending_interrupt_node_runtime_indices;

  /* Input nodes are switched from/to interrupt to/from polling mode
     when average vector length goes above/below polling/interrupt
     thresholds. */
  u32 polling_threshold_vector_length;
  u32 interrupt_threshold_vector_length;

  /* Vector of next frames. */
  vlib_next_frame_t *next_frames;

  /* Vector of internal node's frames waiting to be called. */
  vlib_pending_frame_t *pending_frames;

  /* Timing wheel for scheduling time-based node dispatch. */
  timing_wheel_t timing_wheel;

  vlib_signal_timed_event_data_t *signal_timed_event_data_pool;

  /* Opaque data vector added via timing_wheel_advance. */
  u32 *data_from_advancing_timing_wheel;

  /* CPU time of next process to be ready on timing wheel. */
  u64 cpu_time_next_process_ready;

  /* Vector of process nodes.
     One for each node of type VLIB_NODE_TYPE_PROCESS. */
  vlib_process_t **processes;

  /* Current running process or ~0 if no process running. */
  u32 current_process_index;

  /* Pool of pending process frames. */
  vlib_pending_frame_t *suspended_process_frames;

  /* Vector of event data vectors pending recycle. */
  void **recycled_event_data_vectors;

  /* Current counts of nodes in each state. */
  u32 input_node_counts_by_state[VLIB_N_NODE_STATE];

  /* Hash of (scalar_size,vector_size) to frame_sizes index. */
  uword *frame_size_hash;

  /* Per-size frame allocation information. */
  vlib_frame_size_t *frame_sizes;

  /* Time of last node runtime stats clear. */
  f64 time_last_runtime_stats_clear;

  /* Node registrations added by constructors */
  vlib_node_registration_t *node_registrations;
} vlib_node_main_t;


#define FRAME_QUEUE_MAX_NELTS 32
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 head;
  u64 head_hint;
  u64 tail;
  u32 n_in_use;
  u32 nelts;
  u32 written;
  u32 threshold;
  i32 n_vectors[FRAME_QUEUE_MAX_NELTS];
} frame_queue_trace_t;

typedef struct
{
  u64 count[FRAME_QUEUE_MAX_NELTS];
} frame_queue_nelt_counter_t;

#endif /* included_vlib_node_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
