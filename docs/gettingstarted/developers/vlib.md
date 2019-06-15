
VLIB (Vector Processing Library)
================================

The files associated with vlib are located in the ./src/{vlib,
vlibapi, vlibmemory} folders. These libraries provide vector
processing support including graph-node scheduling, reliable multicast
support, ultra-lightweight cooperative multi-tasking threads, a CLI,
plug in .DLL support, physical memory and Linux epoll support. Parts of
this library embody US Patent 7,961,636.

Init function discovery
-----------------------

vlib applications register for various \[initialization\] events by
placing structures and \_\_attribute\_\_((constructor)) functions into
the image. At appropriate times, the vlib framework walks
constructor-generated singly-linked structure lists, calling the
indicated functions. vlib applications create graph nodes, add CLI
functions, start cooperative multi-tasking threads, etc. etc. using this
mechanism.

vlib applications invariably include a number of VLIB\_INIT\_FUNCTION
(my\_init\_function) macros.

Each init / configure / etc. function has the return type clib\_error\_t
\*. Make sure that the function returns 0 if all is well, otherwise the
framework will announce an error and exit.

vlib applications must link against vppinfra, and often link against
other libraries such as VNET. In the latter case, it may be necessary to
explicitly reference symbol(s) otherwise large portions of the library
may be AWOL at runtime.

Node Graph Initialization
-------------------------

vlib packet-processing applications invariably define a set of graph
nodes to process packets.

One constructs a vlib\_node\_registration\_t, most often via the
VLIB\_REGISTER\_NODE macro. At runtime, the framework processes the set
of such registrations into a directed graph. It is easy enough to add
nodes to the graph at runtime. The framework does not support removing
nodes.

vlib provides several types of vector-processing graph nodes, primarily
to control framework dispatch behaviors. The type member of the
vlib\_node\_registration\_t functions as follows:

-   VLIB\_NODE\_TYPE\_PRE\_INPUT - run before all other node types
-   VLIB\_NODE\_TYPE\_INPUT - run as often as possible, after pre\_input
    nodes
-   VLIB\_NODE\_TYPE\_INTERNAL - only when explicitly made runnable by
    adding pending frames for processing
-   VLIB\_NODE\_TYPE\_PROCESS - only when explicitly made runnable.
    "Process" nodes are actually cooperative multi-tasking threads. They
    **must** explicitly suspend after a reasonably short period of time.

For a precise understanding of the graph node dispatcher, please read
./src/vlib/main.c:vlib\_main\_loop.

Graph node dispatcher
---------------------

Vlib\_main\_loop() dispatches graph nodes. The basic vector processing
algorithm is diabolically simple, but may not be obvious from even a
long stare at the code. Here's how it works: some input node, or set of
input nodes, produce a vector of work to process. The graph node
dispatcher pushes the work vector through the directed graph,
subdividing it as needed, until the original work vector has been
completely processed. At that point, the process recurs.

This scheme yields a stable equilibrium in frame size, by construction.
Here's why: as the frame size increases, the per-frame-element
processing time decreases. There are several related forces at work; the
simplest to describe is the effect of vector processing on the CPU L1
I-cache. The first frame element \[packet\] processed by a given node
warms up the node dispatch function in the L1 I-cache. All subsequent
frame elements profit. As we increase the number of frame elements, the
cost per element goes down.

Under light load, it is a crazy waste of CPU cycles to run the graph
node dispatcher flat-out. So, the graph node dispatcher arranges to wait
for work by sitting in a timed epoll wait if the prevailing frame size
is low. The scheme has a certain amount of hysteresis to avoid
constantly toggling back and forth between interrupt and polling mode.
Although the graph dispatcher supports interrupt and polling modes, our
current default device drivers do not.

The graph node scheduler uses a hierarchical timer wheel to reschedule
process nodes upon timer expiration.

Graph dispatcher internals
--------------------------

This section may be safely skipped. It's not necessary to understand
graph dispatcher internals to create graph nodes.

Vector Data Structure
---------------------

In vpp / vlib, we represent vectors as instances of the vlib_frame_t type:

```c
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

      /* Scalar and vector arguments to next node. */
      u8 arguments[0];
    } vlib_frame_t;
```

Note that one _could_ construct all kinds of vectors - including
vectors with some associated scalar data - using this structure. In
the vpp application, vectors typically use a 4-byte vector element
size, and zero bytes' worth of associated per-frame scalar data.

Frames are always allocated on CLIB_CACHE_LINE_BYTES boundaries.
Frames have u32 indices which make use of the alignment property, so
the maximum feasible main heap offset of a frame is
CLIB_CACHE_LINE_BYTES * 0xFFFFFFFF: 64*4 = 256 Gbytes.

Scheduling Vectors
------------------

As you can see, vectors are not directly associated with graph
nodes. We represent that association in a couple of ways.  The
simplest is the vlib\_pending\_frame\_t:

```c
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
```

Here is the code in .../src/vlib/main.c:vlib_main_or_worker_loop()
which processes frames:

```c
      /*
       * Input nodes may have added work to the pending vector.
       * Process pending vector until there is nothing left.
       * All pending vectors will be processed from input -> output.
       */
      for (i = 0; i < _vec_len (nm->pending_frames); i++)
	cpu_time_now = dispatch_pending_node (vm, i, cpu_time_now);
      /* Reset pending vector for next iteration. */
```

The pending frame node_runtime_index associates the frame with the
node which will process it.

Complications
-------------

Fasten your seatbelt. Here's where the story - and the data structures
\- become quite complicated...

At 100,000 feet: vpp uses a directed graph, not a directed _acyclic_
graph. It's really quite normal for a packet to visit ip\[46\]-lookup
multiple times. The worst-case: a graph node which enqueues packets to
itself.

To deal with this issue, the graph dispatcher must force allocation of
a new frame if the current graph node's dispatch function happens to
enqueue a packet back to itself.

There are no guarantees that a pending frame will be processed
immediately, which means that more packets may be added to the
underlying vlib_frame_t after it has been attached to a
vlib_pending_frame_t. Care must be taken to allocate new
frames and pending frames if a (pending\_frame, frame) pair fills.

Next frames, next frame ownership
---------------------------------

The vlib\_next\_frame\_t is the last key graph dispatcher data structure:

```c
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
```

Graph node dispatch functions call vlib\_get\_next\_frame (...)  to
set "(u32 \*)to_next" to the right place in the vlib_frame_t
corresponding to the ith arc (aka next0) from the current node to the
indicated next node.

After some scuffling around - two levels of macros - processing
reaches vlib\_get\_next\_frame_internal (...). Get-next-frame-internal
digs up the vlib\_next\_frame\_t corresponding to the desired graph
arc.

The next frame data structure amounts to a graph-arc-centric frame
cache. Once a node finishes adding element to a frame, it will acquire
a vlib_pending_frame_t and end up on the graph dispatcher's
run-queue. But there's no guarantee that more vector elements won't be
added to the underlying frame from the same (source\_node,
next\_index) arc or from a different (source\_node, next\_index) arc.

Maintaining consistency of the arc-to-frame cache is necessary. The
first step in maintaining consistency is to make sure that only one
graph node at a time thinks it "owns" the target vlib\_frame\_t.

Back to the graph node dispatch function. In the usual case, a certain
number of packets will be added to the vlib\_frame\_t acquired by
calling vlib\_get\_next\_frame (...).

Before a dispatch function returns, it's required to call
vlib\_put\_next\_frame (...) for all of the graph arcs it actually
used.  This action adds a vlib\_pending\_frame\_t to the graph
dispatcher's pending frame vector.

Vlib\_put\_next\_frame makes a note in the pending frame of the frame
index, and also of the vlib\_next\_frame\_t index.

dispatch\_pending\_node actions
-------------------------------

The main graph dispatch loop calls dispatch pending node as shown
above.

Dispatch\_pending\_node recovers the pending frame, and the graph node
runtime / dispatch function. Further, it recovers the next\_frame
currently associated with the vlib\_frame\_t, and detaches the
vlib\_frame\_t from the next\_frame.

In .../src/vlib/main.c:dispatch\_pending\_node(...), note this stanza:

```c
  /* Force allocation of new frame while current frame is being
     dispatched. */
  restore_frame_index = ~0;
  if (nf->frame_index == p->frame_index)
    {
      nf->frame_index = ~0;
      nf->flags &= ~VLIB_FRAME_IS_ALLOCATED;
      if (!(n->flags & VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH))
	restore_frame_index = p->frame_index;
    }
```

dispatch\_pending\_node is worth a hard stare due to the several
second-order optimizations it implements. Almost as an afterthought,
it calls dispatch_node which actually calls the graph node dispatch
function.

Process / thread model
----------------------

vlib provides an ultra-lightweight cooperative multi-tasking thread
model. The graph node scheduler invokes these processes in much the same
way as traditional vector-processing run-to-completion graph nodes;
plus-or-minus a setjmp/longjmp pair required to switch stacks. Simply
set the vlib\_node\_registration\_t type field to
vlib\_NODE\_TYPE\_PROCESS. Yes, process is a misnomer. These are
cooperative multi-tasking threads.

As of this writing, the default stack size is 2<<15 = 32kb.
Initialize the node registration's process\_log2\_n\_stack\_bytes member
as needed. The graph node dispatcher makes some effort to detect stack
overrun, e.g. by mapping a no-access page below each thread stack.

Process node dispatch functions are expected to be "while(1) { }" loops
which suspend when not otherwise occupied, and which must not run for
unreasonably long periods of time.

"Unreasonably long" is an application-dependent concept. Over the years,
we have constructed frame-size sensitive control-plane nodes which will
use a much higher fraction of the available CPU bandwidth when the frame
size is low. The classic example: modifying forwarding tables. So long
as the table-builder leaves the forwarding tables in a valid state, one
can suspend the table builder to avoid dropping packets as a result of
control-plane activity.

Process nodes can suspend for fixed amounts of time, or until another
entity signals an event, or both. See the next section for a description
of the vlib process event mechanism.

When running in vlib process context, one must pay strict attention to
loop invariant issues. If one walks a data structure and calls a
function which may suspend, one had best know by construction that it
cannot change. Often, it's best to simply make a snapshot copy of a data
structure, walk the copy at leisure, then free the copy.

Process events
--------------

The vlib process event mechanism API is extremely lightweight and easy
to use. Here is a typical example:

```c
    vlib_main_t *vm = &vlib_global_main;
    uword event_type, * event_data = 0;

    while (1)
    {
       vlib_process_wait_for_event_or_clock (vm, 5.0 /* seconds */);

       event_type = vlib_process_get_events (vm, &event_data);

       switch (event_type) {
       case EVENT1:
           handle_event1s (event_data);
           break;

       case EVENT2:
           handle_event2s (event_data);
           break;

       case ~0: /* 5-second idle/periodic */
           handle_idle ();
           break;

       default: /* bug! */
           ASSERT (0);
       }

       vec_reset_length(event_data);
    }
```

In this example, the VLIB process node waits for an event to occur, or
for 5 seconds to elapse. The code demuxes on the event type, calling
the appropriate handler function. Each call to
vlib\_process\_get\_events returns a vector of per-event-type data
passed to successive vlib\_process\_signal\_event calls; it is a
serious error to process only event\_data\[0\].

Resetting the event\_data vector-length to 0 \[instead of calling
vec\_free\] means that the event scheme doesn't burn cycles continuously
allocating and freeing the event data vector. This is a common vppinfra
/ vlib coding pattern, well worth using when appropriate.

Signaling an event is easy, for example:

```c
    vlib_process_signal_event (vm, process_node_index, EVENT1,
        (uword)arbitrary_event1_data); /* and so forth */
```

One can either know the process node index by construction - dig it out
of the appropriate vlib\_node\_registration\_t - or by finding the
vlib\_node\_t with vlib\_get\_node\_by\_name(...).

Buffers
-------

vlib buffering solves the usual set of packet-processing problems,
albeit at high performance. Key in terms of performance: one ordinarily
allocates / frees N buffers at a time rather than one at a time. Except
when operating directly on a specific buffer, one deals with buffers by
index, not by pointer.

Packet-processing frames are u32\[\] arrays, not
vlib\_buffer\_t\[\] arrays.

Packets comprise one or more vlib buffers, chained together as required.
Multiple particle sizes are supported; hardware input nodes simply ask
for the required size(s). Coalescing support is available. For obvious
reasons one is discouraged from writing one's own wild and wacky buffer
chain traversal code.

vlib buffer headers are allocated immediately prior to the buffer data
area. In typical packet processing this saves a dependent read wait:
given a buffer's address, one can prefetch the buffer header
\[metadata\] at the same time as the first cache line of buffer data.

Buffer header metadata (vlib\_buffer\_t) includes the usual rewrite
expansion space, a current\_data offset, RX and TX interface indices,
packet trace information, and a opaque areas.

The opaque data is intended to control packet processing in arbitrary
subgraph-dependent ways. The programmer shoulders responsibility for
data lifetime analysis, type-checking, etc.

Buffers have reference-counts in support of e.g. multicast replication.

Shared-memory message API
-------------------------

Local control-plane and application processes interact with the vpp
dataplane via asynchronous message-passing in shared memory over
unidirectional queues. The same application APIs are available via
sockets.

Capturing API traces and replaying them in a simulation environment
requires a disciplined approach to the problem. This seems like a
make-work task, but it is not. When something goes wrong in the
control-plane after 300,000 or 3,000,000 operations, high-speed replay
of the events leading up to the accident is a huge win.

The shared-memory message API message allocator vl\_api\_msg\_alloc uses
a particularly cute trick. Since messages are processed in order, we try
to allocate message buffering from a set of fixed-size, preallocated
rings. Each ring item has a "busy" bit. Freeing one of the preallocated
message buffers merely requires the message consumer to clear the busy
bit. No locking required.

Debug CLI
---------

Adding debug CLI commands to VLIB applications is very simple.

Here is a complete example:

```c
    static clib_error_t *
    show_ip_tuple_match (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
    {
        vlib_cli_output (vm, "%U\n", format_ip_tuple_match_tables, &routing_main);
        return 0;
    }

    /* *INDENT-OFF* */
    static VLIB_CLI_COMMAND (show_ip_tuple_command) =
    {
        .path = "show ip tuple match",
        .short_help = "Show ip 5-tuple match-and-broadcast tables",
        .function = show_ip_tuple_match,
    };
    /* *INDENT-ON* */
```

This example implements the "show ip tuple match" debug cli
command. In ordinary usage, the vlib cli is available via the "vppctl"
applicationn, which sends traffic to a named pipe. One can configure
debug CLI telnet access on a configurable port.

The cli implementation has an output redirection facility which makes it
simple to deliver cli output via shared-memory API messaging,

Particularly for debug or "show tech support" type commands, it would be
wasteful to write vlib application code to pack binary data, write more
code elsewhere to unpack the data and finally print the answer. If a
certain cli command has the potential to hurt packet processing
performance by running for too long, do the work incrementally in a
process node. The client can wait.

Handing off buffers between threads
-----------------------------------

Vlib includes an easy-to-use mechanism for handing off buffers between
worker threads. A typical use-case: software ingress flow hashing. At
a high level, one creates a per-worker-thread queue which sends packets
to a specific graph node in the indicated worker thread. With the
queue in hand, enqueue packets to the worker thread of your choice.

### Initialize a handoff queue

Simple enough, call vlib_frame_queue_main_init:

```c
   main_ptr->frame_queue_index
       = vlib_frame_queue_main_init (dest_node.index, frame_queue_size);
```

Frame_queue_size means what it says: the number of frames which may be
queued. Since frames contain 1...256 packets, frame_queue_size should
be a reasonably small number (32...64). If the frame queue producer(s)
are faster than the frame queue consumer(s), congestion will
occur. Suggest letting the enqueue operator deal with queue
congestion, as shown in the enqueue example below.

Under the floorboards, vlib_frame_queue_main_init creates an input queue
for each worker thread.

Please do NOT create frame queues until it's clear that they will be
used. Although the main dispatch loop is reasonably smart about how
often it polls the (entire set of) frame queues, polling unused frame
queues is a waste of clock cycles.

### Hand off packets

The actual handoff mechanics are simple, and integrate nicely with
a typical graph-node dispatch function:

```c
    always_inline uword
    do_handoff_inline (vlib_main_t * vm,
         	       vlib_node_runtime_t * node, vlib_frame_t * frame,
    		       int is_ip4, int is_trace)
    {
      u32 n_left_from, *from;
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
      u16 thread_indices [VLIB_FRAME_SIZE];
      u16 nexts[VLIB_FRAME_SIZE], *next;
      u32 n_enq;
      htest_main_t *hmp = &htest_main;
      int i;

      from = vlib_frame_vector_args (frame);
      n_left_from = frame->n_vectors;

      vlib_get_buffers (vm, from, bufs, n_left_from);
      next = nexts;
      b = bufs;

      /*
       * Typical frame traversal loop, details vary with
       * use case. Make sure to set thread_indices[i] with
       * the desired destination thread index. You may
       * or may not bother to set next[i].
       */

      for (i = 0; i < frame->n_vectors; i++)
        {
          <snip>
          /* Pick a thread to handle this packet */
          thread_indices[i] = f (packet_data_or_whatever);
          <snip>

          b += 1;
          next += 1;
          n_left_from -= 1;
        }

       /* Enqueue buffers to threads */
       n_enq =
        vlib_buffer_enqueue_to_thread (vm, hmp->frame_queue_index,
                                       from, thread_indices, frame->n_vectors,
                                       1 /* drop on congestion */);
       /* Typical counters,
      if (n_enq < frame->n_vectors)
        vlib_node_increment_counter (vm, node->node_index,
    				 XXX_ERROR_CONGESTION_DROP,
    				 frame->n_vectors - n_enq);
      vlib_node_increment_counter (vm, node->node_index,
    			         XXX_ERROR_HANDED_OFF, n_enq);
      return frame->n_vectors;
}
```

Notes about calling vlib_buffer_enqueue_to_thread(...):

* If you pass "drop on congestion" non-zero, all packets in the
inbound frame will be consumed one way or the other. This is the
recommended setting.

* In the drop-on-congestion case, please don't try to "help" in the
enqueue node by freeing dropped packets, or by pushing them to
"error-drop." Either of those actions would be a severe error.

* It's perfectly OK to enqueue packets to the current thread.
