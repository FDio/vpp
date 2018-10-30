
VNET (VPP Network Stack)
========================

The files associated with the VPP network stack layer are located in the
*./src/vnet* folder. The Network Stack Layer is basically an
instantiation of the code in the other layers. This layer has a vnet
library that provides vectorized layer-2 and 3 networking graph nodes, a
packet generator, and a packet tracer.

In terms of building a packet processing application, vnet provides a
platform-independent subgraph to which one connects a couple of
device-driver nodes.

Typical RX connections include "ethernet-input" \[full software
classification, feeds ipv4-input, ipv6-input, arp-input etc.\] and
"ipv4-input-no-checksum" \[if hardware can classify, perform ipv4 header
checksum\].

Effective graph dispatch function coding
----------------------------------------

Over the 15 years, multiple coding styles have emerged: a
single/dual/quad loop coding model (with variations) and a
fully-pipelined coding model.

Single/dual loops
-----------------

The single/dual/quad loop model variations conveniently solve problems
where the number of items to process is not known in advance: typical
hardware RX-ring processing. This coding style is also very effective
when a given node will not need to cover a complex set of dependent
reads.

Here is an quad/single loop which can leverage up-to-avx512 SIMD vector
units to convert buffer indices to buffer pointers:

```c
   static uword
   simulated_ethernet_interface_tx (vlib_main_t * vm,
   				 vlib_node_runtime_t *
   				 node, vlib_frame_t * frame)
   {
     u32 n_left_from, *from;
     u32 next_index = 0;
     u32 n_bytes;
     u32 thread_index = vm->thread_index;
     vnet_main_t *vnm = vnet_get_main ();
     vnet_interface_main_t *im = &vnm->interface_main;
     vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
     u16 nexts[VLIB_FRAME_SIZE], *next;

     n_left_from = frame->n_vectors;
     from = vlib_frame_args (frame);

     /* 
      * Convert up to VLIB_FRAME_SIZE indices in "from" to 
      * buffer pointers in bufs[]
      */
     vlib_get_buffers (vm, from, bufs, n_left_from);
     b = bufs;
     next = nexts;

     /* 
      * While we have at least 4 vector elements (pkts) to process.. 
      */
     while (n_left_from >= 4)
       {
         /* Prefetch next quad-loop iteration. */
         if (PREDICT_TRUE (n_left_from >= 8))
   	   {
   	     vlib_prefetch_buffer_header (b[4], STORE);
   	     vlib_prefetch_buffer_header (b[5], STORE);
   	     vlib_prefetch_buffer_header (b[6], STORE);
   	     vlib_prefetch_buffer_header (b[7], STORE);
           }

         /* 
          * $$$ Process 4x packets right here...
          * set next[0..3] to send the packets where they need to go
          */

          do_something_to (b[0]);
          do_something_to (b[1]);
          do_something_to (b[2]);
          do_something_to (b[3]);

         /* Process the next 0..4 packets */
   	 b += 4;
   	 next += 4;
   	 n_left_from -= 4;
   	}
     /* 
      * Clean up 0...3 remaining packets at the end of the incoming frame
      */
     while (n_left_from > 0)
       {
         /* 
          * $$$ Process one packet right here...
          * set next[0..3] to send the packets where they need to go
          */
          do_something_to (b[0]);

         /* Process the next packet */
         b += 1;
         next += 1;
         n_left_from -= 1;
       }

     /*
      * Send the packets along their respective next-node graph arcs
      * Considerable locality of reference is expected, most if not all
      * packets in the inbound vector will traverse the same next-node
      * arc
      */
     vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

     return frame->n_vectors;
   }  
```

Given a packet processing task to implement, it pays to scout around
looking for similar tasks, and think about using the same coding
pattern. It is not uncommon to recode a given graph node dispatch function
several times during performance optimization.

Creating Packets from Scratch
-----------------------------

At times, it's necessary to create packets from scratch and send
them. Tasks like sending keepalives or actively opening connections
come to mind. Its not difficult, but accurate buffer metadata setup is
required.

### Allocating Buffers

Use vlib_buffer_alloc, which allocates a set of buffer indices. For
low-performance applications, it's OK to allocate one buffer at a
time. Note that vlib_buffer_alloc(...) does NOT initialize buffer
metadata. See below.

In high-performance cases, allocate a vector of buffer indices,
and hand them out from the end of the vector; decrement _vec_len(..)
as buffer indices are allocated. See tcp_alloc_tx_buffers(...) and
tcp_get_free_buffer_index(...) for an example.

### Buffer Initialization Example

The following example shows the **main points**, but is not to be
blindly cut-'n-pasted.

```c                               
  u32 bi0;
  vlib_buffer_t *b0;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_buffer_free_list_t *fl;

  /* Allocate a buffer */
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    return -1;

  b0 = vlib_get_buffer (vm, bi0);

  /* Initialize the buffer */
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (b0, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  /* At this point b0->current_data = 0, b0->current_length = 0 */

  /* 
   * Copy data into the buffer. This example ASSUMES that data will fit
   * in a single buffer, and is e.g. an ip4 packet.
   */
  if (have_packet_rewrite)
     {
       clib_memcpy (b0->data, data, vec_len (data));
       b0->current_length = vec_len (data);
     }
  else 
     {
       /* OR, build a udp-ip packet (for example) */
       ip = vlib_buffer_get_current (b0);
       udp = (udp_header_t *) (ip + 1);
       data_dst = (u8 *) (udp + 1);

       ip->ip_version_and_header_length = 0x45;
       ip->ttl = 254;
       ip->protocol = IP_PROTOCOL_UDP;
       ip->length = clib_host_to_net_u16 (sizeof (*ip) + sizeof (*udp) +
                  vec_len(udp_data));
       ip->src_address.as_u32 = src_address->as_u32;
       ip->dst_address.as_u32 = dst_address->as_u32;
       udp->src_port = clib_host_to_net_u16 (src_port);
       udp->dst_port = clib_host_to_net_u16 (dst_port);
       udp->length = clib_host_to_net_u16 (vec_len (udp_data));
       clib_memcpy (data_dst, udp_data, vec_len(udp_data));

       if (compute_udp_checksum)
         {
           /* RFC 7011 section 10.3.2. */
           udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);
           if (udp->checksum == 0)
             udp->checksum = 0xffff;
      }  
      b0->current_length = vec_len (sizeof (*ip) + sizeof (*udp) +
                                   vec_len (udp_data));

    }
  b0->flags |= (VLIB_BUFFER_TOTAL_LENGTH_VALID;

  /* sw_if_index 0 is the "local" interface, which always exists */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;

  /* Use the default FIB index for tx lookup. Set non-zero to use another fib */
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;

```  

If your use-case calls for large packet transmission, use
vlib_buffer_chain_append_data_with_alloc(...) to create the requisite
buffer chain.

### Enqueueing packets for lookup and transmission

The simplest way to send a set of packets is to use
vlib_get_frame_to_node(...) to allocate fresh frame(s) to
ip4_lookup_node or ip6_lookup_node, add the constructed buffer
indices, and dispatch the frame using vlib_put_frame_to_node(...).

```c
    vlib_frame_t *f;
    f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
    f->n_vectors = vec_len(buffer_indices_to_send);
    to_next = vlib_frame_vector_args (f);

    for (i = 0; i < vec_len (buffer_indices_to_send); i++)
      to_next[i] = buffer_indices_to_send[i];

    vlib_put_frame_to_node (vm, ip4_lookup_node_index, f); 
``` 

It is inefficient to allocate and schedule single packet frames.
That's typical in case you need to send one packet per second, but
should **not** occur in a for-loop!

Packet tracer
-------------

Vlib includes a frame element \[packet\] trace facility, with a simple
vlib cli interface. The cli is straightforward: "trace add
input-node-name count".

To trace 100 packets on a typical x86\_64 system running the dpdk
plugin: "trace add dpdk-input 100". When using the packet generator:
"trace add pg-input 100"

Each graph node has the opportunity to capture its own trace data. It is
almost always a good idea to do so. The trace capture APIs are simple.

The packet capture APIs snapshoot binary data, to minimize processing at
capture time. Each participating graph node initialization provides a
vppinfra format-style user function to pretty-print data when required
by the VLIB "show trace" command.

Set the VLIB node registration ".format\_trace" member to the name of
the per-graph node format function.

Here's a simple example:

```c
    u8 * my_node_format_trace (u8 * s, va_list * args)
    {
        vlib_main_t * vm = va_arg (*args, vlib_main_t *);
        vlib_node_t * node = va_arg (*args, vlib_node_t *);
        my_node_trace_t * t = va_arg (*args, my_trace_t *);

        s = format (s, "My trace data was: %d", t-><whatever>);

        return s;
    } 
```

The trace framework hands the per-node format function the data it
captured as the packet whizzed by. The format function pretty-prints the
data as desired.
