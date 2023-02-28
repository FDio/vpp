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

Typical RX connections include “ethernet-input” [full software
classification, feeds ipv4-input, ipv6-input, arp-input etc.] and
“ipv4-input-no-checksum” [if hardware can classify, perform ipv4 header
checksum].

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

.. code:: c

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
        from = vlib_frame_vector_args (frame);

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

Given a packet processing task to implement, it pays to scout around
looking for similar tasks, and think about using the same coding
pattern. It is not uncommon to recode a given graph node dispatch
function several times during performance optimization.

Creating Packets from Scratch
-----------------------------

At times, it’s necessary to create packets from scratch and send them.
Tasks like sending keepalives or actively opening connections come to
mind. Its not difficult, but accurate buffer metadata setup is required.

Allocating Buffers
~~~~~~~~~~~~~~~~~~

Use vlib_buffer_alloc, which allocates a set of buffer indices. For
low-performance applications, it’s OK to allocate one buffer at a time.
Note that vlib_buffer_alloc(…) does NOT initialize buffer metadata. See
below.

In high-performance cases, allocate a vector of buffer indices, and hand
them out from the end of the vector; decrement \_vec_len(..) as buffer
indices are allocated. See tcp_alloc_tx_buffers(…) and
tcp_get_free_buffer_index(…) for an example.

Buffer Initialization Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following example shows the **main points**, but is not to be
blindly cut-’n-pasted.

.. code:: c

     u32 bi0;
     vlib_buffer_t *b0;
     ip4_header_t *ip;
     udp_header_t *udp;

     /* Allocate a buffer */
     if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
       return -1;

     b0 = vlib_get_buffer (vm, bi0);

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
     b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

     /* sw_if_index 0 is the "local" interface, which always exists */
     vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;

     /* Use the default FIB index for tx lookup. Set non-zero to use another fib */
     vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;

If your use-case calls for large packet transmission, use
vlib_buffer_chain_append_data_with_alloc(…) to create the requisite
buffer chain.

Enqueueing packets for lookup and transmission
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The simplest way to send a set of packets is to use
vlib_get_frame_to_node(…) to allocate fresh frame(s) to ip4_lookup_node
or ip6_lookup_node, add the constructed buffer indices, and dispatch the
frame using vlib_put_frame_to_node(…).

.. code:: c

       vlib_frame_t *f;
       f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
       f->n_vectors = vec_len(buffer_indices_to_send);
       to_next = vlib_frame_vector_args (f);

       for (i = 0; i < vec_len (buffer_indices_to_send); i++)
         to_next[i] = buffer_indices_to_send[i];

       vlib_put_frame_to_node (vm, ip4_lookup_node_index, f);

It is inefficient to allocate and schedule single packet frames. That’s
typical in case you need to send one packet per second, but should
**not** occur in a for-loop!

Packet tracer
-------------

Vlib includes a frame element [packet] trace facility, with a simple
debug CLI interface. The cli is straightforward: “trace add
input-node-name count” to start capturing packet traces.

To trace 100 packets on a typical x86_64 system running the dpdk plugin:
“trace add dpdk-input 100”. When using the packet generator: “trace add
pg-input 100”

To display the packet trace: “show trace”

Each graph node has the opportunity to capture its own trace data. It is
almost always a good idea to do so. The trace capture APIs are simple.

The packet capture APIs snapshoot binary data, to minimize processing at
capture time. Each participating graph node initialization provides a
vppinfra format-style user function to pretty-print data when required
by the VLIB “show trace” command.

Set the VLIB node registration “.format_trace” member to the name of the
per-graph node format function.

Here’s a simple example:

.. code:: c

       u8 * my_node_format_trace (u8 * s, va_list * args)
       {
           vlib_main_t * vm = va_arg (*args, vlib_main_t *);
           vlib_node_t * node = va_arg (*args, vlib_node_t *);
           my_node_trace_t * t = va_arg (*args, my_trace_t *);

           s = format (s, "My trace data was: %d", t-><whatever>);

           return s;
       }

The trace framework hands the per-node format function the data it
captured as the packet whizzed by. The format function pretty-prints the
data as desired.

Graph Dispatcher Pcap Tracing
-----------------------------

The vpp graph dispatcher knows how to capture vectors of packets in pcap
format as they’re dispatched. The pcap captures are as follows:

::

       VPP graph dispatch trace record description:

           0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Major Version | Minor Version | NStrings      | ProtoHint     |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Buffer index (big endian)                                     |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          + VPP graph node name ...     ...               | NULL octet    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Buffer Metadata ... ...                       | NULL octet    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Buffer Opaque ... ...                         | NULL octet    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Buffer Opaque 2 ... ...                       | NULL octet    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | VPP ASCII packet trace (if NStrings > 4)      | NULL octet    |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          | Packet data (up to 16K)                                       |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Graph dispatch records comprise a version stamp, an indication of how
many NULL-terminated strings will follow the record header and preceed
packet data, and a protocol hint.

The buffer index is an opaque 32-bit cookie which allows consumers of
these data to easily filter/track single packets as they traverse the
forwarding graph.

Multiple records per packet are normal, and to be expected. Packets will
appear multiple times as they traverse the vpp forwarding graph. In this
way, vpp graph dispatch traces are significantly different from regular
network packet captures from an end-station. This property complicates
stateful packet analysis.

Restricting stateful analysis to records from a single vpp graph node
such as “ethernet-input” seems likely to improve the situation.

As of this writing: major version = 1, minor version = 0. Nstrings
SHOULD be 4 or 5. Consumers SHOULD be wary values less than 4 or greater
than 5. They MAY attempt to display the claimed number of strings, or
they MAY treat the condition as an error.

Here is the current set of protocol hints:

.. code:: c

       typedef enum
         {
           VLIB_NODE_PROTO_HINT_NONE = 0,
           VLIB_NODE_PROTO_HINT_ETHERNET,
           VLIB_NODE_PROTO_HINT_IP4,
           VLIB_NODE_PROTO_HINT_IP6,
           VLIB_NODE_PROTO_HINT_TCP,
           VLIB_NODE_PROTO_HINT_UDP,
           VLIB_NODE_N_PROTO_HINTS,
         } vlib_node_proto_hint_t;

Example: VLIB_NODE_PROTO_HINT_IP6 means that the first octet of packet
data SHOULD be 0x60, and should begin an ipv6 packet header.

Downstream consumers of these data SHOULD pay attention to the protocol
hint. They MUST tolerate inaccurate hints, which MAY occur from time to
time.

Dispatch Pcap Trace Debug CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To start a dispatch trace capture of up to 10,000 trace records:

::

        pcap dispatch trace on max 10000 file dispatch.pcap

To start a dispatch trace which will also include standard vpp packet
tracing for packets which originate in dpdk-input:

::

        pcap dispatch trace on max 10000 file dispatch.pcap buffer-trace dpdk-input 1000

To save the pcap trace, e.g. in /tmp/dispatch.pcap:

::

       pcap dispatch trace off

Wireshark dissection of dispatch pcap traces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It almost goes without saying that we built a companion wireshark
dissector to display these traces. As of this writing, we have
upstreamed the wireshark dissector.

Since it will be a while before wireshark/master/latest makes it into
all of the popular Linux distros, please see the “How to build a vpp
dispatch trace aware Wireshark” page for build info.

Here is a sample packet dissection, with some fields omitted for
clarity. The point is that the wireshark dissector accurately displays
**all** of the vpp buffer metadata, and the name of the graph node in
question.

::

       Frame 1: 2216 bytes on wire (17728 bits), 2216 bytes captured (17728 bits)
           Encapsulation type: USER 13 (58)
           [Protocols in frame: vpp:vpp-metadata:vpp-opaque:vpp-opaque2:eth:ethertype:ip:tcp:data]
       VPP Dispatch Trace
           BufferIndex: 0x00036663
       NodeName: ethernet-input
       VPP Buffer Metadata
           Metadata: flags:
           Metadata: current_data: 0, current_length: 102
           Metadata: current_config_index: 0, flow_id: 0, next_buffer: 0
           Metadata: error: 0, n_add_refs: 0, buffer_pool_index: 0
           Metadata: trace_index: 0, recycle_count: 0, len_not_first_buf: 0
           Metadata: free_list_index: 0
           Metadata:
       VPP Buffer Opaque
           Opaque: raw: 00000007 ffffffff 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
           Opaque: sw_if_index[VLIB_RX]: 7, sw_if_index[VLIB_TX]: -1
           Opaque: L2 offset 0, L3 offset 0, L4 offset 0, feature arc index 0
           Opaque: ip.adj_index[VLIB_RX]: 0, ip.adj_index[VLIB_TX]: 0
           Opaque: ip.flow_hash: 0x0, ip.save_protocol: 0x0, ip.fib_index: 0
           Opaque: ip.save_rewrite_length: 0, ip.rpf_id: 0
           Opaque: ip.icmp.type: 0 ip.icmp.code: 0, ip.icmp.data: 0x0
           Opaque: ip.reass.next_index: 0, ip.reass.estimated_mtu: 0
           Opaque: ip.reass.fragment_first: 0 ip.reass.fragment_last: 0
           Opaque: ip.reass.range_first: 0 ip.reass.range_last: 0
           Opaque: ip.reass.next_range_bi: 0x0, ip.reass.ip6_frag_hdr_offset: 0
           Opaque: mpls.ttl: 0, mpls.exp: 0, mpls.first: 0, mpls.save_rewrite_length: 0, mpls.bier.n_bytes: 0
           Opaque: l2.feature_bitmap: 00000000, l2.bd_index: 0, l2.l2_len: 0, l2.shg: 0, l2.l2fib_sn: 0, l2.bd_age: 0
           Opaque: l2.feature_bitmap_input:   none configured, L2.feature_bitmap_output:   none configured
           Opaque: l2t.next_index: 0, l2t.session_index: 0
           Opaque: l2_classify.table_index: 0, l2_classify.opaque_index: 0, l2_classify.hash: 0x0
           Opaque: policer.index: 0
           Opaque: ipsec.flags: 0x0, ipsec.sad_index: 0
           Opaque: map.mtu: 0
           Opaque: map_t.v6.saddr: 0x0, map_t.v6.daddr: 0x0, map_t.v6.frag_offset: 0, map_t.v6.l4_offset: 0
           Opaque: map_t.v6.l4_protocol: 0, map_t.checksum_offset: 0, map_t.mtu: 0
           Opaque: ip_frag.mtu: 0, ip_frag.next_index: 0, ip_frag.flags: 0x0
           Opaque: cop.current_config_index: 0
           Opaque: lisp.overlay_afi: 0
           Opaque: tcp.connection_index: 0, tcp.seq_number: 0, tcp.seq_end: 0, tcp.ack_number: 0, tcp.hdr_offset: 0, tcp.data_offset: 0
           Opaque: tcp.data_len: 0, tcp.flags: 0x0
           Opaque: sctp.connection_index: 0, sctp.sid: 0, sctp.ssn: 0, sctp.tsn: 0, sctp.hdr_offset: 0
           Opaque: sctp.data_offset: 0, sctp.data_len: 0, sctp.subconn_idx: 0, sctp.flags: 0x0
           Opaque: snat.flags: 0x0
           Opaque:
       VPP Buffer Opaque2
           Opaque2: raw: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
           Opaque2: qos.bits: 0, qos.source: 0
           Opaque2: loop_counter: 0
           Opaque2: gbp.flags: 0, gbp.src_epg: 0
           Opaque2: pg_replay_timestamp: 0
           Opaque2:
       Ethernet II, Src: 06:d6:01:41:3b:92 (06:d6:01:41:3b:92), Dst: IntelCor_3d:f6    Transmission Control Protocol, Src Port: 22432, Dst Port: 54084, Seq: 1, Ack: 1, Len: 36
           Source Port: 22432
           Destination Port: 54084
           TCP payload (36 bytes)
       Data (36 bytes)

       0000  cf aa 8b f5 53 14 d4 c7 29 75 3e 56 63 93 9d 11   ....S...)u>Vc...
       0010  e5 f2 92 27 86 56 4c 21 ce c5 23 46 d7 eb ec 0d   ...'.VL!..#F....
       0020  a8 98 36 5a                                       ..6Z
           Data: cfaa8bf55314d4c729753e5663939d11e5f2922786564c21…
           [Length: 36]

It’s a matter of a couple of mouse-clicks in Wireshark to filter the
trace to a specific buffer index. With that specific kind of filtration,
one can watch a packet walk through the forwarding graph; noting any/all
metadata changes, header checksum changes, and so forth.

This should be of significant value when developing new vpp graph nodes.
If new code mispositions b->current_data, it will be completely obvious
from looking at the dispatch trace in wireshark.

pcap rx, tx, and drop tracing
-----------------------------

vpp also supports rx, tx, and drop packet capture in pcap format,
through the “pcap trace” debug CLI command.

This command is used to start or stop a packet capture, or show the
status of packet capture. Each of “pcap trace rx”, “pcap trace tx”, and
“pcap trace drop” is implemented. Supply one or more of “rx”, “tx”, and
“drop” to enable multiple simultaneous capture types.

These commands have the following optional parameters:

-  rx - trace received packets.

-  tx - trace transmitted packets.

-  drop - trace dropped packets.

-  max *nnnn*\  - file size, number of packet captures. Once packets
   have been received, the trace buffer buffer is flushed to the
   indicated file. Defaults to 1000. Can only be updated if packet
   capture is off.

-  max-bytes-per-pkt *nnnn*\  - maximum number of bytes to trace on a
   per-packet basis. Must be >32 and less than 9000. Default value:

   512.

-  filter - Use the pcap trace rx / tx / drop filter, which must be
   configured. Use classify filter pcap… to configure the filter. The
   filter will only be executed if the per-interface or any-interface
   tests fail.

-  intfc *interface* \| *any*\  - Used to specify a given interface, or
   use ‘any’ to run packet capture on all interfaces. ‘any’ is the
   default if not provided. Settings from a previous packet capture are
   preserved, so ‘any’ can be used to reset the interface setting.

-  file *filename*\  - Used to specify the output filename. The file
   will be placed in the ‘/tmp’ directory. If *filename* already exists,
   file will be overwritten. If no filename is provided, ‘/tmp/rx.pcap
   or tx.pcap’ will be used, depending on capture direction. Can only be
   updated when pcap capture is off.

-  status - Displays the current status and configured attributes
   associated with a packet capture. If packet capture is in progress,
   ‘status’ also will return the number of packets currently in the
   buffer. Any additional attributes entered on command line with a
   ‘status’ request will be ignored.

-  filter - Capture packets which match the current packet trace filter
   set. See next section. Configure the capture filter first.

packet trace capture filtering
------------------------------

The “classify filter pcap \| \| trace” debug CLI command constructs an
arbitrary set of packet classifier tables for use with “pcap trace rx \|
tx \| drop,” and with the vpp packet tracer on a per-interface or
system-wide basis.

Packets which match a rule in the classifier table chain will be traced.
The tables are automatically ordered so that matches in the most
specific table are tried first.

It’s reasonably likely that folks will configure a single table with one
or two matches. As a result, we configure 8 hash buckets and 128K of
match rule space by default. One can override the defaults by specifying
“buckets ” and “memory-size ” as desired.

To build up complex filter chains, repeatedly issue the classify filter
debug CLI command. Each command must specify the desired mask and match
values. If a classifier table with a suitable mask already exists, the
CLI command adds a match rule to the existing table. If not, the CLI
command add a new table and the indicated mask rule

Configure a simple pcap classify filter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       classify filter pcap mask l3 ip4 src match l3 ip4 src 192.168.1.11
       pcap trace rx max 100 filter

Configure a simple per-interface capture filter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       classify filter GigabitEthernet3/0/0 mask l3 ip4 src match l3 ip4 src 192.168.1.11"
       pcap trace rx max 100 intfc GigabitEthernet3/0/0

Note that per-interface capture filters are *always* applied.

Clear per-interface capture filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       classify filter GigabitEthernet3/0/0 del

Configure another fairly simple pcap classify filter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      classify filter pcap mask l3 ip4 src dst match l3 ip4 src 192.168.1.10 dst 192.168.2.10
      pcap trace tx max 100 filter

Configure a vpp packet tracer filter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      classify filter trace mask l3 ip4 src dst match l3 ip4 src 192.168.1.10 dst 192.168.2.10
      trace add dpdk-input 100 filter

Clear all current classifier filters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       classify filter [pcap | <interface> | trace] del

To inspect the classifier tables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

      show classify table [verbose]

The verbose form displays all of the match rules, with hit-counters.

Terse description of the “mask ” syntax:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       l2 src dst proto tag1 tag2 ignore-tag1 ignore-tag2 cos1 cos2 dot1q dot1ad
       l3 ip4 <ip4-mask> ip6 <ip6-mask>
       <ip4-mask> version hdr_length src[/width] dst[/width]
                  tos length fragment_id ttl protocol checksum
       <ip6-mask> version traffic-class flow-label src dst proto
                  payload_length hop_limit protocol
       l4 tcp <tcp-mask> udp <udp_mask> src_port dst_port
       <tcp-mask> src dst  # ports
       <udp-mask> src_port dst_port

To construct **matches**, add the values to match after the indicated
keywords in the mask syntax. For example: “… mask l3 ip4 src” -> “…
match l3 ip4 src 192.168.1.11”

VPP Packet Generator
--------------------

We use the VPP packet generator to inject packets into the forwarding
graph. The packet generator can replay pcap traces, and generate packets
out of whole cloth at respectably high performance.

The VPP pg enables quite a variety of use-cases, ranging from functional
testing of new data-plane nodes to regression testing to performance
tuning.

PG setup scripts
----------------

PG setup scripts describe traffic in detail, and leverage vpp debug CLI
mechanisms. It’s reasonably unusual to construct a pg setup script which
doesn’t include a certain amount of interface and FIB configuration.

For example:

::

       loop create
       set int ip address loop0 192.168.1.1/24
       set int state loop0 up

       packet-generator new {
           name pg0
           limit 100
           rate 1e6
           size 300-300
           interface loop0
           node ethernet-input
           data { IP4: 1.2.3 -> 4.5.6
                  UDP: 192.168.1.10 - 192.168.1.254 -> 192.168.2.10
                  UDP: 1234 -> 2345
                  incrementing 286
           }
       }

A packet generator stream definition includes two major sections: -
Stream Parameter Setup - Packet Data

Stream Parameter Setup
~~~~~~~~~~~~~~~~~~~~~~

Given the example above, let’s look at how to set up stream parameters:

-  **name pg0** - Name of the stream, in this case “pg0”

-  **limit 1000** - Number of packets to send when the stream is
   enabled. “limit 0” means send packets continuously.

-  **maxframe <nnn>** - Maximum frame size. Handy for injecting multiple
   frames no larger than <nnn>. Useful for checking dual / quad loop
   codes

-  **rate 1e6** - Packet injection rate, in this case 1 MPPS. When not
   specified, the packet generator injects packets as fast as possible

-  **size 300-300** - Packet size range, in this case send 300-byte
   packets

-  **interface loop0** - Packets appear as if they were received on the
   specified interface. This datum is used in multiple ways: to select
   graph arc feature configuration, to select IP FIBs. Configure
   features e.g. on loop0 to exercise those features.

-  **tx-interface <name>** - Packets will be transmitted on the
   indicated interface. Typically required only when injecting packets
   into post-IP-rewrite graph nodes.

-  **pcap <filename>** - Replay packets from the indicated pcap capture
   file. “make test” makes extensive use of this feature: generate
   packets using scapy, save them in a .pcap file, then inject them into
   the vpp graph via a vpp pg “pcap <filename>” stream definition

-  **worker <nn>** - Generate packets for the stream using the indicated
   vpp worker thread. The vpp pg generates and injects O(10 MPPS /
   core). Use multiple stream definitions and worker threads to generate
   and inject enough traffic to easily fill a 40 gbit pipe with small
   packets.

Data definition
~~~~~~~~~~~~~~~

Packet generator data definitions make use of a layered implementation
strategy. Networking layers are specified in order, and the notation can
seem a bit counter-intuitive. In the example above, the data definition
stanza constructs a set of L2-L4 headers layers, and uses an
incrementing fill pattern to round out the requested 300-byte packets.

-  **IP4: 1.2.3 -> 4.5.6** - Construct an L2 (MAC) header with the ip4
   ethertype (0x800), src MAC address of 00:01:00:02:00:03 and dst MAC
   address of 00:04:00:05:00:06. Mac addresses may be specified in
   either *xxxx.xxxx.xxxx* format or *xx:xx:xx:xx:xx:xx* format.

-  **UDP: 192.168.1.10 - 192.168.1.254 -> 192.168.2.10** - Construct an
   incrementing set of L3 (IPv4) headers for successive packets with
   source addresses ranging from .10 to .254. All packets in the stream
   have a constant dest address of 192.168.2.10. Set the protocol field
   to 17, UDP.

-  **UDP: 1234 -> 2345** - Set the UDP source and destination ports to
   1234 and 2345, respectively

-  **incrementing 256** - Insert up to 256 incrementing data bytes.

Obvious variations involve “s/IP4/IP6/” in the above, along with
changing from IPv4 to IPv6 address notation.

The vpp pg can set any / all IPv4 header fields, including tos, packet
length, mf / df / fragment id and offset, ttl, protocol, checksum, and
src/dst addresses. Take a look at ../src/vnet/ip/ip[46]_pg.c for
details.

If all else fails, specify the entire packet data in hex:

-  **hex 0xabcd…** - copy hex data verbatim into the packet

When replaying pcap files (“**pcap <filename>**”), do not specify a data
stanza.

Diagnosing “packet-generator new” parse failures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to inject packets into a brand-new graph node, remember to
tell the packet generator debug CLI how to parse the packet data stanza.

If the node expects L2 Ethernet MAC headers, specify “.unformat_buffer =
unformat_ethernet_header”:

.. code:: c

       VLIB_REGISTER_NODE (ethernet_input_node) =
       {
         <snip>
         .unformat_buffer = unformat_ethernet_header,
         <snip>
       };

Beyond that, it may be necessary to set breakpoints in
…/src/vnet/pg/cli.c. Debug image suggested.

When debugging new nodes, it may be far simpler to directly inject
ethernet frames - and add a corresponding vlib_buffer_advance in the new
node - than to modify the packet generator.

Debug CLI
---------

The descriptions above describe the “packet-generator new” debug CLI in
detail.

Additional debug CLI commands include:

::

       vpp# packet-generator enable [<stream-name>]

which enables the named stream, or all streams.

::

       vpp# packet-generator disable [<stream-name>]

disables the named stream, or all streams.

::

       vpp# packet-generator delete <stream-name>

Deletes the named stream.

::

       vpp# packet-generator configure <stream-name> [limit <nnn>]
            [rate <f64-pps>] [size <nn>-<nn>]

Changes stream parameters without having to recreate the entire stream
definition. Note that re-issuing a “packet-generator new” command will
correctly recreate the named stream.
