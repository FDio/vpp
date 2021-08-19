Buffer Metadata
===============

Each vlib_buffer_t (packet buffer) carries buffer metadata which
describes the current packet-processing state. The underlying
techniques have been used for decades, across multiple packet
processing environments.

We will examine vpp buffer metadata in some detail, but folks who need
to manipulate and/or extend the scheme should expect to do a certain
level of code inspection.

Vlib (Vector library) primary buffer metadata
----------------------------------------------

The first 64 octets of each vlib_buffer_t carries the primary buffer
metadata. See .../src/vlib/buffer.h for full details.

Important fields:

* i16 current_data: the signed offset in data[], pre_data[] that we
are currently processing. If negative current header points into
the pre-data (rewrite space) area.
* u16 current_length: nBytes between current_data and the end of this buffer.
* u32 flags: Buffer flag bits. Heavily used, not many bits left
  * src/vlib/buffer.h flag bits
    * VLIB_BUFFER_IS_TRACED: buffer is traced
    * VLIB_BUFFER_NEXT_PRESENT: buffer has multiple chunks
    * VLIB_BUFFER_TOTAL_LENGTH_VALID: total_length_not_including_first_buffer is valid (see below)
  * src/vnet/buffer.h flag bits
    * VNET_BUFFER_F_L4_CHECKSUM_COMPUTED: tcp/udp checksum has been computed
    * VNET_BUFFER_F_L4_CHECKSUM_CORRECT: tcp/udp checksum is correct
    * VNET_BUFFER_F_VLAN_2_DEEP: two vlan tags present
    * VNET_BUFFER_F_VLAN_1_DEEP: one vlan tag present
    * VNET_BUFFER_F_SPAN_CLONE: packet has already been cloned (span feature)
    * VNET_BUFFER_F_LOOP_COUNTER_VALID: packet look-up loop count valid
    * VNET_BUFFER_F_LOCALLY_ORIGINATED: packet built by vpp
    * VNET_BUFFER_F_IS_IP4: packet is ipv4, for checksum offload
    * VNET_BUFFER_F_IS_IP6: packet is ipv6, for checksum offload
    * VNET_BUFFER_F_OFFLOAD_IP_CKSUM: hardware ip checksum offload requested
    * VNET_BUFFER_F_OFFLOAD_TCP_CKSUM: hardware tcp checksum offload requested
    * VNET_BUFFER_F_OFFLOAD_UDP_CKSUM: hardware udp checksum offload requested
    * VNET_BUFFER_F_IS_NATED: natted packet, skip input checks
    * VNET_BUFFER_F_L2_HDR_OFFSET_VALID: L2 header offset valid
    * VNET_BUFFER_F_L3_HDR_OFFSET_VALID: L3 header offset valid
    * VNET_BUFFER_F_L4_HDR_OFFSET_VALID: L4 header offset valid
    * VNET_BUFFER_F_FLOW_REPORT: packet is an ipfix packet
    * VNET_BUFFER_F_IS_DVR: packet to be reinjected into the l2 output path
    * VNET_BUFFER_F_QOS_DATA_VALID: QoS data valid in vnet_buffer_opaque2
    * VNET_BUFFER_F_GSO: generic segmentation offload requested
    * VNET_BUFFER_F_AVAIL1: available bit
    * VNET_BUFFER_F_AVAIL2: available bit
    * VNET_BUFFER_F_AVAIL3: available bit
    * VNET_BUFFER_F_AVAIL4: available bit
    * VNET_BUFFER_F_AVAIL5: available bit
    * VNET_BUFFER_F_AVAIL6: available bit
    * VNET_BUFFER_F_AVAIL7: available bit
* u32 flow_id: generic flow identifier
* u8 ref_count: buffer reference / clone count (e.g. for span replication)
* u8 buffer_pool_index: buffer pool index which owns this buffer
* vlib_error_t (u16) error: error code for buffers enqueued to error handler
* u32 next_buffer: buffer index of next buffer in chain. Only valid if VLIB_BUFFER_NEXT_PRESENT is set
* union
  * u32 current_config_index: current index on feature arc
  * u32 punt_reason: reason code once packet punted. Mutually exclusive with current_config_index
* u32 opaque[10]: primary vnet-layer opaque data (see below)
* END of first cache line / data initialized by the buffer allocator
* u32 trace_index: buffer's index in the packet trace subsystem
* u32 total_length_not_including_first_buffer: see VLIB_BUFFER_TOTAL_LENGTH_VALID above
* u32 opaque2[14]: secondary vnet-layer opaque data (see below)
* u8 pre_data[VLIB_BUFFER_PRE_DATA_SIZE]: rewrite space, often used to prepend tunnel encapsulations
* u8 data[0]: buffer data received from the wire. Ordinarily, hardware devices use b->data[0] as the DMA target but there are exceptions. Do not write code which blindly assumes that packet data starts in b->data[0]. Use vlib_buffer_get_current(...).

Vnet (network stack) primary buffer metadata
--------------------------------------------

Vnet primary buffer metadata occupies space reserved in the vlib
opaque field shown above, and has the type name
vnet_buffer_opaque_t. Ordinarily accessed using the vnet_buffer(b)
macro. See ../src/vnet/buffer.h for full details.

Important fields:

* u32 sw_if_index[2]: RX and TX interface handles. At the ip lookup
  stage, vnet_buffer(b)->sw_if_index[VLIB_TX] is interpreted as a FIB
  index.
* i16 l2_hdr_offset: offset from b->data[0] of the packet L2 header.
  Valid only if b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID is set
* i16 l3_hdr_offset: offset from b->data[0] of the packet L3 header.
  Valid only if b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID is set
* i16 l4_hdr_offset: offset from b->data[0] of the packet L4 header.
  Valid only if b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID is set
* u8 feature_arc_index: feature arc that the packet is currently traversing
* union
  * ip
    * u32 adj_index[2]: adjacency from dest IP lookup in [VLIB_TX], adjacency
      from source ip lookup in [VLIB_RX], set to ~0 until source lookup done
    * union
      * generic fields
      * ICMP fields
      * reassembly fields
  * mpls fields
  * l2 bridging fields, only valid in the L2 path
  * l2tpv3 fields
  * l2 classify fields
  * vnet policer fields
  * MAP fields
  * MAP-T fields
  * ip fragmentation fields
  * COP (whitelist/blacklist filter) fields
  * LISP fields
  * TCP fields
    * connection index
    * sequence numbers
    * header and data offsets
    * data length
    * flags
  * SCTP fields
  * NAT fields
  * u32 unused[6]

Vnet (network stack) secondary buffer metadata
-----------------------------------------------

Vnet primary buffer metadata occupies space reserved in the vlib
opaque2 field shown above, and has the type name
vnet_buffer_opaque2_t. Ordinarily accessed using the vnet_buffer2(b)
macro. See ../src/vnet/buffer.h for full details.

Important fields:

* qos fields
  * u8 bits
  * u8 source
* u8 loop_counter: used to detect and report internal forwarding loops
* group-based policy fields
  * u8 flags
  * u16 sclass: the packet's source class
* u16 gso_size: L4 payload size, persists all the way to
  interface-output in case GSO is not enabled
* u16 gso_l4_hdr_sz: size of the L4 protocol header
* union
  * packet trajectory tracer (largely deprecated)
    * u16 *trajectory_trace; only #if VLIB_BUFFER_TRACE_TRAJECTORY > 0
  * packet generator
    * u64 pg_replay_timestamp: timestamp for replayed pcap trace packets
  * u32 unused[8]

Buffer Metadata Extensions
==========================

Plugin developers may wish to extend either the primary or secondary
vnet buffer opaque unions. Please perform a
manual live variable analysis, otherwise nodes which use shared buffer metadata space may break things.

It's not OK to add plugin or proprietary metadata to the core vpp
engine header files named above. Instead, proceed as follows. The
example concerns the vnet primary buffer opaque union
vlib_buffer_opaque_t. It's a very simple variation to use the vnet
secondary buffer opaque union vlib_buffer_opaque2_t.

In a plugin header file:

```
    /* Add arbitrary buffer metadata */
    #include <vnet/buffer.h>

    typedef struct
    {
      u32 my_stuff[6];
    } my_buffer_opaque_t;

    STATIC_ASSERT (sizeof (my_buffer_opaque_t) <=
                   STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
                   "Custom meta-data too large for vnet_buffer_opaque_t");

    #define my_buffer_opaque(b)  \
      ((my_buffer_opaque_t *)((u8 *)((b)->opaque) + STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))
```
To set data in the custom buffer opaque type given a vlib_buffer_t *b:

```
    my_buffer_opaque (b)->my_stuff[2] = 123;
```

To read data from the custom buffer opaque type:

```
    stuff0 = my_buffer_opaque (b)->my_stuff[2];
```
