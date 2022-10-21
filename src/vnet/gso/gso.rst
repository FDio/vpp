.. _gso_doc:

Generic Segmentation Offload
============================

Overview
________

Modern physical NICs provide offload capabilities to software based network
stacks to transfer some type of the packet processing from CPU to physical
NICs. TCP Segmentation Offload (TSO) is one among many which is provided by
modern physical NICs. Software based network stack can offload big (up to 64KB)
TCP packets to NIC and NIC will segment them into Maximum Segment Size packets.
Hence network stack save CPU cycles by processing few big packets instead of
processing many small packets.

GSO is software based analogous to TSO which is used by virtual interfaces
i.e. tap, virtio, af_packet, vhost-user etc. Typically, virtual interfaces
provide capability to offload big packets (64KB size). But in reality, they
just pass the packet as it is to the other end without segmenting it. Hence, it
is necessary to validate the support of GSO offloading in whole setup otherwise
packet will be dropped when it will be processed by virtual entity which does
not support GSO.

The GSO Infrastructure
_______________________

Software based network stacks implements GSO packet segmentation in software
where egress interface (virtual or physical) does not support GSO or TSO
offload. VPP implements GSO stack to provide support for software based packet
chunking of GSO packets when egress interface does not support GSO or TSO
offload.

It is implemented as a feature node on interface-output feature arc. It
implements support for basic GSO, GSO with VXLAN tunnel and GSO with IPIP
tunnel. GSO with Geneve and GSO with NVGRE are not supported today. But one can
enable GSO feature node on tunnel interfaces i.e. IPSEC etc to segment GSO
packets before they will be tunneled.

Virtual interfaces does not support GSO with tunnels. So, special care is
needed when user configures tunnel(s) along with GSO in the setup. In such case,
either enable GSO feature node on tunnel interface (mean chunk the GSO packets
before they will be encapsulated in tunnel) or disable the GSO offload on the
egress interface (only work for VXLAN tunnel and IPIP tunnel), if it is enabled,
should work fine.

Similarly, many physical interfaces does not support GSO with tunnels too. User
can do the same configuration as it is mentioned previously for virtual
interfaces.

Data structures
^^^^^^^^^^^^^^^

VPP ``vlib_buffer_t`` uses ``VNET_BUFFER_F_GSO`` flags to mark the buffer carrying GSO
packet and also contain metadata fields with respect to GSO:

.. code:: c

  i16 l2_hdr_offset;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;

  u16 gso_size;
  u16 gso_l4_hdr_sz;
  i16 outer_l3_hdr_offset;
  i16 outer_l4_hdr_offset;

Packet header offsets are computed from the reference of ``vlib_buffer_t`` data
pointer.

``l2_hdr_offset``, ``l3_hdr_offset`` and ``l4_hdr_offset`` are set on input of checksum
offload or GSO enabled interfaces or features i.e. host stack. Appropriate
offload flags are also set to ``vnet_buffer_oflags_t`` to reflect the actual packet
offloads which will be used later at egress interface tx node or
interface-output node or GSO node to process the packet appropriately. These
fields are present in 1st cache line and does not incur extra cycles as most of
the VPP features fetch the ``vlib_buffer_t`` 1st cache line to access ``current_data``
or ``current_length`` fields of the packet.

Please note that ``gso_size``, ``gso_l4_hdr_sz``, ``outer_l3_hdr_offset`` and
``outer_l4_hdr_offset`` are in second cache line of ``vlib_buffer_t``. Accessing them in
data plane will incur some extra cycles but cost of these cycles will be
amortized over (up to 64KB) packet.

The ``gso_size`` and ``gso_l4_hdr_sz`` are set on input of GSO enabled interfaces (tap,
virtio, af_packet etc) or features (vpp host stack), when we receive a GSO
packet (a chain of buffers with the first one having ``VNET_BUFFER_F_GSO`` bit set),
and needs to persist all the way to the interface-output, in case the egress
interface is not GSO-enabled - then we need to perform the segmentation, and use
these values to chunk the payload appropriately.

``outer_l3_hdr_offset`` and ``outer_l4_hdr_offset`` are used in case of tunneled packet
(i.e. VXLAN or IPIP). ``outer_l3_hdr_offset`` will point to outer l3 header of the
tunnel headers and ``outer_l4_hdr_offset`` will point to outer l4 header of the
tunnel headers, if any.

Following are the helper functions used to set and clear the offload flags from
``vlib_buffer_t`` metadata:

.. code:: c

  static_always_inline void
  vnet_buffer_offload_flags_set (vlib_buffer_t *b, vnet_buffer_oflags_t oflags)
  {
    if (b->flags & VNET_BUFFER_F_OFFLOAD)
      {
        /* add a flag to existing offload */
        vnet_buffer (b)->oflags |= oflags;
      }
    else
      {
        /* no offload yet: reset offload flags to new value */
        vnet_buffer (b)->oflags = oflags;
        b->flags |= VNET_BUFFER_F_OFFLOAD;
      }
  }

  static_always_inline void
  vnet_buffer_offload_flags_clear (vlib_buffer_t *b, vnet_buffer_oflags_t oflags)
  {
    vnet_buffer (b)->oflags &= ~oflags;
    if (0 == vnet_buffer (b)->oflags)
      b->flags &= ~VNET_BUFFER_F_OFFLOAD;
  }


ENABLE GSO FEATURE NODE
-----------------------

GSO feature node is not enabled by default when egress interface does not
support GSO. User has to enable it explicitly using api or cli.

GSO API
^^^^^^^

This API message is used to enable GSO feature node on an interface.

.. code:: c

  autoreply define feature_gso_enable_disable
  {
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool  enable_disable;
    option vat_help = "<intfc> | sw_if_index <nn> [enable | disable]";
  };

GSO CLI
^^^^^^^

::

  set interface feature gso <intfc> [enable | disable]
