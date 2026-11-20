.. _drv_octeon_net:

==========================================================
Marvell Octeon network (octeon-net) native driver
==========================================================

Overview
========

The ``octeon-net`` driver is a native VPP driver for the network interface
units of the Marvell Octeon 9 and Octeon 10 data processing SoCs (the NIX, NPA
and NPC blocks of the *Resource Virtualization Unit*, RVU). It supports the
physical function (PF) which owns an Ethernet MAC, and the virtual functions
which are created from it, as well as the internal loopback (LBK) and system
DPI packet interface (SDP) functions.

The driver uses the Marvell ROC library, which provides the low level access to
the hardware and the firmware. The crypto
block of the same SoC is supported by the separate :ref:`drv_octeon_crypto`
driver.

The driver is built on the :ref:`dev_framework` and registers on the ``pci``
bus under the name ``octeon-net``. It creates one Ethernet port (port ``0``)
per PCI function.

Supported devices
=================

The driver attaches to PCI vendor ``177d`` (Cavium / Marvell) and the
following device ids:

======== ===========================================================
PCI id   Description
======== ===========================================================
``a063`` Marvell Octeon Resource Virtualization Unit PF
``a064`` Marvell Octeon Resource Virtualization Unit VF
``a0f8`` Marvell Octeon Loopback Unit VF
``a0f7`` Marvell Octeon System DPI Packet Interface Unit VF
======== ===========================================================

Build requirements
==================

The driver is built only for the ``octeon9`` and ``octeon10`` VPP platforms and
only when the Marvell ROC headers and ``libocteon-roc.a`` are available (the
build prints that the driver is disabled otherwise). Select it with the
``VPP_DRIVERS`` cmake variable together with the platform.

Prerequisites
=============

* The functions to be used are bound to ``vfio-pci`` (the PF, and the VFs which
  VPP uses), as with other native PCI drivers.
* The PF and its VFs are different PCI functions. A VF is created from a PF and
  does not have control over the MAC and the physical link.
* Huge pages, and the buffer memory of VPP must be addressable by the device.
* The driver is a *driver level* component: the
  ``npa_max_pools`` argument must be set before the first device is attached
  (see below).

.. note::

   Enable the IOMMU (``intel_iommu=on`` or ``amd_iommu=on`` on the kernel command
   line, and ``iommu=pt`` for the kernel's own devices) when using ``vfio-pci``.
   It improves both performance and security. With an IOMMU the device uses
   VPP virtual addresses directly for DMA, because the IOMMU translates them to
   physical addresses, so the driver does not have to translate the address of
   every buffer and descriptor ring itself. The IOMMU also restricts the device
   to the memory which VPP mapped for it. Without an IOMMU the driver has to
   program physical addresses, and the device can access all of the system
   memory.

Configuration
=============

Sample ``startup.conf``:

.. code-block:: text

   devices {
     driver octeon-net {
       args 'npa_max_pools=128'
     }
     dev pci/0002:02:00.0 {
       driver octeon-net
       args 'egress_tm=false'
       port 0 {
         name oct0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 1024
         tx-queue-size 1024
         args 'eth_pause_frame=on rss_flow_key=0x1f'
       }
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0002:02:00.0 driver octeon-net args egress_tm=false
   vpp# device create-interface pci/0002:02:00.0 port 0 name oct0 args eth_pause_frame=on
   vpp# set interface state oct0 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`.

Arguments
=========

Driver arguments (``driver octeon-net { args '...' }``). They apply to all
devices of the driver and can only be set before the first device is attached,
otherwise the configuration is refused:

``npa_max_pools`` (uint32, default 128)
   Maximum number of NPA (hardware buffer pool) pools the driver may use.

Device arguments (``args '...'`` in the ``dev`` section or ``device attach``):

``egress_tm`` (boolean, default off)
   Enable the egress traffic manager (network devices only). It uses a TX node
   which honors the flow identifier of the buffers and registers the interface
   with the VPP traffic manager (``vnet_tm``) so that the hardware scheduler
   and shapers can be configured.

Port arguments (``args '...'`` in the ``port`` section or ``device
create-interface``). Which arguments exist depends on the kind of function:

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Argument
     - Functions
     - Description
   * - ``eth_pause_frame`` (boolean, default off)
     - PF and VF
     - Enable Ethernet pause frame support.
   * - ``rss_flow_key`` (hex)
     - all
     - RSS flow key bitmap. It selects which header fields are hashed
       (``FLOW_KEY_TYPE_*`` bits of the ROC library). The default selects IPv4,
       IPv6, TCP, UDP and SCTP.
   * - ``switch_header_type`` (enum, default ``none``)
     - PF
     - Type of the header added by an external switch connected to the port:
       ``none``, ``edsa``, ``higig``, ``len_90b``, ``exdsa`` or
       ``vlan_exdsa``.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX and TX queues
     - up to 64
   * - RX and TX queue size
     - 256 to 16384 descriptors, default 1024
   * - Maximum frame size
     - the hardware maximum packet length plus FCS

Supported features
==================

* **Link state and speed** from the MAC firmware, polled every 0.5 s while the
  port is started. The speeds the MAC can use are derived from its supported
  link modes (from 10 Mbit/s up to 100 Gbit/s). The speed can be changed at
  runtime (``set interface link-speed <interface> <speed-kbps>``) if a link
  mode exists for it.
* **Link down on stop (PF).** On a physical function the MAC link is disabled
  while the port is stopped. A virtual function, a loopback function and an SDP
  function cannot control the link.
* **RX offloads**: IPv4 header checksum.
* **TX offloads**: IPv4, TCP and UDP checksum. Segmentation offload is not
  advertised.
* **RSS** with a 48 byte hash key and a 256 entry lookup table, configurable at
  start (``rss-key``, ``rss-lut``) and at runtime (``device set-rss-config``).
  The hashed fields follow ``rss_flow_key``.
* **Interrupt mode** for RX queues when the device provides one completion
  queue interrupt vector per RX queue. Otherwise it is disabled and a warning
  is logged.
* **MAC filtering**: primary and additional unicast addresses and promiscuous
  mode.
* **MTU**: the maximum frame size can be changed while the port is stopped.
* **Hardware flow offload** through the generic VPP flow API: match on
  Ethernet, IPv4/IPv6, n-tuple (also VLAN tagged), VXLAN, GTP-C, GTP-U,
  L2TPv3 over IP, IPsec ESP and AH, with the actions redirect to queue, drop,
  RSS, mark, buffer advance and redirect to node. Flow counters can be read
  and reset.
* **Egress traffic manager** (``egress_tm``) as described above.
* **Hardware buffer pools.** The driver uses NPA pools (auras) for packet
  buffers, see ``npa_max_pools``.
* **Statistics**: port and queue counters from the hardware.

Not supported:

* TCP and UDP segmentation offload.
* Secondary interfaces.
* Octeon devices other than those in the device table.

Counters
========

``show device counters`` shows the port, RX queue and TX queue statistics read
from the hardware. The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Counter
     - Meaning
   * - ``buffer allocation failed, rx queue not refilled``
     - the RX queue could not be refilled
   * - ``completion queue error``
     - the hardware reported an error in a completion
   * - ``drop due to buffer chain > 6``
     - the packet is made of more than six buffers
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``aura batch alloc issue failed``
     - the batch allocation request could not be issued
   * - ``aura batch alloc not ready``
     - the batch allocation was not ready in time
   * - ``mtu exceeded``
     - the packet is longer than the configured maximum frame size
   * - ``tm flow_id valid but unmapped to local queue``
     - (traffic manager) the flow id has no TX queue mapping

Caveats
=======

* Only the platforms ``octeon9`` and ``octeon10`` build the driver.
* The driver level argument ``npa_max_pools`` must be configured before any
  device is attached. A second attempt is refused with ``Driver config
  arguments are already initialized or devices are already initialized``.
* VFs do not control the MAC link. Stopping the port on a VF does not take the
  link down for the link partner.
* A chain of more than six buffers is dropped, so the VPP buffer size and the
  maximum frame size must fit together.
* Interrupt mode is available only when enough completion queue interrupt
  vectors exist.
* The driver depends on the ROC library version. A mismatch with the firmware
  is reported by the ROC error messages at attach time.

Debugging
=========

* ``show device <device-id>`` shows the device, the port and the queue state.
* ``show device counters all <device-id>`` shows all counters.
* Raise the log level with ``logging { class octeon { level debug } class dev {
  level debug } }``. The ``octeon`` log class has subclasses for the flow
  rules and the traffic manager. ROC library errors are logged as ``ROC error
  <message> (<code>)`` together with the failing call.
* Typical errors: ``Failed to get MAC firmware data`` (the MAC information could
  not be read from the firmware), ``no supported link mode for
  speed`` (the requested speed is not possible with the MAC), ``Timed out
  waiting for pending TX batch allocation`` and ``buffers leaked on rx queue``
  (reported when a queue is stopped).
* Packets are traced with ``trace add <interface-name>-rx 10``.
