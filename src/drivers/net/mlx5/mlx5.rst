.. _drv_mlx5:

==========================================================
NVIDIA / Mellanox ConnectX (mlx5) native driver
==========================================================

Overview
========

The ``mlx5`` driver is a native VPP driver for the NVIDIA (Mellanox)
ConnectX-4 and later Ethernet adapters and BlueField DPUs which use the Linux
``mlx5_core`` kernel driver. It is a *passive* driver: the PCI device stays
bound to the Linux kernel driver and VPP accesses it through ``libibverbs``
(rdma-core) and the ``mlx5`` direct verbs (``mlx5dv``) interface. The kernel
driver keeps owning the PHY, the link and the firmware, and the kernel network
interface of the port keeps existing. VPP only takes over the data path.

Compared with the generic :ref:`drv_ibverbs` driver, ``mlx5`` uses the mlx5
specific features: striding receive queues, completion queue entry (CQE)
compression, enhanced multi-packet send WQEs (eMPW) and device level counters.

The driver is built on the :ref:`dev_framework` and registers on the ``pci``
bus under the name ``mlx5``. It creates one Ethernet port for every RDMA port
of the device which has an Ethernet link layer and a kernel network interface.

Supported devices
=================

The driver attaches to any PCI device with the vendor id ``15b3`` (NVIDIA /
Mellanox) which is known to the RDMA subsystem, so it must have an RDMA
device (``ibv_devices`` lists it). The description shown by ``show device`` is
taken from the PCI id database.

Adapters of the ConnectX family and the BlueField DPUs are driven by the kernel
``mlx5_core`` and ``mlx5_ib`` modules and are the intended targets. What the
driver can use (RSS, checksum and segmentation offload, striding RQ, CQE
compression, eMPW) is detected from the device at attach time.

Prerequisites
=============

* The Linux ``mlx5_core`` and ``mlx5_ib`` (RDMA) kernel modules loaded and the
  device **bound to the kernel driver**. Do not bind the device to
  ``vfio-pci``.
* ``ib_uverbs`` loaded so that ``/dev/infiniband/uverbs*`` exists and VPP has
  access to it. VPP normally runs as root.
* The VPP build includes the driver (``VPP_DRIVERS``) and links with rdma-core.
* Bring the kernel network interface of the port up, otherwise the RDMA port
  is not active and VPP reports the link down:

  .. code-block:: console

     # ip link set dev enp24s0f0np0 up

* Check that the RDMA device and its netdev exist:

  .. code-block:: console

     # rdma link show
     link mlx5_0/1 state ACTIVE physical_state LINK_UP netdev enp24s0f0np0

Configuration
=============

Because ``mlx5`` and ``ibverbs`` both accept a Mellanox device, name the
driver explicitly. Sample ``startup.conf``:

.. code-block:: text

   devices {
     dev pci/0000:18:00.0 {
       driver mlx5
       port 1 {
         name cx0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 2048
         tx-queue-size 2048
         args 'no_cqe_compression=off'
       }
     }
   }

The port id is the RDMA port number, which starts at ``1`` (not ``0``).

At runtime:

.. code-block:: text

   vpp# device attach pci/0000:18:00.0 driver mlx5
   vpp# device create-interface pci/0000:18:00.0 port 1 name cx0
   vpp# set interface state cx0 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`.

Arguments
=========

Port arguments (``args '...'`` in the ``port`` section or ``args`` of ``device
create-interface``):

``no_striding_rq`` (boolean, default off)
   Do not use the mlx5 striding receive queue. By default, when the hardware and
   the VPP buffer size allow it, frames larger than one buffer are received
   with a striding RQ, which is more efficient than legacy chained receive.
   Setting it forces the legacy receive queue (at most five chained buffers).

``no_cqe_compression`` (boolean, default off)
   Disable CQE compression with the hash format on the receive queues.

``no_empw`` (boolean, default off)
   Do not use enhanced multi-packet send WQEs. eMPW packs several small packets
   into one send work request and is used by default when the device supports
   it with the VPP configuration.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX and TX queue size
     - 256 up to the device limit (the smaller of max QP work requests and max
       CQ entries, at most 65535), power of two, default 1024
   * - Queues
     - limited by the device (max QPs and CQs)
   * - Maximum frame size
     - the maximum MTU of the kernel network interface plus the Ethernet
       overhead

Supported features
==================

* **Link state and speed** from the RDMA port state, polled once a second while
  the port is started. They follow the kernel network interface.
* **RX offloads**: IPv4 header checksum.
* **TX offloads**: IPv4, TCP and UDP checksum when the device supports raw
  packet checksum offload, and TCP segmentation offload (TSO) when the device
  supports it for packets of 64 KB.
* **RSS** when the device supports RSS for raw packet queues. The 40 byte key
  and the indirection table can be set at start (``rss-key``, ``rss-lut``) and
  at runtime (``device set-rss-config``). The table size is limited by the
  device.
* **Interrupt mode** for RX queues.
* **MAC filtering** with flow steering rules: the primary MAC address is
  programmed through the hardware flow table, additional unicast addresses,
  promiscuous mode and multicast reception are supported.
* **MTU**: the maximum frame size can be changed while the port is stopped. It
  is limited by the maximum MTU of the kernel network interface. Set the MTU of
  the kernel interface to the same value, VPP does not change it.
* **Buffer chaining**: with the striding receive queue frames are received in up
  to eight strides, with the legacy queue in up to five chained buffers. TX
  packets over the chain limit are dropped and counted.
* **Module EEPROM** of the transceiver (``show hardware-interfaces <name>
  eeprom``), read through the kernel network interface.
* **Statistics**: device level counters (see below), polled once a second.
* **Error recovery**: a receive or transmit completion error resets the
  affected queue and the driver recovers it. The event is logged and counted.

Not supported:

* Taking the link down when the port is stopped. The kernel driver owns the
  link, use ``ip link set dev <name> down``.
* Secondary interfaces and flow offload rules.
* InfiniBand link layer ports (only Ethernet ports are used).
* Changing the link speed from VPP.

Counters
========

``show device counters`` shows, per port, the received packets dropped by the
device (``rx drops``), the steering discards, the vport down discards in both
directions and the receive queue out-of-buffer drops, and per RX queue the drop
counter. The out-of-buffer counter needs a hardware queue counter set which not
all firmware versions offer, a notice is logged when it is unavailable.

The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``buffer allocation failed``
     - the RX queue could not be refilled
   * - ``receive completion error, queue reset``
     - a receive completion reported an error and the queue was reset
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``buffer chain too long``
     - the packet needs more segments than allowed, packet dropped
   * - ``tx completion error, queue reset``
     - a send completion reported an error and the queue was reset

Caveats
=======

* The kernel interface of the port must be up for the link to be active.
* The kernel driver and VPP share the device. Do not change the configuration
  that VPP relies on (MTU, offloads, flow control, number of channels) from
  the kernel side while VPP is running, and do not unload ``mlx5_core``.
* The MAC address is the one of the kernel network interface. If it cannot be
  read, a random MAC address is generated.
* If both ``mlx5`` and ``ibverbs`` match a device and no driver is named, the
  first registered driver is used. Always give ``driver mlx5``.
* Port numbers start at 1.

Debugging
=========

* ``show device <device-id>`` shows the RDMA device attributes and the mlx5
  context capabilities (CQE formats, multi-packet send support and others)
  and the port and queue state.
* ``show device counters all <device-id>`` shows all counters.
* ``rdma link show`` and ``ibv_devinfo -v`` verify the RDMA device, the port
  state and the netdev.
* Raise the log level with ``logging { class mlx5 { level debug } class dev {
  level debug } }``.
* Typical errors: ``cannot open verbs device`` (no RDMA device, ``ib_uverbs``
  not loaded or no permission), ``cannot find kernel netdev max mtu`` (the
  port has no kernel network interface), ``ibv_create_qp failed`` and
  ``ibv_reg_mr failed`` (resource limits, check ``ulimit -l``, the locked
  memory limit), ``completion error syndrome`` (a queue was reset, see the
  syndrome in the log).
* Packets are traced with ``trace add <interface-name>-rx 10``.
