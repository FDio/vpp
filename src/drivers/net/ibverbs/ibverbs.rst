.. _drv_ibverbs:

==================================================
Generic RDMA verbs (ibverbs) native driver
==================================================

Overview
========

The ``ibverbs`` driver is a generic native VPP driver for Ethernet ports of
RDMA capable adapters which are accessed through ``libibverbs`` (rdma-core).
Like the :ref:`drv_mlx5` driver it is *passive*: the PCI device stays bound to
its Linux kernel driver, and VPP creates raw packet queue pairs and work queues
on the RDMA device. The kernel driver keeps owning the PHY, the link and the
firmware.

It uses only standard verbs features (raw packet QPs, receive work queues, RSS
through indirection tables, flow steering). For ConnectX adapters the
:ref:`drv_mlx5` driver should be preferred because it uses the mlx5 specific
direct verbs for better performance.

The driver is built on the :ref:`dev_framework` and registers on the ``pci``
bus under the name ``ibverbs``. It creates one Ethernet port for every RDMA
port of the device which has an Ethernet link layer.

Supported devices
=================

The driver attaches to any PCI device which has an RDMA device known to the
kernel (``ibv_devices`` lists it) and which supports raw Ethernet packet
queues. There is no device id table. The description shown by ``show device``
comes from the PCI id database.

Prerequisites
=============

* The kernel driver and its RDMA module loaded and the device **bound to the
  kernel driver** (not to ``vfio-pci``).
* ``ib_uverbs`` loaded so that ``/dev/infiniband/uverbs*`` exists.
* The kernel network interface of the port up, so that the RDMA port is
  active.
* A VPP build with the driver and rdma-core.

Check the RDMA device with ``rdma link show`` and ``ibv_devinfo``.

Configuration
=============

Sample ``startup.conf``:

.. code-block:: text

   devices {
     dev pci/0000:18:00.0 {
       driver ibverbs
       port 1 {
         name rdma0
         num-rx-queues 2
         num-tx-queues 2
         rx-queue-size 1024
         tx-queue-size 1024
       }
     }
   }

The port id is the RDMA port number, which starts at ``1``. At runtime:

.. code-block:: text

   vpp# device attach pci/0000:18:00.0 driver ibverbs
   vpp# device create-interface pci/0000:18:00.0 port 1 name rdma0
   vpp# set interface state rdma0 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`.

Arguments
=========

The driver defines no driver, device or port arguments.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX and TX queue size
     - 256 up to the device limit, power of two, default 512
   * - Queues
     - limited by the device (max QPs and CQs)
   * - Maximum frame size
     - the smaller of five VPP buffers and the maximum MTU of the kernel
       network interface plus the Ethernet overhead

Supported features
==================

* **Link state and speed** from the RDMA port state, polled once a second while
  the port is started. They follow the kernel network interface. Device
  asynchronous events are also handled.
* **RX offloads**: IPv4 header checksum when the device supports raw IP checksum
  offload.
* **TX offloads**: IPv4, TCP and UDP checksum when the device supports it, and
  TCP segmentation offload (TSO) when the device supports it and the scatter
  gather list is long enough for a 64 KB packet.
* **RSS** when the device supports RSS for raw packet queues. The key and the
  indirection table can be set at start and at runtime (``device
  set-rss-config``).
* **Interrupt mode** for RX queues.
* **MAC filtering** with flow steering rules: primary MAC address, additional
  unicast addresses, promiscuous mode and multicast reception.
* **MTU**: the maximum frame size can be changed when the port has a kernel
  network interface, it is limited by the maximum MTU of that interface.
* **Buffer chaining**: receive in up to five chained buffers, transmit with up
  to 32 scatter gather entries. Packets over the limit are dropped and counted.
* **Module EEPROM** (``show hardware-interfaces <name> eeprom``) through the
  kernel network interface.
* **Error recovery**: a completion error resets the affected queue.

Not supported:

* Taking the link down when the port is stopped (the kernel driver owns the
  link).
* Secondary interfaces and flow offload rules.
* Changing the link speed from VPP.
* InfiniBand link layer ports.

Counters
========

The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``buffer allocation failed``
     - the RX queue could not be refilled
   * - ``ibv post recv failed``
     - posting receive work requests failed
   * - ``ibv poll cq failed``
     - polling a completion queue failed
   * - ``receive completion error, queue reset``
     - a receive completion reported an error and the queue was reset
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``buffer chain too long``
     - the packet needs more scatter gather entries than allowed
   * - ``ibv post send failed``
     - posting a send work request failed
   * - ``tx completion error, queue reset``
     - a send completion reported an error and the queue was reset

Caveats
=======

* The kernel interface of the port must be up for the link to be active.
* The kernel driver and VPP share the device. Do not unload the kernel driver
  and do not change the settings VPP relies on from the kernel side while VPP
  runs.
* If both ``mlx5`` and ``ibverbs`` match a Mellanox device and no driver is
  named, the first registered driver is used. Always name the driver.
* Port numbers start at 1.
* Features depend on what the RDMA device and its kernel driver report; check
  ``show device`` for the capabilities that were detected.

Debugging
=========

* ``show device <device-id>`` shows the detected RDMA capabilities and the port
  and queue state.
* ``rdma link show`` and ``ibv_devinfo -v`` verify the RDMA device and the port
  state.
* Raise the log level with ``logging { class ibverbs { level debug } class dev {
  level debug } }``.
* Typical errors: ``cannot open verbs device`` (no RDMA device, ``ib_uverbs``
  not loaded, no permission), ``ibv_add_port: no queues``,
  ``ibv_create_wq failed`` and ``ibv_reg_mr failed`` (device or resource
  limits, check the locked memory limit with ``ulimit -l``),
  ``completion error status`` (a queue was reset).
* Packets are traced with ``trace add <interface-name>-rx 10``.
