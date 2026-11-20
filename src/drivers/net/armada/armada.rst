.. _drv_armada:

==============================================================
Marvell Armada Packet Processor (mvpp2) native driver
==============================================================

Overview
========

The ``mvpp2`` driver is a native VPP driver for the Marvell *Packet Processor
v2* (PP2) network engine found in the Marvell Armada 7K/8K family of SoCs
(the ``marvell,armada-7k-pp22`` device tree compatible). It does not require
the external Marvell Usermode SDK (MUSDK) library.

It is a hybrid driver. VPP maps the PP2 register regions through the Linux
UIO platform driver and runs the data path (receive and transmit queues, buffer
pools, classifier and RSS) itself. The Linux ``mvpp2`` network interface of
each port is kept as the control plane: the kernel interface owns the PHY, SFP
and link management (phylink), and VPP uses it to bring the link up and down
and to program MAC addresses and multicast filters.

The driver is built on the :ref:`dev_framework` and registers on the
``platform`` bus under the name ``mvpp2``. It creates one Ethernet port for
every PP2 port which has a kernel network interface.

Supported devices
=================

The driver attaches to platform devices whose device tree node is compatible
with ``marvell,armada-7k-pp22``. The device id is ``platform/<name>`` where
``<name>`` is the Linux platform device name of the PP2 instance, for example
``platform/f2000000.ethernet``. List the available names with:

.. code-block:: console

   $ ls /sys/bus/platform/devices | grep ethernet
   f2000000.ethernet

Prerequisites
=============

The driver uses the kernel's ``uio_pdrv_genirq`` platform driver to map the
PP, MSPG, and CM3 register regions. The device tree must provide a UIO node
with ``reg`` and ``reg-names`` entries for these regions.

The compatible string is stored as a null-separated device-tree property. It
can be checked through sysfs as follows (adjust the platform device name if
needed):

.. code-block:: console

   $ tr '\0' '\n' < /sys/bus/platform/devices/f2000000.uio_pp_0/of_node/compatible
   generic-uio

Pass that string to ``uio_pdrv_genirq`` when loading the module:

.. code-block:: console

   $ sudo modprobe -r mv_pp_uio
   $ sudo modprobe uio_pdrv_genirq of_id=generic-uio

To make the setting persistent, add the following to a file under
``/etc/modprobe.d/``:

.. code-block:: text

   options uio_pdrv_genirq of_id=generic-uio

The bound driver and exported UIO maps can be verified through sysfs:

.. code-block:: console

   $ DEVICE_PATH=/sys/bus/platform/devices/f2000000.uio_pp_0
   $ basename "$(readlink -f $DEVICE_PATH/driver)"
   uio_pdrv_genirq
   $ grep . $DEVICE_PATH/uio/uio*/maps/map*/name
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map0/name:pp
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map1/name:mspg
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map2/name:cm3

The out-of-tree ``mv_pp_uio`` and ``musdk_cma`` kernel modules are not
required.

Other requirements:

* The Linux ``mvpp2`` network interface of every port that VPP should use must
  exist (the port is skipped, with a warning, when no kernel interface or MAC
  address can be found for it).
* VPP needs one hardware interface (HIF) for each of its threads. The PP2 has
  nine HIFs, so at most nine VPP threads (the main thread included) can use the
  driver. Attaching fails with ``no enough HIFs`` otherwise.
* All VPP buffer pools must be in the same 4 GB address window of the PP2
  buffer manager (see ``force_bppe_addr`` below).

Configuration
=============

Sample ``startup.conf``:

.. code-block:: text

   devices {
     dev platform/f2000000.ethernet {
       port 1 {
         name port1
         num-rx-queues 2
         num-tx-queues 2
         rx-queue-size 1024
         tx-queue-size 1024
         args 'rss_hash=5-tuple'
       }
     }
   }

The port id is the PP2 port number from the device tree. The driver knows the
ports ``0``, ``1`` and ``2`` of each PP2 instance.

At runtime:

.. code-block:: text

   vpp# device attach platform/f2000000.ethernet driver mvpp2
   vpp# device create-interface platform/f2000000.ethernet port 1 name port1 args rss_hash=5-tuple
   vpp# set interface state port1 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`.

Arguments
=========

Device arguments (``args '...'`` in the ``dev`` section or ``device attach``):

``force_bppe_addr`` (boolean, default off)
   Retain the external BPPE arrays and change the global BPPE address-high
   register to match the first VPP pool allocation. All later VPP pools must be
   allocated in that same 4 GB window. This option also changes the address
   window used by kernel-owned pools and must only be used when no kernel-owned
   BPPE pool remains active.

   .. code-block:: text

      devices {
        dev platform/f2000000.ethernet {
          args 'force_bppe_addr=on'
          port 1 { name port1 }
        }
      }

Port arguments (``args '...'`` in the ``port`` section or ``device
create-interface``):

``rss_hash`` (enum ``2-tuple`` or ``5-tuple``, default ``5-tuple``)
   Fields used for the RSS hash when the port has more than one RX queue:
   source and destination IP address (``2-tuple``), or additionally the
   protocol and the L4 ports (``5-tuple``). With one RX queue RSS is not used.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX queues
     - up to 4 per port
   * - TX queues
     - up to 4 per port
   * - RX and TX queue size
     - 32 to 8192 descriptors, power of two, default 512
   * - Maximum frame size
     - 10240 bytes

Supported features
==================

* **Link state, speed and duplex** read from the MAC (GOP) every 0.5 s while the
  port is started.
* **Link down on stop.** The kernel network interface is set down when the port
  is stopped and up when it is started, so the link partner sees the port
  go down.
* **TX offloads**: IPv4 header checksum.
* **RSS** across the RX queues, using the hash configured by ``rss_hash``. The
  hash and the table are programmed at start; changing the key or lookup table
  at runtime is not supported.
* **MAC filtering**: the primary MAC address, additional unicast addresses,
  multicast and promiscuous mode, programmed through the kernel interface and
  the PP2 parser.
* **MTU**: the maximum frame size can be changed.
* **Hardware classifier and statistics**: the classifier counters are collected
  into the port counters.
* **Transmit scheduling** with weighted round robin between TX queues.
* **Flow control**: RX pause frames are disabled on start through the kernel
  interface.

Not supported:

* RX offloads: IP and L4 checksum validation is not advertised.
* TCP and UDP checksum offload on TX and segmentation offload.
* RX interrupt mode, the queues are polled.
* Setting the link speed from VPP.
* Secondary interfaces and flow offload rules.
* Runtime changes of the RSS key and lookup table.

Counters
========

``show device counters`` shows the port counters:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``rx packets``, ``tx packets``
     - packets received and transmitted
   * - ``rx drop fullQ``, ``rx drop early``, ``rx drop BM``
     - packets dropped on receive because the queue is full, by early drop, or
       because the buffer manager has no buffer
   * - ``cls lkp hit``, ``cls flow hit``, ``cls4 hit``
     - classifier lookup, flow and C4 hits
   * - ``rx drop MC overflow``
     - multicast overflow drops
   * - ``tx drop fullQ``, ``tx drop early``, ``tx drop BM``, ``tx drop BM MC``
     - packets dropped on transmit for the same reasons

The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``buffer alloc error``
     - the RX path could not allocate a buffer
   * - ``no free tx slots``
     - TX ring full, packets dropped

Caveats
=======

* The kernel ``mvpp2`` driver must stay loaded: VPP depends on its network
  interface for link control and MAC programming.
* At most nine VPP threads can be used because of the number of PP2 hardware
  interfaces.
* ``force_bppe_addr`` changes the address window used by the kernel as well and
  must only be used when the kernel has no active buffer pool.
* VPP buffers must be allocated in the buffer manager address window. The driver
  refuses pools whose DMA address differs from the window.

Debugging
=========

* ``show device platform/f2000000.ethernet`` shows the PP2 device, the ports,
  queues and buffer state.
* ``show device counters all platform/f2000000.ethernet`` shows all counters.
* Raise the log level with ``logging { class armada { level debug } class dev {
  level debug } }``. The ``armada`` log class has subclasses for the port,
  counters, RSS, netdev and more.
* Typical errors: ``platform MMIO mapping failed`` (the UIO maps are missing,
  check the UIO prerequisites above), ``no enough HIFs`` (too many VPP
  threads), ``failed to get netdev for port`` (no Linux interface for the
  port), ``pool ... DMA address differs from existing VPP BPPE window`` (see
  ``force_bppe_addr``), ``Out of TCAM Entries`` (the classifier is full).
* Packets are traced with ``trace add <interface-name>-rx 10``.
