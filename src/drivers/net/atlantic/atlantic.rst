.. _drv_atlantic:

==========================================================
Marvell Scalable mGig (atlantic) native driver
==========================================================

Overview
========

The ``atlantic`` driver is a native VPP driver for the Marvell (formerly
Aquantia) *Scalable mGig* family of multi-gigabit Ethernet controllers, the
AQC113, AQC114, AQC115 and AQC116 (the second generation *Atlantic 2*
architecture). It programs the device registers directly, controls the PHY
and link through the firmware interface and implements the receive and
transmit data path in VPP.

The driver is built on the :ref:`dev_framework`. It registers on the ``pci``
bus under the name ``atlantic`` and creates one Ethernet port (port ``0``) per
PCI function.

Supported devices
=================

The driver attaches to PCI vendor ``1d6a`` (Aquantia) and the following
device ids:

======== ===========================================
PCI id   Description
======== ===========================================
``00c0`` Marvell Scalable mGig AQC113DEV
``04c0`` Marvell Scalable mGig AQC113
``94c0`` Marvell Scalable mGig AQC113CS
``93c0`` Marvell Scalable mGig AQC114CS
``14c0`` Marvell Scalable mGig AQC113C
``12c0`` Marvell Scalable mGig AQC115C
``34c0`` Marvell Scalable mGig AQC113CA
``11c0`` Marvell Scalable mGig AQC116C
======== ===========================================

The driver requires firmware with interface version 1. Devices with another
firmware interface version are refused at attach time with ``unsupported FW
interface version``.

Prerequisites
=============

* Bind the device to ``vfio-pci`` before starting VPP:

  .. code-block:: console

     # modprobe vfio-pci
     # echo vfio-pci > /sys/bus/pci/devices/0000:05:00.0/driver_override
     # echo 0000:05:00.0 > /sys/bus/pci/devices/0000:05:00.0/driver/unbind
     # echo 0000:05:00.0 > /sys/bus/pci/drivers_probe

* VPP packet buffers with a data size of at least 1024 bytes. A smaller buffer
  data size is refused (``rx buffer data size ... is too small (min 1024)``).

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
     dev pci/0000:05:00.0 {
       driver atlantic
       port 0 {
         name mgig0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 1024
         tx-queue-size 1024
       }
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0000:05:00.0 driver atlantic
   vpp# device create-interface pci/0000:05:00.0 port 0 name mgig0
   vpp# set interface state mgig0 up

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
   * - RX queues
     - up to 4
   * - TX queues
     - up to 4
   * - RX and TX queue size
     - 64 to 8184 descriptors, default 512
   * - Maximum frame size
     - 16352 bytes (including FCS)

Supported features
==================

* **Link state, speed and duplex** read from the firmware once a second while
  the port is started. The supported speeds are reported by the firmware and
  the link speed can be restricted at runtime (``set interface link-speed
  <interface> <speed-kbps>``).
* **Link down on stop.** The firmware link is disabled when the port is stopped,
  so the link partner sees the port go down.
* **RX offloads**: IPv4 header checksum and L4 (TCP/UDP) checksum.
* **TX offloads**: IPv4, TCP and UDP checksum and TCP segmentation offload
  (TSO). UDP segmentation offload is not advertised.
* **RSS** with a 40 byte hash key and a 64 entry lookup table. The key and the
  table can be set at start (``rss-key``, ``rss-lut``) and at runtime
  (``device set-rss-config``). The key must be exactly 40 bytes long and the
  table exactly 64 entries long, entries must refer to enabled RX queues. If
  no table is given, the queues are spread round robin.
* **Interrupt mode** for RX queues, available when the device has at least one
  MSI-X vector more than the number of VPP threads. Otherwise the capability is
  disabled and a notice is logged.
* **MAC filtering**: the primary MAC address is programmed at start and can be
  changed at runtime. Additional unicast addresses are supported in the
  limited number of L2 filter slots of the device. Promiscuous mode is
  supported and multicast is received.
* **MTU**: the maximum frame size can be changed.
* **Buffer chaining**: chained buffers are received and transmitted. A TX
  packet with a chain longer than the descriptor limit is dropped and counted.
* **Statistics**: counters are read from the firmware once a second (disable
  with the ``no-stats`` device flag). A failure to read the statistics or the
  link status is logged once and the recovery is logged too.

Not supported:

* UDP segmentation offload.
* Secondary interfaces and flow offload.
* More than four queues (hardware limit of the supported devices).
* Older generations of the Aquantia controllers (AQC107, AQC108, AQC109
  and others) which use another firmware interface.

Counters
========

Interface and device counters (``show device counters``) come from the
firmware statistics. The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``no free TX slots``
     - TX ring full, packets dropped
   * - ``packet dropped: TX chain too long``
     - the packet needs more descriptors than allowed
   * - ``buffers dropped due to mac_err/dma_err``
     - the hardware flagged a MAC or DMA error in an RX descriptor
   * - ``buffer allocation failed``
     - the RX ring could not be refilled

Caveats
=======

* The device must not be in use by the Linux ``atlantic`` driver while VPP uses
  it.
* RX buffers must have a data size of at least 1024 bytes.
* A port stays down until the interface is set up (the link is disabled while
  the port is stopped).
* The driver does not register a description string, so ``show device drivers``
  shows an empty description column for it.

Debugging
=========

* ``show device <device-id>`` shows the firmware version, the interface version
  and the filter capabilities the driver read at init, plus the port and queue
  state.
* ``show device counters all <device-id>`` shows all counters.
* Raise the log level with ``logging { class atlantic { level debug } class dev
  { level debug } }``.
* Typical errors: ``FW reboot timeout`` and ``FW restart timeout`` (the
  firmware does not come up after reset, power cycle the card),
  ``interface buffer read timeout`` (the firmware mailbox does not answer),
  ``no free RX queues`` and ``no free TX queues`` (more queues requested than
  the device has), ``unsupported FW interface version`` (see above).
* Packets are traced with ``trace add <interface-name>-rx 10``.
