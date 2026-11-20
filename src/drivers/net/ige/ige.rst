.. _drv_ige:

=====================================================
Intel Gigabit Ethernet (ige) native driver
=====================================================

Overview
========

The ``ige`` driver is a native VPP driver for the Intel I211, I225 and I226
family of Gigabit and 2.5 Gigabit Ethernet controllers, which are found on
many embedded boards, mini PCs and workstation motherboards. The driver
programs the controller directly and manages the integrated PHY through the
MDIO interface of the controller.

The driver is built on the :ref:`dev_framework`. It registers on the ``pci``
bus under the name ``ige`` and creates one Ethernet port (port ``0``) per
PCI function.

Supported devices
=================

The driver attaches to PCI vendor ``8086`` and the following device ids:

======== ======================================== ===========
PCI id   Description                              Max speed
======== ======================================== ===========
``1539`` Intel Ethernet Controller I211           1 Gbit/s
``15f2`` Intel Ethernet Controller I225-LM        2.5 Gbit/s
``15f3`` Intel Ethernet Controller I225-V         2.5 Gbit/s
``0d9f`` Intel Ethernet Controller I225-IT        2.5 Gbit/s
``125b`` Intel Ethernet Controller I226-LM        2.5 Gbit/s
``125c`` Intel Ethernet Controller I226-V         2.5 Gbit/s
``125d`` Intel Ethernet Controller I226-IT        2.5 Gbit/s
======== ======================================== ===========

The I211 uses its internal PHY. The I225 and I226 use a GPY211 PHY. Devices
with another PHY are refused at attach time (``Unsupported phy``).

Prerequisites
=============

* Bind the device to ``vfio-pci`` before starting VPP:

  .. code-block:: console

     # modprobe vfio-pci
     # echo vfio-pci > /sys/bus/pci/devices/0000:03:00.0/driver_override
     # echo 0000:03:00.0 > /sys/bus/pci/devices/0000:03:00.0/driver/unbind
     # echo 0000:03:00.0 > /sys/bus/pci/drivers_probe

* VPP packet buffers with a data size of at least 1024 bytes
  (``rx buffer data size ... is too small (min 1024)`` otherwise).

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
     dev pci/0000:03:00.0 {
       driver ige
       port 0 {
         name lan0
         num-rx-queues 2
         num-tx-queues 2
         rx-queue-size 1024
         tx-queue-size 1024
       }
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0000:03:00.0 driver ige
   vpp# device create-interface pci/0000:03:00.0 port 0 name lan0
   vpp# set interface state lan0 up

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
     - 512 to 32768 descriptors, power of two, default 512
   * - Maximum frame size
     - 9728 bytes (including FCS)

Supported features
==================

* **Link state and speed** polled every second while the port is started. The
  controller negotiates 10, 100 and 1000 Mbit/s, and 2.5 Gbit/s on I225 and
  I226. The link speed can be limited at runtime (``set interface link-speed
  <interface> <speed-kbps>``).
* **Link down on stop.** The PHY is powered down when the port is stopped, so the
  link partner sees the link go down.
* **RX offloads**: IPv4 header checksum and L4 (TCP/UDP) checksum.
* **TX offloads**: IPv4, TCP and UDP checksum and TCP segmentation offload
  (TSO). UDP segmentation offload is not advertised.
* **RSS** with a 40 byte hash key and a 128 entry lookup table. The key and the
  table can be set at start (``rss-key``, ``rss-lut``) and at runtime
  (``device set-rss-config``); the key and the table must have exactly these
  sizes. A default key is programmed.
* **Interrupt mode** for RX queues when the device has at least one MSI-X vector
  more than the number of VPP threads. Otherwise the capability is disabled and
  a notice is logged.
* **MAC filtering**: the primary MAC address is programmed at start and can be
  changed at runtime, additional unicast addresses are supported in a limited
  table (an attempt to add an address when the table is full fails and is
  logged), promiscuous mode is supported and multicast is received.
* **MTU**: the maximum frame size can be changed.
* **Buffer chaining**: chained buffers are received and transmitted, a TX
  packet which needs more descriptors than allowed is dropped and counted.
* **Statistics**: hardware counters are read every three seconds (disable with
  the ``no-stats`` device flag).

Not supported:

* UDP segmentation offload.
* Secondary interfaces and flow offload.
* Other Intel gigabit controllers, only the device ids listed above are
  supported.
* Time-sensitive networking features (TSN, PTP timestamping, launch time).

Counters
========

Interface and device counters come from the hardware statistics registers
(``show device counters``). The nodes have these error counters (``show
errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``buffer chain too long``
     - the packet needs more descriptors than allowed, packet dropped
   * - ``buffer allocation failed``
     - the RX ring could not be refilled
   * - ``receive descriptor error``
     - the hardware flagged an error in an RX descriptor, packet dropped

Caveats
=======

* The device must not be in use by the Linux ``igc`` or ``igb`` driver while VPP
  uses it.
* Access to the PHY is slow. The driver logs a warning when a PHY register
  access takes unusually long. Do not poll PHY registers from scripts.
* The minimum ring size is 512 descriptors.
* A port stays down until the interface is set up (the PHY is powered down
  while the port is stopped).
* The driver acquires the PHY through the software/firmware synchronization
  register before accessing it. A ``sw_fw_sync ownership timeout`` error means
  the firmware did not release the PHY.

Debugging
=========

* ``show device <device-id>`` shows the device type, the PHY and the port and
  queue state.
* ``show device counters all <device-id>`` shows all counters.
* Raise the log level with ``logging { class ige { level debug } class dev {
  level debug } }`` to trace the PHY and reset sequence.
* Typical errors: ``reset timeout`` (the controller did not come out of reset,
  power cycle), ``failed to read PHY ID`` and ``phy read timeout`` (PHY
  access problem), ``Unsupported phy`` (unsupported board variant),
  ``no free RX queues`` (more queues requested than the device has).
* Packets are traced with ``trace add <interface-name>-rx 10``.
