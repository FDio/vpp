.. _drv_ice:

=====================================================
Intel E810, E830 and E835 (ice) native driver
=====================================================

Overview
========

The ``ice`` driver is a native VPP driver for the Intel Ethernet 800 series
controllers (E810, E830 and E835). It is a physical function (PF) driver: it
resets and configures the PF itself, talks to the firmware through the admin
queue, and programs the queues, the MAC filter, the RSS configuration and the
PHY directly. It does not use DPDK and does not need the Linux ``ice`` driver
to be loaded for the device.

The driver is built on the :ref:`dev_framework`. It registers on the ``pci``
bus under the name ``ice`` and creates one Ethernet port for every PCI
function it attaches.

Supported devices
=================

The driver attaches to PCI vendor ``8086`` and the following device ids:

======== ================= ===============================
PCI id   Family            Description
======== ================= ===============================
``1591`` E810              Intel E810-C backplane
``1592`` E810              Intel E810-C QSFP
``1593`` E810              Intel E810-C SFP
``1599`` E810              Intel E810-XXV backplane
``159a`` E810              Intel E810-XXV QSFP
``159b`` E810              Intel E810-XXV SFP
``1248`` E835              Intel E835CC backplane
``1249`` E835              Intel E835CC QSFP56
``124a`` E835              Intel E835CC SFP
``1261`` E835              Intel E835C backplane
``1262`` E835              Intel E835C QSFP
``1263`` E835              Intel E835C SFP
``1265`` E835              Intel E835-L backplane
``1266`` E835              Intel E835-L QSFP
``1267`` E835              Intel E835-L SFP
``12d1`` E830              Intel E830-CC backplane
``12d2`` E830              Intel E830-CC QSFP56
``12d3`` E830              Intel E830-CC SFP
``12d5`` E830              Intel E830-C backplane
``12d8`` E830              Intel E830-C QSFP
``12da`` E830              Intel E830-C SFP
``12dc`` E830              Intel E830-L backplane
``12dd`` E830              Intel E830-L QSFP
``12de`` E830              Intel E830-L SFP
======== ================= ===============================

Virtual functions of these devices are handled by the :ref:`drv_iavf` driver
(the ``1889`` adaptive virtual function id).

Prerequisites
=============

* The device is accessed from user space through ``vfio-pci``. Bind it to
  ``vfio-pci`` before starting VPP (or before ``device attach``), for example:

  .. code-block:: console

     # modprobe vfio-pci
     # echo 0000:18:00.0 > /sys/bus/pci/devices/0000:18:00.0/driver/unbind
     # echo vfio-pci > /sys/bus/pci/devices/0000:18:00.0/driver_override
     # echo 0000:18:00.0 > /sys/bus/pci/drivers_probe

  All devices which share an IOMMU group must be bound to ``vfio-pci``
  together.
* The driver checks that the DMA address range of the device covers the packet
  buffer memory.
* Huge pages and a buffer pool on the NUMA node of the device, as for any VPP
  deployment.
* The ``ice`` driver must be part of the build (``VPP_DRIVERS``) and its
  shared object must be present in the ``vpp_drivers`` directory. ``show device
  drivers`` lists it when it was loaded.

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

   cpu {
     main-core 1
     corelist-workers 2-5
   }

   devices {
     dev pci/0000:18:00.0 {
       driver ice
       port 0 {
         name eth0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 1024
         tx-queue-size 1024
         rx-queue-assignment queue-per-thread
       }
     }
   }

The device can also be attached at runtime:

.. code-block:: text

   vpp# device attach pci/0000:18:00.0 driver ice
   vpp# device create-interface pci/0000:18:00.0 port 0 name eth0
   vpp# set interface state eth0 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`. The ``ice`` driver has one port per device (port ``0``).

Port option
-----------

``set device driver ice port-option <device-id> option <0-15>``
   Select the port option (breakout configuration) of the device. The change
   is applied by the firmware only after a power cycle or an EMP reset.

Arguments
=========

The driver defines no driver, device or port arguments. All configuration is
done through the generic framework options.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX queue size
     - 256 to 4096 descriptors, power of two, default 512
   * - TX queue size
     - 256 to 4096 descriptors, power of two, default 512
   * - RX queues
     - limited by the hardware and by 64 (the size of the RSS lookup table)
   * - TX queues
     - limited by the hardware

Supported features
==================

* **Link speeds** reported by the firmware. The speed can be limited at runtime
  (``set interface link-speed <interface> <speed-kbps>``); the driver checks that the PHY supports
  the requested speed.
* **Link state** polled every 0.5 s while the port is started. The link is
  administratively disabled when the port is stopped and stays down after init
  until the port is started, so the link partner sees it go down.
* **RX offloads**: IPv4 header checksum.
* **TX offloads**: IPv4, TCP and UDP checksum. TCP and UDP segmentation offload
  (GSO) is advertised when the buffer size allows packets of 64 KB.
* **RSS** with a 40 byte hash key and a 64 entry lookup table. The key and the
  table are configurable at start (``rss-key``, ``rss-lut``) and at runtime
  (``device set-rss-config``). RSS is programmed for IPv4 and IPv6 with TCP, UDP
  and SCTP.
* **Interrupt mode** for RX queues. It is enabled when the device provides at
  least one MSI-X vector more than the number of VPP threads. Otherwise the
  capability is disabled and a notice is logged.
* **MAC filtering**: the primary MAC address is programmed at start, it can be
  changed at runtime, additional unicast addresses and promiscuous mode are
  supported. Multicast is received.
* **MTU**: the maximum frame size can be changed while the port is stopped. It
  is limited by the hardware maximum and by five RX buffers (the driver
  receives a frame in at most five chained buffers).
* **Buffer chaining**: up to eight descriptors per TX packet, up to 32 for GSO
  packets. Packets over the limit are dropped and counted.
* **SFP and QSFP module EEPROM** (``show hardware-interfaces <name> eeprom``),
  including the paged QSFP upper memory.
* **Counters**: standard interface counters, VSI, port and MAC statistics and
  per priority statistics (see ``show device counters``).
* **Port option selection** (breakout mode) with ``set device driver ice
  port-option``.

Not supported:

* Secondary interfaces.
* Flow offload rules (RX flows).
* Virtual function management (SR-IOV). Use the Linux driver to create VFs.
* Hardware timestamping, DCB/PFC and other features not listed above.

Counters
========

``show device counters`` shows, per port, the VSI counters (unicast, multicast
and broadcast packets and bytes, discards and errors), the port level MAC
statistics (including frame size histograms, pause frames, CRC and length
errors) and the priority flow control counters.

The nodes have the following error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``buffer chain too long``
     - TX packet needs more descriptors than allowed, packet dropped
   * - ``buffer allocation failed``
     - the RX ring could not be refilled
   * - ``receive descriptor error``
     - the hardware reported an error in an RX descriptor, packet dropped

Caveats
=======

* The device must not be in use by the Linux ``ice`` driver while VPP uses it.
  Binding it back to the kernel driver after VPP has stopped works, but
  repeated unbind and bind cycles of hot-pluggable devices should be avoided.
* A port stays down until the interface is set up. This is intended and is
  visible on the link partner.
* Changing the maximum frame size requires the port to be stopped (set the
  interface down first), the request is refused while the port is started.
* RX interrupt mode needs spare MSI-X vectors (see above).
* Changing the port option takes effect only after a power cycle or an EMP
  reset of the card.
* Virtual functions are driven by the :ref:`drv_iavf` driver, not by this one.

Debugging
=========

* ``show device pci/0000:18:00.0`` shows the device, port and queue state and the
  firmware information the driver read at init. Add ``debug`` for more.
* ``show device counters all pci/0000:18:00.0`` shows all counters including zero
  ones.
* ``show hardware-interfaces eth0`` shows the interface view.
* ``show device driver ice phy`` is the first thing to check when the link does
  not come up. It shows the active PHY type, topology, media, the configured and
  default PHY configuration (FEC modes, pause, low power mode, link enable,
  autonegotiation) and the module qualification.
* ``show device driver ice aq`` dumps the admin queue state.
* ``show device driver ice capabilities`` dumps the device and function
  capabilities reported by the firmware.
* ``show device driver ice vsi`` dumps the VSI (virtual switch interface)
  configuration.
* ``show device driver ice rss`` dumps the RSS profiles and the lookup table.
* Increase the log level for the driver and the framework, for example
  ``logging { class ice { level debug } class dev { level debug } }`` in
  ``startup.conf`` and read the messages with ``show logging``. The ``ice`` log
  class has subclasses for the admin queue, the PHY and RSS.
* Common errors: ``unsupported PCI device`` (the device id is not in the table
  above), ``global reset timeout`` (the device is still resetting or in a bad
  state, try a PCI reset or a power cycle), ``BAR0 mapping failed`` (the device
  is not bound to ``vfio-pci``).
* Packets are traced with ``trace add <interface-name>-rx 10``.
