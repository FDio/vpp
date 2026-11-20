.. _drv_virtio_net_pci:

==========================================================
Virtio network device (virtio-net-pci) native driver
==========================================================

Overview
========

The ``virtio-net-pci`` driver is a native VPP driver for *virtio 1.x* (modern)
network devices on the PCI bus, the paravirtualized NIC offered by QEMU/KVM
and other hypervisors. It maps the virtio PCI capabilities of the device
directly, sets up the virtqueues and runs the receive and transmit data path in
VPP.

The driver supports:

* split and packed virtqueues,
* mergeable receive buffers and indirect TX descriptors,
* the control virtqueue: RX mode (promiscuous), primary MAC address, the MAC
  filter table, the number of queue pairs and the RSS configuration,
* multiple queue pairs and RSS,
* TX checksum and TCP segmentation offload, and handling of the checksum and
  GSO information of received packets,
* interrupt mode, using MSI-X vectors (one per RX thread) or INTx when the
  device has fewer vectors,
* link state from the device status and the MTU from the device configuration,
* DMA with virtual addresses when the device uses the platform IOMMU
  (``VIRTIO_F_ACCESS_PLATFORM``).

The driver is built on the :ref:`dev_framework` and registers on the ``pci``
bus under the name ``virtio-net-pci``. It creates one Ethernet port (port
``0``) per virtio device.

Supported devices
=================

The driver attaches to PCI vendor ``1af4`` (Red Hat / virtio) and the
following device ids:

======== ====================================================
PCI id   Description
======== ====================================================
``1041`` Virtio network device (modern, virtio 1.x)
``1000`` Virtio network device (transitional device id)
======== ====================================================

The device must offer ``VIRTIO_F_VERSION_1`` (virtio 1.x) and
``VIRTIO_NET_F_MAC``. A legacy (virtio 0.9) only device is refused with ``not
supported``. When using QEMU, give the NIC ``disable-legacy=on``, or use a
modern QEMU machine type, to get a virtio 1.x device.

Prerequisites
=============

* Bind the virtio device to ``vfio-pci`` in the guest before starting VPP, for
  example:

  .. code-block:: console

     # modprobe vfio-pci
     # echo vfio-pci > /sys/bus/pci/devices/0000:00:04.0/driver_override
     # echo 0000:00:04.0 > /sys/bus/pci/devices/0000:00:04.0/driver/unbind
     # echo 0000:00:04.0 > /sys/bus/pci/drivers_probe

  Leave the management NIC of the guest (the one used for ssh) with the kernel
  ``virtio_net`` driver.

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

   A virtio device only goes through the IOMMU when it offers
   ``VIRTIO_F_ACCESS_PLATFORM`` and the hypervisor emulates an IOMMU for the
   guest. Otherwise virtio bypasses the IOMMU, even under VFIO, and the driver
   uses physical addresses. With QEMU on x86_64, add ``-device
   intel-iommu,intremap=on,caching-mode=on`` (with ``-machine
   q35,kernel-irqchip=split``) and ``iommu_platform=on,ats=off`` to the
   ``virtio-net-pci`` device.

* If the guest has no (virtual) IOMMU, ``vfio-pci`` can be used in the unsafe
  no-IOMMU mode, for testing only:
  ``echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode``.
* Huge pages in the guest, as for any VPP deployment.

Configuration
=============

Sample ``startup.conf``:

.. code-block:: text

   devices {
     dev pci/0000:00:04.0 {
       driver virtio-net-pci
       args 'packed=on rss=on gso=on'
       port 0 {
         name vnet0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 256
         tx-queue-size 256
       }
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0000:00:04.0 driver virtio-net-pci args packed=on
   vpp# device create-interface pci/0000:00:04.0 port 0 name vnet0
   vpp# set interface state vnet0 up

The number of RX queues and TX queues of a port must be equal (they are
virtqueue pairs), the port does not start otherwise. The generic ``dev`` and
``port`` options are described in :ref:`dev_framework`.

Arguments
=========

Device arguments (``args '...'`` in the ``dev`` section or ``device attach``).
All of them only take effect if the device offers the feature, they can only
turn a feature off (or, for ``mac_filter``, on):

``packed`` (boolean, default on)
   Use packed virtqueues when the device offers them. Turn it off to use split
   virtqueues.

``indirect`` (boolean, default on)
   Use indirect descriptors for TX when the device offers them.

``rss`` (boolean, default on)
   Use RSS when the device offers it (a hash key of at least 40 bytes).

``gso`` (boolean, default on)
   Use TCP segmentation offload when the device offers it. This covers
   transmit offload and receive of GSO packets.

``checksum_offload`` (boolean, default on)
   Use the transport checksum offloads when the device offers them. Turning it
   off also turns off ``gso``.

``mac_filter`` (boolean, default off)
   Rely on the device to filter on the destination MAC address. The device must
   offer the control RX feature. When off, the port does not advertise the MAC
   filter capability.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - Queue pairs
     - up to the number the device offers (``max_virtqueue_pairs``), with
       multiqueue; one pair otherwise
   * - RX and TX queue size
     - 64 up to the size offered by the device (at most 4096), power of two,
       default 256
   * - Maximum frame size
     - the device MTU plus the Ethernet header and FCS if the device reports an
       MTU, and at most 127 buffers with mergeable receive buffers or one
       buffer without

Supported features
==================

* **Link state** from the virtio device status, polled every 0.5 s while the
  port is started. If the device does not offer the status feature the link is
  always up. The link is also reported down when the device asks for a reset or
  reports a failure.
* **Link down on stop.** Not applicable: the link of a virtual device cannot be
  controlled from the guest.
* **TX offloads** (when the device offers checksum offload): TCP and UDP
  checksum, and TCP segmentation offload (TSO, if the device offers both IPv4
  and IPv6 TSO).
* **RX offloads**: the checksum and GSO information in the virtio header of
  received packets is converted to buffer flags. GSO reception needs mergeable
  receive buffers.
* **RSS** when offered by the device, with a 40 byte hash key and an
  indirection table of up to 128 entries (a power of two, limited by the
  device). The key and the table can be set at start (``rss-key``,
  ``rss-lut``) and at runtime (``device set-rss-config``). Needs the control
  virtqueue.
* **Multiple queue pairs** through the control virtqueue.
* **Interrupt mode** for RX queues. With MSI-X it needs one vector per VPP
  thread plus one; if the device has fewer vectors a shared INTx interrupt is
  used when available.
* **MAC filtering** (with ``mac_filter=on``): the primary MAC address (changed
  through the control virtqueue, which needs the MAC address control feature),
  up to 64 additional unicast addresses in the filter table, and promiscuous
  mode.
* **MTU**: the maximum frame size can be changed while the port is stopped.
* **Mergeable receive buffers**, packed and split rings, indirect TX
  descriptors, as described above.

Not supported:

* Legacy (virtio 0.9) devices.
* Secondary interfaces and flow offload.
* UDP segmentation offload and IPv4 header checksum offload on RX and TX.
* TX of packets which need more than 127 buffers.

Counters
========

The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Counter
     - Meaning
   * - ``ring-full`` (TX)
     - no free TX slots, packets dropped
   * - ``invalid-packet`` (TX)
     - the TX packet exceeds the frame size or requests an offload the device
       does not support
   * - ``alloc-failed`` (RX)
     - RX buffer allocation failed
   * - ``invalid-packet`` (RX)
     - the device delivered an invalid packet

Caveats
=======

* Only virtio 1.x devices work. The negotiated features depend on what the
  hypervisor offers; ``show device`` lists the features that were offered and
  negotiated.
* Without ``VIRTIO_NET_F_MRG_RXBUF`` each received frame must fit one VPP buffer.
  The port refuses to start if the VPP buffer size is smaller than the maximum
  frame size.
* RX queues and TX queues must be created in equal numbers.
* The device is reset when the port stops. The link state is reported again on
  the next start.
* ``mac_filter=on`` relies on the hypervisor to filter by MAC address. Leave it
  off if you need to receive frames for other addresses without configuring
  them.
* When the virtual machine runs without an IOMMU or the device does not offer
  ``VIRTIO_F_ACCESS_PLATFORM``, VPP uses physical addresses (see the note
  above) and memory protection is not enforced.

Debugging
=========

* ``show device pci/0000:00:04.0`` shows the features the device offered and
  which of them were negotiated, the device status, the number of virtqueues,
  whether the packed ring, indirect descriptors and the control queue are in use
  and the device MTU, plus the ports and the queues. Add ``debug`` for more.
* ``show device counters all pci/0000:00:04.0`` shows all counters.
* Raise the log level with ``logging { class virtio-net-pci { level debug }
  class dev { level debug } }``.
* Typical errors: ``not supported`` at attach (a legacy only device, or the
  device does not offer ``VIRTIO_NET_F_MAC``), ``device reset timeout`` (the
  hypervisor did not complete a reset), ``invalid data`` (the device has
  malformed virtio PCI capabilities), ``buffer allocation failure`` at start (not
  enough buffers for the RX queue sizes).
* Packets are traced with ``trace add <interface-name>-rx 10``.

Testing in a virtual machine
============================

The ``extras/scripts/test-vm`` script builds a minimal, virtio-only guest
kernel and initramfs which runs VPP inside QEMU/KVM with the host root
filesystem shared into the guest. ``-n <n>`` adds data ``virtio-net-pci``
devices attached to host tap interfaces and ``-i`` emulates an IOMMU (Intel
IOMMU on x86_64, SMMUv3 on aarch64) and sets ``iommu_platform=on`` on the
NICs. See the header of the script for its options.
