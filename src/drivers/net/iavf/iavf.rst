.. _drv_iavf:

==================================================
Intel Adaptive Virtual Function (iavf) driver
==================================================

Overview
========

The ``iavf`` driver is a native VPP driver for the Intel *Adaptive Virtual
Function* (AVF). It drives the SR-IOV virtual functions (VFs) of the Intel
X710, X722, E810 and E830 Ethernet controllers. A virtual function has no
control over the physical link or the PHY. All configuration which affects
the hardware beyond the VF itself (queues, MAC address, promiscuous mode,
RSS, link state) is requested from the physical function (PF) driver through
the *virtchnl* message protocol over the VF admin queue.

The driver is built on the :ref:`dev_framework` and registers on the ``pci``
bus under the name ``iavf``. It creates one Ethernet port (port ``0``) per
virtual function.

Supported devices
=================

======== =========================================
PCI id   Description
======== =========================================
``1889`` Intel Adaptive Virtual Function (E810 and E830 VFs, and other devices using the AVF id)
``154c`` Intel X710 Virtual Function
``37cd`` Intel X722 Virtual Function
======== =========================================

The PCI vendor id is ``8086``. The PF driver must support the virtchnl
protocol. The Linux ``ice`` and ``i40e`` drivers do.

Prerequisites
=============

* Create the VF on the host with the PF kernel driver and bind it to
  ``vfio-pci``:

  .. code-block:: console

     # echo 2 > /sys/class/net/enp24s0f0/device/sriov_numvfs
     # modprobe vfio-pci
     # echo vfio-pci > /sys/bus/pci/devices/0000:18:01.0/driver_override
     # echo 0000:18:01.0 > /sys/bus/pci/drivers/iavf/unbind
     # echo 0000:18:01.0 > /sys/bus/pci/drivers_probe

* Optionally set a MAC address, VLAN, trust or spoof checking for the VF on
  the PF (``ip link set <pf> vf <n> mac ...``). The VF uses the MAC address
  assigned by the PF as its default.
* VPP does not need the ``iavf`` Linux driver for the VF and must not share it
  with the kernel.

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
     dev pci/0000:18:01.0 {
       driver iavf
       args 'request_qpairs=4'
       port 0 {
         name vf0
         num-rx-queues 4
         num-tx-queues 4
         rx-queue-size 1024
         tx-queue-size 1024
       }
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0000:18:01.0 driver iavf args request_qpairs=4
   vpp# device create-interface pci/0000:18:01.0 port 0 name vf0
   vpp# set interface state vf0 up

The generic ``dev`` and ``port`` options are described in
:ref:`dev_framework`.

Arguments
=========

Device arguments (``args '...'`` in the ``dev`` section or ``args`` of
``device attach``):

``request_qpairs`` (uint32, 1 to 32, default: not set)
   Number of queue pairs to request from the PF. When the argument is not
   given the PF default allocation is used. The PF may grant fewer queue pairs
   than requested, the driver logs the number it got. On ``i40e`` the PF resets
   the VF as a part of the request and the driver waits for the reset to
   complete.

There are no driver level or port arguments.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - RX and TX queue size
     - 32 to 4096 descriptors, power of two, default 512
   * - Queues
     - up to 32, and not more than the PF granted to the VF

Supported features
==================

* **Link state and speed** reported by the PF through virtchnl link events,
  including the advanced link speed format.
* **RX offloads**: IPv4 header checksum and L4 (TCP/UDP) checksum.
* **TX offloads**: IPv4, TCP and UDP checksum, TCP segmentation offload (TSO)
  and UDP segmentation offload (USO, when the PF advertises it).
* **RSS** when the PF provides RSS (the key must be at least 52 bytes and the
  lookup table is limited to 64 entries). RSS is configured at start and
  programmed through the PF. Changing the key or table at runtime is not
  supported.
* **Interrupt mode** for RX queues. It requires at least one MSI-X vector more
  than the number of VPP threads, otherwise the capability is disabled and a
  notice is logged. The driver uses write-back on ITR when the PF supports it.
* **MAC filtering**: the PF assigned MAC address is programmed through the PF,
  the MAC address can be changed (the PF decides whether to allow it), additional unicast
  addresses and promiscuous mode (unicast and multicast) are supported.
* **MTU**: the maximum frame size can be changed while the port is stopped. It is
  limited by the PF reported maximum.
* **Buffer chaining**: RX frames up to five chained buffers. TX segments are
  limited by the hardware, oversize segments and GSO packets which do not fit
  are dropped and counted.
* **Statistics**: VSI statistics fetched from the PF every second (disable with
  the ``no-stats`` device flag).

Not supported:

* Setting the link speed, bringing the physical link down or controlling the PHY
  (VF limitation, the PF owns the link). Stopping the port does not take the
  link down for the link partner.
* Secondary interfaces and flow offload.
* Changing the RSS key or lookup table at runtime.
* VLAN insertion and filtering offload. The driver negotiates the VLAN
  capabilities with the PF only to disable VLAN stripping, so tags stay in the
  packet.

Counters
========

Interface counters come from the VF VSI statistics (``show device counters``).
The nodes have these error counters (``show errors``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Counter
     - Meaning
   * - ``buffer alloc error``
     - the RX ring could not be refilled
   * - ``segment size exceeded``
     - a TX segment is larger than the hardware allows
   * - ``no free tx slots``
     - TX ring full, packets dropped
   * - ``gso packet drop``
     - a GSO packet could not be transmitted and was dropped

Caveats
=======

* The VF depends on the PF driver. If the PF resets (for example when the PF
  driver is reloaded or the PF link is reconfigured), the VF is reset too and
  the driver has to be re-attached.
* The PF may restrict what the VF can do (trust mode, spoof checking, VLAN,
  MAC address changes, number of queues). A refused request is logged.
* Link state follows the PF. The VF reports link down only when the PF reports
  it, not when VPP stops the port.
* On ``i40e`` PFs, requesting queue pairs resets the VF once, attach takes
  correspondingly longer.
* The VF reports a maximum MTU from the PF. If the PF reports 0 the driver logs
  a warning and falls back to the standard Ethernet maximum frame size (1518
  bytes).

Debugging
=========

* ``show device <device-id>`` shows the VF state, the capabilities negotiated
  with the PF and the queue state.
* ``show device counters all <device-id>`` shows all counters.
* Raise the log level, ``logging { class iavf { level debug } class dev { level
  debug } }``, to see the virtchnl exchange with the PF (opcodes and return
  values).
* Typical errors: ``timeout waiting for VF reset`` (the PF did not complete a
  reset, check the PF driver), ``adminq enqueue timeout`` (the PF does not
  answer, the PF driver is not loaded or the VF is not enabled),
  ``VPP buffer data size ... is too small for RX`` (use a bigger
  ``buffers { default data-size }``).
* Packets are traced with ``trace add <interface-name>-rx 10``.
