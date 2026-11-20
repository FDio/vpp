.. _drv_qat:

==========================================================
Intel QuickAssist (qat) crypto driver
==========================================================

Overview
========

This driver provides native symmetric crypto support for Intel QuickAssist
Technology (QAT) virtual functions. The physical function (PF) stays with the
Linux kernel driver (for example ``qat_4xxx``), which loads the firmware and
assigns a service to each ring pair. The driver uses the VF ring pairs
assigned to symmetric crypto, one crypto queue each, and registers them with
``vnet_crypto`` as an asynchronous crypto engine for IPsec and other users of
the async crypto API.

The driver is built on the :ref:`dev_framework` (see :ref:`dev_crypto`) and
registers on the ``pci`` bus under the name ``qat``. It talks to the PF over the
PF to VF mailbox, which also provides the ring to service map and the
capabilities of the device.

Supported devices
=================

The driver attaches to virtual functions of PCI vendor ``8086``:

======== ======================================================= ============
PCI id   Description                                             Generation
======== ======================================================= ============
``0443`` Intel QuickAssist DH895xCC Virtual Function             gen2
``37c9`` Intel QuickAssist C62x Virtual Function                 gen2
``19e3`` Intel QuickAssist C3xxx Virtual Function                gen2
``4941`` Intel QuickAssist 4xxx Virtual Function                 gen4
======== ======================================================= ============

The PF must be driven by the Linux QAT driver and must have a compatible
PF/VF protocol version (``PF is not compatible with this driver`` otherwise).
The device must report the symmetric crypto, cipher and authentication
capabilities (and for gen4 also the AES-GCM and ChaCha20-Poly1305
capabilities), otherwise attach fails with ``missing capabilities``.

Prerequisites
=============

* A PF bound to the Linux QAT driver with VFs created
  (``echo <n> > /sys/bus/pci/devices/<pf address>/sriov_numvfs``).
* The VFs bound to ``vfio-pci``.
* At least one ring pair of the VF configured for the symmetric crypto service
  (see "PF service configuration" below). Without it attach fails with ``no ring
  pair is configured for symmetric crypto``.

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

Bind the VFs to ``vfio-pci`` and attach them to VPP, either with ``device
attach pci/<vf address> driver qat`` or in the startup config:

.. code-block:: text

   devices {
     dev pci/<vf address> { driver qat }
   }

The queue options of the framework (``num-crypto-queues``,
``crypto-queue-size``, ``crypto-queue <n> { size <n> threads <list> }``) are
described in :ref:`dev_crypto`.

Thread to queue assignment
--------------------------

All VFs of the same QAT generation serve one crypto engine (``qat-gen2-sym`` or
``qat-gen4-sym``), and the queues of all of them are assigned to the VPP
threads together. A device uses its first ``num-crypto-queues`` queues, by
default as many as there are threads, up to the number of its symmetric
crypto ring pairs.

Requests are completed by the thread which submitted them, so each queue
serves exactly one thread. A thread may have several queues, also of
different VFs; it submits each frame to its queue with the fewest requests in
flight. A queue configured with a thread serves that thread, the other queues
are spread round robin over all threads. A thread without a queue drops its
requests and counts them as ``no-queue`` errors of the engine enqueue nodes.

The throughput limit is per PF, so a thread which should use more than one PF
needs queues of VFs of different PFs. For example, with two VFs of different
PFs and four threads:

.. code-block:: text

   devices {
     dev pci/<vf of pf 0> {
       driver qat
       crypto-queue 0 { threads 0 }
       crypto-queue 1 { threads 1 }
     }
     dev pci/<vf of pf 1> {
       driver qat
       crypto-queue 0 { threads 2 }
       crypto-queue 1 { threads 3 }
     }
   }

Without the ``crypto-queue`` settings the same queues are spread over the
threads automatically. ``show device`` shows the threads of each queue.

PF service configuration
------------------------

The services of a PF are set by the kernel driver through
``/sys/bus/pci/devices/<pf address>/qat/cfg_services``. With the common
default ``sym;asym``, the symmetric crypto throughput of the PF is about half
of what the same PF reaches when configured for ``sym`` only. If the system
doesn't need asymmetric crypto offload, configure the PF for ``sym``.

The throughput limit is per PF. Using more VFs of the same PF, or more ring
pairs of a VF, doesn't increase it; to scale, use VFs of several PFs.

The services can only be changed while the PF is down and has no VFs. The VFs
are recreated and need to be bound to ``vfio-pci`` again afterwards:

.. code-block:: console

   $ PF=/sys/bus/pci/devices/<pf address>
   $ echo 0 | sudo tee $PF/sriov_numvfs
   $ echo down | sudo tee $PF/qat/state
   $ echo sym | sudo tee $PF/qat/cfg_services
   $ echo up | sudo tee $PF/qat/state
   $ echo <number of vfs> | sudo tee $PF/sriov_numvfs

The setting doesn't survive a reboot; make it persistent in the configuration
of whatever sets up the QAT devices at boot.

Arguments
=========

The driver defines no driver, device or port arguments.

Queue limits:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Item
     - Value
   * - Queues
     - one per symmetric crypto ring pair of the VF
   * - Queue size
     - 128 to 4096 requests, power of two, default 1024

Supported features
==================

The driver registers the engine with a high priority (100), so it is preferred
over software implementations for the algorithms it supports. Both encrypt
and decrypt directions are provided. Supported asynchronous algorithms:

**All generations:**

* AES-CBC and AES-CTR (128, 192 and 256 bit keys).
* AES-CBC and AES-CTR combined with HMAC-SHA2 (SHA-256, SHA-384 and SHA-512 for
  both modes, and SHA-224 for CBC), both with the full length and with the
  truncated ICVs used by IPsec (12, 14, 16, 24 and 32 bytes as applicable to
  the hash).

**gen4 only (4xxx):**

* AES-GCM with 128, 192 and 256 bit keys, a 16 byte ICV and 8, 12, 20 or 28 byte
  AAD.
* ChaCha20-Poly1305 with a 16 byte ICV and 0, 8 or 12 byte AAD.

Other features:

* **Multiple queues per thread**: a thread uses its queue with the fewest
  requests in flight.
* **Session handling**: keys are converted to hardware sessions through the
  ``vnet_crypto`` key change handler. Session data is released only after the
  requests which use it have completed.
* **Queue recovery and PF events**: the driver follows PF restarts and fatal
  errors reported over the mailbox.
* **Statistics**: per queue counters of the framework (see below).

Not supported:

* Asymmetric crypto (public key operations). Only the symmetric service is
  used.
* HMAC-MD5 and HMAC-SHA1 combined algorithms, and standalone hash algorithms.
* Synchronous (non-async) crypto operations. The engine is registered only as
  an asynchronous engine.

Counters
========

``show device <device-id>`` shows for every queue the framework counters:
enqueued requests, enqueued bytes, queue full, enqueue errors, completed
requests, engine errors and authentication failures. A thread without a queue
counts dropped requests as ``no-queue`` errors in ``show errors`` of the engine
enqueue nodes.

Caveats
=======

* The PF must stay under the kernel driver. When the PF restarts, the VFs lose
  their configuration and have to be re-attached.
* The throughput limit is per PF. To scale, use VFs of several PFs and assign
  threads to them as shown above.
* The ring pair to service assignment belongs to the PF configuration and can
  only be changed while the PF is down and has no VFs.
* Combined algorithms with HMAC-SHA1 and MD5 are not offered, they are handled
  by other crypto engines.
* gen2 devices do not provide AES-GCM and ChaCha20-Poly1305.

Debugging
=========

* ``show device <device-id>`` shows the PCI state, the PF/VF protocol version,
  the capabilities reported by the PF, the ring pairs and the queues.
* ``show crypto engines`` and ``show crypto async handlers`` show which engine
  handles which algorithm.
* ``show device driver qat ring <device-id> [queue <n>] [count <n>]`` dumps the
  request ring of a queue, ``count`` limits the number of entries.
* ``show device driver qat session <crypto-context-index>`` shows the hardware
  session built for a crypto context.
* Raise the log level with ``logging { class qat { level debug } class dev {
  level debug } }``.
* Typical errors: ``no response from PF`` and ``PF did not acknowledge``
  (mailbox problem, check that the PF driver is loaded and the VF is enabled),
  ``mailbox busy``, ``PF is restarting``, ``PF reported a fatal error``,
  ``missing capabilities`` (the PF reports fewer capabilities than the driver
  needs), ``no ring pair is configured for symmetric crypto`` (see PF
  service configuration), ``ring pair reset failed``.
