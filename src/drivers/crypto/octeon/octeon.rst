.. _drv_octeon_crypto:

==========================================================
Marvell Octeon crypto (octeon-cpt) native driver
==========================================================

Overview
========

The ``octeon-cpt`` driver is a native VPP crypto driver for the *CPT*
cryptographic accelerator unit of the Marvell Octeon 9 and Octeon 10 SoCs. It
exposes the CPT logical functions (LFs) as crypto queues and registers them
with ``vnet_crypto`` as an asynchronous crypto engine, so that IPsec and other
users of the VPP async crypto API are offloaded to the accelerator.

The driver uses the Marvell ROC library for access to the hardware. The network
units of the same SoC are driven by the separate :ref:`drv_octeon_net` driver.

The driver is built on the :ref:`dev_framework` (see :ref:`dev_crypto`) and
registers on the ``pci`` bus under the name ``octeon-cpt``.

Supported devices
=================

The driver attaches to PCI vendor ``177d`` and the following virtual function
device ids:

======== ===========================================================
PCI id   Description
======== ===========================================================
``a0f3`` Marvell Octeon-10 Cryptographic Accelerator Unit VF
``a0fe`` Marvell Octeon-9 Cryptographic Accelerator Unit VF
======== ===========================================================

Build requirements
==================

The driver is built only for the ``octeon9`` and ``octeon10`` VPP platforms and
only when the Marvell ROC headers and ``libocteon-roc.a`` are available (the
build prints that the driver is disabled otherwise).

Prerequisites
=============

* The CPT virtual function is bound to ``vfio-pci`` before VPP starts, as with
  other native PCI drivers.
* The VF must have crypto logical functions assigned to it by the PF. The driver
  creates one queue per VPP thread, or as many as there are available LFs if
  fewer.

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
     dev pci/0002:20:00.1 {
       driver octeon-cpt
     }
   }

At runtime:

.. code-block:: text

   vpp# device attach pci/0002:20:00.1 driver octeon-cpt
   vpp# show crypto async handlers

The crypto queue options of the framework (``num-crypto-queues``,
``crypto-queue-size``, ``crypto-queue <n> { size <n> threads <list> }``) are
described in :ref:`dev_crypto`.

Once attached, the driver registers the crypto engine ``octeon-cpt-v<n>`` (the
suffix is the CPT revision of the hardware) with a high priority (100), so it
is preferred over software implementations for the algorithms it supports.
``show crypto engines`` and ``show crypto async handlers`` list it and the
selected handlers.

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
     - one per thread, limited by the logical functions available to the VF
   * - Queue size
     - 1024 to 32768 descriptors, power of two, default 4096

Supported features
==================

The set of algorithms depends on the capabilities of the CPT engines, which the
driver reads from the hardware. The following asynchronous algorithms are
offered when the engine supports them:

* AES-CBC and AES-CTR (128, 192 and 256 bit keys)
* AES-CBC and AES-CTR combined with HMAC-MD5 (CBC only), HMAC-SHA1,
  HMAC-SHA2-256, HMAC-SHA2-384 and HMAC-SHA2-512 (linked cipher and
  integrity algorithms with the truncated ICVs used by IPsec)
* AES-GCM (128, 192 and 256 bit keys) with 8 and 12 byte AAD and a 16 byte ICV
* ChaCha20-Poly1305 with 0, 8 and 12 byte AAD and a 16 byte ICV

Both encrypt and decrypt directions are provided. The algorithms are only
registered while a queue of the engine is started.

Other features:

* **Per thread queues.** Threads use their own queue when enough logical
  functions exist, otherwise queues are shared between threads.
* **Scatter-gather** for chained buffers.
* **Session keys** are converted to hardware sessions when keys are added or
  changed (the key change handler of ``vnet_crypto``).
* **Statistics**: per queue request, byte, queue full and error counters of the
  framework (see ``show device``).

Not supported:

* Synchronous (non-async) crypto operations. The engine is registered only as an
  asynchronous engine.
* Algorithms which are not in the list above, such as AES-GMAC or
  HMAC-only algorithms.

Counters
========

``show device <device-id>`` shows, for every queue, the framework counters:
enqueued requests, enqueued bytes, queue full, enqueue errors, completed
requests, engine errors and authentication failures.

Caveats
=======

* Only the platforms ``octeon9`` and ``octeon10`` build the driver.
* The algorithm list depends on the engine capabilities. An algorithm which the
  hardware does not support is simply not registered and is handled by another
  engine.
* Queues are shared between threads when there are fewer logical functions than
  threads. The enqueue path takes this into account but the throughput per
  thread is then lower.
* The driver relies on the ROC library and the firmware of the SoC. A mismatch is
  reported by ROC error messages at attach time.

Debugging
=========

* ``show device <device-id>`` shows the CPT device, its queue group and queues.
* ``show device driver octeon-cpt groups`` lists the queue group.
* ``show crypto engines`` and ``show crypto async handlers`` show which
  engine handles which algorithm.
* Raise the log level with ``logging { class octeon { level debug } class dev
  { level debug } }``. ROC library errors are logged as ``ROC error <message>
  (<code>)`` with the failing call.
* Typical errors: ``Could not add CPT SE engines`` and ``Could not add CPT IE
  engines`` (the engine groups could not be created, check the VF resources),
  ``could not configure crypto device`` (no logical function available),
  ``Failed to allocate crypto session memory`` and ``Failed to allocate crypto
  scatter gather memory`` (memory shortage).
