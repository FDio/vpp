Intel QuickAssist crypto driver
===============================

Overview
--------

This driver provides native symmetric crypto support for Intel QuickAssist
(QAT) virtual functions. The physical function (PF) stays with the kernel
driver (e.g. ``qat_4xxx``), which loads the firmware and assigns a service to
each ring pair. The driver uses the VF ring pairs assigned to symmetric
crypto, one crypto queue each.

Device setup
------------

Bind the VFs to ``vfio-pci`` and attach them to VPP, either with
``device attach pci/<vf address> driver qat`` or in the startup config:

::

   devices {
     dev pci/<vf address> { driver qat }
   }

Thread to queue assignment
--------------------------

All VFs of the same QAT generation serve one crypto engine (e.g.
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

::

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

::

   $ PF=/sys/bus/pci/devices/<pf address>
   $ echo 0 | sudo tee $PF/sriov_numvfs
   $ echo down | sudo tee $PF/qat/state
   $ echo sym | sudo tee $PF/qat/cfg_services
   $ echo up | sudo tee $PF/qat/state
   $ echo <number of vfs> | sudo tee $PF/sriov_numvfs

The setting doesn't survive a reboot; make it persistent in the configuration
of whatever sets up the QAT devices at boot.
