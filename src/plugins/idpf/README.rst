Intel IDPF device driver
========================

Overview
--------

This plugins provides native device support for Intel Infrastructure
Data Path Function (IDPF). The current IDPF is a driver specification
for future Intel Physical Function devices. IDPF defines communication
channel between Data Plane (DP) and Control Plane (CP).

Prerequisites
-------------

-  Driver requires MSI-X interrupt support, which is not supported by
   uio_pci_generic driver, so vfio-pci needs to be used. On systems
   without IOMMU vfio driver can still be used with recent kernels which
   support no-iommu mode.

Known issues
------------

-  This driver is still in experimental phase, and the corresponding device
is not released yet.

-  Current version only supports device initialization. Basic I/O function
will be supported in the next release.

Usage
-----

Interface Creation
~~~~~~~~~~~~~~~~~~

Interfaces can be dynamically created by using following CLI:

::

   create interface idpf 0000:4b:00.0 vport-num 1 rx-single 1 tx-single 1
   set int state idpf-0/4b/0/0 up

vport-num: number of vport to be created. Each vport is related to one netdev.
rx-single: configure Rx queue mode, split queue mode by default.
tx-single: configure Tx queue mode, split queue mode by default.

Interface Deletion
~~~~~~~~~~~~~~~~~~

Interface can be deleted with following CLI:

::

   delete interface idpf <interface name>

Interface Statistics
~~~~~~~~~~~~~~~~~~~~

Interface statistics can be displayed with
``sh hardware-interface <if-name>`` command.
