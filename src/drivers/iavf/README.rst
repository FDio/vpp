IAVF device driver
==================

Overview
--------

This driver provides native support for Intel Adaptive Virtual Function (AVF).
AVF is driver specification for current and future Intel Virtual Function (VF) devices.
AVF defines communication channel between Physical Functions (PF) and VF.
This driver can be used with Intel X710 and E810 series adapters.

Prerequisites
-------------

* Driver requires ice or i40e PF drivers.
* Driver requires MSI-X interrupt support and OS with SR-IOV support.

Usage
-----

System setup
~~~~~~~~~~~~

1. Determine PF device ID by following command:

::

   $ sudo lshw -class network -businfo
   Bus info          Device          Class          Description
   ============================================================
   pci@0000:2f:00.0  eno5            network        VIC Ethernet NIC
   pci@0000:2f:00.1  eno6            network        VIC Ethernet NIC
   pci@0000:99:00.0  ens3f0np0       network        Ethernet Controller E810-C for QSFP
   pci@0000:99:00.1  ens3f1np1       network        Ethernet Controller E810-C for QSFP

2. Create VF using the following:

::

   $ echo 1 | sudo tee /sys/class/net/ens3f1np1/device/sriov_numvfs

3. Determine VF info:

::

   $ sudo lshw -class network -businfo
   Bus info          Device          Class          Description
   ============================================================
   pci@0000:2f:00.0  eno5            network        VIC Ethernet NIC
   pci@0000:2f:00.1  eno6            network        VIC Ethernet NIC
   pci@0000:99:00.0  ens3f0np0       network        Ethernet Controller E810-C for QSFP
   pci@0000:99:00.1  ens3f1np1       network        Ethernet Controller E810-C for QSFP
   pci@0000:99:11.0  ens3f1v0        network        Ethernet Adaptive Virtual Function

4. Bind VF to vfio-pci driver:

::

   $ sudo ./dpdk-devbind.py --bind=vfio-pci 0000:99:11.0

Interface creation
~~~~~~~~~~~~~~~~~~

::

   vpp# device attach pci/0000:99:11.0 driver iavf
   vpp# device create-interface pci/0000:99:11.0
   vpp# set int ip address iavf0/0 6.0.1.1/24
   vpp# set int state iavf0/0 up


