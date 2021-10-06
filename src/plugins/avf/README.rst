Intel AVF device driver
=======================

Overview
--------

This plugins provides native device support for intel Adaptive Virtual
Function (AVF). AVF is driver specification for current and future Intel
Virtual Function devices. AVF defines communication channel between
Physical Functions (PF) and VF. In essence, today this driver can be
used only with Intel XL710 / X710 / XXV710 adapters.

Prerequisites
-------------

-  Driver requires newer i40e PF linux driver to be installed on the
   system, which supports virtualchnl interface. This code is tested
   with i40e driver version 2.4.6.

-  Driver requires MSI-X interrupt support, which is not supported by
   uio_pci_generic driver, so vfio-pci needs to be used. On systems
   without IOMMU vfio driver can still be used with recent kernels which
   support no-iommu mode.

Known issues
------------

This driver is still in experimental phase, however it shows very good
performance numbers.

Usage
-----

System setup
~~~~~~~~~~~~

1. load VFIO driver

::

   sudo modprobe vfio-pci

2. (systems without IOMMU only) enable unsafe NOIOMMU mode

::

   echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

3. Create and bind SR-IOV virtual function(s)

Following script creates VF, assigns MAC address and binds VF to
vfio-pci

.. code:: bash

   #!/bin/bash

   if [ $USER != "root" ] ; then
       echo "Restarting script with sudo..."
       sudo $0 ${*}
       exit
   fi

   setup () {
     cd /sys/bus/pci/devices/${1}
     driver=$(basename $(readlink driver))
     if [ "${driver}" != "i40e" ]; then
       echo ${1} | tee driver/unbind
       echo ${1} | tee /sys/bus/pci/drivers/i40e/bind
     fi
     ifname=$(basename net/*)
     echo 0 | tee sriov_numvfs > /dev/null
     echo 1 | tee sriov_numvfs > /dev/null
     ip link set dev ${ifname} vf 0 mac ${2}
     ip link show dev ${ifname}
     vf=$(basename $(readlink virtfn0))
     echo ${vf} | tee virtfn0/driver/unbind
     echo vfio-pci | tee virtfn0/driver_override
     echo ${vf} | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
     echo  | tee virtfn0/driver_override
   }

   # Setup one VF on PF 0000:3b:00.0 and assign MAC address
   setup 0000:3b:00.0 00:11:22:33:44:00
   # Setup one VF on PF 0000:3b:00.1 and assign MAC address
   setup 0000:3b:00.1 00:11:22:33:44:01

Promisc mode
~~~~~~~~~~~~

In cases when interface is used in the L2 mode or promisc mode is needed
for some other reason, trust needs to be set to “on” using the linux “ip
link” utility.

::

   ip link set dev <PF inteface name> vf <VF id> trust on

L2 spoofing check
~~~~~~~~~~~~~~~~~

By default Virtual Function is not allowed to send ethernet frames which
have source MAC address different than address assigned to the VF. In
some cases it is expected that VPP will send such frames (e.g. L2
bridging, bonding, l2 cross-connect) and in such cases spoof check needs
to be turned off by issuing following command:

::

   ip link set dev <PF inteface name> vf <VF id> spoofchk off

Interface Creation
~~~~~~~~~~~~~~~~~~

Interfaces can be dynamically created by using following CLI:

::

   create interface avf 0000:3b:02.0
   set int state avf-0/3b/2/0 up

Interface Deletion
~~~~~~~~~~~~~~~~~~

Interface can be deleted with following CLI:

::

   delete interface avf <interface name>

Interface Statistics
~~~~~~~~~~~~~~~~~~~~

Interface statistics can be displayed with
``sh hardware-interface <if-name>`` command.
