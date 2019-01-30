.. _vmxnet3:

VPP with VMware/Vmxnet3
=======================

This section describes a native Vmxnet3 driver that is included with VPP.
This driver is written as a plugin and is found in src/plugin/vmxnet3.

Advantages
----------

The native VPP native vmxnet3 driver provides the following features
that are not provided with the standard dpdk vmxnet3 driver.

-  Interrupt mode
-  Adaptive mode
-  TSO/LRO mode

Does not support
----------------

This driver does yet support the following features.

-  NUMA support
-  RSS/multiple queues
-  VLAN filter

Prerequisites
-------------

-  This code is tested with vfio-pci driver installed with Ubuntu 18.04
   which has kernel version 4.15.0-33-generic.

-  This code is tested with ESXi vSwitch version 6.0, release build
   3620759.

-  Driver requires MSI-X interrupt support, which is not supported by
   uio_pci_generic driver, so vfio-pci needs to be used. On systems
   without IOMMU vfio driver can still be used with recent kernels which
   support no-iommu mode.

VMware Fusion for Mac
---------------------

VMware fusion does not have a menu option to change the default driver (e1000)
to the **vmxnet3** driver. VPP supports the **vmxnet3** driver.

These instructions describe how to change the e100 driver for VMware fusion.

* From the VMware Fusion menu bar select **Window** then **Virtual Machine Library**.
* From the Virtual Machine menu right click on the Virtual Machine you are using and select **Show in Finder**
* Find the name associated with the VM you are using, right click on it and select **Show Package Contents**
* Find the **.vmx** file and edit it.
* Find all the occurences of **e1000** and change them to **vmxnet3**

If you are concerned more with configuration not performance the vmxnet3 driver can be set to
**interrupt** mode in VPP. This will save a great deal on battery usage. Do this with the following

.. code-block:: console

    # vppctl set interface rx-mode <interface> interrupt


System setup
~~~~~~~~~~~~

To use the native VPP vmxnet3 driver use the following Steps

Load VFIO driver

.. code-block:: console

    $ sudo modprobe vfio-pci

For systems without IOMMU only, enable unsafe NOIOMMU mode

.. code-block:: console

    $ echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

To bind interface to vfio-pci first install the :ref:`configutil`. This will download
the dpdk_devbind.py script. It is located in */usr/vpp/vpp-config/scripts* with Centos
and */usr/local/vpp/vpp-config/scripts* with Ubuntu. 

Bind the driver with the following commands:

.. code-block:: console

    $ sudo /usr/local/vpp/vpp-config/scripts/dpdk-devbind.py -s

    Network devices using DPDK-compatible driver
    ============================================
    <none>
    
    Network devices using kernel driver
    ===================================
    0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vmxnet3 unused=vfio-pci,uio_pci_generic 
    0000:0b:00.0 'VMXNET3 Ethernet Controller' drv=vfio-pci unused=vmxnet3,uio_pci_generic
    0000:13:00.0 'VMXNET3 Ethernet Controller' drv=vfio-pci unused=vmxnet3,uio_pci_generic
    .....

    $ sudo /usr/local/vpp/vpp-config/scripts/dpdk-devbind.py --bind vfio-pci 0b:00.0


Interface Creation
~~~~~~~~~~~~~~~~~~

Now create the interface dynamically with following:

.. code-block:: console

    $ sudo vppctl create interface vmxnet3 0000:0b:00.0
    $ sudo set int state vmxnet3-0/b/0/0 up

Interface Deletion
~~~~~~~~~~~~~~~~~~

If the interface needs to be deleted:

.. code-block:: console

    $ sudo delete interface vmxnet3 <if-name>

Show vmxnet3
~~~~~~~~~~~~

Interface and ring information can be obtained with the command
**show vmxnet3 [if-name] [desc]**

For example:

.. code-block:: console

    $ sudo vppctl show vmxnet
    Interface: vmxnet3-0/b/0/0 (ifindex 1)
      Version: 1
      PCI Address: 0000:0b:00.0
      Mac Address: 00:50:56:88:63:be
      hw if index: 1
      Device instance: 0
      Number of interrupts: 2
      Queue 0 (RX)
        RX completion next index 786
        RX completion generation flag 0x80000000
        ring 0 size 4096 fill 4094 consume 785 produce 784
        ring 1 size 4096 fill 4096 consume 0 produce 0
      Queue 0 (TX)
        TX completion next index 216
        TX completion generation flag 0x0
        size 4096 consume 216 produce 245
