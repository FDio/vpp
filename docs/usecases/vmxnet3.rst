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
-  LRO/TSO mode

Does not support
----------------

This driver does yet support the following features.

-  VLAN filter

Prerequisites
-------------

-  This code is tested with vfio-pci driver installed with Ubuntu 18.04
   which has kernel version 4.15.0-33-generic.

-  This code is tested with ESXi vSwitch version 6.5 and 6.7 for LRO/TSO support,
   VMware Workstation 15 Pro (no LRO/TSO), and VMware Fusion 11 Pro (no LRO/TSO).

-  Driver requires MSI-X interrupt support, which is not supported by
   uio_pci_generic driver, so vfio-pci needs to be used. On systems
   without IOMMU vfio driver can still be used with recent kernels which
   support no-iommu mode.

VMware Fusion for Mac
---------------------

VMware fusion does not have a menu option to change the default driver (e1000)
to the **vmxnet3** driver. VPP supports the **vmxnet3** driver.

These instructions describe how to change the e1000 driver for VMware fusion.

* From the VMware Fusion menu bar select **Window** then **Virtual Machine
  Library**.
* From the Virtual Machine menu right click on the Virtual Machine you are using
  and select **Show in Finder**
* Find the name associated with the VM you are using, right click on it and
  select **Show Package Contents**
* Find the **.vmx** file and edit it.
* Find all the occurrences of **e1000** and change them to **vmxnet3**

If you are concerned more with configuration not performance the vmxnet3 driver
can be set to **interrupt** mode in VPP. This will save a great deal on battery
usage. Do this with the following

VMware Workstatiom PRO 15 for Linux
-----------------------------------

VMware Workstation does not have a menu option to change the default driver
(e1000) to the **vmxnet3** driver. VPP supports the **vmxnet3** driver.

These instructions describe how to change the e1000 driver for VMware
Workstation PRO 15 Linux. You may need to be a superuser for performing these
steps.

* Shut down the VM you are about to change.
* From the vmware folder where vmware creates and stores the VM's, change the
  directory to the specific VM which you want to modify, and use your favorite
  text editor to open the corresponding VM's .vmx file. By default, it is
  $HOME/vmware/<vm-name>/<vm-name>.vmx
* Locate the line for the interface which you want to modify. For example, if it
  is ethernet1, then change the line **ethernet1.virtualDev = "e1000"** to
  **ethernet1.virtualDev = "vmxnet3"**
* Save the file and power on the VM.

If you are concerned more with configuration not performance the vmxnet3 driver
can be set to **interrupt** mode in VPP. This will save a great deal on battery
usage. Do this with the following

.. code-block:: console

    $ sudo vppctl set interface rx-mode <interface> interrupt


System setup
~~~~~~~~~~~~

To use the native VPP vmxnet3 driver use the following Steps

Load VFIO driver

.. code-block:: console

    $ sudo modprobe vfio-pci

Make sure the interface is down

.. code-block:: console

    $ sudo ifconfig <if-name> down

The next 2 steps are optional and may be accomplished by specifying the optional
"bind" keyword when creating the vmxnet3 interface.

For systems without IOMMU only, enable unsafe NOIOMMU mode

.. code-block:: console

    $ echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

To bind interface to vfio-pci first install the :ref:`configutil`. This will
download the dpdk_devbind.py script. It is located in
*/usr/vpp/vpp-config/scripts* with Centos and
*/usr/local/vpp/vpp-config/scripts* with Ubuntu.

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

Now create the interface dynamically with following. The bind option must be
specified if pci is not already bound manually by above steps.

.. code-block:: console

    $ sudo vppctl create interface vmxnet3 0000:0b:00.0 bind
    $ sudo vppctl set interface state vmxnet3-0/b/0/0 up

Interface Deletion
~~~~~~~~~~~~~~~~~~

If the interface needs to be deleted:

.. code-block:: console

    $ sudo vppctl delete interface vmxnet3 <if-name>

Show vmxnet3
~~~~~~~~~~~~

Interface and ring information can be obtained with the command
**show vmxnet3 [if-name] [desc]**

For example:

.. code-block:: console

    $ sudo vppctl show vmxnet3
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
