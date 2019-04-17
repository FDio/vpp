# VMWARE vmxnet3 device driver plugin {#vmxnet3_doc}

##Overview
This plugin provides native PCI driver support for VMWare vmxnet3.

##Prerequisites
 * This code is tested with vfio-pci driver installed with Ubuntu 18.04 which
has kernel version 4.15.0-33-generic.

 * This driver is tested with ESXi vSwitch version 6.5/6.7 for LRO/TSO support, VMware Workstation 15 Pro (no LRO/TSO), and VMware Fusion 11 Pro (no LRO/TSO)

 * Driver requires MSI-X interrupt support, which is not supported by
uio_pci_generic driver. So vfio-pci must be used. On systems without IOMMU,
vfio driver can still be used with 4.15.0-33-generic kernel (Ubuntu 18.04) which supports no-iommu mode.

##Known issues

* VLAN filter

## Usage
### System setup

1. load VFIO driver
```
sudo modprobe vfio-pci
```

2. Make sure the interface is down
```
sudo ifconfig <if-name> down
```

Steps 3 and 4 are optional. They can be accomplished by specifying the optional keyword "bind" when creating the vmxnet3 interface.

3. (systems without IOMMU only) enable unsafe NOIOMMU mode
```
echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
```

4. Bind interface to vfio-pci
```
sudo dpdk-devbind.py --bind vfio-pci 0b:00.0
```

### Interface Creation
Interface can be dynamically created with following CLI, with or without the bind option. If step 3 and 4 were executed, bind can be omitted.
```
create interface vmxnet3 0000:0b:00.0 bind
set int state vmxnet3-0/b/0/0 up
```

### Interface Deletion
Interface can be deleted with following CLI:
```
delete interface vmxnet3 <if-name>
```

### Interface Statistics
Interface statistics can be displayed with `show hardware-interface <if-name>`
command.

### Show Interface CLI
Interface and ring information can be obtained with
`show vmxnet3 [if-name] [desc]`
