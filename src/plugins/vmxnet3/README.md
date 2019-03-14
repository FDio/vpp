# VMWARE vmxnet3 device driver plugin

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

### Interface Creation
Interface can be dynamically created with following CLI:
```
create interface vmxnet3 0000:0b:00.0
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
