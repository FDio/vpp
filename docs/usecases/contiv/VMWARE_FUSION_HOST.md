### Preparing a VmWare Fusion Host
The *vmxnet3 driver* is required on a GigE Network Adapter used by VPP. On VmWare
Fusion, the default Network Adapter driver is an *Intel 82545EM (e1000)*, and there
is no GUI to change it to *vmxnet3*. The change must be done manually in the VM's
configuration file as follows:

- Bring up the VM library window: **Window -> Virtual Machine Library**
- Right click on the VM where you want to change the driver:
  <*VM-Name*> **-> Show in Finder**. This pops up a new Finder window with a line
  for each VM that Fusion knows about.
- Right click on the VM where you want to change the driver:
  <*VM-Name*> **-> Show package contents**. This brings up a window with the 
  contents of the package.
- Open the file <*VM-Name*> **.vmx** with your favorite text editor.
- For each Network Adapter that you want used by VPP, look for the 
  Network Adapter's driver configuration. For example, for the VM's first
  Network Adapter look for:
  ```
  ethernet0.virtualDev = "e1000"
  ```
  Replace `e1000` with `vmxnet3`:
  ```
  ethernet0.virtualDev = "vmxnet3"
  ```
and restart the VM.

If you replaced the driver on your VM's primary Network Adapter, you will 
have to change the primary network interface configuration in Linux. 

First, get the new primary network interface name:
```
sudo lshw -class network -businfo

Bus info          Device      Class          Description
========================================================
pci@0000:03:00.0  ens160      network        VMXNET3 Ethernet Controller
```
Replace the existing primary network interface name in `/etc/network/interfaces`
with the above device name (ens160):
```
# This file describes the network interfaces available on your system,
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ens160
iface ens160 inet dhcp