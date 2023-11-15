# Marvell OCTEON native plugin (ONP)

## Overview
This plugin provides native device support for Marvell OCTEON family of SoCs.
The ONP plugin is tailored for maximum performance on OCTEON SoCs through
extensive optimizations of the interface between hardware and VPP fast-path
data structures. Currently it integrates the following hardware accelerators
into VPP:
- Network Interface Controller (aka NIX) for packet ingress and egress
- Network Pool Allocator (aka NPA)

## Supported SoC
- OCTEON CN10KXX

## Usage
The following section demonstrates the steps required to bring up VPP with ONP
plugin on the OCTEON platform.

### Setup

#### Configure NIX VF on OCTEON
-# Determine NIX PF on OCTEON
```
# lspci -d 177d::0200 | grep 'a063'
  0002:02:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
  0002:07:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
```

-# Create 1 VF each for 2 NIX PF
```
# echo 1 > /sys/bus/pci/devices/0002\:02\:00.0/sriov_numvfs
# echo 1 > /sys/bus/pci/devices/0002\:07\:00.0/sriov_numvfs
```

-# Bind NIX VF to vfio-pci driver
```
dpdk-devbind.py -b vfio-pci 0002:02:00.1 0002:07:00.1
```
#### Modify startup.conf
ONP plugin sets vlib buffer external header size, therefore it cannot exist with
input plugins which use this setting eg: DPDK plugin. Therefore the dpdk plugin
should be disabled before enabling ONP plugin. Add the following config to the
startup.conf file.
```
   plugins {
       plugin dpdk_plugin.so { disable }
       plugin onp_plugin.so { enable }
   }
```

-# Add the above NIX devices bound to vfio-pci earlier to the `onp` section as
follows
```
  onp {
      dev 0002:02:00.1
      dev 0002:07:00.1
  }
```

### Launch VPP
Launch VPP with this startup.conf. If ONP plugin is loaded successfully, the
following message will be displayed
```
# vpp -c /etc/vpp/startup.conf
# vppctl -s /run/vpp/cli.sock
      _______    _        _   _____  ___
   __/ __/ _ \  (_)__    | | / / _ \/ _ \
   _/ _// // / / / _ \   | |/ / ___/ ___/
   /_/ /____(_)_/\___/   |___/_/  /_/

   vpp# show version
   vpp v23.02-rc0~763-g39ea666f7 built by root on CRB-106 at 2023-10-12T09:32:17
   vpp#
   vpp# show log
   ...
   ...
   2023/10/12 17:46:39:549 notice     plugin/load    Loaded plugin: onp_plugin.so (Marvell OCTEON native (onp) plugin)
   ...
   ...
```
