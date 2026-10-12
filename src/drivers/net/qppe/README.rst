.. SPDX-License-Identifier: Apache-2.0
.. Copyright (c) 2026 Cisco Systems, Inc.

QPPE device driver
===================

Overview
--------

This driver provides native device support for the Qualcomm PPE (Packet
Processing Engine), found in Qualcomm/Qti IPQ95xx family of SOCs (device
tree compatible ``qcom,ipq9574-ppe``). It uses the generic
``vpp_kdi`` kernel module to manage clocks, reset controls, interconnect
paths, and generic PHY consumers declared by the device tree. The platform
bus API maps registers through UIO.
Generic PHY entries come from ``phys``/``phy-names``; Ethernet
``phy-handle`` links remain part of the network driver's link management.

The driver maps the PPE register window and discovers enabled Ethernet
ports from the device tree. It reports each port's label, PHY mode and MAC
address in VPP, but does not yet configure the PPE hardware or move
traffic. Port start is rejected until hardware setup and packet queues are
implemented.

Prerequisites
-------------

Keep the PPE platform device bound to UIO. The KDI misc device controls its
clocks, resets, interconnect paths, and generic PHY consumers while UIO
continues to expose the MMIO region. Build KDI against the target kernel:

::

   $ ./configure --platform ipq95xx --kdi-kdir /path/to/kernel/build
   $ ninja
   $ sudo insmod build/kdi/vpp_kdi.ko debug=1

The module creates ``/dev/vpp-kdi``. VPP opens each named resource through the
platform bus API, which returns a resource file descriptor. It requires
permission to open both ``/dev/vpp-kdi`` and the matching UIO node. The QPPE
driver enables clocks and pulses declared reset lines during initialization.
Closing a resource descriptor releases that resource. This does not configure
PPE forwarding, PHYs, MACs or EDMA queues yet.

::

   $ ls -l /dev/vpp-kdi /dev/uio*

Usage
-----

Interfaces are created using the vnet dev APIs, CLIs or startup.conf.

Sample startup.conf:

::

   devices {
     dev platform/3a000000.ethernet {
     }
   }

Device identifier in this example is 'platform/3a000000.ethernet' where
'platform' is the bus name and '3a000000.ethernet' is the Linux platform
bus identifier for the PPE, derived from its device tree node
(``ethernet@3a000000``).

Platform identifier can be found in sysfs:

::

   $ ls /sys/bus/platform/devices | grep ethernet
   3a000000.ethernet
