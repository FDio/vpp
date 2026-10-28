.. SPDX-License-Identifier: Apache-2.0
.. Copyright (c) 2026 Cisco Systems, Inc.

Device kernel interfaces
========================

This directory contains operating-system-specific kernel interfaces used by
VPP device drivers. Keep host-specific mechanisms inside their OS backend
directory so another host implementation can be added alongside ``linux``.

Linux
-----

The Linux backend is in ``linux/``. It contains the generic resource-control
module and its ioctl header. The module exposes one ``/dev/vpp-kdi`` device.
Clients request a resource by platform-device name, optional child device-tree
node name, resource type, and resource name. The open ioctl returns a file descriptor for that resource;
resource-specific operations use that descriptor, and ``close`` releases it.
Load the module with ``debug=1`` to emit per-operation details to the kernel
log; the parameter can also be changed through
``/sys/module/vpp_kdi/parameters/debug``.
The target platform device remains bound to its existing driver, such as UIO.
UIO provides MMIO mapping; KDI controls clocks, resets, interconnect paths,
and generic PHY consumers declared in the device tree. The resource interface
is not specific to the platform bus.

The shared ioctl contract is ``kdi.h``, dual-licensed under
Apache-2.0 or GPL-2.0 with the Linux syscall exception. Linux-specific
implementation details remain in ``linux/``. A future FreeBSD backend should
live in a sibling ``freebsd/`` directory and provide the equivalent resource
operations through FreeBSD interfaces.

KDI is selected with ``VPP_PLATFORM_USES_KDI`` in a platform CMake file.
``ipq95xx.cmake`` enables it. Pass the configured Linux kernel build directory
to ``./configure`` with ``--kdi-kdir``. For a cross-build, use a kernel build
tree with host-native Kbuild helper programs, such as the configured kernel
source/build directory. When the configured kernel build tree is available,
KDI is built as part of the normal VPP build. If it is missing, the configure
script prints a warning and continues without KDI.

::

   $ ./configure --platform ipq95xx --kdi-kdir /path/to/kernel/build
   $ ninja

The module is written to ``build/kdi/vpp_kdi.ko``.
