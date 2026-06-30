Armada device driver
=====================

Overview
--------

This driver provides native device support for Marvell PP2 network
device, found in Marvell Armada family of SoCs. It does not require the
external Marvell Usermode SDK library.

Prerequisites
-------------

The driver uses the kernel's ``uio_pdrv_genirq`` platform driver to map the
PP, MSPG, and CM3 register regions. The device tree must provide a UIO node
with ``reg`` and ``reg-names`` entries for these regions.

The compatible string is stored as a NUL-separated device-tree property. It
can be checked through sysfs as follows (adjust the platform device name if
needed):

::

   $ tr '\0' '\n' < /sys/bus/platform/devices/f2000000.uio_pp_0/of_node/compatible
   generic-uio

Pass that string to ``uio_pdrv_genirq`` when loading the module:

::

   $ sudo modprobe -r mv_pp_uio
   $ sudo modprobe uio_pdrv_genirq of_id=generic-uio

To make the setting persistent, add the following to a file under
``/etc/modprobe.d/``:

::

   options uio_pdrv_genirq of_id=generic-uio

The bound driver and exported UIO maps can be verified through sysfs:

::

   $ DEVICE_PATH=/sys/bus/platform/devices/f2000000.uio_pp_0
   $ basename "$(readlink -f $DEVICE_PATH/driver)"
   uio_pdrv_genirq
   $ grep . $DEVICE_PATH/uio/uio*/maps/map*/name
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map0/name:pp
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map1/name:mspg
   /sys/bus/platform/devices/f2000000.uio_pp_0/uio/uio0/maps/map2/name:cm3

The out-of-tree ``mv_pp_uio`` and ``musdk_cma`` kernel modules are not
required.

Usage
-----

Interface Creation and Deletion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Interfaces are using new vnet dev APIs, CLIs or startup.conf to create and
delete interfaces.

Sample startup.conf:

::

   devices {
     dev platform/f2000000.ethernet {
       port 1 { name port1 }
   }

Device identifier in this example is 'platform/f2000000.ethernet' where
'platform' is bus name and 'f2000000.ethernet' is linux platform bus
identifier for specific PP2.

Device Options
~~~~~~~~~~~~~~

``force_bppe_addr`` retains external BPPE arrays and changes the global
BPPE address-high register to match the first VPP pool allocation. All later
VPP pools must be allocated in that same 4 GB window. This option also changes
the address window used by kernel-owned pools and must only be used when no
kernel-owned BPPE pool remains active.

::

   devices {
     dev platform/f2000000.ethernet {
       args 'force_bppe_addr=on'
       port 1 { name port1 }
     }
   }

Platform identifier can be found in sysfs:

::

   $ ls /sys/bus/platform/devices | grep ethernet
   f2000000.ethernet
