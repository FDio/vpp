Armada device plugin
=====================

Overview
--------

This plugins provides native device support for Marvell PP2 network
device, found in Marvel Armada family of SOCs.
It uses Marvell Usermode SDK
(`MUSDK <https://github.com/MarvellEmbeddedProcessors/musdk-marvell>`__).

Prerequisites
-------------

Plugins depends on installed MUSDK and Marvell provided linux in Marvell SDK.
Following kernel modules from MUSDK must be loaded for plugin to work:
``musdk_cma.ko``
``mv_pp_uio.ko``

Musdk 18.09.3 compilation steps
-------------------------------

::

   ./bootstrap
   ./configure --prefix=/opt/vpp/external/aarch64/ CFLAGS="-Wno-error=unused-result -g -fPIC" --enable-shared=no
   sed -i -e  's/marvell,mv-pp-uio/generic-uio/' modules/pp2/mv_pp_uio.c
   sed -i -e  's/O_CREAT/O_CREAT, S_IRUSR | S_IWUSR/' src/lib/file_utils.c
   make
   sudo make install

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
       port 1 { name ppio1 }
   }

Device identifier in this example is 'platform/f2000000.ethernet' where
'platform' is bus name and 'f2000000.ethernet' is linux platform bus
identifier for specific PP2.

Platform identifier can be found in sysfs:

::

   $ ls /sys/bus/platform/devices | grep ethernet
   f2000000.ethernet


