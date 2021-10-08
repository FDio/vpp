Marvell device plugin
=====================

Overview
--------

This plugins provides native device support for Marvell PP2 network
device, by use of Marvell Usermode SDK
(`MUSDK <https://github.com/MarvellEmbeddedProcessors/musdk-marvell>`__).
Code is developed and tested on
`MACCHIATObin <http://macchiatobin.net>`__ board.

Prerequisites
-------------

Plugins depends on installed MUSDK and Marvell provided linux
`kernel <https://github.com/MarvellEmbeddedProcessors/linux-marvell>`__
with MUSDK provided kernel patches (see ``patches/linux`` in musdk repo
and relevant documentation. Kernel version used: **4.14.22
armada-18.09.3** MUSDK version used: **armada-18.09.3** Following kernel
modules from MUSDK must be loaded for plugin to work: \*
``musdk_cma.ko`` \* ``mv_pp_uio.ko``

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

Interface Creation
~~~~~~~~~~~~~~~~~~

Interfaces are dynamically created with following CLI:

::

   create interface marvell pp2 name eth0
   set interface state mv-ppio-0/0 up

Where ``eth0`` is linux interface name and ``mv-ppio-X/Y`` is VPP
interface name where X is PP2 device ID and Y is PPIO ID Interface needs
to be assigned to MUSDK in FDT configuration and linux interface state
must be up.

Interface Deletion
~~~~~~~~~~~~~~~~~~

Interface can be deleted with following CLI:

::

   delete interface marvell pp2 <interface name>

Interface Statistics
~~~~~~~~~~~~~~~~~~~~

Interface statistics can be displayed with
``sh hardware-interface mv-ppio0/0`` command.

Interaction with DPDK plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This plugin doesn’t have any dependency on DPDK or DPDK plugin but it
can work with DPDK plugin enabled or disabled. It is observed that
performance is better around 30% when DPDK plugin is disabled, as DPDK
plugin registers own buffer manager, which needs to deal with additional
metadata in each packet.

DPKD plugin can be disabled by adding following config to the
startup.conf.

::

   plugins {
     dpdk_plugin.so { disable }
   }
