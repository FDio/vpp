.. _vpp_sswan_doc:

VPP-SSWAN
=======================

``VPP-SSWAN`` is a StrongSwan plugin that helps offloading Strongswan IPsec ESP
process from Linux Kernel to ``VPP``.

The kernel-vpp plugin is an interface to the IPsec and networking backend for
`VPP <https://wiki.fd.io/view/VPP>`__ platform using the
`VPP C API <https://wiki.fd.io/view/VPP/How_To_Use_The_C_API>`__.
It provides address and routing lookup functionality and installs routes for
IPsec traffic.
It installs and maintains Security Associations and Policies to the
`VPP IPsec <https://wiki.fd.io/view/VPP/IPSec_and_IKEv2#IPSec>`__.

Prerequisites
-------------

``VPP`` in release mode should be built before compiling ``vpp-swan plugin``.
The dependencies of ``StrongSwan`` should be installed before building
``VPP-SSWAN``. In addition ``libsystemd-dev`` should be installed.

Build VPP Strongswan Plugin
-------------

The following list of things will be done to build ``vpp-swan plugin``:

- download strongswan source code to:
``path/to/vpp/build/external/downloads``

- unzip source code strongswan to:
``path/to/vpp/build-root/build-vpp-native/external/sswan``

- check if you have installed packages: ``libsystemd-dev`` on your OS

- configure strongswan by:
``./configure --prefix=/usr --sysconfdir=/etc --enable-libipsec
--enable-systemd --enable-swanctl --disable-gmp --enable-openssl``

- compile strongswan in:
``path/to/vpp/build-root/build-vpp-native/external/sswan``

- compile ``vpp-swan plugin`` by:

::

   ./make all

- if everything it ok, copy the compiled ``vpp-swan plugin`` to:
``/usr/lib/ipsec/plugins``

Build/install Strongswan
-------------

It is recommended to use ``Strongswan`` in version ``5.9.6`` or ``5.9.5``
installed from this script, due to configuration Strongswan that is required.
Only version ``5.9.5`` and ``5.9.6`` was tested with this plugin.

To install the built Strongswan, please execute the following command:

::

   path/to/vpp/build-root/build-vpp-native/external/sswan/sudo make install

Insert plugin in runtime mode
-------------

After builded this plugin and also installed Strongswan you can loaded plugin
into Strongswan directory by:

::

   ./make install

Or you can do manually copy ``libstrongswan-kernel-vpp.so`` into:
``/usr/lib/ipsec/plugins`` and also ``kernel-vpp.conf`` into: ``/etc/strongswan.d/charon/``

And also you should restart Strongswan by:

::

   systemctl restart strongswan.service

Configuration Strongswan
-------------
In ``swanctl.conf`` file you can find example configuration to initialize
connections between two endpoints.

Copy this file into: ``/etc/swanctl/conf.d/swanctl.conf``

Configuration VPP
-------------

In your ``startup.conf`` add these following commands:

::

   plugins {
     plugin linux_cp_plugin.so { enable }
     plugin ikev2_plugin.so { disable }
    }

   linux-cp {
      lcp-sync
   }

To enable ``CP Plugin`` and disable ``IKEv2`` plugin.

These following commands executed in ``VPP``:

::

   lcp create eth2 host-if eth2
   set interface state eth2 up
   set interface ip address eth2 192.168.0.2/24
   set int state eth1 up
   set int ip addr eth1 192.168.200.1/24

To create interface by ``CP Plugin`` and also setup two ethernet interfaces.

Misc
-------------
This plugin is based on:
`https://github.com/matfabia/strongswan
<https://github.com/matfabia/strongswan>`__

Author: Matus Fabian <matfabia@cisco.com>