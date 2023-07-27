.. _vpp_sswan_doc:

VPP-SSWAN
=======================

``VPP-SSWAN`` is a StrongSwan plugin that helps offloading Strongswan IPsec ESP
process from Linux Kernel to ``VPP``.

The ``VPP-SSWAN`` takes advantage of ``StrongSwan`` extendable plugin design
and translates ``StrongSwan`` SA creation/deletion and routing
update operations into ``VPP`` C API calls. The successful execution of the
API calls means the operations shall be performed by VPP smoothly.

Inside ``VPP-SSWAN``, the kernel-vpp plugin is an interface to the IPsec and
networking backend for `VPP <https://wiki.fd.io/view/VPP>`__ platform using
the `VPP C API <https://wiki.fd.io/view/VPP/How_To_Use_The_C_API>`__.
It provides address and routing lookup functionality and installs routes for
IPsec traffic.

There are two plugins to configuration in the two different mode:
policy and route base IPSec.

The plugin based on policy base mode installs, maintains Security
Associations and Policies to the `VPP IPsec <https://wiki.fd.io/view/VPP/IPSec_and_IKEv2#IPSec>`__.

The plugin based on route based mode installs, maintains Security
Associations and installs ipip interface `VPP IPsec Protection Model <https://wiki.fd.io/view/VPP/IPSec#Protection_Model>`__.

Since ``StrongSwan`` expects both IKE and IPsec traffic coming through the
same network protected interfaces, the ``VPP-SSWAN`` expects the IKE traffic
being diverted to Linux Kernel through the help of
`VPP Linux Control Plane <https://s3-docs.fd.io/vpp/22.10/developer/plugins/
lcp.html>`__. It is important to notice that due to LCP is a Tun/Tap interface,
the IPsec performance will be limited by it if Transport mode of IPsec is used.

Prerequisites
-------------

``VPP`` in release mode should be built before compiling ``vpp-swan plugin``.
User may install ``StrongSwan`` prior to compile the plugin. However the
plugin requires downloading ``StrongSwan`` source to include some of its
header files to compile ``VPP-SSWAN``. In addition ``libsystemd-dev``
should be installed prior to compile the plugin.

Please Note: ONLY Strongswan version ``5.9.5`` and ``5.9.6`` were tested with
this plugin.

Build VPP Strongswan Plugin
-------------

``VPP-SSWAN`` requires ``StrongSwan`` source to compile. To obtain
``StrongSwan`` the simplest way is to run the following commands:

::

   cd path/to/vpp/external/strongswan/vpp_swan/
   make all

Or you may download ``StrongSwan``  from its github page. It is recommended to
use ``Strongswan`` version ``5.9.6`` or ``5.9.5`` for ``VPP-SSWAN`` to be
compiled and integrate. The following steps are required for manually download
``Strongswan`` source:

- download strongswan source code to:
``path/to/vpp/build/external/downloads``

- unzip source code strongswan to:
``path/to/vpp/build-root/build-vpp-native/external/sswan``

- check if you have installed packages: ``libsystemd-dev`` on your OS

- configure strongswan by:
``./autogen.sh``
``./configure --prefix=/usr --sysconfdir=/etc --enable-libipsec
--enable-systemd --enable-swanctl --disable-gmp --enable-openssl``

- compile ``vpp-swan plugin`` by:

::

   cd path/to/vpp/external/strongswan/vpp_swan/
   make

Build/install Strongswan (Optional)
-------------

In case you haven't installed ``Strongswan`` yet, you may use the following
simple command to compile and install ``Strongswan`` from the downloaded source.

::

   cd path/to/vpp/external/strongswan/vpp_swan/
   make pull-swan
   make install-swan

Install VPP-SWAN plugin in policy mode IPSec into StrongSwan
-------------

After the ``VPP-SSWAN`` plugin has been built and ``Strongswan`` was installed,
the following command will install the ``VPP-SSWAN`` plugin into ``Strongswan``.

::

   cd path/to/vpp/external/strongswan/vpp_swan/
   make install-policy

Or you can manually copy:
``libstrongswan-kernel-vpp.so`` into: ``/usr/lib/ipsec/plugins``,
and also ``kernel-vpp.conf`` into: ``/etc/strongswan.d/charon/``.

Install VPP-SWAN plugin in route mode IPSec into StrongSwan
-------------

After the ``VPP-SSWAN`` plugin has been built and ``Strongswan`` was installed,
the following command will install the ``VPP-SSWAN`` plugin into ``Strongswan``.

::

   cd path/to/vpp/external/strongswan/vpp_swan/
   make install-route

Or you can manually copy:
``libstrongswan-kernel-libipsec-vpp.so`` into: ``/usr/lib/ipsec/plugins``,
and also ``kernel-libipsec-vpp.conf`` into: ``/etc/strongswan.d/charon/``.

Please Note: ONLY one of them should be installed into Strongswan directory.

Now you can restart ``Strongswan`` by executing the following command:

::

   systemctl restart strongswan.service

Configuration Strongswan
-------------

As an example, ``policy-based/swanctl.conf`` or ``route-based/swanctl.conf``
files provide an example configuration to initialize connections between
two endpoints.

Please Note: ``swanctl.conf`` depends on type of plugin that was installed.

You may update the file based on your need and copy into:
``/etc/swanctl/conf.d/swanctl.conf``

Configuration VPP
-------------

Some special treatment to VPP are required in your VPP ``startup.conf``.
Since we use ``Strongswan`` to process IKE messages, we should disable VPP's
IKEv2 plugin. Also as mentioned ``Linux Control Plane`` plugin is needed to
route the traffic between VPP interface and Tun/Tap interface. To do so, simply
adding the following commands:

::

   plugins {
     plugin linux_cp_plugin.so { enable }
     plugin ikev2_plugin.so { disable }
    }

   linux-cp {
      lcp-sync
   }

Running VPP
-------------

Based on the provided sample ``swanctl.conf``, the following commands are
required to be executed in ``VPP``:

::

   lcp create eth2 host-if eth2
   set interface state eth2 up
   set interface ip address eth2 192.168.0.2/24
   set int state eth1 up
   set int ip addr eth1 192.168.200.1/24

In the commands above we assume ``eth2`` is the WAN interface to receive both
IKE message and ESP encapsulated packets, and ``eth1`` is the LAN interface to
receive plain packets to be encrypted. With the commands a ``Linux CP`` interface
is created to mirror the ``eth2`` interface to Linux Kernel, and both interfaces
were set the IP addresses followed by the ``swanctl.conf``.

With the commands successfully executed and the security policy is succesfully
agreed between two IKE daemons (one with VPP as IPsec processing engine), you may
see the packets are encrypted/decrypted by VPP smoothly.

Misc
-------------
This plugin is based on:
`https://github.com/matfabia/strongswan
<https://github.com/matfabia/strongswan>`__

Author: Matus Fabian <matfabia@cisco.com>
