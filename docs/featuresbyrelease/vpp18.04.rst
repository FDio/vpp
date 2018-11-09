.. _vpp18.04:

###############################
Features for Release VPP 18.04
###############################

This section lists those features that became available in VPP Release 18.04. There is a summary graphic that identifies what areas the features are associated with, followed by a list of all the features for this release:

.. image:: /_images/Features1804.png

Infrastructure
+++++++++++++++

* DPDK 18.02.1
* ARM aarch64 integrated into CI

VNET & Plugins
+++++++++++++++

* ERSPAN
* L3DSR load balancing support
* VPC bonding / LACP
* IPv4/IPv6 packet reassembly
* IPv6 link-local support
* Asymmetrical static NAT
* 464XLAT for NAT44
* MAP-T CE support
* Intel Adaptive Virtual Function native device driver plugin
* Marvell device plugin
* SRv6 static, dynamic and masquerading proxy plugins
* MPLS Uniform mode
* IGMP plugin
* IPIP tunnel support (IPv4/IPv6 over IPv4/IPv6)
* IPv6 Router Discovery mechanism

VLIB
+++++

* ARM-optimized library variations for key functions
* Better handling of physmem on non-NUMA kernels

Host stack
+++++++++++

* TLS support via OpenSSL or mbedtls software engines
* Session layer can utilize both shm and memfd (secure) FIFO segments
* STCP
* VCL logging / tracing

API framework
++++++++++++++

* New API definition compiler (vppapigen)
* Memory (shm) and socket APIs refactored
* API handlers refactored to make them transport (shared memory or socket) agnostic
* Improved support for bootstrapping of the shm API with memfd segments over the socket API

Packaging
++++++++++

* SELinux for RPM builds
* Debuginfo RPMs
* ARM aarch64 for Ubuntu

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1810>`_

