.. _vpp18.01:

###############################
Features for Release VPP 18.01
###############################

This section lists those features that became available in VPP Release 18.01:

Features
----------

Infrastructure
+++++++++++++++

* DPDK 17.11
* TCP Checksum Offload
* Arm64/Arm-v8 support
* SUSE packaging
* bihash_vec8_8 variant
* PCI rework to support VFIO
* chi-squared test calculator

SNAT / NAT
++++++++++++

* One armed NAT
* Twice NAT44
* NAT hairpinning rework
* NAT64 multi-thread
* NAT64 IPFIX
* NAT64 Fragmentation
* NAT: DS-Lite
* Remove old SNAT API
* ACL-based NAT

VNET 
+++++++
    
* DNS name resolver
* BIER
* GENEVE Tunnel
* IPSec Openssl 1.1.0 api support
* FIB improvements
* tap v2

API
+++++++

* VPP stats (Broadcast & Multicast support)
* SR MPLS
* VPP Object Model (VOM)

Host stack
+++++++++++

* VPP TCP Stack scale / congestion improvements
* Refactor UDP
* Namespace support
* Session rules table
* VPP Comms Library (VCL) improvements


ACL
+++++

* ACL stats

Plugins
++++++++++

* Kube-proxy
* L2 Emulation
* Memif

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1801>`_


