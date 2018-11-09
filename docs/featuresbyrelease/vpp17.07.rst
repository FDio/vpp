.. _vpp17.07:

###############################
Features for Release VPP 17.07
###############################

This section lists those features that became available in VPP Release 17.07:

Features
---------

Infrastructure
+++++++++++++++

* make test; improved debuggability.
* TAB auto-completion on the CLI
* DPDK 17.05
* python 3 support in test infra
	
Host stack
+++++++++++

* Improved Linux TCP stack compatibility using IWL test suite (https://jira.fd.io/browse/VPP-720)
* Improved loss recovery (RFC5681, RFC6582, RF6675)
* Basic implementation of Eifel detection algorithm (RFC3522)
* Basic support for buffer chains
* Refactored session layer API
* Overall performance, scale and hardening

Interfaces
++++++++++++++

* memif: IP mode, jumbo frames, multi queue
* virtio-user support
* vhost-usr; adaptive (poll/interupt) support.

Network features
++++++++++++++++++

* MPLS Multicast FIB
* BFD FIB integration
* NAT64 support
* GRE over IPv6
* Segement routing MPLS
* IOAM configuration for SRv6 localsid
* LISP
   -  NSH support
   -  native forward static routes
   -  L2 ARP
* ACL multi-core suuport
* Flowprobe:
   -  Add flowstartns, flowendns and tcpcontrolbits
   -  Stateful flows and IPv6, L4 recording
* GTP-U support
* VXLAN GPE support for FIB2.0 and bypass.

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1707>`_
