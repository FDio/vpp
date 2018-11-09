.. _vpp17.10:

###############################
Features for Release VPP 17.10
###############################

This section lists those features that became available in VPP Release 17.10:

Features
---------

Infrastructure
+++++++++++++++

* DPDK 17.08
* IP reassembly
* Bounded-index extensible hash bucket-level LRU cache
* Templated timer wheel improvements

API
++++++++++++++

* C/C++ language binding
* API stats
	
Host stack
+++++++++++

* VPP TCP stack scale/congestion improvements
* VPP Comms Library (VCL)
* Overall performance, scale and hardening

Network features
++++++++++++++++++

* IPSec rework - utilize new FIB
* VPLS and VPWS implementation
* NAT
   -  Renamed SNAT to NAT
   -  Performance / Scale
   -  Destination NAT44 with load-balancing
   -  In2out translation as an output feature on the outside interface
   -  Fullback to 3-tuple key for non TCP/UDP/ICMP sessions
* Security Groups/ACLs
   -  "Replace" semantics for adding a new MacIP acl
   -  Test suite tests for MacIP ACLs
* ONE-LISP
   -  Map-server fallback support
   -  Preemptive re-fetch of active mappings that are about to expire
   -  ND termination
* PPPoE
   -  PPPoE Control Plane packet dispatch
   -  PPPoE decapsulation
   -  PPPoE encapsulation

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1710>`_
