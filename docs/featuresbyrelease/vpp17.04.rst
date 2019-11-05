.. _vpp17.04:

###############################
Features for Release VPP 17.04
###############################

This section lists those features that became available in VPP Release 17.04:

Features
---------

Infrastructure
+++++++++++++++


* make test improvements
* vnet: add device-input threadplacement infra
* 64 bit per-thread counters
* process restart cli
* High performance timer wheels
* Plugin infrastructure improvements
   -  Support for .default_disabled, .version_required
* Added MAINTAINERS file

	
Host stack
+++++++++++

* TCP stack (experimental)
* DHCPv4 / DHCPv6 relay multi-destination
* DHCPv4 option 82
* ND proxy
* Attached hosts
* Consolidated DHCPv4 and DHCPv6 implementation

Interfaces
++++++++++++++

* DPDK 17.02 (retire support for DPDK 16.07)
* Add memif - packet memory interface for intra-host communication
* vhost: support interrupt mode
* DPDK as plugin (retired vpp_lite)
* DPDPK input optimizations
* Loopback interface allocation scheme


Network features
++++++++++++++++++

* IP Multicast FIB
* Bridging
   -  Learning on local interfaces
   -  Flushing of MACs from the L2 FIB
* SNAT
   -  CGN (Deterministic and dynamic)
   -  CGN configurable port allocation algorithm
   -  ICMP support
   -  Tenant VRF id for SNAT outside addresses
   -  Session dump / User dump
   -  Port allocation per protocol
* Security groups
   -  Routed interface support
   -  L2+L3 unified processing node
   -  Improve fragment handling
* Segment routing v6
   -  SR policies with weighted SID lists
   -  Binding SID
   -  SR steering policies
   -  SR Local SIDs
   -  Framework to expand local SIDs w/plugins
   -  Documentation
* IOAM
   -  UDP Pinger w/path fault isolation
   -  IOAM as type 2 metadata in NSH
   -  IAOM raw IPFIX collector and analyzer
   -  Anycast active server selection
   -  Documentation
   -  SRv6 Local SID
   -  IP6 HBH header and SR header co-existence
   -  Active probe
* LISP
   -  Statistics collection
   -  Generalize encap for overlay transport (vxlan-gpe support)
   -  Improve data plane speed
* GPE
   -  CLI
   -  NSH added to encap/decap path
   -  Renamed LISP GPE API to GPE
* MPLS
   -  Performance improvements (quad loop)
* BFD
   -  Command line interface
   -  Echo function
   -  Remote demand mode
   -  SHA1 authentication
* IPsec
   -  IKEv2 initiator features
* VXLAN
   -  unify IP4/IP6 control plane handling

API changes
++++++++++++++

* Python API: To avoid conflicts between VPP API messages names and the Python API binding function names, the VPP API methods are put into a separate proxy object https://gerrit.fd.io/r/#/c/5570/ 

  The api methods are now referenced as: vpp_handle = VPP(jsonfiles) vpp_handle.connect(...) vpp = vpp_handle.api vpp.show_version() vpp_handle.disconnect()

  For backwards compatibility VPP API methods are left in the main name space (VPP), but will be removed from 17.07.

   -  Python API: Change from cPython to CFFI.
   
* create_loopback message to be replaced with create_loopback_instance create_loopback will be removed from 17.07. `<https://gerrit.fd.io/r/#/c/5572/>`_ 


Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1704>`_


