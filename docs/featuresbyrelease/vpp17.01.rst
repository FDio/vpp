.. _vpp17.01:

###############################
Features for Release VPP 17.01
###############################

This section lists those features that became available in VPP Release 17.01:

Features
---------

* Integrated November 2016 DPDK release
* Complete rework of Forwarding Information Base (FIB)
* Performance Improvements
   - Improvements in DPDK input and output nodes
   - Improvements in L2 path
   - Improvmeents in IPv4 lookup node
* Feature Arcs Improvements
   - Consolidation of the code
   - New feature arcs
      + device-input
      + interface-output
* DPDK Cryptodev Support
   - Software and Hardware Crypto Support
* DPDK HQoS support
* Simple Port Analyzer (SPAN)
* Bidirectional Forwarding Detection
   - Basic implementation
* IPFIX Improvements
* L2 GRE over IPSec tunnels
* Link Layer Discovery Protocol (LLDP)
* Vhost-user Improvements
   - Performance Improvements
   - Multiqueue
   - Reconnect
* LISP Enhancements
   - Source/Dest control plane support
   - L2 over LISP and GRE
   - Map-Register/Map-Notify/RLOC-probing support
   - L2 API improvements, overall code hardening
* Plugins:
   - New: ACL
   - New: Flow per Packet
   - Improved: SNAT
      + Mutlithreading
      + Flow export
* Doxygen Enhancements
* Luajit API bindings
* API Refactoring
   - file split
   - message signatures
* Python and Scapy based unit testing infrastructure
   - Infrastructure
   - Various tests
* Packet Generator improvements
* TUN/TAP jumbo frames support
* Other various bug fixes and improvements


Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1701>`_
