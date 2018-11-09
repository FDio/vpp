.. _vpp18.10:

###############################
Features for Release VPP 18.10
###############################

This section lists those features that became available in VPP Release 18.10: 

Infrastructure
+++++++++++++++

* DPDK 18.08 Integration
* New Stats infrastructure (interface, error, node performance counters)
* Add configurable "Doug Lea malloc" support

VNET & Plugins
+++++++++++++++

* Load balancing: support per-port VIP and all-port VIP
* Port NSH plugin to VPP
* NAT

  - Configurable port range
  - Virtual Fragmentation Reassembly for endpoint-dependent mode
  - Client-IP based session affinity for load-balancing
  - TCP MSS clamping
  - Session timeout
  - Bug-fixing and performance optimizations

Host stack
+++++++++++

* Support for applications with multiple workers
* Support for binds from multiple app workers to same ip:port
* Switched to a message queue for io and control event notifications
* Support for eventfd based notifications as alternative to mutext-condvar pair
* VCL refactor to support async event notifications and multiple workers
* TLS async support in client for HW accleration
* Performance optimizations and bug-fixing
* A number of binary APIs will be deprecated in favor of using the event message queue. Details in the API section.

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1810>`_

