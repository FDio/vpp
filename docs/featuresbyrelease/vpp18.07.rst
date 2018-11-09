.. _vpp18.07:

###############################
Features for Release VPP 18.07
###############################

This section lists those features that became available in VPP Release 18.07: 

Infrastructure
+++++++++++++++

* DPDK 18.02.1

   - Complete rework of the dpdk-input node
   - Display rx/tx burst function name in "show hardware detail"
   - Improve buffer alloc perfomance
      + This is ~50% improvement in buffer alloc performance. For a 256 buffer allocation, it was ~10 clocks/buffer, now is < 5 clocks.
   - Add per-numa page allocation info to 'show memory'
   - Vectorized bihash_{48,40,24,16}_8 key compare
      + bihash_48_8 case:
         * Scalar code: 6 clocks
         * SSE4.2 code: 3 clocks
         * AVX2 code: 2.27 clocks
         * AVX512 code: 1.5 clocks
   - Pollable Stats
      + Stats are now available to a client in a shared memory segment and in the form of a directory, allowing very high performance polling of stats without directly querying VPP.

VNET & Plugins
+++++++++++++++

* IGMP improvements
   - Enable/Disable an interface for IGMP
   - improve logging
   - refactor common code
   - no orphaned timers
   - IGMP state changes in main thread only
   - Large groups split over multiple state-change reports
   - SSM range configuration API.
   - more tests
* IP: vectorized IP checksum
* VXLAN : HW offload RX flow
* Rework kube-proxy into LB plugin and add NATA66
* NAT:
   - Code refactor
   - Syslog
   - Multiple outside interfaces
   - Endpoint dependent filtering and mapping
* ACL:
   - Tuple Merge algorithm cleanup and integration
   - Processing pipeline optimizations
   - Refactoring
* Experimental AVF driver


Host stack
+++++++++++

* Session: performance improvements, add support for connectionless transports, datagram reception and transmission
* TCP: congestion control improvements and overall fixes
* UDP: datagram mode
* TLS async support

Known issues
---------------

For the full list of issues please refer to fd.io `JIRA <https://jira.fd.io/>`_.

Issues fixed
--------------

For the full list of fixed issues please refer to:

* fd.io `JIRA <https://jira.fd.io/>`_
* git `commit log <https://git.fd.io/vpp/log/?h=stable/1807>`_

