.. _performance:

Performance
===========

One of the benefits of FD.io VPP is it's high performance on relatively low-power computing.
Included are the following.

* A high-performance user-space network stack designed for commodity hardware:

  - L2, L3 and L4 features and encapsulations.

* Optimized packet interfaces supporting a multitude of use cases:

  - An integrated vhost-user backend for high speed VM-to-VM connectivity
  - An integrated memif container backend for high speed Container-to-Container connectivity
  - An integrated vhost based interface to punt packets to the Linux Kernel

* The same optimized code-paths run execute on the host, and inside VMs and Linux containers
* Leverages best-of-breed open source driver technology: `DPDK <https://www.dpdk.org/>`_
* Tested at scale; linear core scaling, tested with millions of flows and mac addresses  

These features have been designed to take full advantage of common micro-processor optimization techniques, such as: 

* Reducing cache and TLS misses by processing packets in vectors
* Realizing `IPC <https://en.wikipedia.org/wiki/Instructions_per_cycle>`_ gains with vector instructions such as: SSE, AVX and NEON
* Eliminating mode switching, context switches and blocking, to always be doing useful work
* Cache-lined aligned buffers for cache and memory efficiency


Continuous System Integration and Testing (CSIT)
------------------------------------------------

The Continuous System Integration and Testing (CSIT) project provides functional and performance
testing for FD.io VPP. This testing is focused on functional and performance regresssions. The results
are posted to `CSIT Test Report <https://docs.fd.io/csit/master/report/>`_.

For more about CSIT checkout the following links:

* `CSIT Code Documentation <https://docs.fd.io/csit/master/doc/overview.html>`_
* `CSIT Test Overview <https://docs.fd.io/csit/master/report/introduction/overview.html>`_
* `VPP Performance Dashboard <https://docs.fd.io/csit/master/trending/introduction/index.html>`_


CSIT Packet Throughput examples
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Following are pointers to a few of the CSIT test reports. The test's titles read like this:

<packet size>-<number of threads><number of cores>-<test>-<interface type> 

For example the test with the title 64b-2t1c-l2switching-base-i40e is the
test that does l2 switching using 64 byte packets, 2 threads, 1 core using an i40e
interface.

Here are a few examples:

* `L2 Ethernet switching <https://docs.fd.io/csit/master/report/vpp_performance_tests/packet_throughput_graphs/l2.html>`_
* `IPv4 Routing <https://docs.fd.io/csit/master/report/vpp_performance_tests/packet_throughput_graphs/ip4.html>`_
* `IPv6 Routing <https://docs.fd.io/csit/master/report/vpp_performance_tests/packet_throughput_graphs/ip6.html>`_


Trending Throughput Graphs
^^^^^^^^^^^^^^^^^^^^^^^^^^ 

These are some of the trending packet throughput graphs from the CSIT `trending dashboard <https://docs.fd.io/csit/master/trending/introduction/index.html>`_. **Please note that**, performance in the trending graphs will change on a nightly basis in line with the software development cycle:

* `L2 Ethernet Switching Trending <https://docs.fd.io/csit/master/trending/trending/l2.html>`_
* `IPv4 Routing Trending <https://docs.fd.io/csit/master/trending/trending/ip4.html>`_
* `IPv6 Routing Trending <https://docs.fd.io/csit/master/trending/trending/ip6.html>`_
