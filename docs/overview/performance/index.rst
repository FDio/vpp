.. _performance:

Performance
===========

Overview
^^^^^^^^

One of the benefits of FD.io VPP, is high performance on relatively low-power computing, this performance is based on the following features:

* A high-performance user-space network stack designed for commodity hardware.

  - L2, L3 and L4 features and encapsulations.

* Optimized packet interfaces supporting a multitude of use cases.

  - An integrated vhost-user backend for high speed VM-to-VM connectivity.
  - An integrated memif container backend for high speed Container-to-Container connectivity. 
  - An integrated vhost based interface to punt packets to the Linux Kernel. 

* The same optimized code-paths run execute on the host, and inside VMs and Linux containers.
* Leverages best-of-breed open source driver technology: `DPDK <https://www.dpdk.org/>`_.
* Tested at scale; linear core scaling, tested with millions of flows and mac addresses.  

These features have been designed to take full advantage of common micro-processor optimization techniques, such as: 

* Reducing cache and TLS misses by processing packets in vectors. 
* Realizing `IPC <https://en.wikipedia.org/wiki/Instructions_per_cycle>`_ gains with vector instructions such as: SSE, AVX and NEON.
* Eliminating mode switching, context switches and blocking, to always be doing useful work.  
* Cache-lined aliged buffers for cache and memory efficiency.


Packet Throughput Graphs
^^^^^^^^^^^^^^^^^^^^^^^^

These are some of the packet throughput graphs for FD.io VPP 18.04 from the CSIT `18.04 benchmarking report <https://docs.fd.io/csit/rls1804/report/>`_.   

.. toctree::

    current_l2_throughput.rst    
    current_ndr_throughput.rst
    current_ipv4_throughput.rst
    current_ipv6_throughput.rst

Trending Throughput Graphs
^^^^^^^^^^^^^^^^^^^^^^^^^^ 

These are some of the trending packet throughput graphs from the CSIT `trending dashboard <https://docs.fd.io/csit/master/trending/introduction/index.html>`_. **Please note that**, performance in the trending graphs will change on a nightly basis in line with the software development cycle.

.. toctree::

    trending_l2_throughput.rst
    trending_ipv4_throughput.rst
    trending_ipv6_throughput.rst

For More information on CSIT 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are FD.io Continuous System Integration and Testing (CSIT)'s documentation links.

* `CSIT Code Documentation <https://docs.fd.io/csit/master/doc/overview.html>`_
* `CSIT Test Overview <https://docs.fd.io/csit/rls1804/report/introduction/overview.html>`_
* `VPP Performance Dashboard <https://docs.fd.io/csit/master/trending/introduction/index.html>`_
