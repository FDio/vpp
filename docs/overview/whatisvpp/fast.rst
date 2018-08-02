.. _fast:

================================
Fast, Scalable and Deterministic
================================

This section describes the ways that VPP is fast, scalable and deterministic:

* `Continuous integration and system testing (CSIT) <https://wiki.fd.io/view/CSIT#Start_Here>`_

  * Including continuous & extensive, latency and throughput testing

* Layer 2 Cross Connect (L2XC), typically achieve 15+ Mpps per core.
* Tested to achieve **zero** packet drops and ~15µs latency.
* Performance scales linearly with core/thread count
* Supporting millions of concurrent lookup tables entries

Please see :ref:`performance` for more information.
