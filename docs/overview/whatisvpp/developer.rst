.. _developer-friendly:

==================
Developer Friendly
==================

This section describes the different ways VPP is friendly to developers:

* Extensive runtime counters; throughput, `intructions per cycle <https://en.wikipedia.org/wiki/Instructions_per_cycle>`_, errors, events etc.
* Integrated pipeline tracing facilities
* Multi-language API bindings
* Integrated command line for debugging
* Fault-tolerant and upgradable

  * Runs as a standard user-space process for fault tolerance, software crashes seldom require more than a process restart. 
  * Improved fault-tolerance and upgradability when compared to running similar packet processing in the kernel, software updates never require system reboots. 
  * Development expierence is easier compared to similar kernel code 
  * Hardware isolation and protection (`iommu <https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit>`_)

* Built for security

  * Extensive white-box testing
  * Image segment base address randomization
  * Shared-memory segment base address randomization
  * Stack bounds checking
  * Static analysis with `Coverity <https://en.wikipedia.org/wiki/Coverity>`_
