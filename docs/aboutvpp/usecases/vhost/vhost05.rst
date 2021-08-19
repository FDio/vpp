.. _vhost05:

Limitations
-----------
There are some limitations when using the qemu vhost driver. Some are described in this section.

Performance
^^^^^^^^^^^

VPP performance with vHost is limited by the Qemu vHost driver. FD.io VPP 18.04 CSIT vHost testing
shows with 2 threads, 2 cores and a Queue size of 1024 the maximum NDR throughput was about 7.5 Mpps.
This is about the limit at this time.

For all the details on the CSIT VM vhost connection refer to the 
`CSIT VM vHost performance tests <https://docs.fd.io/csit/rls1804/report/vpp_performance_tests/packet_throughput_graphs/vm_vhost.html>`_.


Features
^^^^^^^^

These are the features not supported with FD.io VPP vHost.

* VPP implements vHost in device mode only. VPP is intended to work with Qemu which implements vHost in driver mode, it does not implement vHost driver mode.
* VPP vHost implementation does not support checksum or transmit segmentation offload.
* VPP vHost implementation does not support packet receive filtering feature for controlling receive traffic.
