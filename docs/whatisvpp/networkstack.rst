.. _network-stack:

=============
Network Stack
=============

This section describes a little about the FD.io network stack and describes some benefits:

* Layer 2 - 4 Network Stack

  * Fast lookup tables for routes, bridge entries
  * Arbitrary n-tuple classifiers 
  * Control Plane, Traffic Management and Overlays

 
* `Linux <https://en.wikipedia.org/wiki/Linux>`_ and `FreeBSD <https://en.wikipedia.org/wiki/FreeBSD>`_ support

  * Support for standard Operating System Interfaces such as AF_Packet, Tun/Tap & Netmap.

* Network and cryptographic hardware support with `DPDK <https://www.dpdk.org/>`_.
* Container and Virtualization support

  * Para-virtualized interfaces; Vhost and Virtio
  * Network Adapters over PCI passthrough
  * Native container interfaces; MemIF
  
* Host Stack
* Universal Data Plane: one code base, for many use cases
 
  * Discrete appliances; such as `Routers <https://en.wikipedia.org/wiki/Router_(computing)>`_ and `Switches <https://en.wikipedia.org/wiki/Network_switch>`_.
  * `Cloud Infrastructure and Virtual Network Functions <https://en.wikipedia.org/wiki/Network_function_virtualization>`_
  * `Cloud Native Infrastructure <https://www.cncf.io/>`_
  * The same binary package for all use cases. 

* Out of the box production quality, with thanks to `CSIT <https://wiki.fd.io/view/CSIT#Start_Here>`_. 

For more information, please see :ref:`featuresbyrelease` for the complete list.

For more on the TCP Host Stack press next.
