.. _2017_11_15_vpphoststack:

.. toctree::

##############
VPP Host Stack
##############

Event
-----

Although packet forwarding with VPP and DPDK can now scale to tens of millions
of packets per second per core, lack of alternatives to kernel-based
sockets means that containers and host applications cannot
take full advantage of this speed. To fill this gap, VPP 
was recently added functionality specifically designed 
to allow containerized or host applications to communicate 
via shared-memory if co-located, or via a high-performance
TCP stack inter-host.

This presentation was held during the 2017 DPDK Summit
 on September 26th, 2017.

Speakers
--------

* Florin Coras
* Dave Barach
* Keith Burns 
* Dave Wallace

Slideshow
---------

`Presentation PDF <https://wiki.fd.io/images/f/f2/Vpp-hoststack.pdf>`_

Video
-----

`Video Presentation <https://www.youtube.com/watch?v=NWG7A0are00>`_


