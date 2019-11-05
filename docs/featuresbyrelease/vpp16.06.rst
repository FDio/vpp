.. _vpp16.06:

###############################
Features for Release VPP 16.06
###############################

The FD.io Project, relentlessly focused on data IO speed and efficiency supporting the creation of high performance, flexible, and scalable software defined infrastructures, announces the availability of the community's first software release (16.06).

In the four months since launching, FD.io has brought together more than 75 developers from 11 different companies including network operators, solution providers chip vendors, and network equipment vendors who are collaborating to enhance and innovate around the Vector Packet Processing (VPP) technology. The FD.io community has quickly formed to grow the number of projects from the initial VPP project to an additional 6 projects addressing a diverse set of requirements and usability across a variety of deployment environments.

The 16.06 release brings unprecedented performance: 480Gbps/200mpps with 8 million routes and 2k whitelist entries on standard high volume x86 servers.


Features
=========

In addition to the existing full suite of vswitch/vrouter features, the new 16.06 release adds:

* Enhanced Switching and Routing:
   - IPv6 Segment Routing multicast support
   - LISP xTR support
   - VXLAN over IPv6 underlay
   - Per interface whitelists
   - Shared adjacencies in FIB
* New and improved interface support:
   - Jumbo frame support for vhost-user
   - Netmap interface support
   - AF_Packet interface support
* Expanded and improved programmability:
   - Python API bindings
   - Enhanced JVPP Java API bindings
   - Debugging CLI
* Expanded Hardware and Software Support:
   - Support for ARM 32 targets including Raspberry Pi single-board computer
   - Support for DPDK 16.04
