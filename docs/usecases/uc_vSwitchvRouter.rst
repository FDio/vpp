.. _vswitch:

.. toctree::

.. _vswitchrtr:

vSwitch/vRouter
===============


FD.io VPP as a vSwitch/vRouter
------------------------------

.. note::

   We need to provide commands and and show how to use VPP as a vSwitch/vRouter

One of the use cases for the FD.io VPP platform is to implement it as a
virtual switch or router. The following section describes examples of
possible implementations that can be created with the FD.io VPP platform. For
more in depth descriptions about other possible use cases, see the list
of 

.. figure:: /_images/VPP_App_as_a_vSwitch_x201.jpg
   :alt: Figure: Linux host as a vSwitch
   :align: right

   Figure: Linux host as a vSwitch

You can use the FD.io VPP platform to create out-of-the-box virtual switches
(vSwitch) and virtual routers (vRouter). The FD.io VPP platform allows you to
manage certain functions and configurations of these application through
a command-line interface (CLI).

Some of the functionality that a switching application can create
includes:

* Bridge Domains
* Ports (including tunnel ports)
* Connect ports to bridge domains
* Program ARP termination

Some of the functionality that a routing application can create
includes:

* Virtual Routing and Forwarding (VRF) tables (in the thousands)
* Routes (in the millions)
