.. _whatisvpp:

=================================
The Vector Packet Processor (VPP)
=================================

This section describes some of the core concepts and features of FD.io VPP.

To start with FD.io VPP uses a technique called Vector Packet Processing.
This gives FD.io VPP a siginficant performance improvement over packet
processing applications that use scalar processing. 

Also, At the heart of Fd.io VPP's modular design is a 'Packet Processing Graph'.
This makes FD.io VPP scalable and easily extensible.

The FD.io software also includes a feature rich network stack. This includes
a TCP host stack that utilizes VPP’s graph based forwarding model and vectorized
packet processing.

FD.io VPP is tested nightly for functionality and performance with the
CSIT project.

For more information on any of these features click on the links below or
press next.

.. toctree::
   :maxdepth: 1

   scalar-vs-vector-packet-processing.rst
   extensible.rst
   networkstack.rst
   hoststack.rst
   developer.rst
   supported.rst
   performance.rst

Press next for more about Scalar/Vector Packet processing.
