.. _scalar_vector:

==================================
Scalar vs Vector packet processing
==================================

FD.io VPP is developed using vector packet processing, as opposed to
scalar packet processing.

Vector packet processing is a common approach among high performance packet
processing applications such FD.io VPP and `DPDK <https://en.wikipedia.org/wiki/Data_Plane_Development_Kit>`_.
The scalar based approach tends to be favoured by network stacks that
don't necessarily have strict performance requirements.

**Scalar Packet Processing**

A scalar packet processing network stack typically processes one packet at a
time: an interrupt handling function takes a single packet from a Network
Interface, and processes it through a set of functions: fooA calls fooB calls
fooC and so on.

.. code-block:: none 

   +---> fooA(packet1) +---> fooB(packet1) +---> fooC(packet1)
   +---> fooA(packet2) +---> fooB(packet2) +---> fooC(packet2)
   ...
   +---> fooA(packet3) +---> fooB(packet3) +---> fooC(packet3)


Scalar packet processing is simple, but inefficient in these ways:

* When the code path length exceeds the size of the Microprocessor's instruction
  cache (I-cache), `thrashing
  <https://en.wikipedia.org/wiki/Thrashing_(computer_science)>`_ occurs as the
  Microprocessor is continually loading new instructions. In this model, each
  packet incurs an identical set of I-cache misses.
* The associated deep call stack will also add load-store-unit pressure as
  stack-locals fall out of the Microprocessor's Layer 1 Data Cache (D-cache).

**Vector Packet Processing**

In contrast, a vector packet processing network stack processes multiple packets
at a time, called 'vectors of packets' or simply a 'vector'. An interrupt
handling function takes the vector of packets from a Network Interface, and
processes the vector through a set of functions: fooA calls fooB calls fooC and
so on.

.. code-block:: none 

   +---> fooA([packet1, +---> fooB([packet1, +---> fooC([packet1, +--->
               packet2,             packet2,             packet2,
               ...                  ...                  ...
               packet256])          packet256])          packet256])

This approach fixes: 

* The I-cache thrashing problem described above, by amortizing the cost of
  I-cache loads across multiple packets.

* The inefficiencies associated with the deep call stack by receiving vectors
  of up to 256 packets at a time from the Network Interface, and processes them
  using a directed graph of node. The graph scheduler invokes one node dispatch
  function at a time, restricting stack depth to a few stack frames.

The further optimizations that this approaches enables are pipelining and
prefetching to minimize read latency on table data and parallelize packet loads
needed to process packets.

Press next for more on Packet Processing Graphs.
