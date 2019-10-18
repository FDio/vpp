.. _dev_punt:

.. toctree::

Punting Packets
===============

Overview
________

To 'punt' can mean different things to different people. In VPP the
data-plane punts when a packet cannot be handled by any further
nodes. Punt differs from drop, in that VPP is giving other elements of
the system the opportunity to handle this packet.

A popular meaning of punt is to send packets to the user/control-plane.
This is specific option of the more general case above, where VPP is
handing the packet to the control-plane for further processing.

The Punt Infrastructure
_______________________

Exception packets are those that a given node cannot handle via normal
mechanisms.
Punting of exception packets is handled via the VLIB 'punt
infra'. There are two types of nodes; sources and sinks. Sources
allocate a punt 'reason' from the infrastructure and load time. When
they encounter an exception during switch time it will tag the packet
with the reason and ship the packet of the the punt-dispatch node. A
sink will register with the punt infra at load time so it can receive
packets that were punted for that reason. If no sinks are registered
for a given reason the packet is dropped, if multiple sinks register
the packets are replicated.

This mechanism allows us to extend the system to deal with packets
that the source node would otherwise drop.


Punting to the Control Plane
____________________________

Active Punt
-----------

The user/control-plane specifies that this is the type of packet I
want to receive and this is where I want it sent.

Currently there exists 3 ways to describe how to match/classify the
packets to be punted:

1) a matching UDP port
2) a matching IP protocol (i.e. OSPF)
3) a matching punt exception reason (see above)

Depending on the type/classification of the packet to be punted, that
active punt will register itself into the VLIB graph to receive those
packets. For example, if it's a packet matching a UDP port then it
will hook into the UDP port dispatch functions; udp_register_port().

There exists only one sink for passive punt, a unix domain socket. But
more work is underway in this area.

see the API in: vnet/ip/punt.api



Passive Punt
------------

VPP input packet processing can be described as a series of
classifiers. For example, a sequence of input classifications could
be, is it IP? is it for-us? is it UDP? is it a known UDP-port? If at
some point in this pipeline VPP has no further classifications to make,
then the packet can be punted, which means sent to ipX-punt node. This
is described as passive since the control-plane is thus receiving
every packet that VPP does not itself handle.
For passive punt the user can specify where the packets should be
sent and whether/how they should be policed/rate-limited.

see the API in: vnet/ip/ip.api

