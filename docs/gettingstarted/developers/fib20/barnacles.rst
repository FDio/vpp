.. _barnacles:

Barnacles
---------

Features that are stuck on the side of the FIB. Those that directly use
the services that the FIB provides.

In the section on FIB fundamentals it was mentioned  that there is a
separation between what to match and how to forward. In an IP FIB what
to match is the packet's destination address against a table of IP
prefixes, and how to forward is described by a list of paths (the
**fib_path_list_t**).

ACL Based Forwarding
^^^^^^^^^^^^^^^^^^^^

ACL Based Forwarding (ABF) is also know as policy based routing
(PBR). In ABF what to match is described by an ACL.

ABF uses two VPP services; ACL as a service, as provided by the ACL
plugin and FIB path-lists. It just glues them together.

An ABF policy is the combination of an ACL with the forwarding
description of a FIB path-list. An ABF attachment is the association
of [an ordered set of] ABF policies to an interface. The attachment is
consulted on the ingress path of the IP DP (as an input
feature). If the ACL matches then the associated forwarding is
followed, if not, the packet continues along the DP. Simples.

Layer 3 Cross Connect
^^^^^^^^^^^^^^^^^^^^^

An L3 cross-connect (L3XC) matches all packets
that ingress the interface and then forwards using the supplied FIB
path-list. Naturally it runs as an input feature in the IP
path. Super simples.

IP Punt
^^^^^^^

Matches all IP packets that VPP has punted. Why they are punted is not
relevant. All IP punted packets are sent by VPP to the punt feature
arc. This feature 'matches' all packets that it receives and forwards
using the FIB path-list.


Unicast Reverse Path Forwarding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unicast Reverse Path Forwarding (uRPF) is the process of ensuring that
a packet has a conforming source address. It comes in two
flavours:

- loose: The source address must be reachable, i.e. FIB must have a
  route that will forward to the source address. The default route
  counts as long as it does not drop.
- strict: The source address is reachable via the interface on which
  the packet arrived, i.e. the FIB's route for the source address must
  include the input interface as an output interface.

The uRPF feature can run on either the input or output IP feature
arc. In both cases it serves as an anti-spoofing check, though the
semantics are slightly different. On the input arc it enforces that
peers on that link are only using source addresses that they should -
a network admin should employ at the access edge. On the output
arc it enforces that a packet is sourced from a prefix that belongs to
the network, i.e. that is has originated from within an SP's
network, a network admin could use at its peering points.

To perform a uRPF check, the DP performs an IP FIB lookup on the
source address, this always results in a load-balance (LB) object. If
the LB has only 1 bucket and that bucket stacks on a drop DPO, then
both a loose and strict check will fail, otherwise a loose check
will pass. Each LB object has an associated uRPF list object. This
object holds the list of interfaces through which the prefix is
reachable. To pass the strict check, the input/output interface must
be in this list.
