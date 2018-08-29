.. _mplsfib:

MPLS FIB
----------

There is a tight coupling between IP and MPLS forwarding. MPLS forwarding
equivalence classes (FECs) are often an IP prefix Рthat is to say that traffic
matching a given IP prefix is routed into a MPLS label switch path (LSP). It is
thus necessary to be able to associated a given prefix/route with an [out-going]
MPLS label that will be imposed when the packet is forwarded. This is configured
as:

.. code-block:: console

   $ ip route add 1.1.1.1/32 via 10.10.10.10 GigabitEthernet0/8/0 out-label 33

packets matching 1.1.1.1/32 will be forwarded out GigabitEthernet0/8/0 and have MPLS label
33 imposed. More than one out-going label can be specified. Out-going MPLS labels
can be applied to recursive and non-recursive routes, e.g;

.. code-block:: console

   $ ip route add 2.2.2.0/24 via 1.1.1.1 out-label 34

packets matching 2.2.2.0/24 will thus have two MPLS labels imposed; 34 and 33.
This is the realisation of, e,g, an MPLS BGP VPNv4.

To associate/allocate a local-label for a prefix, and thus have packets to that
local-label forwarded equivalently to the prefix do;

.. code-block:: console

   $ mpls local-label 99 2.2.2.0/24

In the API this action is called a *bind*.

The router receiving the MPLS encapsulated packets needs to be programmed with
actions associated which each label value Рthis is the role of the MPLS FIB.
The MPLS FIB Is a table, whose key is the MPLS label value and end-of-stack (EOS)
bit, which stores the action to perform on packets with matching encapsulation.

Currently supported actions are:

#. Pop the label and perform an IPv[46] lookup in a specified table
#. Pop the label and forward via a specified next-hop (this is penultimate-hop-pop, PHP)
#. Swap the label and forward via a specified next-hop.

These can be programmed respectively by:	

#. mpls local-label 33 ip4-lookup-in-table X
#. mpls local-label 33 via 10.10.10.10 GigabitEthernet0/8/0
#. mpls local-label 33 via 10.10.10.10 GigabitEthernet0/8/0 out-label 66

the latter is an example of an MPLS cross connect. Any description of a next-hop,
recursive, non-recursive, labelled, non-labelled, etc, that is valid for an IP
prefix, is also valid for an MPLS local-label.

Implementation
^^^^^^^^^^^^^^^

The MPLS FIB is implemented using exactly the same data structures as the IP FIB. 
The only difference is the implementation of the table. Whereas for IPv4 this is
an mtrie and for IPv6 a hash table, for MPLS it is a flat array indexed by a 21
bit key (label & EOS bit). This implementation is chosen to favour packet
forwarding speed.

MPLS Tunnels
^^^^^^^^^^^^^

VPP no longer supports MPLS tunnels that are coupled to a particular transport,

i.e. MPLSoGRE or MPLSoEth. Such tight coupling is not beneficial. Instead VPP supports;

#. MPLS LSPs associated with IP prefixes and MPLS local-labels (as described above) which are transport independent (i.e. the IP route could be reachable over a GRE tunnel, or any other interface type).
#. A generic uni-directional MPLS tunnel interface that is transport independent.

An MPLS tunnel is effectively an LSP with an associated interface. The LSP can be
described by any next-hop type (recursive, non-recursive etc), e.g.:

mpls tunnel add via 10.10.10.10 GigabitEthernet0/8/0 out-label 66
IP routes and/or MPLS x-connects can be routed via the interface, e.g.

.. code-block:: console

   $ ip route add 2.2.2.0/24 via mpls-tunnel0

packets matching the route for 2.2.2.0/24 would thus have label 66 imposed since
it is transmitted via the tunnel. 

These MPLS tunnels can be used to realise MPLS RSVP-TE tunnels.
