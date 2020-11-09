.. _neighbors:

Neighbours
^^^^^^^^^^^

.. figure:: /_images/ip-neighbor.png

Figure 1: Neighbour data model

Figure 1 shows the data model for IP neighbours. An IP neighbour contains the mapping
between a peer, identified by an IPv4 or IPv6 address, and its MAC address on a given
interface. An IP-table (VRF) is not part of the neighbour's
data/identity. This is because the virtualisation of a router into
different tables (VRFs) is performed at the interface level, i.e. an
IP-table is bound to a particular interface. A neighbour, which is
attached to an interface, is thus implicitly in that table, and
only in that table. It is also worth noting that IP neighbours
contribute forwarding for the egress direction, whereas an IP-table
is an ingress only function.

The *ip_neighbor_t* represents the control-plane addition of the
neighbour. The *ip_adjacency_t* contains the data derived from the *ip_neighbor_t* that is needed to
forward packets to the peer. The additional data in the adjacency are the *rewrite*
and the *link_type*. The *link_type* is a description of the protocol of the packets
that will be forwarded with this adjacency; e.g. IPv4, IPv6 or MPLS. The *link_type*
maps directly to the ether-type in an Ethernet header, or the protocol filed in a
GRE header. The rewrite is a byte string representation of the header that will be
prepended to the packet when it is sent to that peer. For Ethernet interfaces this
is be the src,dst MAC and the ether-type. For LISP tunnels, the IP src,dst pair
and the LISP header.

The *ip_neighbor_t* for an IPv4 peer (learned e.g. over ARP) will
install a *link_type=IPv4* when the entry is created and a
link_type=MPLS on demand (i.e. when a route with output labels resolves via the peer).

Adjacency
---------

There are three sub-types of adjacencies. Purists would argue that some
of these sub-types are not really adjacencies but are instead other
forms of DPOs, and it would be hard to argue against that, but
historically (not just in VPP, but in the FIB implementations from
which VPP draws on for some of its concepts), these have been modelled
as adjacency types, the one thing they have in common is that they
have an associated interface and are terminal. The [sub] sub-types are:

* A Neighbour Adjacency (key={interface, next-hop, link-type}). A
  representation of a peer on a link (as described above). A neighbour adjacency itself has
  two sub-types; terminal and mid-chain. When one speak of 'an
  adjacency' one is usually referring to a terminal neighbour
  sub-type. A mid-chain adjacency represents a neighbor on a virtual
  interface which relies on the FIB to perform further forwarding. This
  adjacency is thus not terminal for the FIB object graph but instead
  appears in the 'middle' (the term chain is a synonym for graph in
  some contexts).
  A neighbour adjacency can be in one of two states; complete and
  incomplete. A complete adjacency knows the rewrite string that
  should be used to reach the peer, an incomplete adjacency does
  not. If the adjacency was added as a result of the addition of an
  *ip_neighbor_t* then the adjacency will be complete (because the
  *ip_neighbor_t* knows the peer's MAC address). An incomplete
  adjacency is created on demand by the FIB when a route's path
  requires to resolve through such an adjacency. It is thus created in
  order to resolve the missing dependency, it will become complete
  once the *ip_neighbor_t* is discovered.
  In the forwarding path a complete adjacency will prepend the rewrite
  string and transmit on the egress interface, an incomplete adjacency
  will construct a ARP/ND request to resolve the peer's IP address.

* A Glean Adjacency (key={interface}). This is a representation of the need to discover
  a peer on the given interface. It is used when it is known that the
  packet is destined to an undiscoverd peer on that interface. The
  difference between the glean adjacency and an
  incomplete neighbour adjacency is that in the forwarding path the
  glean adjacency will construct an ARP/ND request for the peer as
  determined from the packet's destination address. The glean
  adjacency is used to resolve connected prefixes on multi-access
  interfaces.

* A Multicast Adjacency (key={interface}). This represents the need to send an IP
  multicast packet out of the adjacency's associated interface. Since
  IP multicast constructs the destination MAC address from the IP
  packet's destination/group address, the rewrite is always known and
  hence the adjacency is always complete.


All adjacency types can be shared between routes, hence each type is
stored in a DB whose key is appropriate for the type.
