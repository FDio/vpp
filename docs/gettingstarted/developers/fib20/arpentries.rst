.. _arpentries:

ARP Entries
^^^^^^^^^^^

.. figure:: /_images/fib20fig1.png

Figure 1: ARP data model

Figure 1 shows the data model for an ARP entry. An ARP entry contains the mapping
between a peer, identified by an IPv4 address, and its MAC address on a given
interface.  The VRF the interface is bound to, is not part of the data. VRFs are
an ingress function not egress. The ARP entry describes how to send traffic to a
peer, which is an egress function.

The *arp_entry_t* represents the control-plane addition of the ARP entry. The
*ip_adjacency_t* contains the data derived from the *arp_entry_t* that is need to
forward packets to the peer. The additional data in the adjacency are the *rewrite*
and the *link_type*. The *link_type* is a description of the protocol of the packets
that will be forwarded with this adjacency; this can be IPv4 or MPLS. The *link_type*
maps directly to the ether-type in an Ethernet header, or the protocol filed in a
GRE header. The rewrite is a byte string representation of the header that will be
prepended to the packet when it is sent to that peer. For Ethernet interfaces this
would be the src,dst MAC and the ether-type. For LISP tunnels, the IP src,dst pair
and the LISP header.

The *arp_entry_t* will install a *link_type=IPv4* when the entry is created and a
link_type=MPLS when the interface is MPLS enabled. Interfaces must be explicitly
MPLS enabled for security reasons.

So that adjacencies can be shared between route, adjacencies are stored in a single
data-base, the key for which is {interface, next-hop, link-type}. 
