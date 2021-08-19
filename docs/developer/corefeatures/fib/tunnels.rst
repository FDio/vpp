.. _tunnels:

Tunnels
-------

Tunnels share a similar property to recursive routes in that after applying the
tunnel encapsulation, a new packet must be forwarded, i.e. forwarding is
recursive. However, as with recursive routes the tunnel's destination is known
beforehand, so the second lookup can be avoided if the packet can follow the
already constructed data-plane graph for the tunnel's destination. This process
of joining to DP graphs together is termed *stacking*.
  
.. figure:: /_images/fib20fig11.png

Figure 11: Tunnel control plane object diagram

Figure 11 shows the control plane object graph for a route via a tunnel. The two
sub-graphs for the route via the tunnel and the route for the tunnel's
destination are shown to the right and left respectively. The red line shows the
relationship form by stacking the two sub-graphs. The adjacency on the tunnel
interface is termed a 'mid-chain' since it is now present in the middle of the
graph/chain rather than its usual terminal location.

The mid-chain adjacency is contributed by the gre_tunnel_t , which also becomes
part of the FIB control-plane graph. Consequently it will be visited by a
back-walk when the forwarding information for the tunnel's destination changes.
This will trigger it to restack the mid-chain adjacency on the new
*load_balance_t* contributed by the parent *fib_entry_t*.

If the back-walk indicates that there is no route to the tunnel's
destination, or that the resolving route does not meet resolution
constraints, then the tunnel can be marked as down, and fast
convergence can be triggered in the same way as for physical interfaces (see section ...).


Multi-Point Tunnels
^^^^^^^^^^^^^^^^^^^

Multi-point tunnels are an example of a non-broadcast multi-access
interface. In simple terms this means there are many peers on the link
but it is not possible to broadcast a single message to all of them at
once, and hence the usual peer discovery mechanism (as employed,
e.g. by ARP) is not available. Although an *ip_neighbor_t* is a
representation of an IP peer on a link, it is not valid in this
context as it maps the peer's identity to its MAC address. For a
tunnel peer it is required to map the peer's overlay address (the
attached address, the one in the same subnet as the device) with the
peer's underlay address (probably on the other side of the
internet). In the P2P case where there is only one peer on the link,
the peer's underlay address is the same as the tunnel's destination
address.
The data structure that represents the mapping of the peer's overlay
with underlay address is an entry in the Tunnel Endpoint Information
Base (TEIB); the *tieb_entry_t*. TEIB entries are created by the
control plane (e.g. NHRP (RFC2332)).

Each mid-chain adjacency on a multi-point tunnel is stacked on the
*fib_entry_t* object that resolves the peer's underlay address. The
glean adjacency on the tunnel resolves via a drop, since broadcasts
are not possible. A multicast adjacency on a multi-point tunnel is
currently a work in progress.

