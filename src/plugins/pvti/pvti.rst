Packet Vector Tunnel Interface (PVTI)
=====================================

This experimental plugin aims to explore yet another approach to a very old problem:
the reduction of effective MTU during encapsulation.

GRE, IPSec, L2TP, VXLAN, GENEVE, and many more protocols provide a convenient
abstraction layer to alter the topology and properties of the networks - be it
addition of metadata, simple tunneling, or the confidentiality and authenticity.

However, this comes at a cost: each tunneling protocol adds its own headers,
as a result the space available for the application data is reduced. In case
such a transformation happens on the host itself, this problem is generally
served reasonably well by the interface MTU. However, if one were to attempt
to do these services in a "Bump In The Wire" fashion, this becomes more challenging.
If the protocol is unencrypted, like TCP, then techniques like MSS clamping can be used,
but for all the other protocols one has to relay on various mechanisms of discovering
the path MTU, which may or may not provide effective solution.

This plugin implements a tunnel protocol whose sole purpose is chunking the packets
into smaller ones and then encapsulating them into UDP packets with full 5-tuple.
So, the overlay retains the old (or bigger) MTU, and the underlay gets a higher packet rate,
because the packets are split into smaller chunks.

Of course - what about the reassembly ? This experimental plugin uses the observation
that modern network engineering principles in the vast majority of cases provide in-order
delivery of packets within a single 5-tuple flow. This assumption means that chunking
and de-chunking can be done in a much simpler way, because at any given point in time
there is at most one outstanding de-chunking in place. By including the incrementing sequence number
into the underlay packet, we can detect the gap in the sequence space, and
(because of assumption of in-order delivery for a flow), can treat it as a loss.

If there is no loss - then with some minimal markup one can reconstruct the original "larger"
overlay packets and thus "decapsulate" them.

Additionally, since VPP is processing the packets as a vector, it can perform the reverse operation,
and group several smaller packets into a bigger "carriage" packet before sending. Similarly,
on the receive side those can be decapsulated, split and sent along.

Such a simple mechanism requires another assumption: that the substrate underneath is trusted.
Since there is very little randomness beyond the endpoint 5-tuple, one can trivially disrupt
the communications by injecting the packets with bogus sequence numbers. At this stage,
rather than attempt to invent a protection mechanism, we simply require to use a layer with another
protocol, e.g. IPSec, if the underlay can not be considered trusted.

Considerations and Hypotheses
-----------------------------

-  "Packets belonging to the single flow with the same 5-tuple are
   not reordered". Anecdotally, this is true, minus some of the cases with the QoS which will reorder
   the packets. There also are some cases of underlays like MPLS having impact on the packet ordering. However,
   all of these cases are generally impacting the upper level protocols anyway, so it is deemed fair
   to set it as a prerequisite.

-  "Approximately doubling the packet rate is better than clamping the MTU". 
   The answer to this will depend on the environments and the degree of control over the endpoints -
   with no control, a price of doubling the packets per second rate may be worth the MTU transparency that it buys.

-  "Packet loss, even if doubled for large packets, will be tolerable". Since,
   for a simple case of preserving a 1500 byte payload MTU, we will need to chop each big packet in two,
   this doubles the probability of a loss, compared to small packets. Equally, it is hard to exactly say how
   the grouping of the small packets might affect the upper layer protocol behavior. More information is needed.

-  "The underlaying substrate can be trusted". Layering and separation of concerns are sensible engineering principles,
   and for this case they allow to concentrate on just the core function, and keep the code smaller. Thus, if you do not
   trust your wires - layer PVTI on top of IPSec.

Configuration and deployment
----------------------------

There are two modes for PVTI interfaces: point-to-point and point-to-multipoint.

In point-to-point mode, the PVTI interface is similar to any other tunnel interface, but you would typically specify
the underlay MTU:

```DBGvpp# pvti interface create peer 192.0.2.1 12345 50000 underlay-mtu 1000```

The "1000" in this case means that during the encapsulation, we should not see the packets larger than 1000 bytes on the wire.
If the overlay packet is larger - it will be chunked and sent as two separate tunneled packets, each with its full 5-tuple.

From the deployment mode, it may be more convenient to run the PVTI interfaces in point-to-multipoint confuguration:

```DBGvpp# pvti interface create peer 0.0.0.0 12345 50000 underlay-mtu 1000 peer-address-from-payload```

With this configuration, the decapsulator will retrieve the destination address for the underlay from the original payload packet.
This can be useful in case you are adding the PVTI to an existing setup with the tunnel interfaces, and want to minimize
the amount of configuration changes required. However, in this case it is easy to see that we immediately hit a problem:
Assuming the routing is done purely on destinations, we have just created a recursive routing loop!

In order to tackle that issue, we will need to create a separate table with a different routing table and specify it in the CLI:

```DBGvpp# ip table add 42```
... add the routing for the underlay - probably just a correct default route ...

```DBGvpp# pvti interface create peer 0.0.0.0 12345 50000 underlay-mtu 1000 peer-address-from-payload underlay-table 42```

