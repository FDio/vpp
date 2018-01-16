# SRv6 endpoint to SR-unaware appliance via static proxy (End.AS) {#srv6_as_plugin_doc}

## Overview

The static proxy is an SR endpoint behavior for processing SR-MPLS or SRv6
encapsulated traffic on behalf of an SR-unaware service.  This proxy thus
receives SR traffic that is formed of an MPLS label stack or an IPv6 header on
top of an inner packet, which can be Ethernet, IPv4 or IPv6.

A static SR proxy segment is associated with the following mandatory parameters:

- INNER-TYPE: Inner packet type
- S-ADDR: Ethernet or IP address of the service (only for inner type IPv4 and
	IPv6)
- IFACE-OUT: Local interface for sending traffic towards the service
- IFACE-IN: Local interface receiving the traffic coming back from the service
- CACHE: SR information to be attached on the traffic coming back from the
	service

A static SR proxy segment is thus defined for a specific service, inner packet
type and cached SR information.  It is also bound to a pair of directed
interfaces on the proxy.  These may be both directions of a single interface, or
opposite directions of two different interfaces.  The latter is recommended in
case the service is to be used as part of a bi-directional SR SC policy.  If the
proxy and the service both support 802.1Q, IFACE-OUT and IFACE-IN can also
represent sub-interfaces.

The first part of this behavior is triggered when the proxy node receives a
packet whose active segment matches a segment associated with the static proxy
behavior.  It removes the SR information from the packet then sends it on a
specific interface towards the associated service.  This SR information
corresponds to the full label stack for SR-MPLS or to the encapsulation IPv6
header with any attached extension header in the case of SRv6.

The second part is an inbound policy attached to the proxy interface receiving
the traffic returning from the service, IFACE-IN.  This policy attaches to the
incoming traffic the cached SR information associated with the SR proxy segment.
If the proxy segment uses the SR-MPLS data plane, CACHE contains a stack of
labels to be pushed on top the packets.  With the SRv6 data plane, CACHE is
defined as a source address, an active segment and an optional SRH (tag,
segments left, segment list and metadata).  The proxy encapsulates the packets
with an IPv6 header that has the source address, the active segment as
destination address and the SRH as a routing extension header.  After the SR
information has been attached, the packets are forwarded according to the active
segment, which is represented by the top MPLS label or the IPv6 Destination
Address.

In this scenario, there are no restrictions on the operations that can be
performed by the service on the stream of packets.  It may operate at all
protocol layers, terminate transport layer connections, generate new packets and
initiate transport layer connections.  This behavior may also be used to
integrate an IPv4-only service into an SRv6 policy.  However, a static SR proxy
segment can be used in only one service chain at a time.  As opposed to most
other segment types, a static SR proxy segment is bound to a unique list of
segments, which represents a directed SR SC policy.  This is due to the cached
SR information being defined in the segment configuration.  This limitation only
prevents multiple segment lists from using the same static SR proxy segment at
the same time, but a single segment list can be shared by any number of traffic
flows.  Besides, since the returning traffic from the service is re- classified
based on the incoming interface, an interface can be used as receiving interface
(IFACE-IN) only for a single SR proxy segment at a time.  In the case of a
bi-directional SR SC policy, a different SR proxy segment and receiving
interface are required for the return direction.

## SRv6 pseudocode

### Static proxy for inner type Ethernet - End.AS2

Upon receiving an IPv6 packet destined for S, where S is an End.AS2 SID, a node
N does:

```
   1.   IF ENH == 59 THEN                                        ;; Ref1
   2.       Remove the (outer) IPv6 header and its extension headers
   3.       Forward the exposed frame on IFACE-OUT
   4.   ELSE
   5.       Drop the packet
```

Ref1: 59 refers to "no next header" as defined by IANA allocation for Internet
Protocol Numbers.

Upon receiving on IFACE-IN an Ethernet frame with a destination address
different than the interface address, a node N does:

```
   1.   IF CACHE.SRH THEN                                        ;; Ref2
   2.       Push CACHE.SRH on top of the existing Ethernet header
   3.       Set NH value of the pushed SRH to 59
   4.   Push outer IPv6 header with SA, DA and traffic class from CACHE
   5.   Set outer payload length and flow label
   6.   Set NH value to 43 if an SRH was added, or 59 otherwise
   7.   Lookup outer DA in appropriate table and proceed accordingly
```

Ref2: CACHE.SRH represents the SRH defined in CACHE, if any, for the static SR
proxy segment associated with IFACE-IN.

The receiving interface must be configured in promiscuous mode in order to
accept those Ethernet frames.

### Static proxy for inner type IPv4 - End.AS4

Upon receiving an IPv6 packet destined for S, where S is an End.AS4 SID, a node
N does:

```
   1.   IF ENH == 4 THEN                                         ;; Ref1
   2.       Remove the (outer) IPv6 header and its extension headers
   3.       Forward the exposed packet on IFACE-OUT towards S-ADDR
   4.   ELSE
   5.       Drop the packet
```

Ref1: 4 refers to IPv4 encapsulation as defined by IANA allocation for Internet
Protocol Numbers.

Upon receiving a non link-local IPv4 packet on IFACE-IN, a node N does:

```
   1.   IF CACHE.SRH THEN                                        ;; Ref2
   2.       Push CACHE.SRH on top of the existing IPv4 header
   3.       Set NH value of the pushed SRH to 4
   4.   Push outer IPv6 header with SA, DA and traffic class from CACHE
   5.   Set outer payload length and flow label
   6.   Set NH value to 43 if an SRH was added, or 4 otherwise
   7.   Decrement inner TTL and update checksum
   8.   Lookup outer DA in appropriate table and proceed accordingly
```

Ref2: CACHE.SRH represents the SRH defined in CACHE, if any, for the static SR
proxy segment associated with IFACE-IN.

### Static proxy for inner type IPv6 - End.AS6

Upon receiving an IPv6 packet destined for S, where S is an End.AS6 SID, a node
N does:

```
   1.   IF ENH == 41 THEN                                        ;; Ref1
   2.       Remove the (outer) IPv6 header and its extension headers
   3.       Forward the exposed packet on IFACE-OUT towards S-ADDR
   4.   ELSE
   5.       Drop the packet
```

Ref1: 41 refers to IPv6 encapsulation as defined by IANA allocation for Internet
Protocol Numbers.

Upon receiving a non-link-local IPv6 packet on IFACE-IN, a node N does:

```
   1.   IF CACHE.SRH THEN                                        ;; Ref2
   2.       Push CACHE.SRH on top of the existing IPv6 header
   3.       Set NH value of the pushed SRH to 41
   4.   Push outer IPv6 header with SA, DA and traffic class from CACHE
   5.   Set outer payload length and flow label
   6.   Set NH value to 43 if an SRH was added, or 41 otherwise
   7.   Decrement inner Hop Limit
   8.   Lookup outer DA in appropriate table and proceed accordingly
```

Ref2: CACHE.SRH represents the SRH defined in CACHE, if any, for the static SR
proxy segment associated with IFACE-IN.

