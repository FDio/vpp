# SRv6 endpoint to SR-unaware appliance via dynamic proxy (End.AD) {#srv6_ad_plugin_doc}

## Overview

The "Endpoint to SR-unaware appliance via dynamic proxy" (End.AD) is a two-parts
proxy function for processing SRv6 encapsulated traffic on behalf of an
SR-unaware appliance. The first part decapsulates the incoming traffic and sends
it towards an appliance on a specific interface, while the second
re-encapsulates the traffic coming back from the appliance.

In this scenario, there are no restrictions on the operations that can be
performed by the appliance on the stream of packets. It may operate at all
protocol layers, terminate transport layer connections, generate new packets and
initiate transport layer connections. This function may also be used to
integrate an IPv4-only appliance into an SRv6 policy.

The End.AD function relies on a local caching mechanism to learn and
re-encapsulate the traffic with the same headers that were removed. 
This cache is used to store the IPv6 header and its
extension headers while the appliance processes the inner packet. In the
following, we refer to an entry in this cache as C(type,iface), where type is
either IPv4 or IPv6 and iface is the receiving interface on the SRv6 proxy
(IFACE-IN).
