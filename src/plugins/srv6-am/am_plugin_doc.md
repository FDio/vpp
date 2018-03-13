# SRv6 endpoint to SR-unaware appliance via masquerading (End.AM) {#srv6_am_plugin_doc}

The masquerading proxy is an SR endpoint behavior for processing SRv6 traffic on
behalf of an SR-unaware SF. This proxy thus receives SR traffic that is formed
of an IPv6 header and an SRH on top of an inner payload. The masquerading
behavior is independent from the inner payload type. Hence, the inner payload
can be of any type but it is usually expected to be a transport layer packet,
such as TCP or UDP.

A masquerading SR proxy segment is associated with the following mandatory
parameters:

- S-ADDR: Ethernet or IPv6 address of the SF
- IFACE-OUT: Local interface for sending traffic towards the SF
- IFACE-IN: Local interface receiving the traffic coming back from the SF

A masquerading SR proxy segment is thus defined for a specific SF and bound to a
pair of directed interfaces or sub-interfaces on the proxy. As opposed to the
static and dynamic SR proxies, a masquerading segment can be present at the same
time in any number of SR SC policies and the same interfaces can be bound to
multiple masquerading proxy segments. The only restriction is that a
masquerading proxy segment cannot be the last segment in an SR SC policy.

The first part of the masquerading behavior is triggered when the proxy node
receives an IPv6 packet whose Destination Address matches a masquerading proxy
segment. The proxy inspects the IPv6 extension headers and substitutes the
Destination Address with the last segment in the SRH attached to the IPv6
header, which represents the final destination of the IPv6 packet. The packet is
then sent out towards the SF.

The SF receives an IPv6 packet whose source and destination addresses are
respectively the original source and final destination. It does not attempt to
inspect the SRH, as RFC8200 specifies that routing extension headers are not
examined or processed by transit nodes. Instead, the SF simply forwards the
packet based on its current Destination Address. In this scenario, we assume
that the SF can only inspect, drop or perform limited changes to the packets.
For example, Intrusion Detection Systems, Deep Packet Inspectors and non-NAT
Firewalls are among the SFs that can be supported by a masquerading SR proxy.

The second part of the masquerading behavior, also called de- masquerading, is
an inbound policy attached to the proxy interface receiving the traffic
returning from the SF, IFACE-IN. This policy inspects the incoming traffic and
triggers a regular SRv6 endpoint processing (End) on any IPv6 packet that
contains an SRH. This processing occurs before any lookup on the packet
Destination Address is performed and it is sufficient to restore the right
active segment as the Destination Address of the IPv6 packet.

For more information, please see
[draft-xuclad-spring-sr-service-chaining](https://datatracker.ietf.org/doc/draft-xuclad-spring-sr-service-chaining/).

## CLI configuration

The following command instantiates a new End.AM segment that sends masqueraded
traffic on interface `IFACE-OUT` towards an appliance at address `S-ADDR` and
restores the active segment in the IPv6 header of the packets coming back on
interface `IFACE-IN`.

```
sr localsid address SID behavior end.am nh S-ADDR oif IFACE-OUT iif IFACE-IN
```

For example, the below command configures the SID `1::A1` with an End.AM
function for sending traffic on interface `GigabitEthernet0/8/0` to the
appliance at address `A1::`, and receiving it back on interface
`GigabitEthernet0/9/0`.

```
sr localsid address 1::A1 behavior end.am nh A1:: oif GigabitEthernet0/8/0 iif GigabitEthernet0/9/0
```

## Pseudocode

### Masquerading

Upon receiving a packet destined for S, where S is an IPv6 masquerading proxy
segment, a node N processes it as follows.

```
IF NH=SRH & SL > 0 THEN
    Update the IPv6 DA with SRH[0]
    Forward the packet on IFACE-OUT
ELSE
    Drop the packet
```

### De-masquerading

Upon receiving a non-link-local IPv6 packet on IFACE-IN, a node N processes it
as follows.

```
IF NH=SRH & SL > 0 THEN
    Decrement SL
    Update the IPv6 DA with SRH[SL]                             ;; Ref1
    Lookup DA in appropriate table and proceed accordingly
```

**Ref1:** This pseudocode can be augmented to support the Penultimate Segment
Popping (PSP) endpoint flavor. The exact pseudocode modification are provided in
[draft-filsfils-spring-srv6-network-programming](https://datatracker.ietf.org/doc/draft-filsfils-spring-srv6-network-programming/).
