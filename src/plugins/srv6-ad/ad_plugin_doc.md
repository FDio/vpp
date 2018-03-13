# SRv6 endpoint to SR-unaware appliance via dynamic proxy (End.AD) {#srv6_ad_plugin_doc}

## Overview

The dynamic proxy is an improvement over the static proxy (@ref srv6_as_plugin_doc)
that dynamically learns the SR information before removing it from the incoming
traffic. The same information can then be re-attached to the traffic returning
from the SF. As opposed to the static SR proxy, no CACHE information needs to be
configured. Instead, the dynamic SR proxy relies on a local caching mechanism on
the node instantiating this segment. Therefore, a dynamic proxy segment cannot
be the last segment in an SR SC policy. A different SR behavior should thus be
used if the SF is meant to be the final destination of an SR SC policy.

Upon receiving a packet whose active segment matches a dynamic SR proxy
function, the proxy node pops the top MPLS label or applies the SRv6 End
behavior, then compares the updated SR information with the cache entry for the
current segment. If the cache is empty or different, it is updated with the new
SR information. The SR information is then removed and the inner packet is sent
towards the SF.

The cache entry is not mapped to any particular packet, but instead to an SR SC
policy identified by the receiving interface (IFACE-IN). Any non-link-local IP
packet or non-local Ethernet frame received on that interface will be
re-encapsulated with the cached headers as described in @ref srv6_as_plugin_doc. The
SF may thus drop, modify or generate new packets without affecting the proxy.

For more information, please see
[draft-xuclad-spring-sr-service-chaining](https://datatracker.ietf.org/doc/draft-xuclad-spring-sr-service-chaining/).

## CLI configuration

The following command instantiates a new End.AD segment that sends the inner
packets on interface `IFACE-OUT` towards an appliance at address `S-ADDR` and
restores the encapsulation headers of the packets coming back on interface
`IFACE-IN`.

```
sr localsid address SID behavior end.ad nh S-ADDR oif IFACE-OUT iif IFACE-IN
```

For example, the below command configures the SID `1::A1` with an End.AD
function for sending traffic on interface `GigabitEthernet0/8/0` to the
appliance at address `A1::`, and receiving it back on interface
`GigabitEthernet0/9/0`.

```
sr localsid address 1::A1 behavior end.ad nh A1:: oif GigabitEthernet0/8/0 iif GigabitEthernet0/9/0
```

## Pseudocode

The dynamic proxy SRv6 pseudocode is obtained by inserting the following
instructions between lines 1 and 2 of the static proxy SRv6 pseudocode.

```
IF NH=SRH & SL > 0 THEN
    Decrement SL and update the IPv6 DA with SRH[SL]
    IF C(IFACE-IN) different from IPv6 encaps THEN              ;; Ref1
        Copy the IPv6 encaps into C(IFACE-IN)                   ;; Ref2
ELSE
    Drop the packet
```

**Ref1:** "IPv6 encaps" represents the IPv6 header and any attached extension
header.

**Ref2:** C(IFACE-IN) represents the cache entry associated to the dynamic SR proxy
segment. It is identified with IFACE-IN in order to efficiently retrieve the
right SR information when a packet arrives on this interface.

In addition, the inbound policy should check that C(IFACE-IN) has been defined
before attempting to restore the IPv6 encapsulation, and drop the packet
otherwise.
