# SRv6 endpoint to SR-unaware appliance via per-flow dynamic proxy {#srv6_ad_flow_plugin_doc}

## Overview

TBD

## CLI configuration

The following command instantiates a new End.AD.Flow segment that sends the inner
packets on interface `IFACE-OUT` towards an appliance at address `S-ADDR` and
restores the encapsulation headers of the packets coming back on interface
`IFACE-IN`.

```
sr localsid address SID behavior end.ad.flow nh S-ADDR oif IFACE-OUT iif IFACE-IN
```

For example, the below command configures the SID `1::A1` with an End.AD.Flow
function for sending traffic on interface `GigabitEthernet0/8/0` to the
appliance at address `A1::`, and receiving it back on interface
`GigabitEthernet0/9/0`.

```
sr localsid address 1::A1 behavior end.ad.flow nh A1:: oif GigabitEthernet0/8/0 iif GigabitEthernet0/9/0
```
