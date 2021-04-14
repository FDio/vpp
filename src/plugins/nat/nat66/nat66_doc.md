# NAT66: Network Address Translation IPv6 to IPv6

## Introduction

NAT66 allows creating IPv6 to IPv6 static mappings.

## Configuration

### Enable/Disable NAT66 plugin

> nat66 enable [outside-vrf `vrf-id`]

> nat66 disable

### Enable/Disable NAT66 feature on interface

> set interface nat66 in|out `intfc` [del]

### Add static mapping

> nat66 add static mapping local `ip6-addr` external `ip6-addr`
[vfr `table-id`] [del]

### Show commands

```
show nat66 static mappings
show nat66 interfaces
```
