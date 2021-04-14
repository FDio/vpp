# NAT44-ED: Endpoint Dependent Network Address Translation IPv4 to IPv4

## Introduction

Supported features:

- dynamic nat (PAT)
- static mapping
  - address only mapping
    - 1-1 translation withouth ports
  - twice-nat
    - double-nat, translation of source and destination
    - can be combined with out2in-only
  - self-twice-nat
    - double-nat, translation of source and destination, where external
      host address is the same as local host address
    - can be combined with out2in-only
  - out2in-only
    - session is created only from outside nat interface
- identity mapping
  - exceptions to translations
- load-balanced static mapping
  - feature used for translating one outside frontend (`addr`:`port`)
    to multiple backends (`addr`:`port`)
- mss-clamping
- syslog
- ipfix logging
- pre routing / post routing translations
  - pre routing is the default behaviour, nat processing happens before
    ip4-lookup node
  - using output-feature moves processing of nat traffic for the specific
    nat interface after ip4-lookup node
  - output-features enables translating traffic after routing

## Configuraiton

### Enable/Disable NAT44-ED plugin

> nat44 enable sessions `max-number` [static-mappig-only [connection-tracking]]
[inside-vrf `vrf-id`] [outside-vrf `vrf-id`]

> nat44 disable

### Enable/Disable NAT44-ED feature on interface

> set interface nat44 in `intfc` out `intfc` [output-feature] [del]

inside, outside interface index.

### Enable/Disable forwarding

> nat44 forwarding enable|disable

### Add outside address

> nat44 add interface address `interface` [twice-nat] [del]\
nat44 add address `ip4-range-start` [- `ip4-range-end`]
[tenant-vrf `vrf-id`] [twice-nat] [del]

### Configure protocol timeouts

> set nat timeout [udp `sec` | tcp-established `sec` tcp-transitory `sec`
| icmp `sec` | reset]

### Additional configuration

> set nat frame-queue-nelts `number`\
set nat workers `workers-list`

### Configure logging

> nat set logging level `level`\
nat ipfix logging [domain `domain-id`] [src-port `port`] [disable]

### Configure mss-clamping

> nat mss-clamping `mss-value`|disable

### Add static mapping

> nat44 add static mapping tcp|udp|icmp local `addr` [`port|icmp-echo-id`]
external `addr` [`port|icmp-echo-id`] [vrf `table-id`]
[twice-nat|self-twice-nat] [out2in-only] [exact `pool-addr`] [del]

### Add identity mapping

> nat44 add identity mapping `ip4-addr`|external `interface`
[`protocol` `port`] [vrf `table-id`] [del]

### Configure load balanced static mapping

> nat44 add load-balancing back-end protocol tcp|udp external `addr`:`port`
local `addr`:`port` [vrf `table-id`] probability `n` [del]

> nat44 add load-balancing static mapping protocol tcp|udp  external
`addr`:`port` local `addr`:`port` [vrf `table-id`] probability `n`
[twice-nat|self-twice-nat] [out2in-only] [affinity `timeout-seconds`] [del]

### Configure per vrf session limits

> set nat44 session limit `limit` [vrf `table-id`]

### Delete NAT44-ED session

> nat44 del session in|out `addr`:`port` tcp|udp|icmp [vrf `id`]
[external-host `addr`:`port`]

### Show commands

```
show nat workers
show nat timeouts
show nat44 summary
show nat44 addresses
show nat mss-clamping
show nat44 interfaces
nat44 show static mappings
show nat44 interface address
show nat44 sessions [detail|metrics]
show nat44 hash tables [detail|verbose]
```