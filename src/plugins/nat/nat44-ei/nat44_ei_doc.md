# NAT44-EI: NAT44 Endpoint Independent

## Introduction

NAT44-EI is IPv4 endpoint independent network address translation plugin.\
NAT44-EI uses 4 touple`(address, port, protocol and fib)`for matching
communication.

Supported features:
- NAT Overload - PAT (Port Address Translation)
- Dynamic NAT (Network address translation)
- Static NAT (static mappings)
  - address only mapping
    - 1-1 translation withouth ports
  - out2in-dpo
  - identity mapping
    - exceptions to translations
- mss-clamping
- syslog
- ipfix logging
- pre routing / post routing translations
  - pre routing is the default behaviour, nat processing happens
    before ip4-lookup node
  - using output-feature moves processing of nat traffic for the
    specific nat interface after ip4-lookup node
  - output-features enables translating traffic after routing

## Configuraiton

### Enable/disable plugin

> nat44 ei enable sessions max-number [users `max-number`] [static-mappig-only
[connection-tracking] | out2in-dpo] [inside-vrf `vrf-id`] [outside-vrf `vrf-id`]
[user-sessions `max-number`]

> nat44 ei disable

max-number: users, sessions, user-sessions vrf-id: inside, outside vrf id

### Enable/disable feature on interface

> set interface nat44 ei in `intfc` out `intfc` [output-feature] [del]

inside, outside interface index. output-feature: moves NAT in2out packet
processing after ip4-lookup node

### Enable/disable forwarding

> nat44 ei forwarding enable|disable

### Add outside address

> nat44 ei add interface address `interface` [del]\
nat44 ei add address `ip4-range-start` [- `ip4-range-end`]
[tenant-vrf `vrf-id`] [del]

interface: name of the interface ip4-range-start: IPv4 address
ip4-range-end: IPv4 address vrf-id: tenant vrf id

### Configure protocol timeouts

> set nat44 ei timeout [udp `sec` | tcp-established `sec`
tcp-transitory `sec` | icmp `sec` | reset]

Specify number of seconds.

### Additional configuration

> set nat44 ei workers `workers-list`

### Configure port assignment algorithm

> nat44 ei addr-port-assignment-alg `alg-name` [`alg-params`]

Specify algorithm name and optional algorithm parameters.

### Configure logging

> nat44 ei set logging level `level`\
nat44 ei ipfix logging [domain `domain-id`] [src-port `port`] [disable]

level: logging level domain-id: unique domain id
port: collectors TCP or UDP port

### Configure mss-clamping

> nat44 ei mss-clamping `mss-value` | disable

TCP MSS Value

### Add static mapping

> nat44 ei add static mapping tcp|udp|icmp local `addr` [`port | icmp-echo-id`]
external `addr` [`port | icmp-echo-id`] [vrf `table-id`] [del]

addr: IPv4 address port: TCP or UDP port icmp-echo-id: ICMP identifier
table-id: vrf table id

### Add identity mapping

> nat44 ei add identity mapping `ip4-addr`| external `interface`
[`protocol` `port`] [vrf `table-id`] [del]

ip4-addr: IPv4 address interface: interface name protocol: TCP or UDP protocol
port: TCP or UDP port table-id: vrf table id

### Configure high availability

> nat44 ei ha failover `ip4-address`:`port` [refresh-interval `sec`]\
nat44 ei ha listener `ip4-address`:`port` [path-mtu `path-mtu`]\
nat44 ei ha flush\
nat44 ei ha resync

port: TCP or UDP protocol port

Additional manual for high availability
> `nat44_ei_ha_doc.md`

### Clear all NAT44-EI sessions & users

> clear nat44 ei sessions

### Delete NAT44-EI user with all of his sessions

> nat44 ei del user `addr` [fib `index`]

addr: IPv4 local/inside host address

### Delete NAT44-EI session

> nat44 ei del session in | out `addr`:`port` tcp | udp | icmp
[vrf `id`] [external-host `addr`:`port`]

addr: IPv4 address port: TCP, UDP port or ICMP Identifier

### Show commands

```
show nat44 ei ha
show nat44 ei workers
show nat44 ei timeouts
show nat44 ei addresses
show nat44 ei interfaces
show nat44 ei mss-clamping
show nat44 ei static mappings
show nat44 ei addr-port-assignment-alg
show nat44 ei sessions [detail]
show nat44 ei hash tables [detail | verbose]
show nat44 ei interface address
```