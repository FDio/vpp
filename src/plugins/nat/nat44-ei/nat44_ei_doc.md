# NAT44-EI: Endpoint Independent Network Address Translation IPv4 to IPv4

## Introduction

Supported features:
  - dynamic nat (PAT)
  - static mapping
    - address only mapping
  - out2in-dpo
  - identity mapping
  - mss-clamping
  - syslog
  - ipfix logging
  - pre routing / post routing translations

## Configuraiton

### Enable/Disable NAT44-EI plugin

> nat44 ei enable sessions <max-number> [users <max-number>] [static-mappig-only [connection-tracking]|out2in-dpo] [inside-vrf  <vrf-id>] [outside-vrf <vrf-id>] [user-sessions <max-number>]

> nat44 ei disable

### Enable/Disable NAT44-EI feature on interface

> set interface nat44 ei in <intfc> out <intfc> [output-feature] [del]

### Enable/Disable forwarding

> nat44 ei forwarding enable|disable

### Add outside address

> nat44 ei add interface address <interface> [del]

> nat44 ei add address <ip4-range-start> [- <ip4-range-end>] [tenant-vrf <vrf-id>] [del]

### Configure protocol timeouts

> set nat44 ei timeout [udp <sec> | tcp-established <sec> tcp-transitory <sec> | icmp <sec> | reset]

### Additional configuration

> set nat44 ei workers <workers-list>

### Configure port assignment algorithm

> nat44 ei addr-port-assignment-alg <alg-name> [<alg-params>]

### Configure logging

> nat44 ei set logging level <level>

> nat44 ei ipfix logging [domain <domain-id>] [src-port <port>] [disable]

### Configure mss-clamping

> nat44 ei mss-clamping <mss-value>|disable

### Add static mapping

> nat44 ei add static mapping tcp|udp|icmp local <addr> [<port|icmp-echo-id>] external <addr> [<port|icmp-echo-id>] [vrf <table-id>] [del]

### Add identity mapping

> nat44 ei add identity mapping <ip4-addr>|external <interface> [<protocol> <port>] [vrf <table-id>] [del]

### Configure NAT44-EI HA

> nat44 ei ha failover <ip4-address>:<port> [refresh-interval <sec>]

> nat44 ei ha listener <ip4-address>:<port> [path-mtu <path-mtu>]

> nat44 ei ha flush

> nat44 ei ha resync

### Clear all NAT44-EI sessions & users

> clear nat44 ei sessions

### Delete NAT44-EI user with all of his sessions

> nat44 ei del user <addr> [fib <index>]

### Delete NAT44-EI session

> nat44 ei del session in|out <addr>:<port> tcp|udp|icmp [vrf <id>] [external-host <addr>:<port>]

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
show nat44 ei sessions [detail|metrics]
show nat44 ei hash tables [detail|verbose]
show nat44 ei interface address
```
