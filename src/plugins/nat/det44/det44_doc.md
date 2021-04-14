# DET44: Deterministic Network Address Translation (CGNAT)

## Introduction

Carrier-grade NAT allows pools with preallocated sessions and
predetermined translations from inside to outside with port.

## Configuration

### Enable/Disable DET44 plugin

> det44 plugin <enable [inside `vrf`] [outside `vrf`] | disable>

vrf id

### Enable/Disable DET44 feature on interface

> set interface det44 inside `intfc` outside `intfc` [del]

interface index.

### Add DET44 mapping

> det44 add in `addr`/`plen` out `addr`/`plen` [del]

IPv4 address and IPv4 suffix.

### Configure protocol timeouts

> set det44 timeouts <[udp `sec`] [tcp established `sec`]
[tcp transitory `sec`] [icmp `sec`] | reset>

number of seconds.

### Manualy close sessions

> det44 close session out `out_addr`:`out_port` `ext_addr`:`ext_port`\
det44 close session in `in_addr`:`in_port` `ext_addr`:`ext_port`

in_addr: inside IPv4 address, in_port: inside TCP/UDP port\
out_addr: outside IPv4 address, out_port: outside TCP/UDP port

### Get coresponding outside address based on inside address

> det44 forward `addr`

IPv4 address

### Get coresponding inside address based on outside address and port

> det44 reverse `addr`:`port`

IPv4 address and TCP/UDP port

### Show commands

```
show det44 interfaces
show det44 sessions
show det44 timeouts
show det44 mappings
```

## Notes

Deterministic NAT currently preallocates 1000 sessions per user.