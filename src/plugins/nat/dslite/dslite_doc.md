# DSLITE: IPv6 Dual-Stack Lite

## Introduction

DS-Lite NAT (IPv4-in-IPv6) allows tunneling IPv6 traffic over IPv4 network.

## Configuration

### Add dslite pool address

> dslite add pool address `ip4-range-start` [- `ip4-range-end`] [del]

ip4-range-start: IPv4 address, ip4-range-end: IPv4 address

### Set before endpoint address

> dslite set b4-tunnel-endpoint-address `ip6`

ip6: IPv6 address

### Set after endpoint address

> dslite set aftr-tunnel-endpoint-address `ip6`

ip6: IPv6 address

### Show commands

```
show dslite aftr-tunnel-endpoint-address
show dslite b4-tunnel-endpoint-address
show dslite sessions
show dslite pool
```

## Notes

Data structures get allocated after first configuration.
