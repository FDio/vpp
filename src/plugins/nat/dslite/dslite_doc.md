# DSLITE: IPv6 Dual-Stack Lite

## Introduction

DS-Lite NAT (IPv4-in-IPv6) allows tunneling IPv6 traffic over IPv4 network.

## Configuration


### Add dslite pool address

> dslite add pool address <ip4-range-start> [- <ip4-range-end>] [del]

### Set before endpoint address

> dslite set b4-tunnel-endpoint-address <ip6>

### Set after endpoint address

> dslite set aftr-tunnel-endpoint-address <ip6>

### Show commands

```
show dslite aftr-tunnel-endpoint-address
show dslite b4-tunnel-endpoint-address
show dslite sessions
show dslite pool
```

## Notes

After first configuration data structures get allocated.
