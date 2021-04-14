# Stateful NAT64: Network Address and Protocol Translation from IPv6 Clients to IPv4 Servers

## Introduction

Stateful NAT64 in VPP allows IPv6-only clients to contact IPv4 servers using unicast UDP, TCP, or ICMP based on RFC 6146.

## Configuration

### Enable/disable NAT64 feature on the interface

> set interface nat64 in|out <intfc> [del]

in: inside/local/IPv6 network
out: outside/external/IPv4 network
intfc: interface name

### Add/delete NAT64 pool address

One or more public IPv4 addresses assigned to a NAT64 are shared among several IPv6-only clients.

> nat64 add pool address <ip4-range-start> [- <ip4-range-end>] [tenant-vrf <tenant-vrf-id>] [del]

ip4-range-start: First IPv4 address of the range 
ip4-range-end: Last IPv4 address of the range (optional, not used for single address)
tenant-vrf-id: VRF id of the tenant associated with the pool address (optional, if not set pool address is global)

### Add/delete static BIB entry

Stateful NAT64 also supports IPv4-initiated communications to a subset of the IPv6 hosts through staticaly configured bindings.

> nat64 add static bib <ip6-addr> <in-port> <ip4-addr> <out-port> tcp|udp|icmp [vfr <table-id>] [del]

ip6-addr: inside IPv6 address of the host
in-port: inside port or ICMPv6 identifier
ip4-addr: outside IPv4 address of the host
out-port: outside port or ICMPv4 identifier
table-id: VRF id of the tenant associated with the BIB entry (optional, default use global VRF)

### Set NAT64 session timeouts

Session is deleted when timer expires. If all sessions corresponding to a dynamically create BIB entry are deleted, then the BIB entry is also deleted. When packets are flowing sessiom timer is refreshed to keep the session alive.

> set nat64 timeouts udp <sec> icmp <sec> tcp-trans <sec> tcp-est <sec> tcp-incoming-syn <sec> | reset

udp: UDP session timeout value (default 300sec)
icmp: ICMP session timeout value (default 60sec)
tcp-trans: transitory TCP session timeout value (default 240sec)
tcp-est: established TCP session timeout value (default 7440sec)
tcp-incoming-syn: incoming SYN TCP session timeout value (default 6sec)
reset: reset timers to default values

### Set NAT64 prefix 

Stateful NAT64 support the algorithm for generating IPv6 representations of IPv4 addresses defined in RFC 6052. If no prefix is configured, Well-Known Prefix (64:ff9b::/96) is used. 

> nat64 add prefix <ip6-prefix>/<plen> [tenant-vrf <vrf-id>] [del]

ip6-prefix: IPv6 prefix
plen: prefix length (valid values: 32, 40, 48, 56, 64, or 96)
tenant-vrf: VRF id of the tenant associated with the prefix

### Show commands

> show nat64 pool
> show nat64 interfaces
> show nat64 bib tcp|udp|icmp
> show nat64 session table tcp|udp|icmp
> show nat64 timeouts
> show nat64 prefix

## Notes

Multi thread is not supported yet (CLI/API commands are disabled when VPP runs with multiple threads).
