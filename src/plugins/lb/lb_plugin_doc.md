# Load Balancer plugin for VPP    {#lb_plugin_doc}

## Version

The load balancer plugin is currently in *beta* version.
Both CLIs and APIs are subject to *heavy* changes.
Wich also means feedback is really welcome regarding features, apis, etc...

## Overview

This plugin provides load balancing for VPP in a way that is largely inspired
from Google's MagLev: http://research.google.com/pubs/pub44824.html

The load balancer is configured with a set of Virtual IPs (VIP, which can be
prefixes), and for each VIP, with a set of Application Server addresses (ASs).

There are four encap types to steer traffic to different ASs:
1). IPv4+GRE ad IPv6+GRE encap types:
Traffic received for a given VIP (or VIP prefix) is tunneled using GRE towards
the different ASs in a way that (tries to) ensure that a given session will
always be tunneled to the same AS.

2). IPv4+L3DSR encap types:
L3DSR is used to overcome Layer 2 limitations of Direct Server Return Load Balancing.
It maps VIP to DSCP bits, and reuse TOS bits to transfer DSCP bits
to server, and then server will get VIP from DSCP-to-VIP mapping.

Both VIPs or ASs can be IPv4 or IPv6, but for a given VIP, all ASs must be using
the same encap. type (i.e. IPv4+GRE or IPv6+GRE or IPv4+L3DSR).
Meaning that for a given VIP, all AS addresses must be of the same family.

3). IPv4/IPv6 + NAT4/NAT6 encap types:
This type provides kube-proxy data plane on user space,
which is used to replace linux kernal's kube-proxy based on iptables.

Currently, load balancer plugin supports three service types:
a) Cluster IP plus Port: support any protocols, including TCP, UDP.
b) Node IP plus Node Port: currently only support UDP.
c) External Load Balancer.

For Cluster IP plus Port case:
kube-proxy is configured with a set of Virtual IPs (VIP, which can be
prefixes), and for each VIP, with a set of AS addresses (ASs).

For a specific session received for a given VIP (or VIP prefix),
first packet selects a AS according to internal load balancing algorithm,
then does DNAT operation and sent to chosen AS.
At the same time, will create a session entry to store AS chosen result.
Following packets for that session will look up session table first,
which ensures that a given session will always be routed to the same AS.

For returned packet from AS, it will do SNAT operation and sent out.

Please refer to below for details:
https://schd.ws/hosted_files/ossna2017/1e/VPP_K8S_GTPU_OSSNA.pdf


## Performances

The load balancer has been tested up to 1 millions flows and still forwards more
than 3Mpps per core in such circumstances.
Although 3Mpps seems already good, it is likely that performances will be improved
in next versions.

## Configuration

### Global LB parameters

The load balancer needs to be configured with some parameters:

	lb conf [ip4-src-address <addr>] [ip6-src-address <addr>]
	        [buckets <n>] [timeout <s>]

ip4-src-address: the source address used to send encap. packets using IPv4 for GRE4 mode.
                 or Node IP4 address for NAT4 mode.

ip6-src-address: the source address used to send encap. packets using IPv6 for GRE6 mode.
                 or Node IP6 address for NAT6 mode.

buckets:         the *per-thread* established-connexions-table number of buckets.

timeout:         the number of seconds a connection will remain in the
                 established-connexions-table while no packet for this flow
                 is received.

### Configure the VIPs

    lb vip <prefix> [encap (gre6|gre4|l3dsr|nat4|nat6)] \
      [dscp <n>] [port <n> target_port <n> node_port <n>] [new_len <n>] [del]

new_len is the size of the new-connection-table. It should be 1 or 2 orders of
magnitude bigger than the number of ASs for the VIP in order to ensure a good
load balancing.
Encap l3dsr and dscp is used to map VIP to dscp bit and rewrite DSCP bit in packets.
So the selected server could get VIP from DSCP bit in this packet and perform DSR.
Encap nat4/nat6 and port/target_port/node_port is used to do kube-proxy data plane.

Examples:

    lb vip 2002::/16 encap gre6 new_len 1024
    lb vip 2003::/16 encap gre4 new_len 2048
    lb vip 80.0.0.0/8 encap gre6 new_len 16
    lb vip 90.0.0.0/8 encap gre4 new_len 1024
    lb vip 100.0.0.0/8 encap l3dsr dscp 2 new_len 32
    lb vip 90.1.2.1/32 encap nat4 port 3306 target_port 3307 node_port 30964 new_len 1024
    lb vip 2004::/16 encap nat6 port 6306 target_port 6307 node_port 30966 new_len 1024

### Configure the ASs (for each VIP)

    lb as <vip-prefix> [<address> [<address> [...]]] [del]

You can add (or delete) as many ASs at a time (for a single VIP).
Note that the AS address family must correspond to the VIP encap. IP family.

Examples:

    lb as 2002::/16 2001::2 2001::3 2001::4
    lb as 2003::/16 10.0.0.1 10.0.0.2
    lb as 80.0.0.0/8 2001::2
    lb as 90.0.0.0/8 10.0.0.1

### Configure SNAT

    lb set interface nat4 in <intfc> [del]

Set SNAT feature in a specific interface.
(applicable in NAT4 mode only)

    lb set interface nat6 in <intfc> [del]

Set SNAT feature in a specific interface.
(applicable in NAT6 mode only)

## Monitoring

The plugin provides quite a bunch of counters and information.
These are still subject to quite significant changes.

    show lb
    show lb vip
    show lb vip verbose

    show node counters


## Design notes

### Multi-Threading

MagLev is a distributed system which pseudo-randomly generates a
new-connections-table based on AS names such that each server configured with
the same set of ASs ends up with the same table. Connection stickyness is then
ensured with an established-connections-table. Using ECMP, it is assumed (but
not relied on) that servers will mostly receive traffic for different flows.

This implementation pushes the parallelism a little bit further by using
one established-connections table per thread. This is equivalent to assuming
that RSS will make a job similar to ECMP, and is pretty useful as threads don't
need to get a lock in order to write in the table.

### Hash Table

A load balancer requires an efficient read and write hash table. The hash table
used by ip6-forward is very read-efficient, but not so much for writing. In
addition, it is not a big deal if writing into the hash table fails (again,
MagLev uses a flow table but does not heaviliy relies on it).

The plugin therefore uses a very specific (and stupid) hash table.
	- Fixed (and power of 2) number of buckets (configured at runtime)
	- Fixed (and power of 2) elements per buckets (configured at compilation time)

### Reference counting

When an AS is removed, there is two possible ways to react.
	- Keep using the AS for established connections
	- Change AS for established connections (likely to cause error for TCP)

In the first case, although an AS is removed from the configuration, its
associated state needs to stay around as long as it is used by at least one
thread.

In order to avoid locks, a specific reference counter is used. The design is quite
similar to clib counters but:
	- It is possible to decrease the value
	- Summing will not zero the per-thread counters
	- Only the thread can reallocate its own counters vector (to avoid concurrency issues)

This reference counter is lock free, but reading a count of 0 does not mean
the value can be freed unless it is ensured by *other* means that no other thread
is concurrently referencing the object. In the case of this plugin, it is assumed
that no concurrent event will take place after a few seconds.

