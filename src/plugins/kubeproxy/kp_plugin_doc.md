# Kube-proxy plugin for VPP    {#kp_plugin_doc}

## Version

The kube-proxy plugin is currently in *beta* version.
Both CLIs and APIs are subject to *heavy* changes.
Which also means feedback is really welcome regarding features, apis, etc...

## Overview

This plugin provides kube-proxy for VPP in a way that is largely inspired
from Google's MagLev: http://research.google.com/pubs/pub44824.html

The kube-proxy is configured with a set of Virtual IPs (VIP, which can be
prefixes), and for each VIP, with a set of POD addresses (PODs).

Traffic received for a given VIP (or VIP prefix) is tunneled using NAT towards
the different PODs in a way that (tries to) ensure that a given session will
always be routed to the same POD.

Both VIPs or PODs can be IPv4 or IPv6, but for a given VIP, all PODs must be using
the same NAT type (i.e. IPv4+NAT4 or IPv6+NAT6). Meaning that for a given VIP,
all POD addresses must be of the same family.

Please refer: https://schd.ws/hosted_files/ossna2017/1e/VPP_K8S_GTPU_OSSNA.pdf

## Performances

The kube-proxy has been tested up to 1 millions flows and still forwards more
than 3Mpps per core in such circumstances.
Although 3Mpps seems already good, it is likely that performances will be improved
in next versions.

## Configuration

### Global KP parameters

The kube-proxy needs to be configured with some parameters:

	kp conf [buckets <n>] [timeout <s>]

buckets:         the *per-thread* established-connections-table number of buckets.

timeout:         the number of seconds a connection will remain in the
                 established-connections-table while no packet for this flow
                 is received.

### Configure the VIPs

    kp vip <prefix>  port <n> target_port <n> node_port <n> \
      [nat4|nat6)] [new_len <n>] [del]

new_len is the size of the new-connection-table. It should be 1 or 2 orders of
magnitude bigger than the number of PODs for the VIP in order to ensure a good
load balancing.

Examples:

    kp vip 2002::/16 nat64 new_len 1024
    kp vip 2003::/16 nat66 new_len 2048
    kp vip 80.0.0.0/8 nat46 new_len 1024
    kp vip 90.0.0.0/8 nat44 new_len 2048

### Configure the PODs (for each VIP)

    kp pod <vip-prefix> [<address> [<address> [...]]] [del]

You can add (or delete) as many PODs at a time (for a single VIP).
Note that the POD address family must correspond to the VIP's IP family.

Examples:

    kp pod 2002::/16 2001::2 2001::3 2001::4
    kp pod 2003::/16 10.0.0.1 10.0.0.2
    kp pod 80.0.0.0/8 2001::2
    kp pod 90.0.0.0/8 10.0.0.1

## Monitoring

The plugin provides quite a bunch of counters and information.
These are still subject to quite significant changes.

    show kp
    show kp vip
    show kp vip verbose

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

A kube-proxy requires an efficient read and write Hash table. The Hash table
used by ip6-forward is very read-efficient, but not so much for writing. In
addition, it is not a big deal if writing into the Hash table fails (again,
MagLev uses a flow table but does not heaviliy relies on it).

The plugin therefore uses a very specific (and stupid) Hash table.
	- Fixed (and power of 2) number of buckets (configured at runtime)
	- Fixed (and power of 2) elements per buckets (configured at compilation time)

### Reference counting

When an POD is removed, there is two possible ways to react.
	- Keep using the POD for established connections
	- Change POD for established connections (likely to cause error for TCP)

In the first case, although an POD is removed from the configuration, its
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

