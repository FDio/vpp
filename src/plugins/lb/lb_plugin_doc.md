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

Traffic received for a given VIP (or VIP prefix) is tunneled using GRE towards
the different ASs in a way that (tries to) ensure that a given session will 
always be tunneled to the same AS.

Both VIPs or ASs can be IPv4 or IPv6, but for a given VIP, all ASs must be using
the same encap. type (i.e. IPv4+GRE or IPv6+GRE). Meaning that for a given VIP,
all AS addresses must be of the same family.

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
	       
ip4-src-address: the source address used to send encap. packets using IPv4.

ip6-src-address: the source address used to send encap. packets using IPv6.

buckets:         the *per-thread* established-connexions-table number of buckets.

timeout:         the number of seconds a connection will remain in the 
                 established-connexions-table while no packet for this flow
                 is received.
                 

### Configure the VIPs

    lb vip <prefix> [encap (gre6|gre4)] [new_len <n>] [del]
    
new_len is the size of the new-connection-table. It should be 1 or 2 orders of
magnitude bigger than the number of ASs for the VIP in order to ensure a good
load balancing.

Examples:
    
    lb vip 2002::/16 encap gre6 new_len 1024
    lb vip 2003::/16 encap gre4 new_len 2048
    lb vip 80.0.0.0/8 encap gre6 new_len 16
    lb vip 90.0.0.0/8 encap gre4 new_len 1024

### Configure the ASs (for each VIP)

    lb as <vip-prefix> [<address> [<address> [...]]] [del]

You can add (or delete) as many ASs at a time (for a single VIP).
Note that the AS address family must correspond to the VIP encap. IP family.

Examples:

    lb as 2002::/16 2001::2 2001::3 2001::4
    lb as 2003::/16 10.0.0.1 10.0.0.2
    lb as 80.0.0.0/8 2001::2
    lb as 90.0.0.0/8 10.0.0.1
    
    

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

