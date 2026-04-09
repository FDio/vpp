Load Balancer plugin
====================

Version
-------

The load balancer plugin is currently in *beta* version. Both CLIs and
APIs are subject to *heavy* changes, which also means feedback is really
welcome regarding features, apis, etc…

Overview
--------

This plugin provides load balancing for VPP in a way that is largely
inspired from Google’s MagLev:
http://research.google.com/pubs/pub44824.html

The load balancer is configured with a set of Virtual IPs (VIP, which
can be prefixes), and for each VIP, with a set of Application Server
addresses (ASs).

There are four encap types to steer traffic to different ASs: 1).
IPv4+GRE and IPv6+GRE encap types: Traffic received for a given VIP (or
VIP prefix) is tunneled using GRE towards the different ASs in a way
that (tries to) ensure that a given session will always be tunneled to
the same AS.

2). IPv4+L3DSR encap type: L3DSR is used to overcome Layer 2
limitations of Direct Server Return Load Balancing. It maps VIPs to
DSCP bits and reuses TOS bits to transfer DSCP bits to the server; the
server then gets the VIP from the DSCP-to-VIP mapping.

Both VIPs and ASs can be IPv4 or IPv6, but for a given VIP, all ASs must
use the same encap. type (i.e. IPv4+GRE or IPv6+GRE or IPv4+L3DSR),
meaning that for a given VIP, all AS addresses must be of the same
family.

3). IPv4/IPv6 + NAT4/NAT6 encap types: This type provides a kube-proxy
data plane in user space, which is used to replace the Linux kernel’s
iptables-based kube-proxy.

Currently, the load balancer plugin supports three service types: a)
Cluster IP plus Port: supports any protocol, including TCP and UDP. b)
Node IP plus Node Port: currently only supports UDP. c) External Load
Balancer.

For the Cluster IP plus Port case, kube-proxy is configured with a set of
Virtual IPs (VIP, which can be prefixes), and for each VIP, with a set
of AS addresses (ASs).

For a specific session received for a given VIP (or VIP prefix), the
first packet selects an AS according to the internal load balancing
algorithm, then undergoes a DNAT operation and is sent to the chosen
AS. At the same time, a session entry is created to store the chosen
AS. Subsequent packets for that session will look up the session table
first, which ensures that a given session will always be routed to the
same AS.

For return packets from the AS, a SNAT operation is performed and the
packet is sent out.

Please refer to below for details:
https://schd.ws/hosted_files/ossna2017/1e/VPP_K8S_GTPU_OSSNA.pdf

Performance
-----------

The load balancer has been tested up to 1 million flows and still
forwards more than 3Mpps per core in such circumstances. Although 3Mpps
already seems good, it is likely that performance will be improved in
future versions.

Configuration
-------------

Global LB parameters
~~~~~~~~~~~~~~~~~~~~

The load balancer needs to be configured with some parameters:

::

   lb conf [ip4-src-address <addr>] [ip6-src-address <addr>]
           [buckets <n>] [timeout <s>]

ip4-src-address: the source address used to send encap. packets using
IPv4 for GRE4 mode, or the Node IPv4 address for NAT4 mode.

ip6-src-address: the source address used to send encap. packets using
IPv6 for GRE6 mode, or the Node IPv6 address for NAT6 mode.

buckets: the *per-thread* established-connections-table number of
flows.

timeout: the number of seconds a connection will remain in the
established-connections-table while no packet for this flow is received.

Configure the VIPs
~~~~~~~~~~~~~~~~~~

::

   lb vip <prefix> [encap (gre6|gre4|l3dsr|nat4|nat6)] \
     [dscp <n>] [port <n> target_port <n> node_port <n>] [new_len <n>] [del]

new_len is the size of the new-connection-table. It should be 1 or 2
orders of magnitude larger than the number of ASs for the VIP in order
to ensure good load balancing. Encap l3dsr and dscp are used to map the
VIP to a DSCP bit and rewrite the DSCP bit in packets, so the selected
server can get the VIP from the DSCP bit in the packet and perform DSR.
Encap nat4/nat6 and port/target_port/node_port are used for the
kube-proxy data plane.

Examples:

::

   lb vip 2002::/16 encap gre6 new_len 1024
   lb vip 2003::/16 encap gre4 new_len 2048
   lb vip 80.0.0.0/8 encap gre6 new_len 16
   lb vip 90.0.0.0/8 encap gre4 new_len 1024
   lb vip 100.0.0.0/8 encap l3dsr dscp 2 new_len 32
   lb vip 90.1.2.1/32 encap nat4 port 3306 target_port 3307 node_port 30964 new_len 1024
   lb vip 2004::/16 encap nat6 port 6306 target_port 6307 node_port 30966 new_len 1024

Configure the ASs (for each VIP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   lb as <vip-prefix> [<address> [<address> [...]]] [weight <0-100>] [del] [flush]

You can add (or delete) as many ASs at a time (for a single VIP). Note
that the AS address family must correspond to the VIP encap. IP family.

Examples:

::

   lb as 2002::/16 2001::2 2001::3 2001::4
   lb as 2003::/16 10.0.0.1 10.0.0.2
   lb as 80.0.0.0/8 2001::2
   lb as 90.0.0.0/8 10.0.0.1

Weighted ASs
~~~~~~~~~~~~

Each AS has a weight in the range 0-100 (default 100) that controls its
share of the Maglev new-flow table. Bucket allocation is proportional to
an AS's weight relative to the sum of weights across all live ASs on the
VIP. Setting ``weight`` on ``lb as`` either adds a new AS at that weight
or updates an existing AS in place.

Weight 0 means the AS receives no new flows. Existing flows continue to
hit it via the per-thread established-connections-table (sticky hash),
so weight 0 acts as a **graceful drain**.

Appending ``flush`` to a weight update performs a **hard drain**: after
rebuilding the new-flow table, sticky flows pointing at this AS are
evicted, so existing flows are rehashed through the updated Maglev table
onto a different AS. ``flush`` is also accepted with nonzero weight to
force a rehash of surviving sticky flows after a weight update.

Examples:

::

   # Introduce a new AS slowly (1% → 5% → 20% → 100%)
   lb as 90.0.0.0/8 10.0.0.1 weight 1
   lb as 90.0.0.0/8 10.0.0.1 weight 5
   lb as 90.0.0.0/8 10.0.0.1 weight 20
   lb as 90.0.0.0/8 10.0.0.1 weight 100

   # Graceful drain: stop new flows, keep existing sessions
   lb as 90.0.0.0/8 10.0.0.1 weight 0

   # Hard drain: stop new flows AND break existing sessions
   lb as 90.0.0.0/8 10.0.0.1 weight 0 flush

   # Fully remove, also dropping any remaining sessions
   lb as 90.0.0.0/8 10.0.0.1 del flush

Configure SNAT
~~~~~~~~~~~~~~

::

   lb set interface nat4 in <intfc> [del]

Set the SNAT feature on a specific interface. (applicable in NAT4 mode only)

::

   lb set interface nat6 in <intfc> [del]

Set the SNAT feature on a specific interface. (applicable in NAT6 mode only)

Monitoring
----------

The plugin provides a number of counters and other information. These
are still subject to significant changes.

::

   show lb
   show lb vip
   show lb vip verbose

   show node counters

Design notes
------------

Multi-Threading
~~~~~~~~~~~~~~~

MagLev is a distributed system which pseudo-randomly generates a
new-connections-table based on AS names such that each server
configured with the same set of ASs ends up with the same table.
Connection stickiness is then ensured with an
established-connections-table. Using ECMP, it is assumed (but not
relied on) that servers will mostly receive traffic for different
flows.

This implementation pushes parallelism a little bit further by using
one established-connections table per thread. This is equivalent to
assuming that RSS will do a job similar to ECMP, and is quite useful as
threads don’t need to acquire a lock in order to write to the table.

Hash Table
~~~~~~~~~~

A load balancer requires an efficient read and write hash table. The
hash table used by ip6-forward is very read-efficient, but not so much
for writing. In addition, it is not a big deal if writing into the
hash table fails (again, MagLev uses a flow table but does not heavily
rely on it).

The plugin therefore uses a very specific (and simple) hash table. -
Fixed (and power of 2) number of buckets (configured at runtime) -
Fixed (and power of 2) elements per bucket (configured at compilation
time)

Reference counting
~~~~~~~~~~~~~~~~~~

When an AS is removed, there are two possible ways to react. - Keep
using the AS for established connections - Change AS for established
connections (likely to cause errors for TCP)

In the first case, although an AS is removed from the configuration, its
associated state needs to stay around as long as it is used by at least
one thread.

In order to avoid locks, a specific reference counter is used. The
design is quite similar to clib counters but: - It is possible to
decrease the value - Summing will not zero the per-thread counters -
Only the thread can reallocate its own counters vector (to avoid
concurrency issues)

This reference counter is lock free, but reading a count of 0 does not
mean the value can be freed unless it is ensured by *other* means that
no other thread is concurrently referencing the object. In the case of
this plugin, it is assumed that no concurrent event will take place
after a few seconds.
