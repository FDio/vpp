.. _fastconvergence:

Fast Convergence
------------------------------------

This is an excellent description of the topic:

'FIB <https://tools.ietf.org/html/draft-ietf-rtgwg-bgp-pic-12>'_

but if you're interested in my take keep reading...

First some definitions:

- Convergence; When a FIB is forwarding all packets correctly based
  on the network topology (i.e. doing what the routing control plane
  has instructed it to do), then it is said to be 'converged'.
  Not being in a converged state is [hopefully] a transient state,
  when either the topology change (e.g. a link failure) has not been
  observed or processed by the routing control plane, or that the FIB
  is still processing routing updates. Convergence is the act of
  getting to the converged state.
- Fast: In the shortest time possible. There are no absolute limits
  placed on how short this must be, although there is one number often
  mentioned. Apparently the human ear can detect loss/delay/jitter in
  VOIP of 50ms, therefore network failures should last no longer than
  this, and some technologies (notably link-free alternate fast
  reroute) are designed to converge in this time. However, it is
  generally accepted that it is not possible to converge a FIB with
  tens of millions of routes in this time scale, the industry
  'standard' is sub-second.

Converging the FIB quickly is thus a matter of:

- discovering something is down
- updating as few objects as possible
- to determine which objects to update as efficiently as possible
- to update each object as quickly as possible

we'll discuss each in turn.
All output came from VPP version 21.01rc0. In what follows I use IPv4
prefixes, addresses and IPv4 host length masks, however, exactly the
same applies to IPv6.


Failure Detection
^^^^^^^^^^^^^^^^^

The two common forms (we'll see others later on) of failure detection
are:

- link down
- BFD

The FIB needs to hook into these notifications to trigger
convergence.

Whenever an interface goes down, VPP issues a callback to all
registerd clients. The adjacency code is such a client. The adjacency
is a leaf node in the FIB control-plane graph (containing fib_path_t,
fib_entry_t etc). A back-walk from the adjacnecy will trigger a
re-resolution of the paths.

FIB is a client of BFD in order to receive BFD notifications. BFD
comes in two flavours; single and multi hop. Single hop is to protect
a specific peer on an interface, such peers are modelled by an
adjacency. Multi hop is to protect a peer on an unspecified interface
(i.e. a remote peer), this peer is represented by a host-prefix
**fib_entry_t**. In both case FIB will add a delegate to the
**ip_adjacency_t** or **fib_entry_t** that represents the association
to the BFD session. If the BFD session signals up/down then a backwalk
can be triggered from the object to trigger re-resolution and hence
convergence.


Few Updates
^^^^^^^^^^^

In order to talk about what 'a few' is we have to leave the realm of
the FIB as an abstract graph based object DB and move into the
concrete representation of forwarding in a large network. Large
networks are built in layers, it's how you scale them. We'll take
here a hypothetical service provider (SP) network, but the concepts
apply equally to data center leaf-spines. This is a rudimentary
description, but it should serve our purpose. 

An SP manages a BGP autonomous system (AS). The SP's goal is both to
attract traffic into its network to serve its customers, but also to
serve transit traffic passing through it, we'll consider the latter here.
The SP's network is all devices in that AS, these
devices are split into those at the edge (provider edge (PE) routers)
which peer with routers in other SP networks,
and those in the core (termed provider (P) routers). Both the PE and P
routers run the IGP (usually OSPF or ISIS). Only the reachability of the devices
in the AS are advertised in the IGP - thus the scale (i.e. the number
of routes) in the IGP is 'small' -  only the number of
devices that the SP has (typically not more than a few 10k).
PE routers run BGP; they have external BGP sessions to devices in
other ASs and internal BGP sessions to devices in the same AS. BGP is
used to advertise the routes to *all* networks on the internet - at
the time of writing this number is approaching 900k IPv4 route, hopefully by
the time you are reading this the number of IPv6 routes has caught up ...
If we include the additional routes the SP carries to offering VPN service to its
customers the number of BGP routes can grow to the tens of millions.

BGP scale thus exceeds IGP scale by two orders of magnitude... pause for
a moment and let that sink in...

A comparison of BGP and an IGP is way way beyond the scope of this
documentation (and frankly beyond me) so we'll note only the
difference in the form of the routes they present to FIB. A routing
protocol will produce routes that specify the prefixes that are
reachable through its peers. A good IGP
is link state based, it forms peerings to other devices over these
links, hence its routes specify links/interfaces. In
FIB nomenclature this means an IGP produces routes that are
attached-nexthop, e.g.:

.. code-block:: console

    ip route add 1.1.1.1/32 via 10.0.0.1 GigEthernet0/0/0

BGP on the other hand forms peerings only to neighbours, it does not
know, nor care, what interface is used to reach the peer. In FIB
nomenclature therefore BGP produces recursive routes, e.g.:

.. code-block:: console

    ip route 8.0.0.0/16 via 1.1.1.1

where 1.1.1.1 is the BGP peer. It's no accident in this example that
1.1.1.1/32 happens to be the route the IGP advertised... BGP installs
routes for prefixes reachable via other BGP peers, and the IGP install
the routes to those BGP peers.

This has been a very long winded way of describing why the scale of
recursive routes is therefore 2 orders of magnitude greater than
non-recursive/attached-nexthop routes.

If we step back for a moment and recall why we've crawled down this
rabbit hole, we're trying to determine what 'a few' updates means,
does it include all those recursive routes, probably not ... let's
keep crawling.

We started this chapter with an abstract description of convergence,
let's now make that more real. In the event of a network failure an SP
is interested in moving to an alternate forwarding path as quickly as
possible. If there is no alternate path, and a converged FIB will drop
the packet, then who cares how fast it converges. In other words the
interesting convergence scenarios are the scenarios where the network has
alternate paths.

PIC Core
^^^^^^^^

First let's consider alternate paths in the IGP, e.g.;

.. code-block:: console

    ip route add 1.1.1.1/32 via 10.0.0.2 GigEthernet0/0/0
    ip route add 1.1.1.1/32 via 10.0.1.2 GigEthernet0/0/1

this gives us in the FIB:

.. code-block:: console

                DBGvpp# sh ip fib 1.1.1.1/32
                  ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, default-route:1, ]
                  1.1.1.1/32 fib:0 index:15 locks:2
                    API refs:1 src-flags:added,contributing,active,
                      path-list:[23] locks:2 flags:shared, uPRF-list:22 len:2 itfs:[1, 2, ]
                        path:[27] pl-index:23 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved,
                          10.0.0.2 GigEthernet0/0/0
                            [@0]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001111111111dead000000000800
                        path:[28] pl-index:23 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved,
                           10.0.1.2 GigEthernet0/0/1
                             [@0]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

                    forwarding:   unicast-ip4-chain
                      [@0]: dpo-load-balance: [proto:ip4 index:17 buckets:2 uRPF:22 to:[0:0]]
                        [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001111111111dead000000000800
                        [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

There is ECMP across the two paths. Note that the instance/index of the
load-balance present in the forwarding graph is 17.

Let's add a BGP route via this peer;

.. code-block:: console

    ip route add 8.0.0.0/16 via 1.1.1.1

in the FIB we see:


.. code-block:: console

    DBGvpp# sh ip fib 8.0.0.0/16
        ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:1, default-route:1, ]
        8.0.0.0/16 fib:0 index:18 locks:2
          API refs:1 src-flags:added,contributing,active,
            path-list:[24] locks:2 flags:shared, uPRF-list:21 len:2 itfs:[1, 2, ]
              path:[29] pl-index:24 ip4 weight=1 pref=0 recursive:  oper-flags:resolved,
                via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]

          forwarding:   unicast-ip4-chain
            [@0]: dpo-load-balance: [proto:ip4 index:20 buckets:1 uRPF:21 to:[0:0]]
                [0] [@12]: dpo-load-balance: [proto:ip4 index:17 buckets:2 uRPF:22 to:[0:0]]
                  [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001111111111dead000000000800
                  [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800
              
the load-balance object used by this route is index 20, but note that
the next load-balance in the chain is index 17, i.e. it is exactly
the same instance that appears in the forwarding chain for the IGP
route. So in the forwarding plane the packet first encounters
load-balance object 20 (which it will use in ip4-lookup) and then
number 17 (in ip4-load-balance).

What's the significance? Let's shut down one of those IGP paths:

.. code-block:: console

    DBGvpp# set in state GigEthernet0/0/0 down

the resulting update to the IGP route is:

.. code-block:: console

    DBGvpp# sh ip fib 1.1.1.1/32                        
        ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:1, default-route:1, ]
        1.1.1.1/32 fib:0 index:15 locks:4
          API refs:1 src-flags:added,contributing,active,
            path-list:[23] locks:2 flags:shared, uPRF-list:25 len:2 itfs:[1, 2, ]
              path:[27] pl-index:23 ip4 weight=1 pref=0 attached-nexthop: 
                10.0.0.2 GigEthernet0/0/0
                  [@0]: arp-ipv4: via 10.0.0.2 GigEthernet0/0/0
              path:[28] pl-index:23 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved,
                10.0.1.2 GigEthernet0/0/1
                  [@0]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

          recursive-resolution refs:1 src-flags:added, cover:-1

          forwarding:   unicast-ip4-chain
            [@0]: dpo-load-balance: [proto:ip4 index:17 buckets:1 uRPF:25 to:[0:0]]
                [0] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800


notice that the path via 10.0.0.2 is no longer flagged as resolved,
and the forwarding chain does not contain this path as a
choice. However, the key thing to note is the load-balance
instance is still index 17, i.e. it has been modified not
exchanged. In the FIB vernacular we say it has been 'in-place
modified', a somewhat linguistically redundant expression, but one that serves
to emphasise that it was changed whilst still be part of the graph, it
was never at any point removed from the graph and re-added, and it was
modified without worker barrier lock held.

Still don't see the significance? In order to converge around the
failure of the IGP link it was not necessary to update load-balance
object number 20! It was not necessary to update the recursive
route. i.e. convergence is achieved without updating any recursive
routes, it is only necessary to update the affected IGP routes, this is
the definition of 'a few'. We call this 'prefix independent
convergence' (PIC) which should really be called 'recursive prefix
independent convergence' but it isn't...

How was the trick done? As with all problems in computer science, it
was solved by a layer of misdirection, I mean indirection. The
indirection is the load-balance that belongs to the IGP route. By
keeping this object in the forwarding graph and updating it in place,
we get PIC. The alternative design would be to collapse the two layers of
load-balancing into one, which would improve forwarding performance
but would come at the cost of prefix dependent convergence. No doubt
there are situations where the VPP deployment would favour forwarding
performance over convergence, you know the drill, contributions welcome.

This failure scenario is known as PIC core, since it's one of the IGP's
core links that has failed.

iBGP PIC Edge
^^^^^^^^^^^^^

Next, let's consider alternate paths in BGP, e.g:

.. code-block:: console

    ip route add 8.0.0.0/16 via 1.1.1.1
    ip route add 8.0.0.0/16 via 1.1.1.2

the 8.0.0.0/16 prefix is reachable via two BGP next-hops (two PEs).

Our FIB now also contains:

.. code-block:: console

    DBGvpp# sh ip fib 8.0.0.0/16
    ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:2, default-route:1, ]
    8.0.0.0/16 fib:0 index:18 locks:2
      API refs:1 src-flags:added,contributing,active,
        path-list:[15] locks:2 flags:shared, uPRF-list:11 len:2 itfs:[1, 2, ]
          path:[17] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved,
            via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]
          path:[15] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved,
            via 1.1.1.2 in fib:0 via-fib:10 via-dpo:[dpo-load-balance:12]

      forwarding:   unicast-ip4-chain
        [@0]: dpo-load-balance: [proto:ip4 index:20 buckets:2 uRPF:11 to:[0:0]]
           [0] [@12]: dpo-load-balance: [proto:ip4 index:17 buckets:1 uRPF:25 to:[0:0]]
             [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001122334455dead000000000800
             [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800
           [1] [@12]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:13 to:[0:0]]
             [0] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

The first load-balance (LB) in the forwarding graph is index 20 (the astute
reader will note this is the same index as in the previous
section, I am adding paths to the same route, the load-balance is
in-place modified again). Each choice in LB 20 is another LB
contributed by the IGP route through which the route's paths recurse.

So what's the equivalent in BGP to a link down in the IGP? An IGP link
down means it loses its peering out of that link, so the equivalent in
BGP is the loss of the peering and thus the loss of reachability to
the peer. This is signaled by the IGP withdrawing the route to the
peer. But "Wait wait wait", i hear you say ... "just because the IGP
withdraws 1.1.1.1/32 doesn't mean I can't reach 1.1.1.1, perhaps there
is a less specific route that gives reachability to 1.1.1.1". Indeed
there may be. So a little more on BGP network design. I know it's like
a bad detective novel where the author drip feeds you the plot... When
describing iBGP peerings one 'always' describes the peer using one of
its GigEthernet0/0/back addresses. Why? A GigEthernet0/0/back interface
never goes down (unless you admin down it yourself), some muppet can't
accidentally cut through the GigEthernet0/0/back cable whilst digging up the
street. And what subnet mask length does a prefix have on a GigEthernet0/0/back
interface? it's 'always' a /32. Why? because there's no cable to connect
any other devices. This choice justifies there 'always' being a /32
route for the BGP peer. But what prevents there not being a less
specific - nothing.
Now clearly if the BGP peer crashes then the /32 for its GigEthernet0/0/back is
going to be removed from the IGP, but what will withdraw the less
specific - nothing.

So in order to make use of this trick of relying on the withdrawal of
the /32 for the peer to signal that the peer is down and thus the
signal to converge the FIB, we need to force FIB to recurse only via
the /32 and not via a less specific. This is called a 'recursion
constraint'. In this case the constraint is 'recurse via host'
i.e. for ipv4 use a /32.
So we need to update our route additions from before:

.. code-block:: console

    ip route add 8.0.0.0/16 via 1.1.1.1 resolve-via-host
    ip route add 8.0.0.0/16 via 1.1.1.2 resolve-via-host

checking the FIB output is left as an exercise to the reader. I hope
you're doing these configs as you read. There's little change in the
output, you'll see some extra flags on the paths.

Now let's add the less specific, just for fun:


.. code-block:: console

    ip route add 1.1.1.0/28 via 10.0.0.2 GigEthernet0/0/0

nothing changes in resolution of 8.0.0.0/16.

Now withdraw the route to 1.1.1.2/32:

.. code-block:: console

    ip route del 1.1.1.2/32 via 10.0.0.2 GigEthernet0/0/0

In the FIB we see:

.. code-block:: console

    DBGvpp# sh ip fib 8.0.0.0/32                      
      ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:2, default-route:1, ]
      8.0.0.0/16 fib:0 index:18 locks:2
        API refs:1 src-flags:added,contributing,active,
          path-list:[15] locks:2 flags:shared, uPRF-list:13 len:2 itfs:[1, 2, ]
            path:[15] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
              via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]
            path:[17] pl-index:15 ip4 weight=1 pref=0 recursive:  cfg-flags:resolve-host,
              via 1.1.1.2 in fib:0 via-fib:10 via-dpo:[dpo-drop:0]

        forwarding:   unicast-ip4-chain
          [@0]: dpo-load-balance: [proto:ip4 index:20 buckets:1 uRPF:13 to:[0:0]]
            [0] [@12]: dpo-load-balance: [proto:ip4 index:17 buckets:2 uRPF:27 to:[0:0]]
              [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001122334455dead000000000800
              [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

the path via 1.1.1.2 is unresolved, because the recursion constraints
are preventing the the path resolving via 1.1.1.0/28. the LB index 20
has been updated to remove the unresolved path.

Job done? Not quite! Why not?

Let's re-examine the goals of this chapter. We wanted to update 'a
few' objects, which we have defined as not all the millions of
recursive routes. Did we do that here? We sure did, when we
modified LB index 20. So WTF?? Where's the indirection object that can
be modified so that the LBs for the recursive routes are not
modified - it's not there.... WTF?

OK so the great detective has assembled all the suspects in the
drawing room and only now does he drop the bomb; the FIB knows the
scale, we talked above about what the scale **can** be, worst case
scenario, but that's not necessarily what it is in this hypothetical
(your) deployment. It knows how many recursive routes there are that
depend on a /32, it can thus make its own determination of the
definition of 'a few'. In other words, if there are only 'a few'
recursive prefixes that depend on a /32 then it will update them
synchronously (and we'll discuss what synchronously means a bit more later).

So what does FIB consider to be 'a few'. Let's add more routes and
find out.

.. code-block:: console

    DBGvpp# ip route add 8.1.0.0/16 via 1.1.1.2 resolve-via-host via 1.1.1.1 resolve-via-host
      ...
    DBGvpp# ip route add 8.63.0.0/16 via 1.1.1.2 resolve-via-host via 1.1.1.1 resolve-via-host

and we see:

.. code-block:: console

    DBGvpp# sh ip fib 8.8.0.0                         
     ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:4, default-route:1, ]
     8.8.0.0/16 fib:0 index:77 locks:2
     API refs:1 src-flags:added,contributing,active,
       path-list:[15] locks:128 flags:shared,popular, uPRF-list:28 len:2 itfs:[1, 2, ]
         path:[17] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
           via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]
         path:[15] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
           via 1.1.1.2 in fib:0 via-fib:10 via-dpo:[dpo-load-balance:12]

     forwarding:   unicast-ip4-chain
       [@0]: dpo-load-balance: [proto:ip4 index:79 buckets:2 uRPF:28 flags:[uses-map] to:[0:0]]
           load-balance-map: index:0 buckets:2
              index:    0    1
                map:    0    1
         [0] [@12]: dpo-load-balance: [proto:ip4 index:17 buckets:2 uRPF:27 to:[0:0]]
           [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001122334455dead000000000800
           [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800
         [1] [@12]: dpo-load-balance: [proto:ip4 index:12 buckets:1 uRPF:18 to:[0:0]]
           [0] [@3]: arp-ipv4: via 10.0.1.2 GigEthernet0/0/0


Two elements to note here; the path-list has the 'popular' flag and
there is a load-balance map in the forwarding path.

'popular' in this case means that the path-list has passed the limit
of 'a few' in the number of children it has.

here are the children:

.. code-block:: console

  DBGvpp# sh fib path-list 15
    path-list:[15] locks:128 flags:shared,popular, uPRF-list:28 len:2 itfs:[1, 2, ]
      path:[17] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
        via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]
      path:[15] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
        via 1.1.1.2 in fib:0 via-fib:10 via-dpo:[dpo-load-balance:12]
      children:{entry:18}{entry:21}{entry:22}{entry:23}{entry:25}{entry:26}{entry:27}{entry:28}{entry:29}{entry:30}{entry:31}{entry:32}{entry:33}{entry:34}{entry:35}{entry:36}{entry:37}{entry:38}{entry:39}{entry:40}{entry:41}{entry:42}{entry:43}{entry:44}{entry:45}{entry:46}{entry:47}{entry:48}{entry:49}{entry:50}{entry:51}{entry:52}{entry:53}{entry:54}{entry:55}{entry:56}{entry:57}{entry:58}{entry:59}{entry:60}{entry:61}{entry:62}{entry:63}{entry:64}{entry:65}{entry:66}{entry:67}{entry:68}{entry:69}{entry:70}{entry:71}{entry:72}{entry:73}{entry:74}{entry:75}{entry:76}{entry:77}{entry:78}{entry:79}{entry:80}{entry:81}{entry:82}{entry:83}{entry:84}

64 children makes it popular. The number is fixed (there is no API to
change it). Its choice is an attempt to balance the performance cost
of the indirection performance degradation versus the convergence
gain.

Popular path-lists contribute the load-balance map, this is the
missing indirection object. Its indirection happens when choosing the
bucket in the LB. The packet's flow-hash is taken 'mod number of
buckets' to give the 'candidate bucket' then the map will take this
'index' and convert it into the 'map'. You can see in the example above
that no change occurs, i.e. if the flow-hash mod n chooses bucket 1
then it gets bucket 1.

Why is this useful? The path-list is shared (you can convince
yourself of this if you look at each of the 8.x.0.0/16 routes we
added) and all of these routes use the same load-balance map, therefore, to
converge all the recursive routs, we need only change the map and
we're good; we again get PIC.

OK who's still awake... if you're thinking there's more to this story,
you're right. Keep reading.

This failure scenario is called iBGP PIC edge. It's 'edge' because it
refers to the loss of an edge device, and iBGP because the device was
a iBGP peer (we learn iBGP peers in the IGP). There is a similar eBGP
PIC edge scenario, but this is left for an exercise to the reader (hint
there are other recursion constraints - see the RFC).

Which Objects
^^^^^^^^^^^^^

The next topic on our list of how to converge quickly was to
effectively find the objects that need to be updated when a converge
event happens. If you haven't realised by now that the FIB is an
object graph, then can I politely suggest you go back and start from
the beginning ...

Finding the objects affected by a change is simply a matter of walking
from the parent (the object affected) to its children. These
dependencies are kept really for this reason.

So is fast convergence just a matter of walking the graph? Yes and
no. The question to ask yourself is this, "in the case of iBGP PIC edge,
when the /32 is withdrawn, what is the list of objects that need to be
updated and particularly what is the order they should be updated in
order to obtain the best convergence time?" Think breadth v. depth first.

... ponder for a while ...

For iBGP PIC edge we said it's the path-list that provides the
indirection through the load-balance map. Hence once all path-lists
are updated we are converged, thereafter, at our leisure, we can
update the child recursive prefixes. Is the breadth or depth first?

It's breadth first.

Breadth first walks are achieved by spawning an async walk of the
branch of the graph that we don't want to traverse. Withdrawing the /32
triggers a synchronous walk of the children of the /32 route, we want
a synchronous walk because we want to converge ASAP. This synchronous
walk will encounter path-lists in the /32 route's child dependent list.
These path-lists (and thier LB maps) will be updated. If a path-list is
popular, then it will spawn a async walk of the path-list's child
dependent routes, if not it will walk those routes. So the walk
effectively proceeds breadth first across the path-lists, then returns
to the start to do the affected routes.

Now the story is complete. The murderer is revealed.

Let's withdraw one of the IGP routes.

.. code-block:: console

  DBGvpp# ip route del 1.1.1.2/32 via 10.0.1.2 GigEthernet0/0/1

  DBGvpp# sh ip fib 8.8.0.0                         
  ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] epoch:0 flags:none locks:[adjacency:1, recursive-resolution:4, default-route:1, ]
  8.8.0.0/16 fib:0 index:77 locks:2
    API refs:1 src-flags:added,contributing,active,
      path-list:[15] locks:128 flags:shared,popular, uPRF-list:18 len:2 itfs:[1, 2, ]
        path:[17] pl-index:15 ip4 weight=1 pref=0 recursive:  oper-flags:resolved, cfg-flags:resolve-host,
          via 1.1.1.1 in fib:0 via-fib:15 via-dpo:[dpo-load-balance:17]
        path:[15] pl-index:15 ip4 weight=1 pref=0 recursive:  cfg-flags:resolve-host,
          via 1.1.1.2 in fib:0 via-fib:10 via-dpo:[dpo-drop:0]

    forwarding:   unicast-ip4-chain
      [@0]: dpo-load-balance: [proto:ip4 index:79 buckets:1 uRPF:18 to:[0:0]]
        [0] [@12]: dpo-load-balance: [proto:ip4 index:17 buckets:2 uRPF:27 to:[0:0]]
          [0] [@5]: ipv4 via 10.0.0.2 GigEthernet0/0/0: mtu:9000 next:3 001122334455dead000000000800
          [1] [@5]: ipv4 via 10.0.1.2 GigEthernet0/0/1: mtu:9000 next:4 001111111111dead000000010800

the LB Map has gone, since the prefix now only has one path. You'll
need to be a CLI ninja if you want to catch the output showing the LB
map in its transient state of:

.. code-block:: console

           load-balance-map: index:0 buckets:2
              index:    0    1
                map:    0    0

but it happens. Trust me. I've got tests and everything.

On the final topic of how to converge quickly; 'make each update fast'
there are no tricks.



