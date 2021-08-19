.. _ip1:

.. toctree::

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

IP Route
==========

Summary/Usage
--------------

`ip route [add|del] [count <*n*>] <*dst-ip-addr*>/<*width*> [table <*table-id*>] via [next-hop-address[next-hop-interface] [next-hop-table <*value*>] [weight <*value*>] [preference <*value*>] [udp-encap-id <*value*>] [ip4-lookup-in-table <*value*>] [ip6-lookup-in-table <*value*>] [mpls-lookup-in-table <*value*>] [resolve-via-host] [resolve-via-connected] [rx-ip4 <*interface*>] [out-labels <*value value value*>]`

Description
------------

This command is used to add or delete IPv4 or IPv6 routes. All IP Addresses
('<*dst-ip-addr*>/<*width*>', '<*next-hop-ip-addr*>' and '<*adj-hop-ip-addr*>') can be IPv4 or IPv6,
but all must be of the same form in a single command. To display the current set of routes,
use the commands 'show ip fib' and 'show ip6 fib'.

Example Usage
--------------

Example of how to add a straight forward static route:

.. code-block:: console

    vpp# ip route add 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0

Example of how to delete a straight forward static route:

.. code-block:: console

    vpp# ip route del 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0

Mainly for route add/del performance testing, one can add or delete multiple routes by adding
'count N' to the previous item:

.. code-block:: console

    vpp# ip route add count 10 7.0.0.0/24 via 6.0.0.1 GigabitEthernet2/0/0

Add multiple routes for the same destination to create equal-cost multipath:

.. code-block:: console

    vpp# ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0

    vpp# ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0

For unequal-cost multipath, specify the desired weights. This combination of weights
results in 3/4 of the traffic following the second path, 1/4 following the first path:

.. code-block:: console

    vpp# ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0 weight 1

    vpp# ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0 weight 3

To add a route to a particular FIB table (VRF), use:

.. code-block:: console

    vpp# ip route add 172.16.24.0/24 table 7 via GigabitEthernet2/0/0

Declaration and Implementation
---------------------------------

**Declaration:** ip_route_command (src/vnet/ip/lookup.c line 641)

**Implementation:** vnet_ip_route_cmd

Ping
=====

Summary/Usage
--------------

ping {<*ip-addr*> | ipv4 <*ip4-addr*> | ipv6 <*ip6-addr*>} [ipv4 <*ip4-addr*> | ipv6 <*ip6-addr*>] [source <*interface*>] [size <*pktsize*>] [interval <*sec*>] [repeat <*cnt*>] [table-id <*id*>] [verbose]

Description
------------

This command sends an ICMP ECHO_REQUEST to network hosts. The address can be an IPv4 or IPv6
address (or both at the same time).

Example Usage
--------------

Example of how ping an IPv4 address:

.. code-block:: console

    vpp# ping 172.16.1.2 source GigabitEthernet2/0/0 repeat 2

    64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1090 ms
    64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0914 ms

    Statistics: 2 sent, 2 received, 0% packet loss

    Example of how ping both an IPv4 address and IPv6 address at the same time:

    vpp# ping 172.16.1.2 ipv6 fe80::24a5:f6ff:fe9c:3a36 source GigabitEthernet2/0/0 repeat 2 verbose

    Adjacency index: 10, sw_if_index: 1
    Adj: ip6-discover-neighbor
    Adj Interface: 0
    Forced set interface: 1
    Adjacency index: 0, sw_if_index: 4294967295
    Adj: ip4-miss
    Adj Interface: 0
    Forced set interface: 1
    Source address: 172.16.1.1
    64 bytes from 172.16.1.2: icmp_seq=1 ttl=64 time=.1899 ms
    Adjacency index: 10, sw_if_index: 1
    Adj: ip6-discover-neighbor
    Adj Interface: 0
    Forced set interface: 1
    Adjacency index: 0, sw_if_index: 4294967295
    Adj: ip4-miss
    Adj Interface: 0
    Forced set interface: 1
    Source address: 172.16.1.1
    64 bytes from 172.16.1.2: icmp_seq=2 ttl=64 time=.0910 ms

    Statistics: 4 sent, 2 received, 50% packet loss

Declaration and Implementation
-------------------------------

Declaration: ping_command (src/vnet/ip/ping.c line 899)

Implementation: ping_ip_address

Set Interface IP Address
=========================

`Set Interface IP Address <../interface/setinterface.html#set-interface-ip-address>`_

Show IP Arp
=============

`Show IP-Arp <../show/show.html#show-ip-arp>`_


Show IP Fib
============

`Show IP-Fib <../show/show.html#show-ip-fib>`_
