.. _interface:

.. toctree::

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .

Show Bridge-Domain
===================

`Show Bridge-Domain <../interface/hardware.html#show-bridge-domain>`_

Show Interface
================

`Show Interface <../interface/basic.html#show-interface>`_

Show IP Arp
============

Summary/Usage
---------------

show ip arp

Description
------------

Display all the IPv4 ARP entries.

Example Usage
--------------
Example of how to display the IPv4 ARP table:

.. code-block:: console

   vpp# **show ip arp**
       Time      FIB        IP4       Flags      Ethernet              Interface
       346.3028   0       6.1.1.3            de:ad:be:ef:ba:be   GigabitEthernet2/0/0
      3077.4271   0       6.1.1.4       S    de:ad:be:ef:ff:ff   GigabitEthernet2/0/0
      2998.6409   1       6.2.2.3            de:ad:be:ef:00:01   GigabitEthernet2/0/0
    Proxy arps enabled for:
    Fib_index 0   6.0.0.1 - 6.0.0.11

	
Declaration and Implementation
-------------------------------

**Declaration:** show_ip4_arp_command (src/vnet/ethernet/arp.c line 1465)

**Implementation:** show_ip4_arp

Show IP Fib
=============

Summary/Usage
---------------

show ip fib [summary] [table <*table-id*>] [index <*fib-id*>] [<*ip4-addr*>[/<*mask*>]] [mtrie] [detail]

Description
------------

This command displays the IPv4 FIB Tables (VRF Tables) and the route entries for each table.

.. note:: 
	This command will run for a long time when the FIB tables are comprised of
	millions of entries. For those senarios, consider displaying a single table or summary mode.

Example Usage
--------------
Example of how to display all the IPv4 FIB tables:

.. code-block:: console

    vpp# **show ip fib**

    ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
    0.0.0.0/0
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:0 buckets:1 uRPF:0 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    0.0.0.0/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:1 buckets:1 uRPF:1 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    6.0.1.2/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:30 buckets:1 uRPF:29 to:[0:0]]
      [0] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
    7.0.0.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:31 buckets:4 uRPF:30 to:[0:0]]
      [0] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
      [1] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
      [2] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
      [3] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
    224.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:3 buckets:1 uRPF:3 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    240.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:2 buckets:1 uRPF:2 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    255.255.255.255/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:4 buckets:1 uRPF:4 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
    0.0.0.0/0
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    0.0.0.0/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    172.16.1.0/24
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
      [0] [@4]: ipv4-glean: af_packet0
    172.16.1.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
      [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
    172.16.1.2/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
      [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -> 26:a5:f6:9c:3a:36
    172.16.2.0/24
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
      [0] [@4]: ipv4-glean: af_packet1
    172.16.2.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
      [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
    224.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    240.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    255.255.255.255/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
      [0] [@0]: dpo-drop ip6

Example of how to display a single IPv4 FIB table:

.. code-block:: console

    vpp# **show ip fib table 7**

    ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
    0.0.0.0/0
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    0.0.0.0/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    172.16.1.0/24
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
      [0] [@4]: ipv4-glean: af_packet0
    172.16.1.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
      [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
    172.16.1.2/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
      [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -*> 26:a5:f6:9c:3a:36
    172.16.2.0/24
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
      [0] [@4]: ipv4-glean: af_packet1
    172.16.2.1/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
      [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
    224.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    240.0.0.0/8
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
      [0] [@0]: dpo-drop ip6
    255.255.255.255/32
      unicast-ip4-chain
      [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
      [0] [@0]: dpo-drop ip6

Example of how to display a summary of all IPv4 FIB tables:

.. code-block:: console

    vpp# **show ip fib summary**

    ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
        Prefix length         Count
                       0               1
                       8               2
                      32               4
    ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
        Prefix length         Count
                       0               1
                       8               2
                      24               2
                      32               4

Declaration and Implementation
-------------------------------

**Declaration:** ip4_show_fib_command (src/vnet/fib/ip4_fib.c line 873)

**Implementation:** ip4_show_fib

Show L2fib  
============

Summary/Usage 
------------------

show l2fib [all] | [bd_id <*nn*> | bd_index <*nn*>] [learn | add] | [raw]

Description
------------

This command displays the MAC Address entries of the L2 FIB table. 
Output can be filtered to just get the number of MAC Addresses or display each 
MAC Address for all bridge domains or just a single bridge domain.

Example Usage
--------------
Example of how to display the number of MAC Address entries in the L2 FIB table:


.. code-block:: console

    vpp# **show l2fib**

    3 l2fib entries

    Example of how to display all the MAC Address entries in the L2 FIB table:

    vpp# **show l2fib all**

        Mac Address     BD Idx           Interface           Index  static  filter  bvi  refresh  timestamp
     52:54:00:53:18:33    1      GigabitEthernet0/8/0.200      3       0       0     0      0         0
     52:54:00:53:18:55    1      GigabitEthernet0/8/0.200      3       1       0     0      0         0
     52:54:00:53:18:77    1                 N/A                -1      1       1     0      0         0
    3 l2fib entries

Declaration and Implementation
-------------------------------

**Declaration:** show_l2fib_cli (src/vnet/l2/l2_fib.c line 311)

**Implementation:** show_l2fib

Show Trace
===========

Summary/Usage
--------------

show trace buffer [max COUNT]

Declaration and Implementation
------------------------------

**Declaration:** show_trace_cli (src/vlib/trace.c line 347)

**Implementation:** cli_show_trace_buffer

Show Vhost-User
================

`Show Vhost-User <../vhost/vhostuser.html#show-vhost-user>`_

