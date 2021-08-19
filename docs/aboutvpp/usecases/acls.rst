.. _aclwithvpp:

Access Control Lists (ACLs) with FD.io VPP
==========================================

This section is overview of the options available to implement ACLs in
FD.io VPP. As there are a number of way's to address ACL-like functionality,
it is worth a separate survey of these options with some commentary on
features and performance

All performance numbers and examples from this document are reused from
the `FD.io CSIT v19.04 performance report <https://docs.fd.io/csit/rls1904/report/>`__
All information and performance is accurate for
`FD.io VPP 19.04 <https://git.fd.io/vpp/tag/?h=v19.04>`__ release. The
sections *performance* & *operational data* below correlate directly with
those sections from the FD.io CSIT performance report.

Summary
-------

+---------------------+-----------+-----------------------------------+
| Option              | Relative  | Features & Notes                  |
|                     | Performan |                                   |
|                     | ce        |                                   |
+=====================+===========+===================================+
| :ref:`aclplugin`    | Lowest    | Match on restricted L2-L4 fields, |
|                     |           | stateful & stateless              |
+---------------------+-----------+-----------------------------------+
| :ref:`vppcop`       | Highest   | Match on Layer 3 IPs, stateless   |
|                     | (software |                                   |
|                     | only)     |                                   |
+---------------------+-----------+-----------------------------------+
| :ref:`vppflow`      | Highest   | Match on restricted L2-L4 fields, |
|                     | (accelera | stateless, limited number of      |
|                     | ted)      | flows                             |
+---------------------+-----------+-----------------------------------+
| :ref:`classifiers`  | TBD       | Match on any field in the first   |
|                     |           | 80 bytes, Not measured            |
+---------------------+-----------+-----------------------------------+

FD.io VPP ACL Options
---------------------

.. _aclplugin:

The FD.io VPP ACL Plugin
~~~~~~~~~~~~~~~~~~~~~~~~

The plugin was originally developed as part of FD.io VPP and OpenStack
integration. The plugin needs to be enabled on specific interfaces.

Supports stateful and stateless ACLs on …
""""""""""""""""""""""""""""""""""""""""""

- MACs
- IPS
- UDP Ports
- TCP Ports & Flags
- ICMP Messages

Directional
"""""""""""

* Input ACLs

  * Run before the IP flow classification.

* ACLs

  * Run before interface output.

Actions
"""""""
- Permit (sl)
- Drop (sf)
- Permit+Reflect (sf)

Stateful (sf)
"""""""""""""

- Actions: permit+reflect
- Most heavily optimized, as are the most common use case.
- Faster because stateful uses a flow cache, it means the ACL hit is only taken once, up front for the flow and then becomes just look-up.
- Uses more memory, less deterministic as the flow cache makes it
  more susceptible to the effects of the memory hierarchy and
  locality.

Stateless (sl)
""""""""""""""

-  Actions : permit, drop
-  Less optimized, less common use case.
-  Slower as there is no flow-cache, every new packet incurs the same
   amount ACL processing.
-  Uses less memory, and are more deterministic (compared to
   stateful).

Operational Data
----------------

Input/Stateless
~~~~~~~~~~~~~~~

Test Case: 10ge2p1x520-ethip4udp-ip4base-iacl1sl-10kflows-ndrpdr
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: console

       DUT1: 
       Thread 0 vpp_main (lcore 1) 
       Time 3.8, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00 
         vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0 
                    Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
       acl-plugin-fa-cleaner-process   any wait                 0               0              14          1.29e3            0.00 
       acl-plugin-fa-worker-cleaner-pinterrupt wa               7               0               0          9.18e2            0.00 
       api-rx-from-ring                 active                  0               0              52          8.96e4            0.00 
       dpdk-process                    any wait                 0               0               1          1.35e4            0.00 
       fib-walk                        any wait                 0               0               2          2.69e3            0.00 
       ip6-icmp-neighbor-discovery-ev  any wait                 0               0               4          1.32e3            0.00 
       lisp-retry-service              any wait                 0               0               2          2.90e3            0.00 
       unix-epoll-input                 polling              7037               0               0          1.25e6            0.00 
       vpe-oam-process                 any wait                 0               0               2          2.28e3            0.00 

       Thread 1 vpp_wk_0 (lcore 2) 
       Time 3.8, average vectors/node 249.02, last 128 main loops 32.00 per node 273.07 
         vector rates in 6.1118e6, out 6.1118e6, drop 0.0000e0, punt 0.0000e0 
                    Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
       TenGigabitEtherneta/0/0-output   active              47106        11721472               0          9.47e0          248.83 
       TenGigabitEtherneta/0/0-tx       active              47106        11721472               0          4.22e1          248.83 
       TenGigabitEtherneta/0/1-output   active              47106        11721472               0          1.02e1          248.83 
       TenGigabitEtherneta/0/1-tx       active              47106        11721472               0          4.18e1          248.83 
       acl-plugin-fa-worker-cleaner-pinterrupt wa               7               0               0          1.39e3            0.00 
       acl-plugin-in-ip4-fa             active              94107        23442944               0          1.75e2          249.11 
       dpdk-input                       polling             47106        23442944               0          4.64e1          497.66 
       ethernet-input                   active              94212        23442944               0          1.55e1          248.83 
       ip4-input-no-checksum            active              94107        23442944               0          3.23e1          249.11 
       ip4-lookup                       active              94107        23442944               0          2.91e1          249.11 
       ip4-rewrite                      active              94107        23442944               0          2.48e1          249.11 
       unix-epoll-input                 polling                46               0               0          1.54e3            0.00

Input/Stateful
~~~~~~~~~~~~~~

Test Case: 64b-1t1c-ethip4udp-ip4base-iacl1sf-10kflows-ndrpdr
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: console

       DUT1: 
       Thread 0 vpp_main (lcore 1) 
       Time 3.9, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00 
         vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0 
                    Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
       acl-plugin-fa-cleaner-process   any wait                 0               0              16          1.40e3            0.00 
       acl-plugin-fa-worker-cleaner-pinterrupt wa               8               0               0          8.97e2            0.00 
       api-rx-from-ring                 active                  0               0              52          7.12e4            0.00 
       dpdk-process                    any wait                 0               0               1          1.69e4            0.00 
       fib-walk                        any wait                 0               0               2          2.55e3            0.00 
       ip4-reassembly-expire-walk      any wait                 0               0               1          1.27e4            0.00 
       ip6-icmp-neighbor-discovery-ev  any wait                 0               0               4          1.09e3            0.00 
       ip6-reassembly-expire-walk      any wait                 0               0               1          2.57e3            0.00 
       lisp-retry-service              any wait                 0               0               2          1.18e4            0.00 
       statseg-collector-process       time wait                0               0               1          6.38e3            0.00 
       unix-epoll-input                 polling              6320               0               0          1.41e6            0.00 
       vpe-oam-process                 any wait                 0               0               2          7.53e3            0.00 

       Thread 1 vpp_wk_0 (lcore 2) 
       Time 3.9, average vectors/node 252.74, last 128 main loops 32.00 per node 273.07 
         vector rates in 7.5833e6, out 7.5833e6, drop 0.0000e0, punt 0.0000e0 
                    Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
       TenGigabitEtherneta/0/0-output   active              58325        14738944               0          9.41e0          252.70 
       TenGigabitEtherneta/0/0-tx       active              58325        14738944               0          4.32e1          252.70 
       TenGigabitEtherneta/0/1-output   active              58323        14738944               0          1.02e1          252.71 
       TenGigabitEtherneta/0/1-tx       active              58323        14738944               0          4.31e1          252.71 
       acl-plugin-fa-worker-cleaner-pinterrupt wa               8               0               0          1.62e3            0.00 
       acl-plugin-in-ip4-fa             active             116628        29477888               0          1.01e2          252.75 
       dpdk-input                       polling             58325        29477888               0          4.63e1          505.41 
       ethernet-input                   active             116648        29477888               0          1.53e1          252.71 
       ip4-input-no-checksum            active             116628        29477888               0          3.21e1          252.75 
       ip4-lookup                       active             116628        29477888               0          2.90e1          252.75 
       ip4-rewrite                      active             116628        29477888               0          2.48e1          252.75 
       unix-epoll-input                 polling                57               0               0          2.39e3            0.00  
                           
Output/Stateless
~~~~~~~~~~~~~~~~

Test Case: 64b-1t1c-ethip4udp-ip4base-oacl10sl-10kflows-ndrpdr
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

   .. code-block:: console

       DUT1: 
        Thread 0 vpp_main (lcore 1) 
        Time 3.8, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00 
          vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0 
                     Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
        acl-plugin-fa-cleaner-process   any wait                 0               0              14          1.43e3            0.00 
        acl-plugin-fa-worker-cleaner-pinterrupt wa               7               0               0          9.23e2            0.00 
        api-rx-from-ring                 active                  0               0              52          8.01e4            0.00 
        dpdk-process                    any wait                 0               0               1          1.59e6            0.00 
        fib-walk                        any wait                 0               0               2          6.81e3            0.00 
        ip6-icmp-neighbor-discovery-ev  any wait                 0               0               4          2.81e3            0.00 
        lisp-retry-service              any wait                 0               0               2          3.64e3            0.00 
        unix-epoll-input                 polling              4842               0               0          1.81e6            0.00 
        vpe-oam-process                 any wait                 0               0               1          2.24e4            0.00 
         
        Thread 1 vpp_wk_0 (lcore 2) 
        Time 3.8, average vectors/node 249.29, last 128 main loops 36.00 per node 271.06 
          vector rates in 5.9196e6, out 5.9196e6, drop 0.0000e0, punt 0.0000e0 
                     Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
        TenGigabitEtherneta/0/0-output   active              45595        11363584               0          9.22e0          249.23 
        TenGigabitEtherneta/0/0-tx       active              45595        11363584               0          4.25e1          249.23 
        TenGigabitEtherneta/0/1-output   active              45594        11363584               0          9.75e0          249.23 
        TenGigabitEtherneta/0/1-tx       active              45594        11363584               0          4.21e1          249.23 
        acl-plugin-fa-worker-cleaner-pinterrupt wa               7               0               0          1.28e3            0.00 
        acl-plugin-out-ip4-fa            active              91155        22727168               0          1.78e2          249.32 
        dpdk-input                       polling             45595        22727168               0          4.64e1          498.46 
        ethernet-input                   active              91189        22727168               0          1.56e1          249.23 
        interface-output                 active              91155        22727168               0          1.13e1          249.32 
        ip4-input-no-checksum            active              91155        22727168               0          1.95e1          249.32 
        ip4-lookup                       active              91155        22727168               0          2.88e1          249.32 
        ip4-rewrite                      active              91155        22727168               0          3.53e1          249.32 
        unix-epoll-input                 polling                44               0               0          1.53e3            0.00 
                           
Output/Stateful
~~~~~~~~~~~~~~~

Test Case: 64b-1t1c-ethip4udp-ip4base-oacl10sf-10kflows-ndrpdr
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: console

       DUT1: 
        Thread 0 vpp_main (lcore 1) 
        Time 3.8, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00 
          vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0 
                     Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
        acl-plugin-fa-cleaner-process   any wait                 0               0              16          1.47e3            0.00 
        acl-plugin-fa-worker-cleaner-pinterrupt wa               8               0               0          8.51e2            0.00 
        api-rx-from-ring                 active                  0               0              50          7.24e4            0.00 
        dpdk-process                    any wait                 0               0               2          1.93e4            0.00 
        fib-walk                        any wait                 0               0               2          2.02e3            0.00 
        ip4-reassembly-expire-walk      any wait                 0               0               1          3.96e3            0.00 
        ip6-icmp-neighbor-discovery-ev  any wait                 0               0               4          9.84e2            0.00 
        ip6-reassembly-expire-walk      any wait                 0               0               1          3.76e3            0.00 
        lisp-retry-service              any wait                 0               0               2          1.49e4            0.00 
        statseg-collector-process       time wait                0               0               1          4.98e3            0.00 
        unix-epoll-input                 polling              5653               0               0          1.55e6            0.00 
        vpe-oam-process                 any wait                 0               0               2          1.90e3            0.00 
         
        Thread 1 vpp_wk_0 (lcore 2) 
        Time 3.8, average vectors/node 250.85, last 128 main loops 36.00 per node 271.06 
          vector rates in 7.2686e6, out 7.2686e6, drop 0.0000e0, punt 0.0000e0 
                     Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
        TenGigabitEtherneta/0/0-output   active              55639        13930752               0          9.33e0          250.38 
        TenGigabitEtherneta/0/0-tx       active              55639        13930752               0          4.27e1          250.38 
        TenGigabitEtherneta/0/1-output   active              55636        13930758               0          9.81e0          250.39 
        TenGigabitEtherneta/0/1-tx       active              55636        13930758               0          4.33e1          250.39 
        acl-plugin-fa-worker-cleaner-pinterrupt wa               8               0               0          1.62e3            0.00 
        acl-plugin-out-ip4-fa            active             110988        27861510               0          1.04e2          251.03 
        dpdk-input                       polling             55639        27861510               0          4.62e1          500.76 
        ethernet-input                   active             111275        27861510               0          1.55e1          250.38 
        interface-output                 active             110988        27861510               0          1.21e1          251.03 
        ip4-input-no-checksum            active             110988        27861510               0          1.95e1          251.03 
        ip4-lookup                       active             110988        27861510               0          2.89e1          251.03 
        ip4-rewrite                      active             110988        27861510               0          3.55e1          251.03 
        unix-epoll-input                 polling                54               0               0          2.43e3            0.00  
                           
Performance
-----------

+---------------------------------------+-------+-------------------+
| Test Case                             | MPPS  | Cycles per packet |
+---------------------------------------+-------+-------------------+
| ethip4-ip4base                        | 18.26 | 136               |
+---------------------------------------+-------+-------------------+
| ethip4ip4udp-ip4base-iacl1sl-10kflows | 9.134 | 273               |
+---------------------------------------+-------+-------------------+
| ethip4ip4udp-ip4base-iacl1sf-10kflows | 11.06 | 226               |
+---------------------------------------+-------+-------------------+

Input ACLS (SKX)
~~~~~~~~~~~~~~~~

.. figure:: /_images/ip4-2n-iacl.png

Output ACLs (HSW)
~~~~~~~~~~~~~~~~~

.. figure:: /_images/ip4-3n-oacl.png

Configuration
-------------

Stateful
~~~~~~~~

.. code-block:: console

       $ sudo vppctl ip_add_del_route 20.20.20.0/24 via 1.1.1.2  sw_if_index 1 resolve-attempts 10 count 1     
       $ sudo vppctl acl_add_replace  ipv4 permit src 30.30.30.1/32 dst 40.40.40.1/32 sport 1000 dport 1000, ipv4 permit+reflect src 10.10.10.0/24, ipv4 permit+reflect src 20.20.20.0/24        
       $ sudo vppctl acl_interface_set_acl_list sw_if_index 2 input 0 
       $ sudo vppctl acl_interface_set_acl_list sw_if_index 1 input 0 
                           
Stateless
~~~~~~~~~

.. code-block:: console

       $ sudo vppctl ip_add_del_route 20.20.20.0/24 via 1.1.1.2  sw_if_index 1 resolve-attempts 10 count 1     
       $ sudo vppctl acl_add_replace  ipv4 permit src 30.30.30.1/32 dst 40.40.40.1/32 sport 1000 dport 1000, ipv4 permit src 10.10.10.0/24, ipv4 permit src 20.20.20.0/24        
       $ sudo vppctl acl_interface_set_acl_list sw_if_index 2 input 0 
       $ sudo vppctl acl_interface_set_acl_list sw_if_index 1 input 0
              
Links
~~~~~

-  `FD.io Security Groups overview <https://wiki.fd.io/view/VPP/SecurityGroups>`__
-  `Reflexive Access Control Lists <https://packetlife.net/blog/2008/nov/25/reflexive-access-lists/>`__
-  `Andrew Yuort's Blog on ACLs <http://stdio.be/blog/2017-12-09-Debugging-VPP-MACIP-ACLs/>`__

.. _vppcop:

FD.io VPP COP
-------------

IPv4/IPv6 white-lists using the FD.io VPP FIB, with support for multiple
nested white-lists.

Design notes:
~~~~~~~~~~~~~

- The cop graph nodes (input & white-list) make reuse of the FD.io VPP in FIB 2.0 implementation. Essentially
  a successful lookup in the FIB, indicates that a packet has been white-listed and may be forwarded.

- cop-input: Determines if the frame is IPv4 or IPv6, and forwards to ipN-copwhitelist graph node.

- ipN-copwhitelist: uses the ip4_fib_[mtrie,lookup] functions to confirm the packet's ip matches a route in the white-list fib.

- Match: if it matches, it is then either sent to the next whitelist or to the ip layer.

- No Match: if it there is not match, it is sent to error-drop.

Operational Data
~~~~~~~~~~~~~~~~

Note: the double-pass of the ip4-lookup and ip4-rewrite.

.. code-block:: console

    DUT1: 
     Thread 0 vpp_main (lcore 1) 
     Time 3.9, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00 
       vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0 
                  Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
     api-rx-from-ring                 active                  0               0              53          4.20e4            0.00 
     dpdk-process                    any wait                 0               0               1          1.75e4            0.00 
     fib-walk                        any wait                 0               0               2          1.59e3            0.00 
     ip4-reassembly-expire-walk      any wait                 0               0               1          2.20e3            0.00 
     ip6-icmp-neighbor-discovery-ev  any wait                 0               0               4          1.14e3            0.00 
     ip6-reassembly-expire-walk      any wait                 0               0               1          1.50e3            0.00 
     lisp-retry-service              any wait                 0               0               2          2.19e3            0.00 
     statseg-collector-process       time wait                0               0               1          2.48e3            0.00 
     unix-epoll-input                 polling              2800               0               0          3.15e6            0.00 
     vpe-oam-process                 any wait                 0               0               2          7.00e2            0.00 

     Thread 1 vpp_wk_0 (lcore 2) 
     Time 3.9, average vectors/node 220.84, last 128 main loops 20.87 per node 190.86 
       vector rates in 1.0724e7, out 1.0724e7, drop 0.0000e0, punt 0.0000e0 
                  Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call   
     TenGigabitEtherneta/0/0-output   active              94960        20698112               0          1.03e1          217.97 
     TenGigabitEtherneta/0/0-tx       active              94960        20698112               0          3.97e1          217.97 
     TenGigabitEtherneta/0/1-output   active              92238        20698112               0          9.92e0          224.39 
     TenGigabitEtherneta/0/1-tx       active              92238        20698112               0          4.26e1          224.39 
     cop-input                        active              94960        20698112               0          1.98e1          217.97 
     dpdk-input                       polling             95154        41396224               0          4.58e1          435.04 
     ethernet-input                   active              92238        20698112               0          1.59e1          224.39 
     ip4-cop-whitelist                active              94960        20698112               0          3.24e1          217.97 
     ip4-input                        active              94960        20698112               0          3.13e1          217.97 
     ip4-input-no-checksum            active              92238        20698112               0          2.23e1          224.39 
     ip4-lookup                       active             187198        41396224               0          3.08e1          221.14 
     ip4-rewrite                      active             187198        41396224               0          2.47e1          221.14 
     unix-epoll-input                 polling                93               0               0          1.35e3            0.00 
                    
Performance
~~~~~~~~~~~

+-------------------------------+-------+-------------------+
| Test Case                     | MPPS  | Cycles per packet |
+-------------------------------+-------+-------------------+
| ethip4-ip4base                | 18.81 | 132               |
+-------------------------------+-------+-------------------+
| ethip4-ip4base-copwhtlistbase | 15.12 | 165               |
+-------------------------------+-------+-------------------+

.. figure:: /_images/ip4-acl-features-ndr.png

Configuration
~~~~~~~~~~~~~

Note: a new VRF 1 is created which holds the whitelist, which then
applied to the interface 1.

.. code-block:: console

    $ sudo vppctl ip_add_del_route 10.10.10.0/24 via 1.1.1.1  sw_if_index 2 resolve-attempts 10 count 1     
    $ sudo vppctl ip_table_add_del table 1  
    $ sudo vppctl ip_add_del_route 20.20.20.0/24  vrf 1  resolve-attempts 10 count 1    local 
    $ sudo vppctl cop_whitelist_enable_disable sw_if_index 1 ip4 fib-id 1 
    $ sudo vppctl cop_interface_enable_disable sw_if_index 1  
                    
Links
~~~~~

-  `FIB 2.0: Hierarchical, Protocol Independent. <https://wiki.fd.io/images/7/71/FIB_2.0_-_Hierarchical,_Protocol_Independent..pdf>`__

.. _vppflow:

FD.io VPP Flow
--------------

FD.io VPP Flow adds the ability for FD.io VPP to support matching of
flows and taking an associated action. This information is then used to
program hardware accelerations such as those available on network cards,
e.g. Intel® Ethernet Flow Director technology on the Intel® Ethernet
Controller X710/XXV710/XL710.

Supports
~~~~~~~~

Actions
"""""""

-  Count: don't now what this does, presume it count's matches.
-  Mark: Associate a matched flow with arbitrary data such as vxlan tunnel, for a lookup in the redirect graph node.
-  Buffer Advance: Can be used advance to an encapsulated ethernet or ip header.
-  Redirect to node: When you see a packet from flow xyz, the next node in FD.io VPP is the indicated graph node.
-  Redirect to queue: When you see a packet from flow xyz, is to redirect to rx queue n.
-  Drop: When you see a packet from flow xyz, drop the packet (next node is error drop).

Design Notes
~~~~~~~~~~~~

-  Currently the only place in FD.io VPP that this is used, is to accelerate VXLAN bypassing the Ethernet and IP Layers.
-  Flow uses DPDK rte_flow API under the hood for those network interfaces programmed through DPDK.
-  Redirect to node: worth remember that if you are bypassing a graph, you are bypassing all the checks in the graph node, e.e time-to-live, crcs and the like.

Operational Data
~~~~~~~~~~~~~~~~

FD.io CSIT numbers for VXLan do not use FD.io Flow support.

Performance
~~~~~~~~~~~

FD.io CSIT numbers for VXLan do not use FD.io Flow support.

Configuration
~~~~~~~~~~~~~

-  `Flow API <https://git.fd.io/vpp/tree/src/vnet/flow/flow.h>`__

.. _classifiers:

FD.io VPP Classifiers
---------------------

The most flexible form of ACLs in FD.io VPP enable the user to match anywhere in the first
80 bytes of the packet header.

Configuration
~~~~~~~~~~~~~

Match an IPv6….

.. code-block:: console

    $ sudo vppctl classify table mask l3 ip6 dst buckets 64
    $ sudo vppctl classify session hit-next 0 table-index 0 match l3 ip6 dst 2001:db8:1::2 opaque-index 42
    $ sudo vppctl set interface l2 input classify intfc host-s0_s1 ip6-table 0
                           
Links
~~~~~

-  `Overview of classifiers <https://wiki.fd.io/view/VPP/SecurityGroups#Existing_functionality>`__
-  `FD.io VPP Classifiers Overview <https://wiki.fd.io/view/VPP/Introduction_To_N-tuple_Classifiers>`__
-  `FD.io VPP Classifiers CLI <https://docs.fd.io/vpp/19.04/clicmd_src_vnet_classify.html>`__
-  `Sample Code from Andrew Yourt <http://stdio.be/vpp/t/aytest-bridge-tap-py.txt>`__
