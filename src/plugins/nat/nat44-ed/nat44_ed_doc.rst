.. _NAT44_Endpoint_Dependent:

.. toctree::

NAT44-ED: NAT44 Endpoint Dependent
==================================

Introduction
------------

NAT44-ED is the IPv4 endpoint dependent network address translation
plugin. The component implements an address and port-dependent mapping
and address and port-dependent filtering NAT as described in
`RFC4787 <https://tools.ietf.org/html/rfc4787>`__.

The outside address and port (X1’:x1’) is reused for internal hosts
(X:x) for different values of Y:y. A flow is matched by {source address,
destination address, protocol, transport source port, transport
destination port, fib index}. As long as all these are unique the
mapping is valid. While a single outside address in theory allows for
2^16 source ports \* 2^32 destination IP addresses \* 2^16 destination
ports = 2^64 sessions, this number is much smaller in practice. Few
destination ports are generally used (80, 443) and a fraction of the IP
address space is available. The limitation is 2^16 bindings per outside
IP address to a single destination address and port (Y:y).

The implementation is split, a control-plane / slow-path and a
data-plane / fast-path. Essentially acting as a flow router. The
data-plane does a 6-tuple flow lookup (SA, DA, P, SP, DP, FIB) and on a
match runs the per-flow packet handling instructions on the packet. On a
flow lookup miss, the packet is punted to the slow-path, where depending
on policy new sessions are created.

The support set of packet handling instructions is ever-increasing.
Currently, the implementation supports rewrite of SA, DA, SP, DP and TCP
MSS. The fast-path also does connection tracking and expiry of older
sessions.

NAT44-ED uses 6
tuple\ ``(src address, src port, dst address, dst port, protocol and fib)``\ for
matching communication.

Structure
~~~~~~~~~

1) Dynamic NAT

-  also called PAT (Port Address Translation)
-  supports port overloading

2) Static NAT

-  types of Static NAT:

   a) identity mapping

   -  exceptions to translations

   b) static mapping

   -  supported features:

      1. address only mapping

      -  one to one translation without ports

      2. twice-nat

      -  double-nat, translation of source and destination

      3. self-twice-nat

      -  double nat, translation of source and destination, where
         external host address is the same as local host address

      4. out2in-only mapping

      -  session is created only from outside interface (out2in feature)

   c) load balanced static mapping

   -  translates one frontend (``addr``:``port``) to multiple backends
      (``addr``:``port``)

3) Interfaces

a) inside interface (in2out feature) - local to external network
   translation - feature is before ip4-lookup
b) outside interface (out2in feature) - external to local network
   translation - feature is before ip4-lookup
c) inside & outside interface (classify feature) - local or external
   network translation - correct type of translation is determined per
   communication - feature is before ip4-lookup
d) output interface (output feature) - used for post routing translation
   - feature is after ip4-lookup

4) Addresses

a) interface address - automatically managed external address - first
   address of VPP interface
b) pool address - range of external addresses

5) Logging and Accounting

a) ipfix logging
b) syslog

6) Miscellaneous Features

a) inter-vrf translation control 1. basic

   -  nat44 plugin enable inside-vrf / outside-vrf
   -  inside/outside interface vrf’s

      2. advanced

   -  vrf table routing feature

b) udp/tcp/icmp timeouts - configurable timeouts for these protocols
c) session limiting 1. basic (plugin enable [sessions ] 2. advanced
   (per vrf table / global limiting)
d) mss-clamping - MSS (maximum segment size) is by default determined by
   egress interface MTU (maximum transmission unit) size - used to lower
   MSS value in VPN tunnel scenarios where additional headers can
   enlarge the packet beyond MTU causing drops
e) hairpinning - hosts on the same lan segment communicating via
   external address
f) forwarding - if enabled translation only occurs if active session or
   static configuration exist, rest of the traffic is passed without
   being translated

Session Table
-------------

Session table exists per thread and contains pool of sessions that can
be either expired or not expired. NAT44-ED plugin doesn’t use scavenging
for clearing expired sessions. Rather then using scavenging plugin uses
LRU doubly-linked list. LRU contains ordered list of sessions indices.
Head of the list contains last updated session. Each session holds
record of the LRU head (tcp transitory, tcp established, udp, icmp or
unknown lru head). Because of this plugin can reach maximum number of
sessions without requirement to clear old sessions. During session
creation if a maximum number of sessions was reached LRU head is
checked. Expired head record gets deleted and a new session gets
created. For better performance LRU head records exist. Each time a new
packet is received session index gets moved to the tail of LRU list.

Terminology
-----------

IN2OUT (inside to outside translation) OUT2IN (outside to inside
translation)

NAT (network address translation) PAT (port address translation) MSS
(maximum segment size) MTU (maximum transmission unit) VRF (virtual
routing and forwarding)

HAIRPINNING

Dynamic NAT (Minimal Required Configuration)
--------------------------------------------

::

       +-------------+
       | 10.0.0.0/24 |
       +-------------+
              |
   +----------------------+
   | GigabitEthernet0/8/0 |
   +----------------------+
   +----------------------+
   | GigabitEthernet0/a/0 |
   +----------------------+
              |
       +-------------+
       | 10.0.1.0/24 |
       +-------------+

1) enable nat plugin

..

   nat44 plugin enable sessions 10000

2) configure NAT interfaces, two options:

a) add inside NAT interface on local VPP interface, add outside NAT
   interface on external VPP interface

..

   set interface nat44 in GigabitEthernet0/8/0 out GigabitEthernet0/a/0

b) add output NAT interface on external VPP interface

..

   set interface nat44 in GigabitEthernet0/a/0 output-feature

3) configure NAT address

a) add external address range

..

   nat44 add address 10.0.1.1

b) add external VPP interface address

..

   nat44 add interface address GigabitEthernet0/a/0

Static NAT
----------

Identity Mapping
~~~~~~~~~~~~~~~~

   nat44 add identity mapping ``ip4-addr``\ \|external ``interface``
   [``protocol`` ``port``] [vrf ``table-id``] [del]

Static Mapping
~~~~~~~~~~~~~~

   nat44 add static mapping tcp|udp|icmp local ``addr``
   [``port|icmp-echo-id``] external ``addr`` [``port|icmp-echo-id``]
   [vrf ``table-id``] [twice-nat|self-twice-nat] [out2in-only] [exact
   ``pool-addr``] [del]

Load Balanced Static Mapping
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   nat44 add load-balancing back-end protocol tcp|udp external
   ``addr``:``port`` local ``addr``:``port`` [vrf ``table-id``]
   probability ``n`` [del]

..

   nat44 add load-balancing static mapping protocol tcp|udp external
   ``addr``:``port`` local ``addr``:``port`` [vrf ``table-id``]
   probability ``n`` [twice-nat|self-twice-nat] [out2in-only] [affinity
   ``timeout-seconds``] [del]

Interfaces
----------

Inside Interface
~~~~~~~~~~~~~~~~

::

        NAT INSIDE IF
   +----------------------+
   | GigabitEthernet0/8/0 |
   +----------------------+

..

   set interface nat44 in GigabitEthernet0/8/0 [del]

NAT inside interface is used for translating local to external
communication. Translates Dynamic and Static NAT traffic. If no matching
session is found a new session is created for both Dynamic NAT and
Static NAT. Dynamic NAT sessions can get created only on inside
interface.

Outside Interface
~~~~~~~~~~~~~~~~~

::

        NAT OUTSIDE IF
   +----------------------+
   | GigabitEthernet0/a/0 |
   +----------------------+

..

   set interface nat44 out GigabitEthernet0/a/0 [del]

NAT outside interface is used for translating external to local
communication. Translates Dynamic and Static NAT traffic. New session
gets created only if no matching session is found and matching Static
NAT configuration exists.

Inside & Outside Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       NAT IN AND OUT IF
   +----------------------+
   | GigabitEthernet0/8/0 |
   +----------------------+
       NAT IN AND OUT IF
   +----------------------+
   | GigabitEthernet0/a/0 |
   +----------------------+

..

   set interface nat44 in GigabitEthernet0/8/0 out GigabitEthernet0/8/0
   [del]

   set interface nat44 in GigabitEthernet0/a/0 out GigabitEthernet0/a/0
   [del]

If one VPP interface is configured both as inside and outside NAT
interface then classification feature is used. By default NAT inside
interface uses in2out feature and NAT outside uses out2in feature.
Classification feature determines if the communication should be passed
to in2out feature or to out2in feature. Traffic will get passed to
out2in feature if destination address is one of NAT addresses or a
static mapping in out2in direction flow matches this communication. By
default all traffic is passed to in2out feature.

Output Interface
~~~~~~~~~~~~~~~~

::

       +-------------+          +-------------+
       | 10.0.2.0/24 |          | 10.0.3.0/24 |
       +-------------+          +-------------+
              |                        |
   +----------------------+ +----------------------+
   | GigabitEthernet0/7/0 | | GigabitEthernet0/8/0 |
   +----------------------+ +----------------------+
                     NAT OUTPUT IF
               +----------------------+
               | GigabitEthernet0/a/0 |
               +----------------------+
                      +----------+
                      | 10.0.1.1 |
                      +----------+
                           |
                     +-------------+
                     | 10.0.1.0/24 |
                     +-------------+

..

   set interface nat44 in GigabitEthernet0/a/0 output-feature [del]

NAT output interface acts as both inside and outside interfaces. Inside
rules apply for all egress communication on VPP interface and outside
rules apply for all ingress communication. Compared to inside/outside
NAT configuration method non of the local interfaces require to be
configured as inside NAT interfaces. Translation only occurs after
routing decision has been made and just before leaving NAT output
interface. In above example all traffic destined for 10.0.1.0/24 from
10.0.2.0/24 or 10.0.3.0/24 will get translated. NAT output interface
acts as post-routing feature.

Addresses
---------

Interface Address
~~~~~~~~~~~~~~~~~

   nat44 add interface address ``interface`` `twice-nat <#twice-nat>`__
   [del]

NAT interface address is a standard external pool address that gets auto
added upon resolving first VPP interface address. Supports both standard
address and twice-nat address. Twice-nat address is used in conjunction
with static mapping twice-nat and self-twice-nat feature.

Pool Address
~~~~~~~~~~~~

   nat44 add address ``ip4-range-start`` [- ``ip4-range-end``]
   [tenant-vrf ``vrf-id``] `twice-nat <#twice-nat>`__ [del]

Statically configured address or range of addresses that supports both
standard and twice-nat address. Specifying vrf-id lets user assign
address/addresses to specific NAT inside interfaces that belong to the
same vrf table.

Logging
-------

   nat set logging level ``level``

Configuration of logging level is used only for internal VPP logging.

   nat ipfix logging [domain ``domain-id``] [src-port ``port``]
   [disable]

Both syslog and ipfix support connection tracking capabilities. Session
creation, session deletion, maximum sessions exceeded among other things
are logged by syslog and ipfix.

Miscellaneous
-------------

VRFs
~~~~

::

            VRF 0                    VRF 1
       +-------------+          +-------------+
       | 10.0.2.0/24 |          | 10.0.3.0/24 |
       +-------------+          +-------------+
              |                        |
        NAT INSIDE IF            NAT INSIDE IF
   +----------------------+  +----------------------+
   | GigabitEthernet0/7/0 |  | GigabitEthernet0/8/0 |
   +----------------------+  +----------------------+
        NAT OUTSIDE IF           NAT OUTSIDE IF
   +----------------------+  +----------------------+
   | GigabitEthernet0/a/0 |  | GigabitEthernet0/b/0 |
   +----------------------+  +----------------------+
            VRF 2                      VRF 3
              |                          |
              +--------------------------+
                           |
        +------------+------------+------------+
        |            |            |            |
   +----------+ +----------+ +----------+ +----------+
   | 10.0.0.1 | | 10.0.0.2 | | 10.0.1.1 | | 10.0.1.2 |
   +----------+ +----------+ +----------+ +----------+
    VRF 0 POOL   VRF 1 POOL   VRF 0 POOL   VRF 1 POOL

..

   nat44 add address ``ip4-addr`` [tenant-vrf ``vrf-id``] [del]

   nat44 plugin enable inside-vrf ``vrf-id`` outside-vrf ``vrf-id``
   [disable]",

Default behavior
^^^^^^^^^^^^^^^^

By design NAT supports passing communication between VRFs. Passing
communication between multiple different VRFs is also supported (GE0/7/0
-> GE0/b/0, GE0/8/0 -> GE0/a/0).

NAT pool address tenant-vrf configuration parameter is used to constrain
pool address to specific inside VRF. Example communication (in the above
diagram): 1) from GE0/7/0 -> GE0/b/0 would choose 10.0.1.1 pool address
2) from GE0/8/0 -> GE0/b/0 would choose 10.0.1.2 pool address

Plugin enable parameters inside-vrf and outside-vrf are used as follows:

Both ``inside-vrf`` and ``outside-vrf`` configuration parameters are
used in conjunction with Static NAT, inside-vrf is only used for Static
NAT.

inside VRF: - used only in conjunction with static mappings - default
inside VRF parameter is used in in2out feature to lookup static mapping
if mapping can’t be found by inside interface VRF - used as default when
adding static mappings as in2out vrf

outside VRF: - used in conjunction with static mappings - secondary
option for looking up static mappings in in2out feature based on outside
VRF - used as default destination vrf in in2out feature during session
creation if non of outside interfaces can resolve destination IP address

Session creation default behavior (in2out only): - ingress interface fib
is used as inside fib - Outside fib is chosen based on ability to
resolve destination address in one of the outside interface networks. if
there is no such network that is able to resolve destination a default
outside fib (outside vrf index) is used.

Default behavior enables use of multiple outside and inside fibs with
some limitations. The limitation in the default behavior is that if each
interface belonging to different fib contains default gateway every time
first interface network fib gets used as outside fib index during
session creation.

VRF tables
^^^^^^^^^^

   nat44 vrf table [add|del] ``vrf-id``

..

   nat44 vrf route [add|del] table ``vrf-id`` ``vrf-id``

VRF tables change the default behavior of working with inter-vrf
communication. Adding empty VRF table disables passing communication
between VRFs. Adding additional routes to the table makes destination
VRF decision making algorithm do lookups into these tables. During
session creation destination VRF in in2out feature is resolved by
traversing VRF routes in the matching VRF table. If VRF route resolves
destination IPv4 address then this VRF gets used. If non VRF route can
resolve destination IPv4 address If VRF route can’t be found source VRF
will be used. Priority of VRF routes is based on order of configuration.

Timeouts
~~~~~~~~

   set nat timeout [udp ``sec`` \| tcp-established ``sec``
   tcp-transitory ``sec`` \| icmp ``sec`` \| reset]

Session Limiting
~~~~~~~~~~~~~~~~

   nat44 plugin enable sessions ``max-number``

Maximum number of sessions value is used on per-thread (per-worker)
basis.

   set nat44 session limit ``limit`` [vrf ``table-id``]

Per-vrf session limiting makes it possible to split maximum number of
sessions between different VRFs.

MSS Clamping
~~~~~~~~~~~~

   nat mss-clamping ``mss-value``\ \|disable

Forwarding
~~~~~~~~~~

   nat44 forwarding enable|disable

Additional Configuration Commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

   | set nat frame-queue-nelts ``number``
   | set nat workers ``workers-list``
   | nat44 del session in|out ``addr``:``port`` tcp|udp|icmp [vrf
     ``id``] [external-host ``addr``:``port``]

Show commands
^^^^^^^^^^^^^

::

   show nat workers
   show nat timeouts
   show nat44 summary
   show nat44 sessions
   show nat44 addresses
   show nat mss-clamping
   show nat44 interfaces
   show nat44 vrf tables
   show nat44 hash tables
   nat44 show static mappings
   show nat44 interface address

Configuration Examples
----------------------

TWICE-NAT
~~~~~~~~~

Twice NAT lets you translate both the source and destination address in
a single rule. Currently, twice NAT44 is supported only for local
network service session initiated from outside network. Twice NAT static
mappings can only get initiated (create sessions) from outside network.

Topology
^^^^^^^^

::

   +--------------------------+
   | 10.0.0.2/24 (local host) |
   +--------------------------+
               |
   +---------------------------------+
   | 10.0.0.1/24 (eth0) (nat inside) |
   | 20.0.0.1/24 (eth1) (nat outside)|
   +---------------------------------+
               |
   +---------------------------+
   | 20.0.0.2/24 (remote host) |
   +---------------------------+

In this example traffic will be initiated from remote host. Remote host
will be accessing local host via twice-nat mapping.

Translation will occur as follows:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

outside to inside translation:


   | src address: 20.0.0.2 -> 192.168.160.101
   | dst address: 20.0.0.1 -> 10.0.0.2

inside to outside translation:


   | src address: 10.0.0.2 -> 20.0.0.1
   | dst address: 192.168.160.101 -> 20.0.0.2

Configuration
^^^^^^^^^^^^^

Enable nat44-ed plugin:


::

   nat44 plugin enable sessions 1000

Configure inside interface:


::

   set int state eth0 up
   set int ip address eth0 10.0.0.1/24
   set int nat44 in eth0

Configure outside interface:


::

   set int state eth1 up
   set int ip address eth1 20.0.0.1/24
   set int nat44 out eth1

Configure nat address pools:


::

   nat44 add address 20.0.0.1
   nat44 add address 192.168.160.101 twice-nat

-  alternatively we could use ``nat44 add interface address eth1``
-  both pools are required
-  pool ``20.0.0.1`` is used for out2in incoming traffic
-  special twice-nat pool ``192.168.160.101`` is used for secondary
   translation

Finally, add twice-nat mapping:


   nat44 add static mapping tcp local 10.0.0.2 5201 external 20.0.0.1
   5201 twice-nat

SELF TWICE-NAT
~~~~~~~~~~~~~~

Self twice NAT works similar to twice NAT with few exceptions. Self
twice NAT is a feature that lets client and service running on the same
host to communicate via NAT device. This means that external address is
the same address as local address. Self twice NAT static mappings can
only get initiated (create sessions) from outside network.

.. _topology-self-twice-nat:

Topology
^^^^^^^^

::

   +--------------------------+
   | 10.0.0.2/24 (local host) |
   +--------------------------+
               |
   +-------------------------------------------+
   | 10.0.0.1/24 (eth0) (nat inside & outside) |
   +-------------------------------------------+

In this example traffic will be initiated from local host. Local host
will be accessing itself via self-twice-nat mapping.

.. _translation-will-occur-as-follows-1:

Translation will occur as follows:
''''''''''''''''''''''''''''''''''

.. _outside-to-inside-translation-1:

outside to inside translation:


   | src address: 10.0.0.2 -> 192.168.160.101
   | dst address: 10.0.0.1 -> 10.0.0.2

.. _inside-to-outside-translation-1:

inside to outside translation:


   | src address: 10.0.0.2 -> 10.0.0.1
   | dst address: 192.168.160.101 -> 10.0.0.2

.. _configuration-1:

Configuration
^^^^^^^^^^^^^

.. _enable-nat44-ed-plugin-1:

Enable nat44-ed plugin:


::

   nat44 plugin enable sessions 1000

Configure NAT interface:


::

   set int state eth0 up
   set int ip address eth0 10.0.0.1/24
   set int nat44 in eth0
   set int nat44 out eth0

.. _configure-nat-address-pools-1:

Configure nat address pools:


::

   nat44 add address 10.0.0.1
   nat44 add address 192.168.160.101 twice-nat

Finally, add self-twice-nat mapping:


   nat44 add static mapping tcp local 10.0.0.2 5201 external 10.0.0.1
   5201 self-twice-nat
