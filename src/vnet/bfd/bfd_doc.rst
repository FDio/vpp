.. _bfd_doc:

BFD module
==========

Overview
--------

Bidirectional Forwarding Detection in VPP currently supports single-hop
UDP transport based on RFC 5880 and RFC 5881.

VPP can also act as a Seamless BFD (S-BFD) reflector, based on RFC 7880
and RFC 7881, see `Seamless BFD reflector`_.

Usage
-----

General usage
~~~~~~~~~~~~~

BFD sessions are created using APIs only. The following CLIs are
implemented, which call the APIs to manipulate the BFD:

Show commands:
^^^^^^^^^^^^^^

   ``show bfd [keys|sessions|echo-source|sbfd-reflectors]``

Show the existing keys, sessions, echo-source or S-BFD reflector
discriminators.

Key manipulation
^^^^^^^^^^^^^^^^

Create a new key or modify an existing key
''''''''''''''''''''''''''''''''''''''''''

   bfd key set conf-key-id type <keyed-sha1|meticulous-keyed-sha1>
   secret

Parameters:

-  conf-key-id - local configuration key ID, used to uniquely identify
   this key
-  type - type of the key
-  secret - shared secret (hex data)

Example:

   bfd key set conf-key-id 2368880803 type meticulous-keyed-sha1 secret
   69d685b0d990cdba46872706dc

Notes:

-  in-use key cannot be modified

Delete an existing key
''''''''''''''''''''''

   bfd key del conf-key-id

Parameters:

-  conf-key-id - local configuration key ID, used to uniquely identify
   this key

Example:

   bfd key del conf-key-id 2368880803

Notes:

-  in-use key cannot be deleted

Create a new (plain or authenticated) BFD session
'''''''''''''''''''''''''''''''''''''''''''''''''

   bfd udp session add interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

   desired-min-tx required-min-rx detect-mult [ conf-key-id bfd-key-id ]

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)
-  desired-min-tx - desired minimum tx interval (microseconds)
-  required-min-rx - required minimum rx interval (microseconds)
-  detect-mult - detect multiplier (must be non-zero)
-  conf-key-id - local configuration key ID
-  bfd-key-id - BFD key ID, as carried in BFD control frames

Example:

   bfd udp session add interface pg0 local-addr fd01:1::1 peer-addr
   fd01:1::2 desired-min-tx 100000 required-min-rx 100000 detect-mult 3
   conf-key-id 1029559112 bfd-key-id 13

Notes:

-  if conf-key-id and bfd-key-id are not specified, session is
   non-authenticated
-  desired-min-tx controls desired transmission rate of both control
   frames and echo packets

Modify BFD session
''''''''''''''''''

   bfd udp session mod interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

   desired-min-tx required-min-rx detect-mult

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)
-  desired-min-tx - desired minimum tx interval (microseconds)
-  required-min-rx - required minimum rx interval (microseconds)
-  detect-mult - detect multiplier (must be non-zero)

Example:

   bfd udp session mod interface pg0 local-addr 172.16.1.1 peer-addr
   172.16.1.2 desired-min-tx 300000 required-min-rx 200000 detect-mult
   12

Notes:

-  desired-min-tx controls desired transmission rate of both control
   frames and echo packets

Delete an existing BFD session
''''''''''''''''''''''''''''''

   bfd udp session del interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)

Example:

   bfd udp session del interface pg0 local-addr 172.16.1.1 peer-addr
   172.16.1.2

Set session admin-up or admin-down
''''''''''''''''''''''''''''''''''

   bfd udp session set-flags interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

   admin <up|down>

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)
-  admin - up/down based on desired action

Example:

   bfd udp session set-flags admin down interface pg0 local-addr
   172.16.1.1 peer-addr 172.16.1.2

Activate/change authentication for existing session
'''''''''''''''''''''''''''''''''''''''''''''''''''

   bfd udp session auth activate interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

   conf-key-id bfd-key-id [ delayed <yes|no> ]

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)
-  conf-key-id - local configuration key ID
-  bfd-key-id - BFD key ID, as carried in BFD control frames
-  delayed - is yes then this action is delayed until the peer performs
   the same action

Example:

   bfd udp session auth activate interface pg0 local-addr 172.16.1.1
   peer-addr 172.16.1.2 conf-key-id 540928695 bfd-key-id 239 delayed yes

Notes:

-  see `Delayed option <#delayed-option>`__ for more information

Deactivate authentication for existing session
''''''''''''''''''''''''''''''''''''''''''''''

   bfd udp session auth deactivate interface local-addr

   .. raw:: html

      <address>

   peer-addr

   .. raw:: html

      <address>

   [ delayed <yes|no> ]

Parameters:

-  interface - interface to which this session is tied to
-  local-addr - local address (ipv4 or ipv6)
-  peer-addr - peer address (ipv4 or ipv6, must match local-addr family)
-  delayed - is yes then this action is delayed until the peer performs
   the same action

Example:

   bfd udp session auth deactivate interface pg0 local-addr 172.16.1.1
   peer-addr 172.16.1.2

Notes:

-  see `Delayed option <#delayed-option>`__ for more information

Set echo-source interface
'''''''''''''''''''''''''

   bfd udp echo-source set interface

Parameters:

-  interface - interface used for getting source address for echo
   packets

Example:

   bfd udp echo-source set interface loop0

Delete echo-source interface
''''''''''''''''''''''''''''

   bfd udp echo-source del

Example:

   bfd udp echo-source del

Authentication
~~~~~~~~~~~~~~

BFD sessions should be authenticated for security purposes. SHA1 and
meticulous SHA1 authentication is supported by VPP. First,
authentication keys are configured in VPP and afterwards they can be
used by sessions.

There are two key IDs in the scope of BFD session:

-  configuration key ID is the internal unique key ID inside VPP and is
   never communicated to any peer, it serves only the purpose of
   identifying the key
-  BFD key ID is the key ID carried in BFD control frames and is used
   for verifying authentication

Turning auth on/off
^^^^^^^^^^^^^^^^^^^

Authentication can be turned on or off at any time. Care must be taken
however, to either synchronize the authentication manipulation with
peer’s actions to avoid the session going down.

Delayed option
''''''''''''''

Delayed option is useful for synchronizing authentication changes with a
peer. If it’s specified, then authentication change is not performed
immediately. In this case, VPP continues to transmit packets using the
old authentication method (unauthenticated or using old sha1 key). If a
packet is received, which does not pass the current authentication, then
VPP tries to authenticate it using the new method (which might be none,
if deactivating authentication) and if it passes, then the new
authentication method is put in use.

The recommended procedure for enabling/changing/disabling session
authentication is:

1. perform authentication change on vpp’s side with delayed option set
   to yes
2. perform authentication change on peer’s side (without delayed option)

Notes:

-  if both peers use delayed option at the same time, the change will
   never be carried out, since none of the peers will see any packet
   with the new authentication which could trigger the change
-  remote peer does not need to support or even be aware of this
   mechanism for it to work properly

Echo function
~~~~~~~~~~~~~

Echo function is used by VPP whenever a peer declares the willingness to
support it, echo-source is set and it contains a usable subnet (see
below). When echo function is switched on, the required min rx interval
advertised to peer is set to 1 second (or the configured value, if its
higher).

Echo source address
^^^^^^^^^^^^^^^^^^^

Because echo packets are only looped back (and not processed in any way)
by a peer, it’s necessary to set the source address in a way which
avoids packet drop due to spoofing protection by VPP. Per RFC, the
source address should not be in the subnet set on the interface over
which the echo packets are sent. Also, it must not be any VPP-local
address, otherwise the packet gets dropped on receipt by VPP. The
solution is to create a loopback interface with a (private) IPv4/IPv6
subnet assigned as echo-source. The BFD then picks an unused address
from the subnet by flipping the last bit and uses that as source address
in the echo packets, thus meeting RFC recommendation while avoiding
spoofing protection.

Example: if 10.10.10.3/31 is the subnet, then 10.10.10.2 will be used as
source address in (IPv4) echo packets

Demand mode
~~~~~~~~~~~

Demand mode is respected by VPP, but not used locally. The only scenario
when demand mode could make sense currently is when echo is active.
Because echo packets are inherently insecure against an adversary
looping them back a poll sequence would be required for slow periodic
connectivity verification anyway. It’s more efficient to just ask the
remote peer to send slow periodic control frames without VPP initiating
periodic poll sequences.

Admin-down
~~~~~~~~~~

Session may be put admin-down at any time. This immediately causes the
state to be changed to AdminDown and remain so unless the session is put
admin-up.

Seamless BFD reflector
~~~~~~~~~~~~~~~~~~~~~~

VPP can answer Seamless BFD (S-BFD) requests as a reflector, as defined
in RFC 7880 and RFC 7881, over IPv4 and IPv6. An S-BFD initiator checks
its path to VPP by sending BFD control packets to UDP port 7784, with
one of VPP's S-BFD discriminators as Your Discriminator. A request that
is IP routed goes to one of VPP's local addresses. A request sent over
an MPLS path goes to an address in 127/8 or ::ffff:127.0.0.0/104 (RFC
7881 section 5.1) and arrives as plain IP after the last label is
popped, with an Explicit NULL label, or with a label of VPP's own that
is popped for a lookup in the default table. VPP answers each valid
request at once and keeps no state per initiator, so any worker can
answer and no session is created.

S-BFD discriminators are configured one at a time. They are kept apart
from the discriminators of classic BFD sessions and are the same in
every FIB table. Classic BFD on UDP ports 3784 and 4784 is not affected.
VPP listens on port 7784 only while at least one discriminator is
configured.

A request is answered if it passes the basic packet checks of RFC 5880
section 6.8.6 (version, length, Detect Mult, Multipoint bit, My
Discriminator), has no authentication, has the Demand bit set, does not
come from UDP port 7784, has a unicast source address, has a TTL or hop
limit other than 0, has a unicast destination address or one in 127/8
or ::ffff:127.0.0.0/104, and carries a configured discriminator.
RFC 7881 section 5.1 has the initiator send TTL or hop limit 1 to 127/8
and ::ffff:127.0.0.0/104, but VPP does not require it: uniform-mode
label disposition copies the label TTL into the IP header. The reply:

-  swaps My Discriminator and Your Discriminator and clears Demand
-  has state Up, or AdminDown with diagnostic 7 (Administratively Down)
   if the discriminator is configured admin-down
-  copies Detect Mult and Desired Min TX Interval from the request, sets
   Required Min RX Interval to the configured value and Required Min
   Echo RX Interval to 0
-  answers a Poll with a Final
-  swaps the IP addresses and UDP ports (source port 7784), uses TTL or
   hop limit 255 and the TOS set with ``bfd_udp_set_tos``. The default
   TOS is 0; set it to 192 (CS6, network control) to mark replies. The
   setting applies to classic BFD too.
-  for a request sent to 127/8 or ::ffff:127.0.0.0/104, comes from the
   source address configured for the discriminator, or else from an
   address of the interface the request came in on, chosen as for ICMP
   errors (RFC 7881 section 6.1); the request is dropped if there is
   none. For IPv6 that address is link-local only if the request came
   from a link-local address, so from an initiator on the same link:
   RFC 7881 section 6.1 rules out a link-local source only for an
   initiator multiple hops away.
-  is IP routed in the FIB table of the interface the request came in
   on

Requests sent over MPLS paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

VPP has no local address in 127/8 or ::ffff:127.0.0.0/104. While at
least one discriminator is configured, the reflector adds the FIB
entries 127.0.0.0/8 and ::ffff:127.0.0.0/104, with source ``sbfd``, to
the default IPv4 and IPv6 tables. No route has to be configured. The
entries lead to the nodes ``bfd-sbfd-reflector4-dpo`` and
``bfd-sbfd-reflector6-dpo``. How a request gets there depends on how it
arrives:

-  as plain IP, after the last label is popped: through ``ip4-input``
   or ``ip6-input`` and the FIB lookup, as any IP packet
-  with an Explicit NULL label: from the MPLS lookup straight to the
   FIB lookup, without the header checks of ``ip4-input`` and
   ``ip6-input``
-  with a label of VPP's own whose path pops it for a lookup, such as
   ``mpls local-label add <label> eos via ip4-lookup-in-table 0``:
   through the label disposition node, which applies the header checks
   of ``ip4-input`` or ``ip6-input`` and counts failures under its own
   name, for example ``ip4-mpls-label-disposition-pipe``, and then to
   the FIB lookup. IPv4 options go to ``ip4-options``, as from
   ``ip4-input``.

Neither labelled form runs the IP input feature arcs (see
Limitations). As Explicit NULL requests skip the header checks, the
``-dpo`` nodes check the IP header themselves: the version, the IPv4
header checksum, and that the IP length does not go beyond the end of
the packet, which ``ip6-input`` and the label disposition do not check
for IPv6. They take only IPv4 headers without options, as ``ip4-input``
punts packets with options and ``ip4-local`` expects a 20-byte header.
UDP datagrams to port 7784 that pass and are not fragments go to
``ip4-local`` or ``ip6-local`` and on to the reflector, as requests to a
local address do. All other packets are dropped.

This changes how VPP handles other traffic to these prefixes, for as
long as at least one discriminator is configured:

-  Packets to 127/8 or ::ffff:127.0.0.0/104 in the default tables that
   are not S-BFD requests are dropped, even if a route covering them,
   such as a default route, would forward them. These addresses must
   not appear outside a host (RFC 1122 section 3.2.1.3) and are not to
   be forwarded (RFC 6890). Without a covering route they are dropped
   anyway. For the same reason VPP has no route back to these
   addresses, so packets from them to VPP's own addresses fail the
   source check of ``ip4-local`` and ``ip6-local``, as they do without a
   covering route.
-  The ``sbfd`` source has a high priority, so it overrides a route to
   127.0.0.0/8 or ::ffff:127.0.0.0/104 that the operator configured.
   That route is used again once the last discriminator is deleted. A
   more specific route, to part of these prefixes, is still used for
   that part, and requests sent to it are not answered.

What matters is the FIB table the IP payload is looked up in. Plain IP
and requests with an Explicit NULL label are looked up in the table of
the interface they came in on, so on an interface in another table they
are not answered, and that traffic is handled as without a reflector. A
label of VPP's own can name the default table for the lookup, and then
takes requests to the reflector from any interface. ``ip4-local`` and
``ip6-local`` check the source in the table of the lookup, so that table
needs a route back to the initiator; the reply is routed in the table of
the interface the request came in on.

Configuration
^^^^^^^^^^^^^

Add a discriminator::

   bfd udp sbfd reflector add discriminator <discriminator> [required-min-rx <usec>] [admin-down] [src-address <IPv4 address>] [src-address <IPv6 address>]

-  discriminator - local S-BFD discriminator, non-zero and unique
-  required-min-rx - Required Min RX Interval sent in replies, in
   microseconds, non-zero, default 50000
-  admin-down - reply with state AdminDown instead of Up
-  src-address - source of replies to requests sent over MPLS paths, one
   IPv4 and one IPv6 address at most; a unicast address of this node
   that the initiator can reach (RFC 7881 section 6.1), not IPv6
   link-local or IPv4-mapped (::ffff:0:0/96). VPP does not check that
   the address is configured on this node, so it can be set before the
   address is. Without it, an address of the interface the request came
   in on is used. Replies to IP routed requests always come from the
   address the request was sent to.

Delete a discriminator, and show the configured ones::

   bfd udp sbfd reflector del discriminator <discriminator>
   show bfd sbfd-reflectors

Example::

   bfd udp sbfd reflector add discriminator 1001 required-min-rx 10000 src-address 192.0.2.1

Change a discriminator in place, without deleting it. Requests for it
are answered throughout, as long as a reply source is available, with
the new values from the next reply on::

   bfd udp sbfd reflector mod discriminator <discriminator> [admin <up|down>] [required-min-rx <usec>] [src-address <IPv4 address>] [src-address <IPv6 address>]

Settings that are not given keep their values; ``src-address 0.0.0.0``
or ``src-address ::`` removes the source of that family. Removing the
only source a request sent over an MPLS path can be answered from, when
the interface it comes in on has no address of that family, leaves such
requests unanswered and counted as ``no_src_addr``. VPP does not
start a Poll Sequence (RFC 7880 section 7.5) when the Required Min RX
Interval changes, so an initiator that waits for one keeps its old
transmit interval.

The binary API has the same operations: ``bfd_udp_sbfd_reflector_add_del``,
``bfd_udp_sbfd_reflector_mod``, which sets all values of a discriminator
at once, and ``bfd_udp_sbfd_reflector_dump``, which returns one
``bfd_udp_sbfd_reflector_details`` per discriminator. These messages are
marked in progress and may still change.

Counters
^^^^^^^^

The nodes ``bfd-sbfd-reflector4-input`` and ``bfd-sbfd-reflector6-input``
count every packet they handle, in the counters below. Their names are
the stats segment keys ``/err/<node>/<name>``; ``show errors`` prints
each counter's description instead, for example "S-BFD packets
reflected" for ``reflected``. Requests sent over MPLS paths are counted
there too. A bad UDP length or checksum is counted as for any packet to
a local address, under ``ip4-local``, or ``ip6-input`` for IPv6.

=================  =====================================================
Name               Meaning
=================  =====================================================
``reflected``      request answered
``bad``            malformed (RFC 5880 checks, length, chained buffer)
``auth``           Authentication Present bit set
``bad_sport``      UDP source port 7784
``demand_clear``   Demand bit clear: already a reply, answering would loop
``non_unicast``    source in 0.0.0.0/8, 127.0.0.0/8 or 224.0.0.0 and
                   above (IPv4); ::, ::1, ::ffff:0:0/96 or multicast
                   (IPv6); destination the same, except 127/8 and
                   ::ffff:127.0.0.0/104
``no_disc``        Your Discriminator not configured
``bad_ttl``        TTL or hop limit 0, whatever the destination; only
                   requests with an Explicit NULL label get here:
                   ``ip4-input``, ``ip6-input`` and the label
                   disposition drop the others and send an ICMP Time
                   Exceeded
``no_src_addr``    request to 127/8 or ::ffff:127.0.0.0/104, no source
                   address configured and no unicast address of that
                   family on the receiving interface
=================  =====================================================

Everything but ``reflected`` is dropped.

The nodes ``bfd-sbfd-reflector4-dpo`` and ``bfd-sbfd-reflector6-dpo``
count every packet they get, that is every packet to 127/8 or
::ffff:127.0.0.0/104 looked up in the default tables while a
discriminator is configured. Plain IP and requests on a label of VPP's
own have their IP header checked before (see `Requests sent over MPLS
paths`_), so only requests with an Explicit NULL label can fail
``bad_version``, ``bad_ihl`` or ``bad_checksum``; ``bad_length`` also
catches IPv6 requests that arrive in other ways:

=================  =====================================================
Name               Meaning
=================  =====================================================
``request``        S-BFD request, passed to ``ip4-local`` or
                   ``ip6-local``
``not_request``    not UDP to port 7784, or a fragment
``bad_version``    IP version not 4 in ``bfd-sbfd-reflector4-dpo``, or
                   not 6 in ``bfd-sbfd-reflector6-dpo``
``bad_ihl``        IPv4 header length not 20 bytes: options, or too
                   short
``bad_checksum``   bad IPv4 header checksum
``bad_length``     IP length beyond the end of the packet, or IPv4
                   total length below the header length
=================  =====================================================

Everything but ``request`` is dropped.

Limitations
^^^^^^^^^^^

-  VPP is only a reflector; it cannot be an S-BFD initiator yet.
-  Authentication is not supported; authenticated requests are dropped
   and counted as ``auth``.
-  VPP adds the 127/8 and ::ffff:127.0.0.0/104 entries only to the
   default IPv4 and IPv6 tables. Requests sent over MPLS paths whose IP
   payload is looked up in another table are not answered: plain IP and
   Explicit NULL requests that arrive on interfaces in other tables, and
   requests on a label of VPP's own that looks up in another table.
-  The TTL expiry exception path of RFC 7881 section 5.1.1 is not
   supported yet: requests that take it are not answered. Depending on
   how they arrive, they are dropped before they reach the reflector or
   by the reflector itself.
-  Replies are IP routed (RFC 7881 section 6), never label switched.
-  IP input features, such as the ACL plugin, classifier policers and
   uRPF, run on IPv4 and IPv6 input. Requests that arrive as plain IP,
   including those sent over MPLS paths after the last label is popped,
   pass them. Requests that arrive with a label, Explicit NULL or VPP's
   own, do not: they go from the MPLS lookup to the IPv4 or IPv6 FIB
   lookup without the input feature arcs, even where the label
   disposition checks the IP header. The source check of ``ip4-local``
   and ``ip6-local`` still applies to them.
-  IPv4 requests with options, such as the Router Alert option, are not
   answered: VPP punts IPv4 packets with options and passes on only IGMP
   with Router Alert, and the ``-dpo`` nodes drop them as ``bad_ihl``.
   Initiators have to send requests without IP options.
-  S-BFD echo is not supported.

Protecting the reflector
^^^^^^^^^^^^^^^^^^^^^^^^

The reflector answers every valid request, at whatever rate requests
arrive. It does not filter by initiator or rate-limit. Use VPP features
that run on the input interface, before the reflector. They run on IPv4
and IPv6 input, so they do not see requests that arrive with a label
(see Limitations). The examples use interface ``GigabitEthernet0/8/0``;
repeat them for each interface that receives S-BFD requests.

Accept S-BFD only from known initiators, with the ACL plugin. Here the
initiators are in 192.0.2.0/24 and 2001:db8::/32, one ACL per address
family, and ``acl 0`` and ``acl 1`` are the indexes printed by the first
two commands::

   set acl-plugin acl permit src 192.0.2.0/24 dst 0.0.0.0/0 proto 17 dport 7784, deny src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 dport 7784, permit src 0.0.0.0/0 dst 0.0.0.0/0
   set acl-plugin acl permit src 2001:db8::/32 dst ::/0 proto 17 dport 7784, deny src ::/0 dst ::/0 proto 17 dport 7784, permit src ::/0 dst ::/0
   set acl-plugin interface GigabitEthernet0/8/0 input acl 0
   set acl-plugin interface GigabitEthernet0/8/0 input acl 1

Each ACL ends by permitting all other traffic of its address family.
Apply both even if S-BFD uses only one family: on an interface with an
input ACL, packets that match no rule are dropped.

VPP already drops packets to its own addresses, and S-BFD requests sent
to 127/8 or ::ffff:127.0.0.0/104, from sources it has no route to, so
loose uRPF adds nothing here. Strict uRPF also drops
requests whose source is routed through another interface, which
catches spoofed sources. Use it, for IPv4 and IPv6, on interfaces where
the route back to every initiator uses the same interface::

   set urpf ip4 rx strict GigabitEthernet0/8/0
   set urpf ip6 rx strict GigabitEthernet0/8/0

Rate-limit S-BFD with a policer, selected by the classifier so that
other traffic is not policed (see :ref:`policer`). Here one policer is
shared by IPv4 and IPv6, and ``table-index 0`` and ``table-index 1`` are
the indexes of the two classifier tables, as listed by
``show classify tables``::

   policer add name sbfd type 1r2c cir 1000 cb 10000 rate kbps conform-action transmit violate-action drop
   classify table mask l3 ip4 proto l4 dst_port buckets 1
   classify session policer-hit-next sbfd table-index 0 match l3 ip4 proto 17 l4 dst_port 7784
   set policer classify interface GigabitEthernet0/8/0 ip4-table 0
   classify table mask l3 ip6 proto l4 dst_port buckets 1
   classify session policer-hit-next sbfd table-index 1 match l3 ip6 proto 17 l4 dst_port 7784
   set policer classify interface GigabitEthernet0/8/0 ip6-table 1

BFD implementation notes
------------------------

Because BFD can work over different transport layers, the BFD code is
separated into core BFD functionality - main module implemented in
bfd_main.c and transport-specific code implemented in bfd_udp.c.

Main module
~~~~~~~~~~~

Main module is responsible for handling all the BFD functionality
defined in RFC 5880.

Internal API
^^^^^^^^^^^^

Internal APIs defined in bfd_main.h are called from transport-specific
code to create/modify/delete

Packet receipt
^^^^^^^^^^^^^^

When a packet is received by the transport layer, it is forwarded to
main module (to main thread) via an RPC call. At this point, the
authentication has been verified, so the packet is consumed, session
parameters are updated accordingly and state change (if applicable).
Based on these, the timeouts are adjusted if required and an event is
sent to the process node to wake up and recalculate sleep time.

Packet transmit
^^^^^^^^^^^^^^^

Main module allocates a vlib_buffer_t, creates the required BFD frame
(control or echo in it), then calls the transport layer to add the
transport layer. Then a frame containing the buffer to the appropriate
node is created and enqueued.

Process node
^^^^^^^^^^^^

Main module implements one process node which is a simple loop. The
process node gets next timeout from the timer wheel, sleeps until the
timeout expires and then calls a timeout routine which drives the state
machine for each session which timed out. The sleep is interrupted
externally via vlib event, when a session is added or modified in a way
which might require timer wheel manipulation. In this case the caller
inserts the necessary timeout to timer wheel and then signals the
process node to wake up early, handle possible timeouts and recalculate
the sleep time again.

State machine
^^^^^^^^^^^^^

Default state of BFD session when created is Down, per RFC 5880. State
changes to Init, Up or Down based on events like received state from
peer and timeouts. The session state can be set AdminDown using a binary
API, which prevents it from going to any other state, until this
limitation is removed. This state is advertised to peers in slow
periodic control frames.

For each session, the following timeouts are maintained:

1. tx timeout - used for sending out control frames
2. rx timeout - used for detecting session timeout
3. echo tx timeout - used for sending out echo frames
4. echo rx timeout - used for detecting session timeout based on echo

These timeouts are maintained in cpu clocks and recalculated when
appropriate (e.g. rx timeout is bumped when a packet is received,
keeping the session alive). Only the earliest timeout is inserted into
the timer wheel at a time and timer wheel events are never deleted,
rather spurious events are ignored. This allows efficient operation,
like not inserting events into timing wheel for each packet received or
ignoring left-over events in case a bfd session gets removed and a new
one is recreated with the same session index.

Authentication keys management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Authentication keys are managed internally in a pool, with each key
tracking it’s use count. The removal/modification is only allowed if the
key is not in use.

UDP module
~~~~~~~~~~

UDP module is responsible for:

1. public APIs/CLIs to configure BFD over UDP.
2. support code called by main module to encapsulate/decapsulate BFD
   packets

This module implements two graph nodes - for consuming ipv4 and ipv6
packets target at BFD ports 3874 and 3875.

.. _packet-receipt-1:

Packet receipt
^^^^^^^^^^^^^^

BFD packet receipt receipt starts in the bfd udp graph nodes. Since the
code needs to verify IP/UDP header data, it relies on ip4-local (and
ip6-local) nodes to store pointers to the appropriate headers. First,
your discriminator is extracted from BFD packet and used to lookup the
existing session. In case it’s zero, the pair of IP addresses and
sw_if_index is used to lookup session. Then, main module is called to
verify the authentication, if present. Afterwards a check is made if the
IP/UDP headers are correct. If yes, then an RPC call is made to the main
thread to consume the packet and take action upon it.

Packet transmission
^^^^^^^^^^^^^^^^^^^

When process node decides that there is a need to transmit the packet,
it creates a buffer, fills the BFD frame data in and calls the UDP
module to add the transport layer. This is a simple operation for the
control frames consisting of just adding UDP/IP headers based on session
data. For echo frames, an additional step, looking at the echo-source
interface and picking and address is performed and if this fails, then
the packet cannot be transmitted and an error is returned to main
thread.
