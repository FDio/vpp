# BFD module    {#bfd_doc}

## Overview

Bidirectional Forwarding Detection in VPP currently supports single-hop UDP
transport based on RFC 5880 and RFC 5881.

## Usage

### General usage

BFD sessions are created using APIs only. The following CLIs are implemented,
which call the APIs to manipulate the BFD:

#### Show commands:

> show bfd [keys|sessions|echo-source]

Show the existing keys, sessions or echo-source.

#### Key manipulation

##### Create a new key or modify an existing key

> bfd key set conf-key-id <id> type <keyed-sha1|meticulous-keyed-sha1> secret <secret>

Parameters:

* conf-key-id     - local configuration key ID, used to uniquely identify this key
* type            - type of the key
* secret          - shared secret (hex data)

Example:

> bfd key set conf-key-id 2368880803 type meticulous-keyed-sha1 secret 69d685b0d990cdba46872706dc

Notes:

* in-use key cannot be modified

##### Delete an existing key

> bfd key del conf-key-id <id>

Parameters:

* conf-key-id     - local configuration key ID, used to uniquely identify this key

Example:

> bfd key del conf-key-id 2368880803

Notes:

*  in-use key cannot be deleted

##### Create a new (plain or authenticated) BFD session

> bfd udp session add interface <interface> local-addr <address> peer-addr <address> desired-min-tx <interval> required-min-rx <interval> detect-mult <multiplier> [ conf-key-id <ID> bfd-key-id <ID> ]

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)
* desired-min-tx  - desired minimum tx interval (microseconds)
* required-min-rx - required minimum rx interval (microseconds)
* detect-mult     - detect multiplier (must be non-zero)
* conf-key-id     - local configuration key ID
* bfd-key-id      - BFD key ID, as carried in BFD control frames

Example:

> bfd udp session add interface pg0 local-addr fd01:1::1 peer-addr fd01:1::2 desired-min-tx 100000 required-min-rx 100000 detect-mult 3 conf-key-id 1029559112 bfd-key-id 13

Notes:

* if conf-key-id and bfd-key-id are not specified, session is non-authenticated
* desired-min-tx controls desired transmission rate of both control frames and echo packets

##### Modify BFD session

> bfd udp session mod interface <interface> local-addr <address> peer-addr <address> desired-min-tx <interval> required-min-rx <interval> detect-mult <multiplier>

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)
* desired-min-tx  - desired minimum tx interval (microseconds)
* required-min-rx - required minimum rx interval (microseconds)
* detect-mult     - detect multiplier (must be non-zero)

Example:

> bfd udp session mod interface pg0 local-addr 172.16.1.1 peer-addr 172.16.1.2 desired-min-tx 300000 required-min-rx 200000 detect-mult 12

Notes:

* desired-min-tx controls desired transmission rate of both control frames and echo packets

##### Delete an existing BFD session

> bfd udp session del interface <interface> local-addr <address> peer-addr<address>

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)

Example:

> bfd udp session del interface pg0 local-addr 172.16.1.1 peer-addr 172.16.1.2

##### Set session admin-up or admin-down

> bfd udp session set-flags interface <interface> local-addr <address> peer-addr <address> admin <up|down>

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)
* admin           - up/down based on desired action

Example:

> bfd udp session set-flags admin down interface pg0 local-addr 172.16.1.1 peer-addr 172.16.1.2

##### Activate/change authentication for existing session

> bfd udp session auth activate interface <interface> local-addr <address> peer-addr <address> conf-key-id <ID> bfd-key-id <ID> [ delayed <yes|no> ]

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)
* conf-key-id     - local configuration key ID
* bfd-key-id      - BFD key ID, as carried in BFD control frames
* delayed         - is yes then this action is delayed until the peer performs the same action

Example:

> bfd udp session auth activate interface pg0 local-addr 172.16.1.1 peer-addr 172.16.1.2 conf-key-id 540928695 bfd-key-id 239 delayed yes

Notes:

* see [Delayed option] for more information

##### Deactivate authentication for existing session

> bfd udp session auth deactivate interface <interface> local-addr <address> peer-addr <address> [ delayed <yes|no> ]

Parameters:

* interface       - interface to which this session is tied to
* local-addr      - local address (ipv4 or ipv6)
* peer-addr       - peer address (ipv4 or ipv6, must match local-addr family)
* delayed         - is yes then this action is delayed until the peer performs the same action

Example:

> bfd udp session auth deactivate interface pg0 local-addr 172.16.1.1 peer-addr 172.16.1.2

Notes:

* see [Delayed option] for more information

##### Set echo-source interface

> bfd udp echo-source set interface <interface>

Parameters:

* interface       - interface used for getting source address for echo packets

Example:

> bfd udp echo-source set interface loop0

##### Delete echo-source interface

> bfd udp echo-source del

Example:

> bfd udp echo-source del

### Authentication

BFD sessions should be authenticated for security purposes. SHA1 and meticulous
SHA1 authentication is supported by VPP. First, authentication keys are
configured in VPP and afterwards they can be used by sessions.

There are two key IDs in the scope of BFD session:

* configuration key ID is the internal unique key ID inside VPP and is never
  communicated to any peer, it serves only the purpose of identifying the key
* BFD key ID is the key ID carried in BFD control frames and is used for
  verifying authentication

#### Turning auth on/off

Authentication can be turned on or off at any time. Care must be taken however,
to either synchronize the authentication manipulation with peer's actions
to avoid the session going down.

##### Delayed option

Delayed option is useful for synchronizing authentication changes with a peer.
If it's specified, then authentication change is not performed immediately.
In this case, VPP continues to transmit packets using the old authentication
method (unauthenticated or using old sha1 key). If a packet is received, which
does not pass the current authentication, then VPP tries to authenticate it
using the new method (which might be none, if deactivating authentication)
and if it passes, then the new authentication method is put in use.

The recommended procedure for enabling/changing/disabling session 
authentication is:

1. perform authentication change on vpp's side with delayed option set to yes
2. perform authentication change on peer's side (without delayed option)

Notes:

* if both peers use delayed option at the same time, the change will never
  be carried out, since none of the peers will see any packet with the new
  authentication which could trigger the change
* remote peer does not need to support or even be aware of this mechanism
  for it to work properly


### Echo function

Echo function is used by VPP whenever a peer declares the willingness
to support it, echo-source is set and it contains a usable subnet (see below).
When echo function is switched on, the required min rx interval advertised
to peer is set to 1 second (or the configured value, if its higher).

#### Echo source address

Because echo packets are only looped back (and not processed in any way)
by a peer, it's necessary to set the source address in a way which avoids
packet drop due to spoofing protection by VPP. Per RFC, the source address
should not be in the subnet set on the interface over which the echo packets
are sent. Also, it must not be any VPP-local address, otherwise the packet
gets dropped on receipt by VPP. The solution is to create a loopback interface
with a (private) IPv4/IPv6 subnet assigned as echo-source. The BFD then picks
an unused address from the subnet by flipping the last bit and uses that as
source address in the echo packets, thus meeting RFC recommendation while
avoiding spoofing protection.

Example: if 10.10.10.3/31 is the subnet, then 10.10.10.2 will be used as
         source address in (IPv4) echo packets

### Demand mode

Demand mode is respected by VPP, but not used locally. The only scenario when
demand mode could make sense currently is when echo is active. Because echo
packets are inherently insecure against an adversary looping them back a poll
sequence would be required for slow periodic connectivity verification anyway.
It's more efficient to just ask the remote peer to send slow periodic control
frames without VPP initiating periodic poll sequences.

### Admin-down

Session may be put admin-down at any time. This immediately causes the state
to be changed to AdminDown and remain so unless the session is put admin-up.

## BFD implementation notes

Because BFD can work over different transport layers, the BFD code is separated
into core BFD functionality - main module implemented in bfd_main.c
and transport-specific code implemented in bfd_udp.c.

### Main module

Main module is responsible for handling all the BFD functionality defined
in RFC 5880.

#### Internal API

Internal APIs defined in bfd_main.h are called from transport-specific code
to create/modify/delete

#### Packet receipt

When a packet is received by the transport layer, it is forwarded to main
module (to main thread) via an RPC call. At this point, the authentication has
been verified, so the packet is consumed, session parameters are updated
accordingly and state change (if applicable). Based on these, the timeouts
are adjusted if required and an event is sent to the process node to wake up
and recalculate sleep time.

#### Packet transmit

Main module allocates a vlib_buffer_t, creates the required BFD frame (control
or echo in it), then calls the transport layer to add the transport layer.
Then a frame containing the buffer to the aprropriate node is created
and enqueued.

#### Process node

Main module implements one process node which is a simple loop. The process
node gets next timeout from the timer wheel, sleeps until the timeout expires
and then calls a timeout routine which drives the state machine for each
session which timed out. The sleep is interrupted externally via vlib event,
when a session is added or modified in a way which might require timer wheel
manipulation. In this case the caller inserts the necessary timeout to timer
wheel and then signals the process node to wake up early, handle possible
timeouts and recalculate the sleep time again.

#### State machine

Default state of BFD session when created is Down, per RFC 5880. State changes
to Init, Up or Down based on events like received state from peer and timeouts.
The session state can be set AdminDown using a binary API, which prevents it
from going to any other state, until this limitation is removed. This state
is advertised to peers in slow periodic control frames.

For each session, the following timeouts are maintained:

1. tx timeout - used for sending out control frames
2. rx timeout - used for detecting session timeout
3. echo tx timeout - used for sending out echo frames
3. echo rx timeout - used for detecting session timeout based on echo

These timeouts are maintained in cpu clocks and recalculated when appropriate
(e.g. rx timeout is bumped when a packet is received, keeping the session
alive). Only the earliest timeout is inserted into the timer wheel at a time
and timer wheel events are never deleted, rather spurious events are ignored.
This allows efficient operation, like not inserting events into timing wheel
for each packet received or ignoring left-over events in case a bfd session
gets removed and a new one is recreated with the same session index.

#### Authentication keys management

Authentication keys are managed internally in a pool, with each key tracking
it's use count. The removal/modification is only allowed if the key is not in
use.

### UDP module

UDP module is responsible for:

1. public APIs/CLIs to configure BFD over UDP.
2. support code called by main module to encapsulate/decapsulate BFD packets

This module implements two graph nodes - for consuming ipv4 and ipv6 packets
target at BFD ports 3874 and 3875.

#### Packet receipt

BFD packet receipt receipt starts in the bfd udp graph nodes. Since the code
needs to verify IP/UDP header data, it relies on ip4-local (and ip6-local)
nodes to store pointers to the appropriate headers. First, your discriminator
is extracted from BFD packet and used to lookup the existing session. In case
it's zero, the pair of IP addresses and sw_if_index is used to lookup session.
Then, main module is called to verify the authentication, if present.
Afterwards a check is made if the IP/UDP headers are correct. If yes, then
an RPC call is made to the main thread to consume the packet and take action
upon it.

#### Packet transmission

When process node decides that there is a need to transmit the packet, it
creates a buffer, fills the BFD frame data in and calls the UDP module to
add the transport layer. This is a simple operation for the control frames
consisting of just adding UDP/IP headers based on session data. For echo
frames, an additional step, looking at the echo-source interface and picking
and address is performed and if this fails, then the packet cannot be
transmitted and an error is returned to main thread.
