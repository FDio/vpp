IP Reassembly
=============

Some VPP functions need access to whole packet and/or stream
classification based on L4 headers. Reassembly functionality allows
both former and latter.

Full reassembly vs shallow (virtual) reassembly
-----------------------------------------------

There are two kinds of reassembly available in VPP:

1. Full reassembly changes a stream of packet fragments into one
packet containing all data reassembled with fragment bits cleared
and fragment header stripped (in case of ip6). Note that resulting
packet may come out of reassembly as a buffer chain. Because it's
impractical to parse headers which are split over multiple vnet
buffers, vnet_buffer_chain_linearize() is called after reassembly so
that L2/L3/L4 headers can be found in first buffer. Full reassembly
is costly and shouldn't be used unless necessary. Full reassembly is by
default enabled for both ipv4 and ipv6 traffic for "forus" traffic
- that is packets aimed at VPP addresses. This can be disabled via API
if desired, in which case "forus" fragments are dropped.

2. Shallow (virtual) reassembly allows various classifying and/or
translating features to work with fragments without having to
understand fragmentation. It works by extracting L4 data and adding
them to vnet_buffer for each packet/fragment passing throught SVR
nodes. This operation is performed for both fragments and regular
packets, allowing consuming code to treat all packets in same way. SVR
caches incoming packet fragments (buffers) until first fragment is
seen. Then it extracts L4 data from that first fragment, fills it for
any cached fragments and transmits them in the same order as they were
received. From that point on, any other passing fragments get L4 data
populated in vnet_buffer based on reassembly context.

Multi-worker behaviour
^^^^^^^^^^^^^^^^^^^^^^

Both reassembly types deal with fragments arriving on different workers
via handoff mechanism. All reassembly contexts are stored in pools.
Bihash mapping 5-tuple key to a value containing pool index and thread
index is used for lookups. When a lookup finds an existing reasembly on
a different thread, it hands off the fragment to that thread. If lookup
fails, a new reassembly context is created and current worker becomes
owner of that context. Further fragments received on other worker
threads are then handed off owner worker thread.

Full reassembly also remembers thread index where first fragment (as in
fragment with fragment offset 0) was seen and uses handoff mechanism to
send the reassembled packet out on that thread even if pool owner is
a different thread. This then requires an additional handoff to free
reassembly context as only pool owner can do that in a thread-safe way.

Limits
^^^^^^

Because reassembly could be an attack vector, there is a configurable
limit on the number of concurrent reassemblies and also maximum
fragments per packet.

Custom applications
^^^^^^^^^^^^^^^^^^^

Both reassembly features allow to be used by custom applicatind which
are not part of VPP source tree. Be it patches or 3rd party plugins,
they can build their own graph paths by using "-custom*" versions of
nodes. Reassembly then reads next_index and error_next_index for each
buffer from vnet_buffer, allowing custom application to steer
both reassembled packets and any packets which are considered an error
in a way the custom application requires.

Full reassembly
---------------

Configuration
^^^^^^^^^^^^^

Configuration is via API (``ip_reassembly_enable_disable``) or CLI:

``set interface reassembly <interface-name> [on|off|ip4|ip6]``

here ``on`` means both ip4 and ip6.

A show command is provided to see reassembly contexts:

For ip4:

``show ip4-full-reassembly [details]``

For ip6:

``show ip6-full-reassembly [details]``

Global full reassembly parameters can be modified using API
``ip_reassembly_set`` and retrieved using ``ip_reassembly_get``.

Defaults
""""""""

For defaults values, see #defines in ip4_full_reass.c/ip6_full_reass.c.

Finished/expired contexts
^^^^^^^^^^^^^^^^^^^^^^^^^

Reassembly contexts are freed either when reassembly is finished - when
all data has been received or in case of timeout. There is a process
walking all reassemblies, freeing any expired ones.

Shallow (virtual) reassembly
----------------------------

Configuration
^^^^^^^^^^^^^

Configuration is via API (``ip_reassembly_enable_disable``) only as
there is no value in turning SVR on by hand without a feature consuming
buffer metadata. SVR is designed to be turned on by a feature requiring
it in a programmatic way.

A show command is provided to see reassembly contexts:

For ip4:

``show ip4-sv-reassembly [details]``

For ip6:

``show ip6-sv-reassembly [details]``

Global shallow reassembly parameters can be modified using API
``ip_reassembly_set`` and retrieved using ``ip_reassembly_get``.

Expiring contexts
^^^^^^^^^^^^^^^^^

There is no way of knowing when a reassembly is finished without
performing (an almost) full reassembly, so contexts in SVR cannot be
freed in the same way as in full reassembly. Instead a different
approach is taken. Least recently used (LRU) list is maintained where
reassembly contexts are ordered based on last update. The oldest
context is then freed whenever SVR hits limit on numbeer of concurrent
reassembly contexts. This allows a context to live indefinitely in case
there is not enough fragmented traffic but it also allows rapid reuse
of pool elements without requiring deep knowledge about state of
reassembly.

Truncated packets
^^^^^^^^^^^^^^^^^

When SVR detects that a packet has been truncated in a way where L4
headers are not available, it will mark it as such in vnet_buffer,
allowing downstream features to handle such packets as they deem fit.

Fast path/slow path
^^^^^^^^^^^^^^^^^^^

SVR runs is implemented fast path/slow path way. By default, it assumes
that any passing traffic doesn't contain fragments, processing buffers
in a dual-loop. If it sees a fragment, it then jumps to single-loop
processing.

Feature enabled by other features/reference counting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SVR feature is enabled by some other features, like NAT, when those
features are enabled. For this to work, it implements a reference
counted API for enabling/disabling SVR.
