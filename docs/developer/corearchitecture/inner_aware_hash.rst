.. _inner_aware_hash:

Inner-aware flow hash for tunnel traffic
========================================

Motivation
----------

VPP's IP and Ethernet flow-hash functions consult the outer 5-tuple to
spread traffic across ECMP next-hops and across LAG / bond members.  For
plain (non-tunnel) traffic this works well: every flow has its own
``(src,dst,sport,dport,proto)`` tuple.

For transit traffic where many flows share the same outer 5-tuple - for
example IPv4-in-IPv4, IPv6-in-IPv4, GRE-IP, and NVGRE encapsulations
between two fixed endpoints - the hash collapses to a single member.
This wastes path capacity and is a real problem for SmartNIC / DPU
scenarios that carry many tenant flows under one outer pair.

VXLAN and Geneve are explicitly excluded because their outer UDP source
port is required by the standard to carry inner-flow entropy
(see RFC 7348 §4.2 and RFC 8926 §3.3).

Design
------

A new helper, ``ip_inner_resolve`` (in
``src/vnet/ip/ip_inner_aware_hash.h``), parses the outer payload, walks
past optional GRE headers and NVGRE/TEB inner Ethernet, walks any inner
IPv6 extension headers, and returns a descriptor pointing at the inner
IP addresses and the first 4 bytes of the inner L4 header (containing
the inner src/dst ports for TCP and UDP, or a zero placeholder).

The helper is enabled in two different ways depending on the hash
surface; both surfaces are **opt-in** to preserve byte-for-byte
behaviour for existing users:

IP-layer opt-in
~~~~~~~~~~~~~~~

A new bit ``IP_FLOW_HASH_PEEK_INNER`` (bit 9, value ``0x200``) in
``flow_hash_config_t`` enables inner-aware hashing on a per-FIB basis.
``IP_FLOW_HASH_DEFAULT`` is unchanged, so existing users see no
behavior change unless they opt in.

The CLI keyword is ``peek_inner``::

    set ip flow-hash table 0 src dst sport dport proto peek_inner
    set ip6 flow-hash table 0 src dst sport dport proto peek_inner

LAG opt-in
~~~~~~~~~~

A new bond load-balance algorithm,
``BOND_API_LB_ALGO_L34_INNER`` (value ``6``), is added.  It is backed
by a new registered Ethernet hash function ``hash-eth-l34-inner``
which attempts an inner peek for IPinIP / GRE / NVGRE traffic and
transparently falls back to the outer-only L34 hash when the inner
header cannot be resolved (non-tunnel traffic, fragmented outer,
unsupported GRE protocol type, etc.).  The existing
``BOND_API_LB_ALGO_L34`` algorithm and the ``hash-eth-l34`` hash
function are left byte-for-byte unchanged, so existing bonds keep
their current behaviour; operators opt in by creating bonds with the
new algorithm::

    create bond mode lacp load-balance l34-inner

or via the API (``bond_create2`` with ``lb`` set to
``BOND_API_LB_ALGO_L34_INNER``).

Safety
------

The helper enforces strict bounds checks: every byte read from the
packet is verified against the ``remaining`` count passed by the
caller.  When any check fails (truncated packet, unknown inner IP
version, fragmented inner header, unsupported GRE protocol type, or an
unsupported inner IPv6 extension header such as Fragment/ESP/AH), the
helper marks the descriptor invalid and the caller falls back to the
outer-only hash.  Outer fragmented packets (IPv4 fragments or IPv6 with
Fragment ext header) likewise skip peeking - they may not carry a
complete inner header.

Performance
-----------

The helper is a single inline-able function chain and adds at most one
cache line of accesses (the inner IP header) plus a small constant
number of branches.  When the opt-in IP flag is not set, the only cost
is one extra branch on ``flow_hash_config_t`` - well below measurement
noise.  Bonds using ``BOND_API_LB_ALGO_L34`` are untouched and so see
zero overhead.

Testing
-------

Unit tests in ``test/test_inner_aware_hash.py`` cover:

  * ECMP distribution across 3 next-hops for IPinIP / GRE-IP / NVGRE
    over IPv4 and IPv6 outers with IPv4 and IPv6 inners (12 cases).
  * LAG distribution across 2 bond members for the same matrix.
  * Plain (non-tunnel) regression: ECMP / LAG of plain UDP-over-v4 and
    UDP-over-v6 still distribute as before.
  * Opt-in semantics: ``TestPeekInnerOff`` confirms that without the
    flag the tunnel ECMP collapses to a single path (upstream
    behavior).
  * Safety: outer-fragmented packets, inner v6 with Hop-by-Hop ext,
    inner v6 with Fragment ext, and truncated tunnel payloads must
    fall back without crashing.

Files
-----

Implementation:

  * ``src/vnet/ip/ip_flow_hash.h``           - flag bit definition
  * ``src/vnet/ip/ip_inner_aware_hash.h``    - helper
  * ``src/vnet/ip/ip4_inlines.h``            - v4 caller
  * ``src/vnet/ip/ip6_inlines.h``            - v6 caller
  * ``src/vnet/hash/hash_eth.c``             - LAG caller (new hash-eth-l34-inner)
  * ``src/vnet/bonding/bond.api``            - new BOND_API_LB_ALGO_L34_INNER
  * ``src/vnet/bonding/node.h``              - new BOND_LB_L34_INNER enum
  * ``src/vnet/bonding/cli.c``               - new "l34-inner" CLI / ``hash_func`` wiring
