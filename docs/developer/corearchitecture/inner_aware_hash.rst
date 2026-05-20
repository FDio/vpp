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

SRv6 is likewise out of scope: the IPv6 flow label is the
architecture-defined entropy carrier for segment-routed traffic
(RFC 6437 and RFC 8754 §7), so transit hashing should consult the
flow label rather than peek past the Segment Routing Header.  The
helper does not parse the IPv6 Routing extension header (next
header 43); SRv6 packets fall through to the outer 5-tuple hash
unchanged.

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

::

 Software packet-generator harness on dev-VM L1 KVM,
  1 M pkts x 3 reps per scenario, single VPP worker, no DPDK.
 Topology puts two BondEthernets (xor mode, 4 loopback members each)
 behind an ECMP default route, so both code paths the patch touches
 get exercised end-to-end.  Five binaries / configs from the same
 tree, the same compiler flags:

     A = unpatched VPP (upstream 435fda04), bond load-balance l34
     B = patched VPP, IP_FLOW_HASH_PEEK_INNER unset, bond l34
     C = patched VPP, IP_FLOW_HASH_PEEK_INNER set,   bond l34
     D = patched VPP, IP_FLOW_HASH_PEEK_INNER unset, bond l34-inner
     E = patched VPP, IP_FLOW_HASH_PEEK_INNER set,   bond l34-inner
         (E = both new features enabled)

 Key take-aways:

 1. With both new knobs at their defaults (B path -- patch present
    but nothing opted in) the patch is essentially a no-op on the
    hot path: B-A is within +-2 cyc/pkt for every node and every
    profile measured, well inside per-rep noise.  Deployments that
    pick up the patch but do not change any config see no
    measurable cost.

 2. The two new features are independent, opt-in knobs and each
    one pays its own cost only inside the node it touches:
        IP_FLOW_HASH_PEEK_INNER   -> ip4-lookup
        BOND_LB_L34_INNER         -> BondEthernet-tx
    An operator that wants only one of the two pays only that one
    (C and D below).  Even with both turned on (E), the worst-case
    end-to-end overhead is modest:
        non-tunneled IPv4   +8.9 cyc/pkt   (no inner to peek at,
                                            cost is just the branch
                                            plus the fixed bond
                                            algorithm rework)
        IPinIP v4/v4       +18.0 cyc/pkt
        NVGRE  v4/v4       +35.6 cyc/pkt   (full inner-Ethernet
                                            pop + inner-L3/L4 parse)
    All numbers are paid only on a per-packet basis and only when
    there is actually something to peek at, so the upper bound is
    tied to tunnel traffic mix.

 Per-packet cost inside the two graph nodes whose code is touched
 by the patch -- ip4-lookup (the peek) and BondEthernet-tx (the new
 BOND_LB_L34_INNER algorithm); median of 3 reps:

   ip4-lookup
     baseline v4 UDP    A unpatched/l34          ->  39.1 cycles/pkt
     baseline v4 UDP    B patched/l34/off        ->  36.9 cycles/pkt
     baseline v4 UDP    C patched/l34/on         ->  40.8 cycles/pkt
     baseline v4 UDP    D patched/l34-inner/off  ->  36.6 cycles/pkt
     baseline v4 UDP    E patched/l34-inner/on   ->  43.2 cycles/pkt
     IPinIP v4/v4       A unpatched/l34          ->  37.6 cycles/pkt
     IPinIP v4/v4       B patched/l34/off        ->  37.8 cycles/pkt
     IPinIP v4/v4       C patched/l34/on         ->  43.4 cycles/pkt
     IPinIP v4/v4       D patched/l34-inner/off  ->  40.2 cycles/pkt
     IPinIP v4/v4       E patched/l34-inner/on   ->  42.7 cycles/pkt
     NVGRE  v4/v4       A unpatched/l34          ->  38.0 cycles/pkt
     NVGRE  v4/v4       B patched/l34/off        ->  37.6 cycles/pkt
     NVGRE  v4/v4       C patched/l34/on         ->  55.0 cycles/pkt
     NVGRE  v4/v4       D patched/l34-inner/off  ->  36.7 cycles/pkt
     NVGRE  v4/v4       E patched/l34-inner/on   ->  53.2 cycles/pkt

   BondEthernet-tx (average over the bond(s) that received traffic)
     baseline v4 UDP    A unpatched/l34          ->  23.6 cycles/pkt
     baseline v4 UDP    B patched/l34/off        ->  24.4 cycles/pkt
     baseline v4 UDP    C patched/l34/on         ->  24.2 cycles/pkt
     baseline v4 UDP    D patched/l34-inner/off  ->  26.9 cycles/pkt
     baseline v4 UDP    E patched/l34-inner/on   ->  28.4 cycles/pkt
     IPinIP v4/v4       A unpatched/l34          ->  16.1 cycles/pkt
     IPinIP v4/v4       B patched/l34/off        ->  16.6 cycles/pkt
     IPinIP v4/v4       C patched/l34/on         ->  19.5 cycles/pkt
     IPinIP v4/v4       D patched/l34-inner/off  ->  25.3 cycles/pkt
     IPinIP v4/v4       E patched/l34-inner/on   ->  29.0 cycles/pkt
     NVGRE  v4/v4       A unpatched/l34          ->  16.2 cycles/pkt
     NVGRE  v4/v4       B patched/l34/off        ->  17.3 cycles/pkt
     NVGRE  v4/v4       C patched/l34/on         ->  18.9 cycles/pkt
     NVGRE  v4/v4       D patched/l34-inner/off  ->  30.3 cycles/pkt
     NVGRE  v4/v4       E patched/l34-inner/on   ->  36.6 cycles/pkt

 Cost decomposition (median, cyc/pkt):

   patch-present, nothing opted in        B - A
     baseline v4 UDP    ip4-lookup -2.2  bond-tx +0.8  total -1.4
     IPinIP v4/v4       ip4-lookup +0.2  bond-tx +0.5  total +0.7
     NVGRE  v4/v4       ip4-lookup -0.4  bond-tx +1.1  total +0.7
                                                        (within noise)

   peek-inner alone                       C - B
     baseline v4 UDP    ip4-lookup +3.9  bond-tx -0.2  total +3.7
     IPinIP v4/v4       ip4-lookup +5.6  bond-tx +2.9  (*)
     NVGRE  v4/v4       ip4-lookup +17.4 bond-tx +1.6  (*)
         (*) bond-tx delta is partially attributable to ECMP no
             longer collapsing to a single bond, i.e. the cost
             measured on a hotter cache footprint -- a benefit of
             the feature, not a cost of it.

   l34-inner alone                        D - B
     baseline v4 UDP    ip4-lookup -0.3  bond-tx +3.0  total +2.7
     IPinIP v4/v4       ip4-lookup +2.4  bond-tx +8.7  total +11.1
     NVGRE  v4/v4       ip4-lookup -0.9  bond-tx +13.0 total +12.1

   both features on                       E - A
     baseline v4 UDP    ip4-lookup +4.1  bond-tx +4.8  total  +8.9
     IPinIP v4/v4       ip4-lookup +5.1  bond-tx +12.9 total +18.0
     NVGRE  v4/v4       ip4-lookup +15.2 bond-tx +20.4 total +35.6

 Correctness (this is what the patch is actually for): packets per
 BondEthernet (ECMP) and packets per loopback member (LAG), rep 1:

   baseline v4 UDP (outer 5-tuple varies, already spreads)
     A..E   ECMP 50/50,   LAG 8 loops, spread <=2.3%

   IPinIP v4/v4 (inner varies, outer fixed)
     A unpatched/l34         ECMP 100/0   LAG 1 loop  (worst case)
     B patched/l34/off       ECMP 100/0   LAG 1 loop
     C patched/l34/on        ECMP 50/50   LAG 1 loop per side (l34 sees fixed outer L4)
     D patched/l34-inner/off ECMP 100/0   LAG 4 loops (l34-inner on the surviving bond)
     E patched/l34-inner/on  ECMP 50/50   LAG 8 loops total <=2.3% spread

   NVGRE v4/v4 (inner varies, outer fixed)
     A unpatched/l34         ECMP 100/0   LAG 1 loop  (worst case)
     B patched/l34/off       ECMP 100/0   LAG 1 loop
     C patched/l34/on        ECMP 50/50   LAG 1 loop per side
     D patched/l34-inner/off ECMP 100/0   LAG 4 loops
     E patched/l34-inner/on  ECMP 50/50   LAG 8 loops total <=2.3% spread

 Only E spreads both layers.  The cost is paid only on tunneled
 traffic and only when the inner is reachable; pure-IPv4 (baseline)
 overhead is under +10 cyc/pkt end-to-end.

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
