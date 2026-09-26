.. _fastacl_plugin_doc:

.. toctree::

FastACL Packet Filter
=====================

Overview
________

This plugin filters packets against an RFC 8955/8956 FlowSpec rule set at
line rate. It is built for volumetric DDoS mitigation, where the rule count is
large, the rules change while traffic is running, and the interesting decision
is almost always "drop this".

Rules are classified by Tuple Space Search, so per-packet cost scales with the
number of distinct *mask shapes* in the rule set rather than with the number of
rules: a million rules that share two shapes cost the same two hash probes as
two rules would. The filter runs on both the routed and the bridged path from a
single datapath, and matched packets can be mirrored to Linux over the kernel
psample channel before the action is applied, so a rule can show what it
dropped.

Maturity level
______________

Production. The drop path sustains 100 GbE line rate with a million rules loaded in
the project's hardware lab.

Features
________

-  All 12 RFC 8955/8956 match types, IPv4 and IPv6: destination and source
   prefix, IP protocol, destination/source/either port ranges, ICMP type and
   code, TCP flags with a bitmask, packet length, DSCP, fragment flags
-  ``drop`` and ``permit`` actions, with the action carried in the classifier
   result so discarding a packet never dereferences the rule pool
-  Exact (not statistical) 1-in-N per-rule sampling to the kernel psample
   channel, taken before the action
-  Rule ordering by RFC 8955 §5.1 component-wise precedence, with single and
   batch installation
-  Dual-stack scoping that follows the rule: a rule applies to the family its
   addresses name, and to both families when it names no address
-  Per-rule and aggregate counters in the VPP stats segment, including pps,
   L3 bps and L1 bps
-  Routed and bridged operation from one datapath
-  Full CLI and binary API

Architecture
____________

Classification: Tuple Space Search
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A rule's *mask shape* is which fields it constrains plus the prefix lengths it
uses — not the values. Rules sharing a shape go into one VPP bihash keyed on
the masked packet fields, and that bihash is a *tuple*. Lookup masks the packet
once per tuple and probes it, so the cost is O(distinct shapes), not O(rules).

``show fastacl tuples`` reports the live shapes, the key width each one chose
and how many rules it holds. Shape count is the number to watch when tuning a
rule set: adding rules to an existing shape is close to free, while each new
shape adds a probe to every packet.

It also reports ``chains``, ``chained`` and ``deepest``. Rules whose key fully
determines the match resolve in the probe alone; rules that produce the same
key -- same prefix and protocol, differing only in port ranges, TCP flags,
pkt-len, DSCP or fragment bits -- form a chain that a matching packet walks,
re-checking those fields per member. ``deepest`` is the worst-case walk length
for that shape, and the number to watch once shape count is under control.

Key narrowing
~~~~~~~~~~~~~

A tuple whose mask permits it drops from the wide 24-byte (IPv4) or 40-byte
(IPv6) key to a compact 8-byte or 16-byte one. The compact forms fit
``bihash_8_8`` and ``bihash_16_8``, whose bucket and key-value pair share a
cache line, so a probe costs one dependent memory access instead of two. On a
working-set-bound lookup that is the difference that matters, rather than the
byte count itself.

Verdict in the hash value
~~~~~~~~~~~~~~~~~~~~~~~~~

The 8-byte bihash value carries the rule index, the action type, and a bit
recording whether the key covered the rule completely. When it did, no field
outside the key needs re-checking, so the verdict is the probe's own. The
datapath still reads the matched rule out of the pool, because the action
parameters and the trace live there. Rules that constrain fields outside the key — port ranges, TCP flags,
packet length, DSCP, fragment flags — are re-verified against the candidate
after the probe.

Chains and precedence
~~~~~~~~~~~~~~~~~~~~~

Several rules can share one masked key; those form a chain held in precedence
order, so the walk stops at the first rule that both outranks the current best
and matches. Precedence is rule order first, then RFC 8955 §5.1 component-wise
comparison, then the rule index as a final tiebreak. The result does not depend
on the order tuples are probed in, which is what allows tuples to be added and
removed while traffic runs.

Datapath placement
~~~~~~~~~~~~~~~~~~

The filter is one node per path, attached as a feature:

-  ``fastacl-filter`` on the ``ip4-unicast`` and ``ip6-unicast`` arcs
-  ``fastacl-filter-l2`` on the ``l2-input-ip4`` and ``l2-input-ip6`` arcs

Both share the same classifier and rule set; only packet parsing differs. The
node prefetches the next packet's headers and its TSS bucket while classifying
the current one. The node is built per CPU variant through
``MULTIARCH_SOURCES``, so VPP selects the best instruction set at runtime.

Enabling the filter on an interface arms all four arcs at once; there is no
mode to select in the plugin. Which node a packet reaches is decided by how
the interface is configured in VPP itself, and that configuration differs
between the two modes.

Bridged -- the interface is in a bridge domain or a cross-connect, so packets
traverse ``l2-input-ip4``/``l2-input-ip6`` and ``fastacl-filter-l2`` runs:

::

    vpp# set interface l2 xconnect TenGigabitEthernet0/0/0 TenGigabitEthernet0/0/1
    vpp# set interface l2 xconnect TenGigabitEthernet0/0/1 TenGigabitEthernet0/0/0
    vpp# set interface state TenGigabitEthernet0/0/0 up
    vpp# set interface state TenGigabitEthernet0/0/1 up
    vpp# set interface fastacl TenGigabitEthernet0/0/0
    vpp# set interface fastacl TenGigabitEthernet0/0/1

Routed -- the interface carries an IP address, so packets traverse
``ip4-unicast``/``ip6-unicast`` and ``fastacl-filter`` runs:

::

    vpp# set interface ip address TenGigabitEthernet0/0/0 10.0.0.1/24
    vpp# set interface state TenGigabitEthernet0/0/0 up
    vpp# set interface fastacl TenGigabitEthernet0/0/0

The ``set interface fastacl`` line is identical in both; the arc that stays
dormant costs nothing. An interface moved between a bridge domain and a routed
configuration starts using the other node with no change to the filter.

Configuration
_____________

::

    fastacl {
      tss-bihash-buckets 65536
    }

``tss-bihash-buckets`` is allocated per rule shape, so raise it for very large
rule sets; a million-rule table runs ``1048576``. Values below ``1024`` are
clamped up.

The settings outside the ``fastacl`` stanza matter as much as the ones inside
it. A 32-worker ConnectX-7 box carrying a million rules at 100 GbE runs:

::

    memory {
      main-heap-size       12G
      main-heap-page-size  2M
    }
    statseg {
      size 12G
    }
    buffers {
      buffers-per-numa 2097152
    }
    cpu {
      main-core        0
      corelist-workers 1-31
    }
    dpdk {
      no-multi-seg
      no-tx-checksum-offload
      dev 0000:81:00.0 {
        num-rx-queues 32  num-tx-queues 32
        num-rx-desc   4096  num-tx-desc 4096
        rss { ipv4 ipv6 l3-src-only }
      }
    }

``num-rx-desc`` matters more than it looks. Large RX buffers evict the rule
table from the last-level cache, which turns every per-rule counter write into
a cache miss; 4096 measures an order of magnitude less ingress loss than 8192
at a million rules, and 2048 measures the same as 4096 with less burst
headroom. This is a recommendation, not a plugin default -- nothing in the
plugin sets it.

``statseg`` holds the per-rule counters, so ``size`` must cover
``rules x (workers + 1) x 16`` bytes.

``main-heap-size`` has to cover the classifier as well as VPP's own needs. The
bihash templates set ``BIHASH_USE_HEAP``, so every tuple's table allocates from
the main heap rather than reserving its own region. 2 MB heap pages are worth
setting; 4 KB pages cost measurably more TLB pressure on a table this size.

``rss { ipv4 ipv6 }`` is not optional for dual-stack work. Without ``ipv6`` in
the list the NIC hashes IPv6 to a single queue and the whole family lands on
one worker.

CLI configuration
_________________

The mutating commands are a debug convenience. They are not synchronised
against the worker threads, so using them while traffic is running can corrupt
the classifier; each prints a warning when workers are configured. The binary
API is the control plane -- VPP dispatches its handlers under the worker
barrier -- and is what automation should use. The ``show`` commands are
read-only and safe at any time.

Arm the filter on an interface, then add rules:

::

    vpp# set interface fastacl TenGigabitEthernet0/0/0 enable

    vpp# fastacl rule add order 10 dst 203.0.113.0/24 proto 17 dst-port 53 action drop
    vpp# fastacl rule add order 20 dst6 2001:db8::/32 proto 6 tcp-flags value 0x02 mask 0x02 action drop

    vpp# fastacl rule add order 30 dst 203.0.113.0/24 action permit sample 1000

    vpp# fastacl rule del 0
    vpp# fastacl rule del all

``permit`` matches and forwards unchanged, which is what makes a sample-only
rule possible. An action is mandatory: action type 0 is ``drop``, so an omitted
action would silently discard the traffic a tap rule was added to observe.

A rule that names no address applies to both families, so the following filters
IPv4 and IPv6 rather than exempting IPv6:

::

    vpp# fastacl rule add order 40 proto 17 dst-port 53 action drop

Sampling
________

Mirroring matched packets requires the kernel ``psample`` module. Sampling is
per rule, and the ratio is exact rather than probabilistic:

::

    vpp# fastacl psample enable
    vpp# show fastacl sampling

Operational data
________________

::

    vpp# show fastacl rules
    vpp# show fastacl aggregate-counters
    vpp# show fastacl tuples
    vpp# show fastacl interface
    vpp# clear fastacl counters

Per-rule counters are exported through the stats segment, so an external
collector can read them without the binary API or CLI scraping:

-  ``/fastacl/rule`` — packets and bytes per rule, a counter-pair vector shaped
   ``[thread][rule_index]``
-  ``/fastacl/rule/gen`` — the allocation generation of each rule index. Rule
   indices come from a pool that recycles freed slots, so this is how a
   collector detects that an index changed hands: an odd value means the slot
   holds a live rule, and any change means a cached ``rule_index`` to rule
   mapping must be re-resolved

Per-rule counting is exact and enabled by default. At a very large rule count
it is a scattered write per packet, so it can be switched off:

::

    vpp# fastacl per-rule-stats disable
    vpp# fastacl per-rule-stats enable

Aggregate counters are always exact regardless of this setting.
