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

Rules are classified by VPP's ACL plugin: the filter loads them into one ACL
in RFC 8955 order and matches packets against the ACL plugin's TupleMerge hash
tables for its lookup context, as ABF does. What the ACL does not carry --
packet length, DSCP, fragment flags, and the FlowSpec rule that ports never
match a later fragment -- is checked on each candidate the tables offer. The filter runs on both
the routed and the bridged path from a single datapath, and matched packets
can be mirrored to Linux over the kernel psample channel before the action is
applied, so a rule can show what it dropped.

Maturity level
______________

Production. The drop path filters 430 Mpps with 65,000 rules on a 62-worker
system in the project's hardware lab.

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

Classification: the ACL plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each rule becomes one or more ACL entries: one per address family it applies
to, one per protocol when it names ports without a protocol (TCP and UDP), and
two when it matches either port (source side and destination side). All
entries go into one ACL, in precedence order, through the ACL plugin's own
``acl_add_replace`` message handler, called in-process, so the ACL's first
match is the rule with
the highest precedence. Precedence is rule order first, then RFC 8955 §5.1
component-wise comparison, then the rule index as a final tiebreak.

``show fastacl classifier`` reports the number of ACL entries, the ACL index and
the lookup context.

Candidate check
~~~~~~~~~~~~~~~

The node fills the ACL 5-tuple from its own packet parser and walks the ACL
plugin's TupleMerge tables for its lookup context with its own inline lookup,
read-only. Each candidate the tables offer is checked; a rejected candidate is
skipped and the lookup continues with the next one. The check re-runs the
full rule only when
the rule constrains packet length, DSCP or fragment flags, or when the ACL
cannot judge the packet exactly: a later fragment, which carries no ports, or
a truncated L4 header. Every other candidate is accepted as the ACL found it.

Later fragments follow RFC 8955. A later fragment is looked up through the
hash with its ports zeroed, and every candidate is re-checked, so port, ICMP
and TCP-flag rules are rejected and only rules without L4 constraints match
it. The lookup does not update the ACL plugin's shared per-entry hit counter.

Rule updates
~~~~~~~~~~~~

Adding or deleting a rule rebuilds the ACL. A batch add, and the sweep at the
end of a replace, rebuild it once. Rebuilds run on the main thread under the
worker barrier.

VPP requirements
~~~~~~~~~~~~~~~~

Stock FD.io VPP with the ACL plugin loaded. The filter uses the ACL plugin's
exported methods, its installed lookup headers, and its ``acl_add_replace``
message handler; it needs no ACL plugin changes.

Datapath placement
~~~~~~~~~~~~~~~~~~

The filter is one node per path, attached as a feature:

-  ``fastacl-filter`` on the ``ip4-unicast`` and ``ip6-unicast`` arcs
-  ``fastacl-filter-l2`` on the ``l2-input-ip4`` and ``l2-input-ip6`` arcs

Both share the same classifier and rule set; only packet parsing differs. The
node prefetches the next packet's headers while classifying the current one.
The node is built per CPU variant through ``MULTIARCH_SOURCES``, so VPP selects
the best instruction set at runtime.

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

The plugin has no startup stanza of its own, and needs nothing in the
``acl-plugin`` one. What matters is VPP's own configuration. The hardware lab's 32-worker ConnectX-7
box at 100 GbE runs:

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

``main-heap-size`` bounds the rule-set size. It holds the rule pool and
everything the ACL plugin builds from the rules: its rule copies, the
per-context entries and its hash tables, which bihash allocates from the main
heap. A million rules that each expand to one ACL entry take about 0.9 GB of it
(measured: 869 MB above an idle VPP), and a rule that expands to several
entries costs proportionally more, so 12G leaves room for several million. The
``acl-plugin`` stanza's ``hash lookup heap size`` and ``hash lookup hash
memory`` have no effect on current VPP; ``hash lookup hash buckets`` (default
65536) is the only setting there worth raising for very large rule sets. 2 MB
heap pages are worth setting; 4 KB pages cost measurably more TLB pressure.

``rss { ipv4 ipv6 }`` is not optional for dual-stack work. Without ``ipv6`` in
the list the NIC hashes IPv6 to a single queue and the whole family lands on
one worker.

CLI configuration
_________________

The mutating commands are a debug convenience. They are not synchronized
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
    vpp# show fastacl classifier
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
