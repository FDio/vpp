# Copyright (c) 2017 Comcast Cable Communications Management, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decodes the serialized VPP node graph structure."""

from copy import copy

from vpp_papi_unserialize import VPPUnserialize


"""Node state strings. See state_string_enum_t in
vlibapi/node_unserialize.c"""
_node_state = [
    "done",
    "disabled",
    "time wait",
    "event wait",
    "any wait",
    "polling",
    "interrupt wait",
    "internal"
]


class VPPNodeStats(VPPUnserialize):
    """Statistics gathered at VPP nodes"""
    clocks = 0
    calls = 0
    vectors = 0
    suspends = 0

    struct = [
        ['clocks', '>u64'],
        ['calls', '>u64'],
        ['vectors', '>u64'],
        ['suspends', '>u64'],
    ]

    def __repr__(self):
        r = [
            'clocks: %d' % self.clocks,
            'calls: %d' % self.calls,
            'vectors: %d' % self.vectors,
            'suspends: %d' % self.suspends,
        ]
        return "VPPNodeStats(%s)" % ", ".join(r)


class VPPNode(VPPUnserialize):
    """A VPP graph node"""
    name = None
    state_code = 0

    type = None

    _nnexts = 0
    _next_nodes = None  # idx ref list
    next_nodes = None   # obj ref list

    _nstats = 0
    stats = None

    struct = [
        ['name', 'cstring'],
        ['state_code', 'suint'],
        ['type', 'suint'],
        ['_nnexts', 'suint'],
        ['_next_nodes', 'list', '_nnexts', 'suint'],
        ['_nstats', 'suint'],
        ['stats', 'list', '_nstats', VPPNodeStats],
    ]

    def __init__(self, buf=None):
        self._next_nodes = []
        self.next_nodes = []
        super(VPPNode, self).__init__(buf)

    def decode(self, buf):
        super(VPPNode, self).decode(buf)

        # If we have stats, replace the list with a single entry
        if self._nstats > 0:
            self.stats = self.stats[0]
        else:
            self.stats = None

    @property
    def state_string(self):
        if self.state_code < len(_node_state):
            return _node_state[self.state_code]
        return "unknown"

    def __repr__(self):
        nexts = []
        for i in range(self._nnexts):
            if i < len(self.next_nodes) and self.next_nodes[i]:
                nexts.append(self.next_nodes[i].name)
            else:
                nexts.append("%d" % i)

        r = [
            'name: %s' % repr(self.name),
            'state_code: %d' % self.state_code,
            'state_string: %s' % repr(self.state_string),
            'type: %d' % self.type,
            'next_nodes: %s' % (
                "["+", ".join(nexts)+"]" if len(nexts) else "none"),
            'stats: %s' % (repr(self.stats) if self.stats else 'none'),
        ]
        return "VPPNode(%s)" % ", ".join(r)


class VPPNodes(VPPUnserialize):
    """A list of VPP graph nodes"""
    _nnodes = 0
    nodes = None  # list

    struct = [
        ['_nnodes', 'suint'],
        ['nodes', 'list', '_nnodes', VPPNode],
    ]

    def __init__(self, buf=None):
        self.nodes = []
        super(VPPNodes, self).__init__(buf)

    def decode(self, buf):
        super(VPPNodes, self).decode(buf)
        self.wire_node_refs()

    def wire_node_refs(self):
        # Fill in the object references to next-nodes for each of our nodes
        m = len(self.nodes)
        for idx in range(m):
            node = self.nodes[idx]

            def f(n):
                return self.nodes[n] if n < m else None

            node.next_nodes = [f(n) for n in node._next_nodes]

    def __repr__(self):
        return "VPPNodes(%d)%s" % (self._nnodes, self.nodes)


class VPPNodeThreads(VPPUnserialize):
    """A set of VPP graph nodes per thread"""
    _nthreads = 0
    threads = None  # list

    struct = [
        ['_nthreads', 'suint'],
        ['threads', 'list', '_nthreads', VPPNodes]
    ]

    def __init__(self, buf=None):
        self.threads = []
        super(VPPNodeThreads, self).__init__(buf)

    def coalesce_threads(self):
        """Helper method to merge the nodes of multiple threads into
        a single graph. This is currently likely somewhat fragile.
        While it does sum the statistics, it will mean attributes such
        as 'state_code' lose their meaning.

        :rtype: VPPNodes
        :return: The coalesced graph.
        """

        nodes = {}
        vn = VPPNodes()
        for thread in self.threads:
            for node in thread.nodes:
                if node.name not in nodes:
                    other = nodes[node.name] = VPPNode()
                    vn.nodes.append(other)
                    # make a copy of static items
                    for a in ('name', 'type',
                              '_nnexts', '_next_nodes',
                              '_nstats'):
                        setattr(other, a, copy(getattr(node, a)))
                    other.state_code = -1  # unknown
                    other.stats = VPPNodeStats()
                else:
                    other = nodes[node.name]

                other.stats.clocks += node.stats.clocks
                other.stats.calls += node.stats.calls
                other.stats.vectors += node.stats.vectors
                other.stats.suspends += node.stats.suspends

        # Wire up the node object references
        vn.wire_node_refs()

        return vn

    def __repr__(self):
        return "VPPNodeThreads(%s)%s" % (self._nthreads, self.threads)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
