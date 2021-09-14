#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsLabel, \
    VppIpTable, FibPathProto
from vpp_acl import AclRule, VppAcl

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from ipaddress import IPv4Network, IPv6Network

from vpp_object import VppObject

NUM_PKTS = 67


def find_abf_policy(test, id):
    policies = test.vapi.abf_policy_dump()
    for p in policies:
        if id == p.policy.policy_id:
            return True
    return False


def find_abf_itf_attach(test, id, sw_if_index):
    attachs = test.vapi.abf_itf_attach_dump()
    for a in attachs:
        if id == a.attach.policy_id and \
           sw_if_index == a.attach.sw_if_index:
            return True
    return False


class VppAbfPolicy(VppObject):

    def __init__(self,
                 test,
                 policy_id,
                 acl,
                 paths):
        self._test = test
        self.policy_id = policy_id
        self.acl = acl
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            1,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            0,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})

    def query_vpp_config(self):
        return find_abf_policy(self._test, self.policy_id)

    def object_id(self):
        return ("abf-policy-%d" % self.policy_id)


class VppAbfAttach(VppObject):

    def __init__(self,
                 test,
                 policy_id,
                 sw_if_index,
                 priority,
                 is_ipv6=0):
        self._test = test
        self.policy_id = policy_id
        self.sw_if_index = sw_if_index
        self.priority = priority
        self.is_ipv6 = is_ipv6

    def add_vpp_config(self):
        self._test.vapi.abf_itf_attach_add_del(
            1,
            {'policy_id': self.policy_id,
             'sw_if_index': self.sw_if_index,
             'priority': self.priority,
             'is_ipv6': self.is_ipv6})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.abf_itf_attach_add_del(
            0,
            {'policy_id': self.policy_id,
             'sw_if_index': self.sw_if_index,
             'priority': self.priority,
             'is_ipv6': self.is_ipv6})

    def query_vpp_config(self):
        return find_abf_itf_attach(self._test,
                                   self.policy_id,
                                   self.sw_if_index)

    def object_id(self):
        return ("abf-attach-%d-%d" % (self.policy_id, self.sw_if_index))


class TestAbf(VppTestCase):
    """ ABF Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestAbf, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAbf, cls).tearDownClass()

    def setUp(self):
        super(TestAbf, self).setUp()

        self.create_pg_interfaces(range(5))

        for i in self.pg_interfaces[:4]:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestAbf, self).tearDown()

    def test_abf4(self):
        """ IPv4 ACL Based Forwarding
        """

        #
        # We are not testing the various matching capabilities
        # of ACLs, that's done elsewhere. Here ware are testing
        # the application of ACLs to a forwarding path to achieve
        # ABF
        # So we construct just a few ACLs to ensure the ABF policies
        # are correctly constructed and used. And a few path types
        # to test the API path decoding.
        #

        #
        # Rule 1
        #
        rule_1 = AclRule(is_permit=1, proto=17, ports=1234,
                         src_prefix=IPv4Network("1.1.1.1/32"),
                         dst_prefix=IPv4Network("1.1.1.2/32"))
        acl_1 = VppAcl(self, rules=[rule_1])
        acl_1.add_vpp_config()

        #
        # ABF policy for ACL 1 - path via interface 1
        #
        abf_1 = VppAbfPolicy(self, 10, acl_1,
                             [VppRoutePath(self.pg1.remote_ip4,
                                           self.pg1.sw_if_index)])
        abf_1.add_vpp_config()

        #
        # Attach the policy to input interface Pg0
        #
        attach_1 = VppAbfAttach(self, 10, self.pg0.sw_if_index, 50)
        attach_1.add_vpp_config()

        #
        # fire in packet matching the ACL src,dst. If it's forwarded
        # then the ABF was successful, since default routing will drop it
        #
        p_1 = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src="1.1.1.1", dst="1.1.1.2") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))
        self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg1)

        #
        # Attach a 'better' priority policy to the same interface
        #
        abf_2 = VppAbfPolicy(self, 11, acl_1,
                             [VppRoutePath(self.pg2.remote_ip4,
                                           self.pg2.sw_if_index)])
        abf_2.add_vpp_config()
        attach_2 = VppAbfAttach(self, 11, self.pg0.sw_if_index, 40)
        attach_2.add_vpp_config()

        self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg2)

        #
        # Attach a policy with priority in the middle
        #
        abf_3 = VppAbfPolicy(self, 12, acl_1,
                             [VppRoutePath(self.pg3.remote_ip4,
                                           self.pg3.sw_if_index)])
        abf_3.add_vpp_config()
        attach_3 = VppAbfAttach(self, 12, self.pg0.sw_if_index, 45)
        attach_3.add_vpp_config()

        self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg2)

        #
        # remove the best priority
        #
        attach_2.remove_vpp_config()
        self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg3)

        #
        # Attach one of the same policies to Pg1
        #
        attach_4 = VppAbfAttach(self, 12, self.pg1.sw_if_index, 45)
        attach_4.add_vpp_config()

        p_2 = (Ether(src=self.pg1.remote_mac,
                     dst=self.pg1.local_mac) /
               IP(src="1.1.1.1", dst="1.1.1.2") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))
        self.send_and_expect(self.pg1, p_2 * NUM_PKTS, self.pg3)

        #
        # detach the policy from PG1, now expect traffic to be dropped
        #
        attach_4.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg1, p_2 * NUM_PKTS, "Detached")

        #
        # Swap to route via a next-hop in the non-default table
        #
        table_20 = VppIpTable(self, 20)
        table_20.add_vpp_config()

        self.pg4.set_table_ip4(table_20.table_id)
        self.pg4.admin_up()
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

        abf_13 = VppAbfPolicy(self, 13, acl_1,
                              [VppRoutePath(self.pg4.remote_ip4,
                                            0xffffffff,
                                            nh_table_id=table_20.table_id)])
        abf_13.add_vpp_config()
        attach_5 = VppAbfAttach(self, 13, self.pg0.sw_if_index, 30)
        attach_5.add_vpp_config()

        self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg4)

        self.pg4.unconfig_ip4()
        self.pg4.set_table_ip4(0)

    def test_abf6(self):
        """ IPv6 ACL Based Forwarding
        """

        #
        # Simple test for matching IPv6 packets
        #

        #
        # Rule 1
        #
        rule_1 = AclRule(is_permit=1, proto=17, ports=1234,
                         src_prefix=IPv6Network("2001::2/128"),
                         dst_prefix=IPv6Network("2001::1/128"))
        acl_1 = VppAcl(self, rules=[rule_1])
        acl_1.add_vpp_config()

        #
        # ABF policy for ACL 1 - path via interface 1
        #
        abf_1 = VppAbfPolicy(self, 10, acl_1,
                             [VppRoutePath("3001::1",
                                           0xffffffff)])
        abf_1.add_vpp_config()

        attach_1 = VppAbfAttach(self, 10, self.pg0.sw_if_index,
                                45, is_ipv6=True)
        attach_1.add_vpp_config()

        #
        # a packet matching the rule
        #
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src="2001::2", dst="2001::1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        #
        # packets are dropped because there is no route to the policy's
        # next hop
        #
        self.send_and_assert_no_replies(self.pg1, p * NUM_PKTS, "no route")

        #
        # add a route resolving the next-hop
        #
        route = VppIpRoute(self, "3001::1", 32,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index)])
        route.add_vpp_config()

        #
        # now expect packets forwarded.
        #
        self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
