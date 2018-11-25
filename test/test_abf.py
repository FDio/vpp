#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from vpp_udp_encap import *
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


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

    def encode_paths(self):
        br_paths = []
        for p in self.paths:
            lstack = []
            for l in p.nh_labels:
                if type(l) == VppMplsLabel:
                    lstack.append(l.encode())
                else:
                    lstack.append({'label': l, 'ttl': 255})
            n_labels = len(lstack)
            while (len(lstack) < 16):
                lstack.append({})
            br_paths.append({'next_hop': p.nh_addr,
                             'weight': 1,
                             'afi': p.proto,
                             'sw_if_index': 0xffffffff,
                             'preference': 0,
                             'table_id': p.nh_table_id,
                             'next_hop_id': p.next_hop_id,
                             'is_udp_encap': p.is_udp_encap,
                             'n_labels': n_labels,
                             'label_stack': lstack})
        return br_paths

    def add_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            1,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.encode_paths()})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            0,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.encode_paths()})

    def query_vpp_config(self):
        return find_abf_policy(self._test, self.policy_id)

    def __str__(self):
        return self.object_id()

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

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("abf-attach-%d-%d" % (self.policy_id, self.sw_if_index))


class TestAbf(VppTestCase):
    """ ABF Test Case """

    def setUp(self):
        super(TestAbf, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
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
        # are correclty constructed and used. And a few path types
        # to test the API path decoding.
        #

        #
        # Rule 1
        #
        rule_1 = ({'is_permit': 1,
                   'is_ipv6': 0,
                   'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1234,
                   'src_ip_prefix_len': 32,
                   'src_ip_addr': inet_pton(AF_INET, "1.1.1.1"),
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_prefix_len': 32,
                   'dst_ip_addr': inet_pton(AF_INET, "1.1.1.2")})
        acl_1 = self.vapi.acl_add_replace(acl_index=4294967295, r=[rule_1])

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
               Raw('\xa5' * 100))
        self.send_and_expect(self.pg0, p_1*65, self.pg1)

        #
        # Attach a 'better' priority policy to the same interface
        #
        abf_2 = VppAbfPolicy(self, 11, acl_1,
                             [VppRoutePath(self.pg2.remote_ip4,
                                           self.pg2.sw_if_index)])
        abf_2.add_vpp_config()
        attach_2 = VppAbfAttach(self, 11, self.pg0.sw_if_index, 40)
        attach_2.add_vpp_config()

        self.send_and_expect(self.pg0, p_1*65, self.pg2)

        #
        # Attach a policy with priority in the middle
        #
        abf_3 = VppAbfPolicy(self, 12, acl_1,
                             [VppRoutePath(self.pg3.remote_ip4,
                                           self.pg3.sw_if_index)])
        abf_3.add_vpp_config()
        attach_3 = VppAbfAttach(self, 12, self.pg0.sw_if_index, 45)
        attach_3.add_vpp_config()

        self.send_and_expect(self.pg0, p_1*65, self.pg2)

        #
        # remove the best priority
        #
        attach_2.remove_vpp_config()
        self.send_and_expect(self.pg0, p_1*65, self.pg3)

        #
        # Attach one of the same policies to Pg1
        #
        attach_4 = VppAbfAttach(self, 12, self.pg1.sw_if_index, 45)
        attach_4.add_vpp_config()

        p_2 = (Ether(src=self.pg1.remote_mac,
                     dst=self.pg1.local_mac) /
               IP(src="1.1.1.1", dst="1.1.1.2") /
               UDP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))
        self.send_and_expect(self.pg1, p_2 * 65, self.pg3)

        #
        # detach the policy from PG1, now expect traffic to be dropped
        #
        attach_4.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg1, p_2 * 65, "Detached")

    def test_abf6(self):
        """ IPv6 ACL Based Forwarding
        """

        #
        # Simple test for matching IPv6 packets
        #

        #
        # Rule 1
        #
        rule_1 = ({'is_permit': 1,
                   'is_ipv6': 1,
                   'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1234,
                   'src_ip_prefix_len': 128,
                   'src_ip_addr': inet_pton(AF_INET6, "2001::2"),
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_prefix_len': 128,
                   'dst_ip_addr': inet_pton(AF_INET6, "2001::1")})
        acl_1 = self.vapi.acl_add_replace(acl_index=4294967295,
                                          r=[rule_1])

        #
        # ABF policy for ACL 1 - path via interface 1
        #
        abf_1 = VppAbfPolicy(self, 10, acl_1,
                             [VppRoutePath("3001::1",
                                           0xffffffff,
                                           proto=DPO_PROTO.IP6)])
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
             Raw('\xa5' * 100))

        #
        # packets are dropped because there is no route to the policy's
        # next hop
        #
        self.send_and_assert_no_replies(self.pg1, p * 65, "no route")

        #
        # add a route resolving the next-hop
        #
        route = VppIpRoute(self, "3001::1", 32,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        #
        # now expect packets forwarded.
        #
        self.send_and_expect(self.pg0, p * 65, self.pg1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
