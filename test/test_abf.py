#!/usr/bin/env python

from framework import VppTestCase, VppTestRunner
from vpp_udp_encap import *
from vpp_abf import *
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, DpoProto

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS


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

    def send_and_expect(self, input, output, pkts):
        self.vapi.cli("clear trace")
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = output.get_capture(len(pkts))
        return rx

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for i in self.pg_interfaces:
            i.get_capture(0)
            i.assert_nothing_captured(remark=remark)

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
        self.send_and_expect(self.pg0, self.pg1, p_1*65)

        #
        # Attach a 'better' priority policy to the same interface
        #
        abf_2 = VppAbfPolicy(self, 11, acl_1,
                             [VppRoutePath(self.pg2.remote_ip4,
                                           self.pg2.sw_if_index)])
        abf_2.add_vpp_config()
        attach_2 = VppAbfAttach(self, 11, self.pg0.sw_if_index, 40)
        attach_2.add_vpp_config()

        self.send_and_expect(self.pg0, self.pg2, p_1*65)

        #
        # Attach a policy with priority in the middle
        #
        abf_3 = VppAbfPolicy(self, 12, acl_1,
                             [VppRoutePath(self.pg3.remote_ip4,
                                           self.pg3.sw_if_index)])
        abf_3.add_vpp_config()
        attach_3 = VppAbfAttach(self, 12, self.pg0.sw_if_index, 45)
        attach_3.add_vpp_config()

        self.send_and_expect(self.pg0, self.pg2, p_1*65)

        #
        # remove the best priority
        #
        attach_2.remove_vpp_config()
        self.send_and_expect(self.pg0, self.pg3, p_1*65)

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
        self.send_and_expect(self.pg1, self.pg3, p_2 * 65)

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
                                           proto=DpoProto.DPO_PROTO_IP6)])
        abf_1.add_vpp_config()

        attach_1 = VppAbfAttach(self, 10, self.pg0.sw_if_index, 45, is_ipv6=1)
        attach_1.add_vpp_config()

        #
        # a apcket matching the rule
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
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        #
        # now expect packets forwarded.
        #
        self.send_and_expect(self.pg0, self.pg1, p * 65)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
