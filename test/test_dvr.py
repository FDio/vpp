#!/usr/bin/env python
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppDot1QSubint
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_l2 import L2_VTR_OP, L2_PORT_TYPE

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
from socket import AF_INET, inet_pton


class TestDVR(VppTestCase):
    """ Distributed Virtual Router """

    def setUp(self):
        super(TestDVR, self).setUp()

        self.create_pg_interfaces(range(4))
        self.create_loopback_interfaces(1)

        for i in self.pg_interfaces:
            i.admin_up()

        self.loop0.config_ip4()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        self.loop0.unconfig_ip4()

        super(TestDVR, self).tearDown()

    def assert_same_mac_addr(self, tx, rx):
        t_eth = tx[Ether]
        for p in rx:
            r_eth = p[Ether]
            self.assertEqual(t_eth.src, r_eth.src)
            self.assertEqual(t_eth.dst, r_eth.dst)

    def assert_has_vlan_tag(self, tag, rx):
        for p in rx:
            r_1q = p[Dot1Q]
            self.assertEqual(tag, r_1q.vlan)

    def assert_has_no_tag(self, rx):
        for p in rx:
            self.assertFalse(p.haslayer(Dot1Q))

    def test_dvr(self):
        """ Distributed Virtual Router """

        #
        # A packet destined to an IP address that is L2 bridged via
        # a non-tag interface
        #
        ip_non_tag_bridged = "10.10.10.10"
        ip_tag_bridged = "10.10.10.11"
        any_src_addr = "1.1.1.1"

        pkt_no_tag = (Ether(src=self.pg0.remote_mac,
                            dst=self.loop0.local_mac) /
                      IP(src=any_src_addr,
                         dst=ip_non_tag_bridged) /
                      UDP(sport=1234, dport=1234) /
                      Raw('\xa5' * 100))
        pkt_tag = (Ether(src=self.pg0.remote_mac,
                         dst=self.loop0.local_mac) /
                   IP(src=any_src_addr,
                      dst=ip_tag_bridged) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))

        #
        # Two sub-interfaces so we can test VLAN tag push/pop
        #
        sub_if_on_pg2 = VppDot1QSubint(self, self.pg2, 92)
        sub_if_on_pg3 = VppDot1QSubint(self, self.pg3, 93)
        sub_if_on_pg2.admin_up()
        sub_if_on_pg3.admin_up()

        #
        # Put all the interfaces into a new bridge domain
        #
        self.vapi.sw_interface_set_l2_bridge(self.pg0.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg2.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg3.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(self.loop0.sw_if_index, 1,
                                             port_type=L2_PORT_TYPE.BVI)

        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg2.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  92)
        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg3.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  93)

        #
        # Add routes to bridge the traffic via a tagged an nontagged interface
        #
        route_no_tag = VppIpRoute(
            self, ip_non_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          self.pg1.sw_if_index,
                          is_dvr=1)])
        route_no_tag.add_vpp_config()

        #
        # Inject the packet that arrives and leaves on a non-tagged interface
        # Since it's 'bridged' expect that the MAC headed is unchanged.
        #
        rx = self.send_and_expect(self.pg0, pkt_no_tag * 65, self.pg1)
        self.assert_same_mac_addr(pkt_no_tag, rx)
        self.assert_has_no_tag(rx)

        #
        # Add routes to bridge the traffic via a tagged interface
        #
        route_with_tag = VppIpRoute(
            self, ip_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          sub_if_on_pg3.sw_if_index,
                          is_dvr=1)])
        route_with_tag.add_vpp_config()

        #
        # Inject the packet that arrives non-tag and leaves on a tagged
        # interface
        #
        rx = self.send_and_expect(self.pg0, pkt_tag * 65, self.pg3)
        self.assert_same_mac_addr(pkt_tag, rx)
        self.assert_has_vlan_tag(93, rx)

        #
        # Tag to tag
        #
        pkt_tag_to_tag = (Ether(src=self.pg2.remote_mac,
                                dst=self.loop0.local_mac) /
                          Dot1Q(vlan=92) /
                          IP(src=any_src_addr,
                             dst=ip_tag_bridged) /
                          UDP(sport=1234, dport=1234) /
                          Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg2, pkt_tag_to_tag * 65, self.pg3)
        self.assert_same_mac_addr(pkt_tag_to_tag, rx)
        self.assert_has_vlan_tag(93, rx)

        #
        # Tag to non-Tag
        #
        pkt_tag_to_non_tag = (Ether(src=self.pg2.remote_mac,
                                    dst=self.loop0.local_mac) /
                              Dot1Q(vlan=92) /
                              IP(src=any_src_addr,
                                 dst=ip_non_tag_bridged) /
                              UDP(sport=1234, dport=1234) /
                              Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg2, pkt_tag_to_non_tag * 65, self.pg1)
        self.assert_same_mac_addr(pkt_tag_to_tag, rx)
        self.assert_has_no_tag(rx)

        #
        # Add an output L3 ACL that will block the traffic
        #
        rule_1 = ({'is_permit': 0,
                   'is_ipv6': 0,
                   'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1234,
                   'src_ip_prefix_len': 32,
                   'src_ip_addr': inet_pton(AF_INET, any_src_addr),
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_prefix_len': 32,
                   'dst_ip_addr': inet_pton(AF_INET, ip_non_tag_bridged)})
        acl = self.vapi.acl_add_replace(acl_index=4294967295,
                                        r=[rule_1])

        #
        # Apply the ACL on the output interface
        #
        self.vapi.acl_interface_set_acl_list(self.pg1.sw_if_index,
                                             0,
                                             [acl.acl_index])

        #
        # Send packet's that should match the ACL and be dropped
        #
        rx = self.send_and_assert_no_replies(self.pg2, pkt_tag_to_non_tag * 65)

        #
        # cleanup
        #
        self.vapi.acl_interface_set_acl_list(self.pg1.sw_if_index,
                                             0, [])
        self.vapi.acl_del(acl.acl_index)

        self.vapi.sw_interface_set_l2_bridge(self.pg0.sw_if_index, 1,
                                             enable=0)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index, 1,
                                             enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg2.sw_if_index,
                                             1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg3.sw_if_index,
                                             1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(self.loop0.sw_if_index,
                                             1, port_type=L2_PORT_TYPE.BVI,
                                             enable=0)

        #
        # Do a FIB dump to make sure the paths are correctly reported as DVR
        #
        routes = self.vapi.ip_fib_dump()

        for r in routes:
            if (inet_pton(AF_INET, ip_tag_bridged) == r.address):
                self.assertEqual(r.path[0].sw_if_index,
                                 sub_if_on_pg3.sw_if_index)
                self.assertEqual(r.path[0].is_dvr, 1)
            if (inet_pton(AF_INET, ip_non_tag_bridged) == r.address):
                self.assertEqual(r.path[0].sw_if_index,
                                 self.pg1.sw_if_index)
                self.assertEqual(r.path[0].is_dvr, 1)

        #
        # the explicit route delete is require so it happens before
        # the sbu-interface delete. subinterface delete is required
        # because that object type does not use the object registry
        #
        route_no_tag.remove_vpp_config()
        route_with_tag.remove_vpp_config()
        sub_if_on_pg3.remove_vpp_config()
        sub_if_on_pg2.remove_vpp_config()

    def test_l2_emulation(self):
        """ L2 Emulation """

        #
        # non distinct L3 packets, in the tag/non-tag combos
        #
        pkt_no_tag = (Ether(src=self.pg0.remote_mac,
                            dst=self.pg1.remote_mac) /
                      IP(src="2.2.2.2",
                         dst="1.1.1.1") /
                      UDP(sport=1234, dport=1234) /
                      Raw('\xa5' * 100))
        pkt_to_tag = (Ether(src=self.pg0.remote_mac,
                            dst=self.pg2.remote_mac) /
                      IP(src="2.2.2.2",
                         dst="1.1.1.2") /
                      UDP(sport=1234, dport=1234) /
                      Raw('\xa5' * 100))
        pkt_from_tag = (Ether(src=self.pg3.remote_mac,
                              dst=self.pg2.remote_mac) /
                        Dot1Q(vlan=93) /
                        IP(src="2.2.2.2",
                           dst="1.1.1.1") /
                        UDP(sport=1234, dport=1234) /
                        Raw('\xa5' * 100))
        pkt_from_to_tag = (Ether(src=self.pg3.remote_mac,
                                 dst=self.pg2.remote_mac) /
                           Dot1Q(vlan=93) /
                           IP(src="2.2.2.2",
                              dst="1.1.1.2") /
                           UDP(sport=1234, dport=1234) /
                           Raw('\xa5' * 100))
        pkt_bcast = (Ether(src=self.pg0.remote_mac,
                           dst="ff:ff:ff:ff:ff:ff") /
                     IP(src="2.2.2.2",
                        dst="255.255.255.255") /
                     UDP(sport=1234, dport=1234) /
                     Raw('\xa5' * 100))

        #
        # A couple of sub-interfaces for tags
        #
        sub_if_on_pg2 = VppDot1QSubint(self, self.pg2, 92)
        sub_if_on_pg3 = VppDot1QSubint(self, self.pg3, 93)
        sub_if_on_pg2.admin_up()
        sub_if_on_pg3.admin_up()

        #
        # Put all the interfaces into a new bridge domain
        #
        self.vapi.sw_interface_set_l2_bridge(self.pg0.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg2.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg3.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg2.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  92)
        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg3.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  93)

        #
        # Disable UU flooding, learning and ARP terminaation. makes this test
        # easier as unicast packets are dropped if not extracted.
        #
        self.vapi.bridge_flags(1, 0, (1 << 0) | (1 << 3) | (1 << 4))

        #
        # Add a DVR route to steer traffic at L3
        #
        route_1 = VppIpRoute(self, "1.1.1.1", 32,
                             [VppRoutePath("0.0.0.0",
                                           self.pg1.sw_if_index,
                                           is_dvr=1)])
        route_2 = VppIpRoute(self, "1.1.1.2", 32,
                             [VppRoutePath("0.0.0.0",
                                           sub_if_on_pg2.sw_if_index,
                                           is_dvr=1)])
        route_1.add_vpp_config()
        route_2.add_vpp_config()

        #
        # packets are dropped because bridge does not flood unknown unicast
        #
        self.send_and_assert_no_replies(self.pg0, pkt_no_tag)

        #
        # Enable L3 extraction on pgs
        #
        self.vapi.sw_interface_set_l2_emulation(self.pg0.sw_if_index)
        self.vapi.sw_interface_set_l2_emulation(self.pg1.sw_if_index)
        self.vapi.sw_interface_set_l2_emulation(sub_if_on_pg2.sw_if_index)
        self.vapi.sw_interface_set_l2_emulation(sub_if_on_pg3.sw_if_index)

        #
        # now we expect the packet forward according to the DVR route
        #
        rx = self.send_and_expect(self.pg0, pkt_no_tag * 65, self.pg1)
        self.assert_same_mac_addr(pkt_no_tag, rx)
        self.assert_has_no_tag(rx)

        rx = self.send_and_expect(self.pg0, pkt_to_tag * 65, self.pg2)
        self.assert_same_mac_addr(pkt_to_tag, rx)
        self.assert_has_vlan_tag(92, rx)

        rx = self.send_and_expect(self.pg3, pkt_from_tag * 65, self.pg1)
        self.assert_same_mac_addr(pkt_from_tag, rx)
        self.assert_has_no_tag(rx)

        rx = self.send_and_expect(self.pg3, pkt_from_to_tag * 65, self.pg2)
        self.assert_same_mac_addr(pkt_from_tag, rx)
        self.assert_has_vlan_tag(92, rx)

        #
        # but broadcast packets are still flooded
        #
        self.send_and_expect(self.pg0, pkt_bcast * 33, self.pg2)

        #
        # cleanup
        #
        self.vapi.sw_interface_set_l2_emulation(self.pg0.sw_if_index,
                                                enable=0)
        self.vapi.sw_interface_set_l2_emulation(self.pg1.sw_if_index,
                                                enable=0)
        self.vapi.sw_interface_set_l2_emulation(sub_if_on_pg2.sw_if_index,
                                                enable=0)
        self.vapi.sw_interface_set_l2_emulation(sub_if_on_pg3.sw_if_index,
                                                enable=0)

        self.vapi.sw_interface_set_l2_bridge(self.pg0.sw_if_index,
                                             1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index,
                                             1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg2.sw_if_index,
                                             1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg3.sw_if_index,
                                             1, enable=0)

        route_1.remove_vpp_config()
        route_2.remove_vpp_config()
        sub_if_on_pg3.remove_vpp_config()
        sub_if_on_pg2.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
