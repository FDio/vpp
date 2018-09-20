#!/usr/bin/env python
import unittest
from framework import VppTestCase, VppTestRunner
from vpp_udp_encap import *
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, VppMplsLabel

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS


class TestUdpEncap(VppTestCase):
    """ UDP Encap Test Case """

    def setUp(self):
        super(TestUdpEncap, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        # setup interfaces
        # assign them different tables.
        table_id = 0
        self.tables = []

        for i in self.pg_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                self.tables.append(tbl)
                tbl = VppIpTable(self, table_id, is_ip6=1)
                tbl.add_vpp_config()
                self.tables.append(tbl)

            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.admin_down()
        super(TestUdpEncap, self).tearDown()

    def validate_outer4(self, rx, encap_obj):
        self.assertEqual(rx[IP].src, encap_obj.src_ip_s)
        self.assertEqual(rx[IP].dst, encap_obj.dst_ip_s)
        self.assertEqual(rx[UDP].sport, encap_obj.src_port)
        self.assertEqual(rx[UDP].dport, encap_obj.dst_port)

    def validate_outer6(self, rx, encap_obj):
        self.assertEqual(rx[IPv6].src, encap_obj.src_ip_s)
        self.assertEqual(rx[IPv6].dst, encap_obj.dst_ip_s)
        self.assertEqual(rx[UDP].sport, encap_obj.src_port)
        self.assertEqual(rx[UDP].dport, encap_obj.dst_port)

    def validate_inner4(self, rx, tx, ttl=None):
        self.assertEqual(rx[IP].src, tx[IP].src)
        self.assertEqual(rx[IP].dst, tx[IP].dst)
        if ttl:
            self.assertEqual(rx[IP].ttl, ttl)
        else:
            self.assertEqual(rx[IP].ttl, tx[IP].ttl)

    def validate_inner6(self, rx, tx):
        self.assertEqual(rx.src, tx[IPv6].src)
        self.assertEqual(rx.dst, tx[IPv6].dst)
        self.assertEqual(rx.hlim, tx[IPv6].hlim)

    def test_udp_encap(self):
        """ UDP Encap test
        """

        #
        # construct a UDP encap object through each of the peers
        # v4 through the first two peears, v6 through the second.
        #
        udp_encap_0 = VppUdpEncap(self,
                                  self.pg0.local_ip4,
                                  self.pg0.remote_ip4,
                                  330, 440)
        udp_encap_1 = VppUdpEncap(self,
                                  self.pg1.local_ip4,
                                  self.pg1.remote_ip4,
                                  331, 441,
                                  table_id=1)
        udp_encap_2 = VppUdpEncap(self,
                                  self.pg2.local_ip6,
                                  self.pg2.remote_ip6,
                                  332, 442,
                                  table_id=2)
        udp_encap_3 = VppUdpEncap(self,
                                  self.pg3.local_ip6,
                                  self.pg3.remote_ip6,
                                  333, 443,
                                  table_id=3)
        udp_encap_0.add_vpp_config()
        udp_encap_1.add_vpp_config()
        udp_encap_2.add_vpp_config()
        udp_encap_3.add_vpp_config()

        self.logger.info(self.vapi.cli("sh udp encap"))

        self.assertTrue(find_udp_encap(self, udp_encap_2))
        self.assertTrue(find_udp_encap(self, udp_encap_3))
        self.assertTrue(find_udp_encap(self, udp_encap_0))
        self.assertTrue(find_udp_encap(self, udp_encap_1))

        #
        # Routes via each UDP encap object - all combinations of v4 and v6.
        #
        route_4o4 = VppIpRoute(self, "1.1.0.1", 32,
                               [VppRoutePath("0.0.0.0",
                                             0xFFFFFFFF,
                                             is_udp_encap=1,
                                             next_hop_id=udp_encap_0.id)])
        route_4o6 = VppIpRoute(self, "1.1.2.1", 32,
                               [VppRoutePath("0.0.0.0",
                                             0xFFFFFFFF,
                                             is_udp_encap=1,
                                             next_hop_id=udp_encap_2.id)])
        route_6o4 = VppIpRoute(self, "2001::1", 128,
                               [VppRoutePath("0.0.0.0",
                                             0xFFFFFFFF,
                                             is_udp_encap=1,
                                             next_hop_id=udp_encap_1.id)],
                               is_ip6=1)
        route_6o6 = VppIpRoute(self, "2001::3", 128,
                               [VppRoutePath("0.0.0.0",
                                             0xFFFFFFFF,
                                             is_udp_encap=1,
                                             next_hop_id=udp_encap_3.id)],
                               is_ip6=1)
        route_4o4.add_vpp_config()
        route_4o6.add_vpp_config()
        route_6o6.add_vpp_config()
        route_6o4.add_vpp_config()

        #
        # 4o4 encap
        #
        p_4o4 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.0.1") /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_4o4*65, self.pg0)
        for p in rx:
            self.validate_outer4(p, udp_encap_0)
            p = IP(p["UDP"].payload.load)
            self.validate_inner4(p, p_4o4)
        self.assertEqual(udp_encap_0.get_stats()['packets'], 65)

        #
        # 4o6 encap
        #
        p_4o6 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.2.1") /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_4o6*65, self.pg2)
        for p in rx:
            self.validate_outer6(p, udp_encap_2)
            p = IP(p["UDP"].payload.load)
            self.validate_inner4(p, p_4o6)
        self.assertEqual(udp_encap_2.get_stats()['packets'], 65)

        #
        # 6o4 encap
        #
        p_6o4 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="2001::100", dst="2001::1") /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_6o4*65, self.pg1)
        for p in rx:
            self.validate_outer4(p, udp_encap_1)
            p = IPv6(p["UDP"].payload.load)
            self.validate_inner6(p, p_6o4)
        self.assertEqual(udp_encap_1.get_stats()['packets'], 65)

        #
        # 6o6 encap
        #
        p_6o6 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="2001::100", dst="2001::3") /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_6o6*65, self.pg3)
        for p in rx:
            self.validate_outer6(p, udp_encap_3)
            p = IPv6(p["UDP"].payload.load)
            self.validate_inner6(p, p_6o6)
        self.assertEqual(udp_encap_3.get_stats()['packets'], 65)

        #
        # A route with an output label
        # the TTL of the inner packet is decremented on LSP ingress
        #
        route_4oMPLSo4 = VppIpRoute(self, "1.1.2.22", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  0xFFFFFFFF,
                                                  is_udp_encap=1,
                                                  next_hop_id=1,
                                                  labels=[VppMplsLabel(66)])])
        route_4oMPLSo4.add_vpp_config()

        p_4omo4 = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IP(src="2.2.2.2", dst="1.1.2.22") /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_4omo4*65, self.pg1)
        for p in rx:
            self.validate_outer4(p, udp_encap_1)
            p = MPLS(p["UDP"].payload.load)
            self.validate_inner4(p, p_4omo4, ttl=63)
        self.assertEqual(udp_encap_1.get_stats()['packets'], 130)


class TestUDP(VppTestCase):
    """ UDP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestUDP, cls).setUpClass()

    def setUp(self):
        super(TestUDP, self).setUp()
        self.vapi.session_enable_disable(is_enabled=1)
        self.create_loopback_interfaces(2)

        table_id = 0

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add(namespace_id="0",
                                    sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add(namespace_id="1",
                                    sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enabled=0)
        super(TestUDP, self).tearDown()

    def test_udp_transfer(self):
        """ UDP echo client/server transfer """

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)])
        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=0)], table_id=1)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Start builtin server and client
        uri = "udp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test echo server appns 0 fifo-size 4 no-echo" +
                              "uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertEqual(error.find("failed"), -1)

        error = self.vapi.cli("test echo client mbytes 10 appns 1 " +
                              "fifo-size 4 no-output test-bytes " +
                              "syn-timeout 2 no-return uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertEqual(error.find("failed"), -1)

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
