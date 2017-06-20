#!/usr/bin/env python
import random
import unittest
import time
from socket import AF_INET6

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppP2PSubint
from vpp_ip_route import VppIpRoute, VppRoutePath
from util import mactobinary


class P2PEthernet(VppTestCase):
    """P2P Ethernet tests"""

    p2p_sub_ifs = []
    packets = []

    @classmethod
    def setUpClass(cls):
        super(P2PEthernet, cls).setUpClass()

        # Create pg interfaces
        cls.create_pg_interfaces(range(4))

        # Packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

        # Set up all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

        cls.pg0.config_ip4()
        cls.pg0.configure_ipv4_neighbors()
        cls.pg1.config_ip4()
        cls.pg1.configure_ipv4_neighbors()

        cls.pg2.generate_remote_hosts(3)
        cls.pg2.configure_ipv6_neighbors()

        cls.pg3.config_ip6()
        cls.pg3.generate_remote_hosts(3)
        cls.pg3.configure_ipv6_neighbors()
        cls.pg3.disable_ipv6_ra()

        cls.create_p2p_ethernet(cls.pg2, 1, cls.pg2._remote_hosts[0].mac)
        cls.create_p2p_ethernet(cls.pg2, 2, cls.pg2._remote_hosts[1].mac)
        cls.vapi.cli("trace add p2p-ethernet-input 50")

    def setUp(self):
        for p in self.packets:
            self.packets.remove(p)

    @classmethod
    def create_p2p_ethernet(self, parent_if, sub_id, remote_mac):
        p2p = VppP2PSubint(self, parent_if, sub_id, mactobinary(remote_mac))
        p2p.admin_up()
        p2p.config_ip6()
        p2p.disable_ipv6_ra()
        self.p2p_sub_ifs.append(p2p)

    def create_stream(self, src_mac=None, dst_mac=None,
                      src_ip=None, dst_ip=None,
                      size=None, ip_ver='v6'):
        pkt_size = size
        if size is None:
            pkt_size = random.choice(self.pg_if_packet_sizes)
        p = Ether(src=src_mac, dst=dst_mac)
        if ip_ver == 'v4':
            p /= IP(src=src_ip, dst=dst_ip)
        else:
            p /= IPv6(src=src_ip, dst=dst_ip)
        p /= (UDP(sport=1234, dport=4321) / Raw('\xa5' * 20))
        self.extend_packet(p, pkt_size)
        return p

    def send_packets(self, src_if=None, dst_if=None, packets=None, count=None):
        self.pg_enable_capture([dst_if])
        if packets is None:
            packets = self.packets
        src_if.add_stream(packets)
        self.pg_start()
        if count is None:
            count = len(packets)
        return dst_if.get_capture(count)

    def verify_counters(self, counter_id, expected_value):
        counters = self.vapi.cli("sh errors").split('\n')
        counter_value = -1
        for i in range(1, len(counters)-1):
            results = counters[i].split()
            if results[1] == counter_id:
                counter_value = int(results[0])
                break
        self.assertEqual(counter_value, expected_value)

    def test_api(self):
        """delete/create p2p subifs"""
        self.logger.info("FFP_TEST_START_0000")
        intfs = self.vapi.cli("show interface")

        self.assertNotEqual(intfs.find('pg2.1'), -1)
        self.assertNotEqual(intfs.find('pg2.2'), -1)
        self.assertEqual(intfs.find('pg2.3'), -1)

        # create pg2.3 subif
        self.create_p2p_ethernet(self.pg2, 3, self.pg2._remote_hosts[2].mac)
        intfs = self.vapi.cli("show interface")
        self.assertNotEqual(intfs.find('pg2.3'), -1)
        # delete pg2.3 subif
        r = self.vapi.delete_p2pethernet_subif(self.pg2.sw_if_index,
                                               mactobinary(
                                                   self.pg2._remote_hosts[
                                                       2].mac))
        intfs = self.vapi.cli("show interface")

        self.assertNotEqual(intfs.find('pg2.1'), -1)
        self.assertNotEqual(intfs.find('pg2.2'), -1)
        self.assertEqual(intfs.find('pg2.3'), -1)

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_no_p2p_subif(self):
        """standard routing without p2p subinterfaces"""
        self.logger.info("FFP_TEST_START_0001")

        route_8000 = VppIpRoute(self, "8000::", 64,
                                [VppRoutePath(self.pg2.remote_ip6,
                                              self.pg2.sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_8000.add_vpp_config()

        self.packets = [(Ether(dst=self.pg3.local_mac,
                               src=self.pg3.remote_mac) /
                         IPv6(src="3001::1", dst="8000::100") /
                         UDP(sport=1234, dport=1234) /
                         Raw('\xa5' * 100))]
        self.send_packets(self.pg3, self.pg2)

        self.logger.info("FFP_TEST_FINISH_0001")

    def test_rx_p2p_subif(self):
        """send packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0002")

        route_9001 = VppIpRoute(self, "9001::", 64,
                                [VppRoutePath(self.pg3._remote_hosts[0].ip6,
                                              self.pg3.sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(ip_ver='v6',
                               src_mac=self.pg2._remote_hosts[0].mac,
                               dst_mac=self.pg2.local_mac,
                               src_ip=self.p2p_sub_ifs[0].remote_ip6,
                               dst_ip="9001::100"))

        self.send_packets(self.pg2, self.pg3, self.packets)
        self.verify_counters('p2p-ethernet-input', 1)

        self.logger.info("FFP_TEST_FINISH_0002")

    def test_rx_p2p_subif_route(self):
        """route rx packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0003")

        self.pg2.config_ip6()

        route_9001 = VppIpRoute(self, "9000::", 64,
                                [VppRoutePath(self.pg3._remote_hosts[0].ip6,
                                              self.pg3.sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(ip_ver='v6',
                               src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg2.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        # no packet received
        self.send_packets(self.pg2, self.pg3)

        self.pg2.unconfig_ip6()

        self.logger.info("FFP_TEST_FINISH_0003")

    def test_rx_p2p_subif_drop(self):
        """drop rx packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0004")

        route_9001 = VppIpRoute(self, "9000::", 64,
                                [VppRoutePath(self.pg3._remote_hosts[0].ip6,
                                              self.pg3.sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(ip_ver='v6',
                               src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg2.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        # no packet received
        self.send_packets(self.pg2, self.pg3, count=0)
        self.logger.info("FFP_TEST_FINISH_0004")

    def test_tx_p2p_subif(self):
        """receive packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0005")

        route_8000 = VppIpRoute(self, "8000::", 64,
                                [VppRoutePath(self.pg2.remote_ip6,
                                              self.pg2.sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_8000.add_vpp_config()
        route_8001 = VppIpRoute(self, "8001::", 64,
                                [VppRoutePath(self.p2p_sub_ifs[0].remote_ip6,
                                              self.p2p_sub_ifs[0].sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_8001.add_vpp_config()
        route_8002 = VppIpRoute(self, "8002::", 64,
                                [VppRoutePath(self.p2p_sub_ifs[1].local_ip6,
                                              self.p2p_sub_ifs[1].sw_if_index,
                                              is_ip6=1)],
                                is_ip6=1)
        route_8002.add_vpp_config()

        for i in range(0, 3):
            self.packets.append(
                self.create_stream(ip_ver='v6',
                                   src_mac=self.pg3.remote_mac,
                                   dst_mac=self.pg3.local_mac,
                                   src_ip=self.pg3.remote_ip6,
                                   dst_ip="800%d::100" % i))

        self.send_packets(self.pg3, self.pg2, count=3)

        self.logger.info("FFP_TEST_FINISH_0005")

    def test_tx_p2p_subif_drop(self):
        """drop tx packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0006")

        self.packets.append(
            self.create_stream(ip_ver='v6',
                               src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg2.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        # no packet received
        self.send_packets(self.pg2, self.pg3, count=0)
        self.logger.info("FFP_TEST_FINISH_0006")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
