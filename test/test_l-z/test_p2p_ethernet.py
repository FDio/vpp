#!/usr/bin/env python
import random
import unittest
import datetime
import re

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_sub_interface import VppP2PSubint
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from util import mactobinary


class P2PEthernetAPI(VppTestCase):
    """P2P Ethernet tests"""

    p2p_sub_ifs = []

    @classmethod
    def setUpClass(cls):
        super(P2PEthernetAPI, cls).setUpClass()

        # Create pg interfaces
        cls.create_pg_interfaces(range(4))

        # Set up all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

    def create_p2p_ethernet(self, parent_if, sub_id, remote_mac):
        p2p = VppP2PSubint(self, parent_if, sub_id, mactobinary(remote_mac))
        self.p2p_sub_ifs.append(p2p)

    def delete_p2p_ethernet(self, parent_if, remote_mac):
        self.vapi.delete_p2pethernet_subif(parent_if.sw_if_index,
                                           mactobinary(remote_mac))

    def test_api(self):
        """delete/create p2p subif"""
        self.logger.info("FFP_TEST_START_0000")

        self.create_p2p_ethernet(self.pg0, 1, "de:ad:00:00:00:01")
        self.create_p2p_ethernet(self.pg0, 2, "de:ad:00:00:00:02")
        intfs = self.vapi.cli("show interface")

        self.assertNotEqual(intfs.find('pg0.1'), -1)
        self.assertNotEqual(intfs.find('pg0.2'), -1)
        self.assertEqual(intfs.find('pg0.5'), -1)

        # create pg2.5 subif
        self.create_p2p_ethernet(self.pg0, 5, "de:ad:00:00:00:ff")
        intfs = self.vapi.cli("show interface")
        self.assertNotEqual(intfs.find('pg0.5'), -1)
        # delete pg2.5 subif
        self.delete_p2p_ethernet(self.pg0, "de:ad:00:00:00:ff")

        intfs = self.vapi.cli("show interface")

        self.assertNotEqual(intfs.find('pg0.1'), -1)
        self.assertNotEqual(intfs.find('pg0.2'), -1)
        self.assertEqual(intfs.find('pg0.5'), -1)

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_p2p_subif_creation_1k(self):
        """create 1k of p2p subifs"""
        self.logger.info("FFP_TEST_START_0001")

        macs = []
        clients = 1000
        mac = int("dead00000000", 16)

        for i in range(1, clients+1):
            try:
                macs.append(':'.join(re.findall('..', '{:02x}'.format(mac+i))))
                self.vapi.create_p2pethernet_subif(self.pg2.sw_if_index,
                                                   mactobinary(macs[i-1]),
                                                   i)
            except Exception:
                print "Failed to create subif %d %s" % (i, macs[i-1])
                raise

        intfs = self.vapi.cli("show interface").split("\n")
        count = 0
        for intf in intfs:
            if intf.startswith('pg2.'):
                count += 1
        self.assertEqual(count, clients)

        self.logger.info("FFP_TEST_FINISH_0001")

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_p2p_subif_creation_10k(self):
        """create 100k of p2p subifs"""
        self.logger.info("FFP_TEST_START_0001")

        macs = []
        clients = 100000
        mac = int("dead00000000", 16)

        s_time = datetime.datetime.now()
        for i in range(1, clients+1):
            if i % 1000 == 0:
                e_time = datetime.datetime.now()
                print "Created 1000 subifs in %s secs" % (e_time - s_time)
                s_time = e_time
            try:
                macs.append(':'.join(re.findall('..', '{:02x}'.format(mac+i))))
                self.vapi.create_p2pethernet_subif(self.pg3.sw_if_index,
                                                   mactobinary(macs[i-1]),
                                                   i)
            except Exception:
                print "Failed to create subif %d %s" % (i, macs[i-1])
                raise

        intfs = self.vapi.cli("show interface").split("\n")
        count = 0
        for intf in intfs:
            if intf.startswith('pg3.'):
                count += 1
        self.assertEqual(count, clients)

        self.logger.info("FFP_TEST_FINISH_0001")


class P2PEthernetIPV6(VppTestCase):
    """P2P Ethernet IPv6 tests"""

    p2p_sub_ifs = []
    packets = []

    @classmethod
    def setUpClass(cls):
        super(P2PEthernetIPV6, cls).setUpClass()

        # Create pg interfaces
        cls.create_pg_interfaces(range(3))

        # Packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

        # Set up all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

        cls.pg0.generate_remote_hosts(3)
        cls.pg0.configure_ipv6_neighbors()

        cls.pg1.config_ip6()
        cls.pg1.generate_remote_hosts(3)
        cls.pg1.configure_ipv6_neighbors()
        cls.pg1.disable_ipv6_ra()

    def setUp(self):
        super(P2PEthernetIPV6, self).setUp()
        for p in self.packets:
            self.packets.remove(p)
        self.create_p2p_ethernet(self.pg0, 1, self.pg0._remote_hosts[0].mac)
        self.create_p2p_ethernet(self.pg0, 2, self.pg0._remote_hosts[1].mac)
        self.p2p_sub_ifs[0].config_ip6()
        self.p2p_sub_ifs[1].config_ip6()
        self.vapi.cli("trace add p2p-ethernet-input 50")

    def tearDown(self):
        self.delete_p2p_ethernet(self.pg0, self.pg0._remote_hosts[0].mac)
        self.delete_p2p_ethernet(self.pg0, self.pg0._remote_hosts[1].mac)
        super(P2PEthernetIPV6, self).tearDown()

    def create_p2p_ethernet(self, parent_if, sub_id, remote_mac):
        p2p = VppP2PSubint(self, parent_if, sub_id, mactobinary(remote_mac))
        p2p.admin_up()
        p2p.config_ip6()
        p2p.disable_ipv6_ra()
        self.p2p_sub_ifs.append(p2p)

    def delete_p2p_ethernet(self, parent_if, remote_mac):
        self.vapi.delete_p2pethernet_subif(parent_if.sw_if_index,
                                           mactobinary(remote_mac))

    def create_stream(self, src_mac=None, dst_mac=None,
                      src_ip=None, dst_ip=None, size=None):
        pkt_size = size
        if size is None:
            pkt_size = random.choice(self.pg_if_packet_sizes)
        p = Ether(src=src_mac, dst=dst_mac)
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

    def test_no_p2p_subif(self):
        """standard routing without p2p subinterfaces"""
        self.logger.info("FFP_TEST_START_0001")

        route_8000 = VppIpRoute(self, "8000::", 64,
                                [VppRoutePath(self.pg0.remote_ip6,
                                              self.pg0.sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_8000.add_vpp_config()

        self.packets = [(Ether(dst=self.pg1.local_mac,
                               src=self.pg1.remote_mac) /
                         IPv6(src="3001::1", dst="8000::100") /
                         UDP(sport=1234, dport=1234) /
                         Raw('\xa5' * 100))]
        self.send_packets(self.pg1, self.pg0)

        self.logger.info("FFP_TEST_FINISH_0001")

    def test_ip6_rx_p2p_subif(self):
        """receive ipv6 packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0002")

        route_9001 = VppIpRoute(self, "9001::", 64,
                                [VppRoutePath(self.pg1.remote_ip6,
                                              self.pg1.sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(src_mac=self.pg0._remote_hosts[0].mac,
                               dst_mac=self.pg0.local_mac,
                               src_ip=self.p2p_sub_ifs[0].remote_ip6,
                               dst_ip="9001::100"))

        self.send_packets(self.pg0, self.pg1, self.packets)
        self.verify_counters('p2p-ethernet-input', 1)

        route_9001.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_ip6_rx_p2p_subif_route(self):
        """route rx ip6 packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0003")

        self.pg0.config_ip6()

        route_3 = VppIpRoute(self, "9000::", 64,
                             [VppRoutePath(self.pg1._remote_hosts[0].ip6,
                                           self.pg1.sw_if_index,
                                           proto=DpoProto.DPO_PROTO_IP6)],
                             is_ip6=1)
        route_3.add_vpp_config()

        self.packets.append(
            self.create_stream(src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg0.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        self.send_packets(self.pg0, self.pg1)

        self.pg0.unconfig_ip6()

        route_3.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0003")

    def test_ip6_rx_p2p_subif_drop(self):
        """drop rx packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0004")

        route_9001 = VppIpRoute(self, "9000::", 64,
                                [VppRoutePath(self.pg1._remote_hosts[0].ip6,
                                              self.pg1.sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg0.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        # no packet received
        self.send_packets(self.pg0, self.pg1, count=0)
        self.logger.info("FFP_TEST_FINISH_0004")

    def test_ip6_tx_p2p_subif(self):
        """send packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0005")

        route_8000 = VppIpRoute(self, "8000::", 64,
                                [VppRoutePath(self.pg0.remote_ip6,
                                              self.pg0.sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_8000.add_vpp_config()
        route_8001 = VppIpRoute(self, "8001::", 64,
                                [VppRoutePath(self.p2p_sub_ifs[0].remote_ip6,
                                              self.p2p_sub_ifs[0].sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_8001.add_vpp_config()
        route_8002 = VppIpRoute(self, "8002::", 64,
                                [VppRoutePath(self.p2p_sub_ifs[1].remote_ip6,
                                              self.p2p_sub_ifs[1].sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
                                is_ip6=1)
        route_8002.add_vpp_config()

        for i in range(0, 3):
            self.packets.append(
                self.create_stream(src_mac=self.pg1.remote_mac,
                                   dst_mac=self.pg1.local_mac,
                                   src_ip=self.pg1.remote_ip6,
                                   dst_ip="800%d::100" % i))

        self.send_packets(self.pg1, self.pg0, count=3)

        route_8000.remove_vpp_config()
        route_8001.remove_vpp_config()
        route_8002.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0005")

    def test_ip6_tx_p2p_subif_drop(self):
        """drop tx ip6 packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0006")

        self.packets.append(
            self.create_stream(src_mac="02:03:00:00:ff:ff",
                               dst_mac=self.pg0.local_mac,
                               src_ip="a000::100",
                               dst_ip="9000::100"))

        # no packet received
        self.send_packets(self.pg0, self.pg1, count=0)
        self.logger.info("FFP_TEST_FINISH_0006")


class P2PEthernetIPV4(VppTestCase):
    """P2P Ethernet IPv4 tests"""

    p2p_sub_ifs = []
    packets = []

    @classmethod
    def setUpClass(cls):
        super(P2PEthernetIPV4, cls).setUpClass()

        # Create pg interfaces
        cls.create_pg_interfaces(range(3))

        # Packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

        # Set up all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

        cls.pg0.config_ip4()
        cls.pg0.generate_remote_hosts(5)
        cls.pg0.configure_ipv4_neighbors()

        cls.pg1.config_ip4()
        cls.pg1.generate_remote_hosts(5)
        cls.pg1.configure_ipv4_neighbors()

    def setUp(self):
        super(P2PEthernetIPV4, self).setUp()
        for p in self.packets:
            self.packets.remove(p)
        self.create_p2p_ethernet(self.pg0, 1, self.pg0._remote_hosts[0].mac)
        self.create_p2p_ethernet(self.pg0, 2, self.pg0._remote_hosts[1].mac)
        self.p2p_sub_ifs[0].config_ip4()
        self.p2p_sub_ifs[1].config_ip4()
        self.vapi.cli("trace add p2p-ethernet-input 50")

    def tearDown(self):
        self.delete_p2p_ethernet(self.pg0, self.pg0._remote_hosts[0].mac)
        self.delete_p2p_ethernet(self.pg0, self.pg0._remote_hosts[1].mac)
        super(P2PEthernetIPV4, self).tearDown()

    def create_stream(self, src_mac=None, dst_mac=None,
                      src_ip=None, dst_ip=None, size=None):
        pkt_size = size
        if size is None:
            pkt_size = random.choice(self.pg_if_packet_sizes)
        p = Ether(src=src_mac, dst=dst_mac)
        p /= IP(src=src_ip, dst=dst_ip)
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

    def create_p2p_ethernet(self, parent_if, sub_id, remote_mac):
        p2p = VppP2PSubint(self, parent_if, sub_id, mactobinary(remote_mac))
        p2p.admin_up()
        p2p.config_ip4()
        self.p2p_sub_ifs.append(p2p)

    def delete_p2p_ethernet(self, parent_if, remote_mac):
        self.vapi.delete_p2pethernet_subif(parent_if.sw_if_index,
                                           mactobinary(remote_mac))

    def test_ip4_rx_p2p_subif(self):
        """receive ipv4 packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0002")

        route_9000 = VppIpRoute(self, "9.0.0.0", 16,
                                [VppRoutePath(self.pg1.remote_ip4,
                                              self.pg1.sw_if_index)])
        route_9000.add_vpp_config()

        self.packets.append(
            self.create_stream(src_mac=self.pg0._remote_hosts[0].mac,
                               dst_mac=self.pg0.local_mac,
                               src_ip=self.p2p_sub_ifs[0].remote_ip4,
                               dst_ip="9.0.0.100"))

        self.send_packets(self.pg0, self.pg1, self.packets)

        self.verify_counters('p2p-ethernet-input', 1)

        route_9000.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_ip4_rx_p2p_subif_route(self):
        """route rx packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0003")

        route_9001 = VppIpRoute(self, "9.0.0.0", 24,
                                [VppRoutePath(self.pg1.remote_ip4,
                                              self.pg1.sw_if_index)])
        route_9001.add_vpp_config()

        self.packets.append(
            self.create_stream(src_mac="02:01:00:00:ff:ff",
                               dst_mac=self.pg0.local_mac,
                               src_ip="8.0.0.100",
                               dst_ip="9.0.0.100"))

        self.send_packets(self.pg0, self.pg1)

        route_9001.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0003")

    def test_ip4_tx_p2p_subif(self):
        """send ip4 packet via p2p subinterface"""
        self.logger.info("FFP_TEST_START_0005")

        route_9100 = VppIpRoute(self, "9.1.0.100", 24,
                                [VppRoutePath(self.pg0.remote_ip4,
                                              self.pg0.sw_if_index,
                                              )])
        route_9100.add_vpp_config()
        route_9200 = VppIpRoute(self, "9.2.0.100", 24,
                                [VppRoutePath(self.p2p_sub_ifs[0].remote_ip4,
                                              self.p2p_sub_ifs[0].sw_if_index,
                                              )])
        route_9200.add_vpp_config()
        route_9300 = VppIpRoute(self, "9.3.0.100", 24,
                                [VppRoutePath(self.p2p_sub_ifs[1].remote_ip4,
                                              self.p2p_sub_ifs[1].sw_if_index
                                              )])
        route_9300.add_vpp_config()

        for i in range(0, 3):
            self.packets.append(
                self.create_stream(src_mac=self.pg1.remote_mac,
                                   dst_mac=self.pg1.local_mac,
                                   src_ip=self.pg1.remote_ip4,
                                   dst_ip="9.%d.0.100" % (i+1)))

        self.send_packets(self.pg1, self.pg0)

        # route_7000.remove_vpp_config()
        route_9100.remove_vpp_config()
        route_9200.remove_vpp_config()
        route_9300.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0005")

    def test_ip4_tx_p2p_subif_drop(self):
        """drop tx ip4 packet not matching p2p subinterface"""
        self.logger.info("FFP_TEST_START_0006")

        self.packets.append(
            self.create_stream(src_mac="02:01:00:00:ff:ff",
                               dst_mac=self.pg0.local_mac,
                               src_ip="8.0.0.100",
                               dst_ip="9.0.0.100"))

        # no packet received
        self.send_packets(self.pg0, self.pg1, count=0)
        self.logger.info("FFP_TEST_FINISH_0006")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
