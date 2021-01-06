#!/usr/bin/env python3

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestL2xc(VppTestCase):
    """ L2XC Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.

        :var int hosts_nr: Number of hosts to be created.
        :var int dl_pkts_per_burst: Number of packets in burst for dual-loop
            test.
        :var int sl_pkts_per_burst: Number of packets in burst for single-loop
            test.
        """
        super(TestL2xc, cls).setUpClass()

        # Test variables
        cls.hosts_nr = 10
        cls.dl_pkts_per_burst = 257
        cls.sl_pkts_per_burst = 2

        try:
            # create 4 pg interfaces
            cls.create_pg_interfaces(range(4))

            # packet flows mapping pg0 -> pg1, pg2 -> pg3, etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1]
            cls.flows[cls.pg1] = [cls.pg0]
            cls.flows[cls.pg2] = [cls.pg3]
            cls.flows[cls.pg3] = [cls.pg2]

            # packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            cls.interfaces = list(cls.pg_interfaces)

            # Create bi-directional cross-connects between pg0 and pg1
            cls.vapi.sw_interface_set_l2_xconnect(
                cls.pg0.sw_if_index, cls.pg1.sw_if_index, enable=1)
            cls.vapi.sw_interface_set_l2_xconnect(
                cls.pg1.sw_if_index, cls.pg0.sw_if_index, enable=1)

            # Create bi-directional cross-connects between pg2 and pg3
            cls.vapi.sw_interface_set_l2_xconnect(
                cls.pg2.sw_if_index, cls.pg3.sw_if_index, enable=1)
            cls.vapi.sw_interface_set_l2_xconnect(
                cls.pg3.sw_if_index, cls.pg2.sw_if_index, enable=1)

            # mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()

            # Create host MAC and IPv4 lists
            cls.create_host_lists(cls.hosts_nr)

            # setup all interfaces
            for i in cls.interfaces:
                i.admin_up()

        except Exception:
            super(TestL2xc, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2xc, cls).tearDownClass()

    def setUp(self):
        super(TestL2xc, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2xc, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show l2patch"))

    @classmethod
    def create_host_lists(cls, count):
        """
        Method to create required number of MAC and IPv4 addresses.
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address too.

        :param count: Number of hosts to create MAC and IPv4 addresses for.
        """
        for pg_if in cls.pg_interfaces:
            cls.hosts_by_pg_idx[pg_if.sw_if_index] = []
            hosts = cls.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(0, count):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_stream(self, src_if, packet_sizes, packets_per_burst):
        """
        Create input packet stream for defined interface.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param int packets_per_burst: Number of packets in burst.
        :return: Stream of packets.
        """
        pkts = []
        for i in range(0, packets_per_burst):
            dst_if = self.flows[src_if][0]
            dst_host = random.choice(self.hosts_by_pg_idx[dst_if.sw_if_index])
            src_host = random.choice(self.hosts_by_pg_idx[src_if.sw_if_index])
            pkt_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                 IP(src=src_host.ip4, dst=dst_host.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            pkt_info.data = p.copy()
            size = random.choice(packet_sizes)
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        """
        Verify captured input packet stream for defined interface.

        :param object pg_if: Interface to verify captured packet stream for.
        :param list capture: Captured packet stream.
        """
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (pg_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Port %u: Packet expected from source %u didn't"
                            " arrive" % (dst_sw_if_index, i.sw_if_index))

    def run_l2xc_test(self, pkts_per_burst):
        """ L2XC test """

        # Create incoming packet streams for packet-generator interfaces
        for i in self.interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                      pkts_per_burst)
            i.add_stream(pkts)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            self.logger.info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

    def test_l2xc_sl(self):
        """ L2XC single-loop test

        Test scenario:
            1. config
                2 pairs of 2 interfaces, l2xconnected

            2. sending l2 eth packets between 4 interfaces
                64B, 512B, 1518B, 9018B (ether_size)
                burst of 2 packets per interface
        """

        self.run_l2xc_test(self.sl_pkts_per_burst)

    def test_l2xc_dl(self):
        """ L2XC dual-loop test

        Test scenario:
            1. config
                2 pairs of 2 interfaces, l2xconnected

            2. sending l2 eth packets between 4 interfaces
                64B, 512B, 1518B, 9018B (ether_size)
                burst of 257 packets per interface
        """

        self.run_l2xc_test(self.dl_pkts_per_burst)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
