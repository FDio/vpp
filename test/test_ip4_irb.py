#!/usr/bin/env python3
"""IRB Test Case HLD:

**config**
    - L2 MAC learning enabled in l2bd
    - 2 routed interfaces untagged, bvi (Bridge Virtual Interface)
    - 2 bridged interfaces in l2bd with bvi

**test**
    - sending ip4 eth pkts between routed interfaces
        - 2 routed interfaces
        - 2 bridged interfaces

    - 64B, 512B, 1518B, 9200B (ether_size)

    - burst of pkts per interface
        - 257pkts per burst
        - routed pkts hitting different FIB entries
        - bridged pkts hitting different MAC entries

**verify**
    - all packets received correctly

"""

import unittest
from random import choice

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from vpp_papi import MACAddress
from vpp_l2 import L2_PORT_TYPE, VppBridgeDomainPort, VppBridgeDomain, \
    VppL2FibEntry
from vpp_bvi_interface import VppBviInterface
from vpp_lo_interface import VppLoInterface
from vpp_sub_interface import VppDot1QSubint
from vpp_neighbor import VppNeighbor
from vpp_ip_route import VppIpRoute, VppRoutePath


class TestIpIrb(VppTestCase):
    """IRB Test Case"""

    @classmethod
    def setUpClass(cls):
        """
        #. Create BD with MAC learning enabled and put interfaces to this BD.
        #. Configure IPv4 addresses on BVI interface and routed interface.
        #. Configure MAC address binding to IPv4 neighbors on bvi0.
        #. Configure MAC address on pg2.
        #. BVI interface has remote hosts, one half of hosts are
           behind pg0 second behind pg1.
        """
        super(TestIpIrb, cls).setUpClass()

        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]  # packet sizes
        cls.bd_id = 10
        cls.remote_hosts_count = 250

        # create 3 pg interfaces, 1 BVI interface
        cls.create_pg_interfaces(range(3))
        cls.create_bvi_interfaces(1)

        cls.interfaces = list(cls.pg_interfaces)
        cls.interfaces.extend(cls.bvi_interfaces)

        for i in cls.interfaces:
            i.admin_up()

        # Create BD with MAC learning enabled and put interfaces to this BD
        cls.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=cls.bvi0.sw_if_index, bd_id=cls.bd_id,
            port_type=L2_PORT_TYPE.BVI)
        cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=cls.pg0.sw_if_index,
                                            bd_id=cls.bd_id)
        cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=cls.pg1.sw_if_index,
                                            bd_id=cls.bd_id)

        # Configure IPv4 addresses on BVI interface and routed interface
        cls.bvi0.config_ip4()
        cls.pg2.config_ip4()

        # Configure MAC address binding to IPv4 neighbors on bvi0
        cls.bvi0.generate_remote_hosts(cls.remote_hosts_count)
        cls.bvi0.configure_ipv4_neighbors()
        # configure MAC address on pg2
        cls.pg2.resolve_arp()

        # BVI interface has remote hosts, one half of hosts are behind
        # pg0 second behind pg1
        half = cls.remote_hosts_count // 2
        cls.pg0.remote_hosts = cls.bvi0.remote_hosts[:half]
        cls.pg1.remote_hosts = cls.bvi0.remote_hosts[half:]

    @classmethod
    def tearDownClass(cls):
        super(TestIpIrb, cls).tearDownClass()

    def tearDown(self):
        """Run standard test teardown and log ``show l2patch``,
        ``show l2fib verbose``,``show bridge-domain <bd_id> detail``,
        ``show ip neighbors``.
        """
        super(TestIpIrb, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show l2patch"))
        self.logger.info(self.vapi.cli("show l2fib verbose"))
        self.logger.info(self.vapi.cli("show bridge-domain %s detail" %
                                       self.bd_id))
        self.logger.info(self.vapi.cli("show ip neighbors"))

    def create_stream(self, src_ip_if, dst_ip_if, packet_sizes):
        pkts = []
        for i in range(0, 257):
            remote_dst_host = choice(dst_ip_if.remote_hosts)
            info = self.create_packet_info(src_ip_if, dst_ip_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_ip_if.local_mac, src=src_ip_if.remote_mac) /
                 IP(src=src_ip_if.remote_ip4,
                    dst=remote_dst_host.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def create_stream_l2_to_ip(self, src_l2_if, src_ip_if, dst_ip_if,
                               packet_sizes):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_ip_if, dst_ip_if)
            payload = self.info_to_payload(info)

            host = choice(src_l2_if.remote_hosts)

            p = (Ether(src=host.mac,
                       dst=src_ip_if.local_mac) /
                 IP(src=host.ip4,
                    dst=dst_ip_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))

            info.data = p.copy()
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)

            pkts.append(p)
        return pkts

    def verify_capture_l2_to_ip(self, dst_ip_if, src_ip_if, capture):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None

        dst_ip_sw_if_index = dst_ip_if.sw_if_index

        for packet in capture:
            ip = packet[IP]
            udp = packet[IP][UDP]
            payload_info = self.payload_to_info(packet[IP][UDP][Raw])

            self.assertEqual(payload_info.dst, dst_ip_sw_if_index)

            next_info = self.get_next_packet_info_for_interface2(
                payload_info.src, dst_ip_sw_if_index,
                last_info[payload_info.src])
            last_info[payload_info.src] = next_info
            self.assertTrue(next_info is not None)
            saved_packet = next_info.data
            self.assertTrue(next_info is not None)

            # MAC: src, dst
            self.assertEqual(packet.src, dst_ip_if.local_mac)
            self.assertEqual(packet.dst, dst_ip_if.remote_mac)

            # IP: src, dst
            host = src_ip_if.host_by_ip4(ip.src)
            self.assertIsNotNone(host)
            self.assertEqual(ip.dst, saved_packet[IP].dst)
            self.assertEqual(ip.dst, dst_ip_if.remote_ip4)

            # UDP:
            self.assertEqual(udp.sport, saved_packet[UDP].sport)
            self.assertEqual(udp.dport, saved_packet[UDP].dport)

    def verify_capture(self, dst_ip_if, src_ip_if, capture):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None

        dst_ip_sw_if_index = dst_ip_if.sw_if_index

        for packet in capture:
            ip = packet[IP]
            udp = packet[IP][UDP]
            payload_info = self.payload_to_info(packet[IP][UDP][Raw])
            packet_index = payload_info.index

            self.assertEqual(payload_info.dst, dst_ip_sw_if_index)

            next_info = self.get_next_packet_info_for_interface2(
                payload_info.src, dst_ip_sw_if_index,
                last_info[payload_info.src])
            last_info[payload_info.src] = next_info
            self.assertTrue(next_info is not None)
            self.assertEqual(packet_index, next_info.index)
            saved_packet = next_info.data
            self.assertTrue(next_info is not None)

            # MAC: src, dst
            self.assertEqual(packet.src, dst_ip_if.local_mac)
            host = dst_ip_if.host_by_mac(packet.dst)

            # IP: src, dst
            self.assertEqual(ip.src, src_ip_if.remote_ip4)
            self.assertEqual(ip.dst, saved_packet[IP].dst)
            self.assertEqual(ip.dst, host.ip4)

            # UDP:
            self.assertEqual(udp.sport, saved_packet[UDP].sport)
            self.assertEqual(udp.dport, saved_packet[UDP].dport)

    def test_ip4_irb_1(self):
        """ IPv4 IRB test 1

        Test scenario:
            - ip traffic from pg2 interface must ends in both pg0 and pg1
            - arp entry present in bvi0 interface for destination IP
            - no l2 entry configured, pg0 and pg1 are same
        """

        stream = self.create_stream(
            self.pg2, self.bvi0, self.pg_if_packet_sizes)
        self.pg2.add_stream(stream)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        packet_count = self.get_packet_count_for_if_idx(self.bvi0.sw_if_index)

        rcvd1 = self.pg0.get_capture(packet_count)
        rcvd2 = self.pg1.get_capture(packet_count)

        self.verify_capture(self.bvi0, self.pg2, rcvd1)
        self.verify_capture(self.bvi0, self.pg2, rcvd2)

        self.assertListEqual(rcvd1.res, rcvd2.res)

    def send_and_verify_l2_to_ip(self):
        stream1 = self.create_stream_l2_to_ip(
            self.pg0, self.bvi0, self.pg2, self.pg_if_packet_sizes)
        stream2 = self.create_stream_l2_to_ip(
            self.pg1, self.bvi0, self.pg2, self.pg_if_packet_sizes)
        self.vapi.cli("clear trace")
        self.pg0.add_stream(stream1)
        self.pg1.add_stream(stream2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rcvd = self.pg2.get_capture(514)
        self.verify_capture_l2_to_ip(self.pg2, self.bvi0, rcvd)

    def test_ip4_irb_2(self):
        """ IPv4 IRB test 2

        Test scenario:
            - ip traffic from pg0 and pg1 ends on pg2
        """
        self.send_and_verify_l2_to_ip()

        # change the BVI's mac and resed traffic
        self.bvi0.set_mac(MACAddress("00:00:00:11:11:33"))

        self.send_and_verify_l2_to_ip()
        # check it wasn't flooded
        self.pg1.assert_nothing_captured(remark="UU Flood")


class TestBVI(VppTestCase):
    """BVI Test Case"""

    def tearDown(self):
        super(TestBVI, self).tearDown()

    def setUp(self):
        super(TestBVI, self).setUp()

        # 4 pg interfaces
        self.create_pg_interfaces(range(5))

        for i in self.pg_interfaces:
            i.admin_up()

    def mk_lo(self, parent, i):
        return VppLoInterface(self)

    def mk_bvi(self, parent, i):
        return VppBviInterface(self)

    def mk_vlan(self, parent, i):
        return VppDot1QSubint(self, parent, 100 + i)

    def do_test(self, parent, bvi_generator):
        #
        # 4 BDs and 4 BVIs
        #
        bds = []
        bvis = []
        pkts = []

        # another L3 interface to inject from
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

        for i in range(4):
            # create the BD
            bds.append(VppBridgeDomain(self, i+1).add_vpp_config())

            # add the PG interface
            VppBridgeDomainPort(self, bds[i],
                                self.pg_interfaces[i]).add_vpp_config()

            # create, configure and add the BVI
            bvis.append(bvi_generator(parent, i))
            bvis[i].admin_up()
            bvis[i].config_ip4()
            VppBridgeDomainPort(self, bds[i], bvis[i],
                                port_type=L2_PORT_TYPE.BVI).add_vpp_config()

            # a neighbor/host on the BVI/BD to route to
            VppNeighbor(self,
                        bvis[i].sw_if_index,
                        bvis[i].remote_mac,
                        bvis[i].remote_ip4).add_vpp_config()

            # an L2 FIB entry for the host
            VppL2FibEntry(self, bds[i],
                          bvis[i].remote_mac,
                          self.pg_interfaces[i]).add_vpp_config()

            # route via neighbour
            VppIpRoute(self, "10.0.0.%d" % i, 32,
                       [VppRoutePath(bvis[i].remote_ip4,
                                     bvis[i].sw_if_index)]).add_vpp_config()

            pkts.append(Ether(dst=self.pg4.local_mac,
                              src=self.pg4.remote_mac) /
                        IP(src=self.pg4.remote_ip4,
                           dst="10.0.0.%d" % i) /
                        UDP(sport=1234, dport=1234) /
                        Raw(b'\xa5' * 100))

        # # all packets via bvi0
        N_PKTS = 63
        self.send_and_expect(self.pg4, pkts[0] * N_PKTS, self.pg0)

        # alternate oackets to the different BVIs
        tx = pkts + pkts + pkts + pkts

        self.pg4.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in range(4):
            self.assertEqual(4, len(self.pg_interfaces[i].get_capture(4)))

        # two BVIs at a time
        tx = [pkts[0], pkts[0], pkts[1], pkts[1]]
        tx += tx + tx + tx

        self.logger.error(self.vapi.cli("clear trace"))
        self.pg4.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in range(2):
            self.assertEqual(8, len(self.pg_interfaces[i].get_capture(8)))

        self.pg4.unconfig_ip4()
        self.pg4.admin_down()

    def test_bvi_vlans(self):
        """ BVI as VLAN on BVI interface type """
        parent = VppBviInterface(self)
        parent.admin_up()
        self.do_test(parent, self.mk_vlan)

    def test_lo_vlans(self):
        """ BVI as VLAN on Loopback interface type """
        parent = VppLoInterface(self)
        parent.admin_up()
        self.do_test(parent, self.mk_vlan)

    def test_bvi(self):
        """ BVI as BVI interface type """
        self.do_test(None, self.mk_bvi)

    def test_lo(self):
        """ BVI as Loopback interface type """
        self.do_test(None, self.mk_lo)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
