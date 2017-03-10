#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP


class TestFlowperpkt(VppTestCase):
    """ Flow-per-packet plugin: test both L2 and IP4 reporting """

    def setUp(self):
        """
        Set up

        **Config:**
            - create three PG interfaces
        """
        super(TestFlowperpkt, self).setUp()

        self.create_pg_interfaces(range(3))

        self.pg_if_packet_sizes = [150]

        self.interfaces = list(self.pg_interfaces)

        for intf in self.interfaces:
            intf.admin_up()
            intf.config_ip4()
            intf.resolve_arp()

    def create_stream(self, src_if, dst_if, packet_sizes):
        """Create a packet stream to tickle the plugin

        :param VppInterface src_if: Source interface for packet stream
        :param VppInterface src_if: Dst interface for packet stream
        :param list packet_sizes: Sizes to test
        """
        pkts = []
        for size in packet_sizes:
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=4321) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    @staticmethod
    def compare_with_mask(payload, masked_expected_data):
        if len(payload) * 2 != len(masked_expected_data):
            return False

        # iterate over pairs: raw byte from payload and ASCII code for that
        # byte from masked payload (or XX if masked)
        for i in range(len(payload)):
            p = payload[i]
            m = masked_expected_data[2 * i:2 * i + 2]
            if m != "XX":
                if "%02x" % ord(p) != m:
                    return False
        return True

    def verify_ipfix(self, collector_if):
        """Check the ipfix capture"""
        found_data_packet = False
        found_template_packet = False
        found_l2_data_packet = False
        found_l2_template_packet = False

        # Scapy, of course, understands ipfix not at all...
        # These data vetted by manual inspection in wireshark
        # X'ed out fields are timestamps, which will absolutely
        # fail to compare.

        data_udp_string = "1283128300370000000a002fXXXXXXXX000000000000000101"\
            "00001f0000000100000002ac100102ac10020200XXXXXXXXXXXXXXXX0092"

        template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000000"\
            "010002002401000007000a0004000e000400080004000c000400050001009c00"\
            "0801380002"

        l2_data_udp_string = "12831283003c0000000a0034XXXXXXXX000000010000000"\
            "1010100240000000100000002%s02020000ff020008XXXXXXXXXXX"\
            "XXXXX0092" % self.pg1.local_mac.translate(None, ":")

        l2_template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000"\
            "000010002002401010007000a0004000e0004003800060050000601000002009"\
            "c000801380002"

        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))
        # expecting 4 packets on collector interface based on traffic on other
        # interfaces
        capture = collector_if.get_capture(4)

        for p in capture:
            ip = p[IP]
            udp = p[UDP]
            self.logger.info("src %s dst %s" % (ip.src, ip.dst))
            self.logger.info(" udp src_port %s dst_port %s"
                             % (udp.sport, udp.dport))

            payload = str(udp)

            if self.compare_with_mask(payload, data_udp_string):
                self.logger.info("found ip4 data packet")
                found_data_packet = True
            elif self.compare_with_mask(payload, template_udp_string):
                self.logger.info("found ip4 template packet")
                found_template_packet = True
            elif self.compare_with_mask(payload, l2_data_udp_string):
                self.logger.info("found l2 data packet")
                found_l2_data_packet = True
            elif self.compare_with_mask(payload, l2_template_udp_string):
                self.logger.info("found l2 template packet")
                found_l2_template_packet = True
            else:
                unmasked_payload = "".join(["%02x" % ord(c) for c in payload])
                self.logger.error("unknown pkt '%s'" % unmasked_payload)

        self.assertTrue(found_data_packet, "Data packet not found")
        self.assertTrue(found_template_packet, "Template packet not found")
        self.assertTrue(found_l2_data_packet, "L2 data packet not found")
        self.assertTrue(found_l2_template_packet,
                        "L2 template packet not found")

    def test_L3_fpp(self):
        """ Flow per packet L3 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        self.pg_enable_capture(self.pg_interfaces)
        self.pg2.configure_ipv4_neighbors()
        self.vapi.set_ipfix_exporter(collector_address=self.pg2.remote_ip4n,
                                     src_address=self.pg2.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        # Export flow records for all pkts transmitted on pg1
        self.vapi.cli("flowperpkt feature add-del pg1")
        self.vapi.cli("flowperpkt feature add-del pg1 l2")

        # Arrange to minimally trace generated ipfix packets
        self.vapi.cli("trace add flowperpkt-ipv4 10")
        self.vapi.cli("trace add flowperpkt-l2 10")

        # Create a stream from pg0 -> pg1, which causes
        # an ipfix packet to be transmitted on pg2

        pkts = self.create_stream(self.pg0, self.pg1,
                                  self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()

        # Flush the ipfix collector, so we don't need any
        # asinine time.sleep(5) action
        self.vapi.cli("ipfix flush")

        # Make sure the 4 pkts we expect actually showed up
        self.verify_ipfix(self.pg2)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
