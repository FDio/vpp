#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, UDP
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from struct import *

# IP4 stream
def create_stream_ip4(self, src_if, dst_if, packet_sizes):
    """Create a packet stream to tickle the plugin

    :param VppInterface src_if: Source interface for packet stream
    :param VppInterface src_if: Dst interface for packet stream
    :param list packet_sizes: Sizes to test
    """
    pkts = []
    for size in packet_sizes:
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        p = (Ether(src=src_if.local_mac, dst=dst_if.remote_mac) /
             IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
             UDP(sport=1234, dport=4321) /
             Raw(payload))
        info.data = p.copy()
        self.extend_packet(p, size)
        pkts.append(p)
    return pkts

# IP6 stream
def create_stream_ip6(self, src_if, dst_if, packet_sizes):
    """Create a packet stream to tickle the plugin

    :param VppInterface src_if: Source interface for packet stream
    :param VppInterface src_if: Dst interface for packet stream
    :param list packet_sizes: Sizes to test
    """
    pkts = []
    for size in packet_sizes:
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        p = (Ether(src=src_if.local_mac, dst=dst_if.remote_mac) /
             IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6) /
             UDP(sport=1234, dport=4321) /
             Raw(payload))
        info.data = p.copy()
        self.extend_packet(p, size)
        pkts.append(p)
    return pkts

class TestL2Flowperpkt(VppTestCase):
    """ Flow-per-packet plugin: test L2 reporting """

    def setUp(self):
        """
       Set up

        **Config:**
            - create three PG interfaces
        """
        super(TestL2Flowperpkt, self).setUp()
        try:
            self.create_pg_interfaces(range(3))
            self.pg_if_packet_sizes = [150]
            self.interfaces = list(self.pg_interfaces)
            for intf in self.interfaces:
                intf.config_ip4()
                intf.config_ip6()
                intf.admin_up()
                intf.resolve_arp()
                intf.resolve_ndp()
            self.pg2.configure_ipv4_neighbors()
        except Exception:
            super(TestL2Flowperpkt, self.tearDown())
            raise


    def verify_ipfix_l2_ip4(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)
            #self.assertEqual('\x02\xfe\xe5\x6c\xdd\x84', record[56]) 
            # Destination Mac Address: 02:02:00:00:ff:02 (80)
            self.assertEqual('\x02\x02\x00\x00\xff\x02', record[80])

            self.assertEqual('\x08\x00', record[256])       # Ethernet Type: 8 (256)
            self.assertEqual('\xac\x10\x01\x02', record[8]) # SrcAddr: 172.16.1.2 (8)
            self.assertEqual('\xac\x10\x02\x02', record[12])# DstAddr: 172.16.2.2 (12)
            self.assertEqual('\x00', record[5])             # IP ToS: 0x00 (5)

    def verify_ipfix_l2_only(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)
            #self.assertEqual('\x02\xfe\xe5\x6c\xdd\x84', record[56]) 
            # Destination Mac Address: 02:02:00:00:ff:02 (80)
            self.assertEqual('\x02\x02\x00\x00\xff\x02', record[80])

            self.assertEqual('\x08\x00', record[256])       # Ethernet Type: 8 (256)

    def verify_ipfix_l2_ip6(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)
            #self.assertEqual('\x02\xfe\xe5\x6c\xdd\x84', record[56]) 
            # Destination Mac Address: 02:02:00:00:ff:02 (80)
            self.assertEqual('\x02\x02\x00\x00\xff\x02', record[80])

            self.assertEqual('\x86\xdd', record[256])       # Ethernet Type: 8 (256)

    def verify_ipfix_ip6_only(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)

    def test_l2_ip4_fpp(self):
        """ Flow per packet L2/IP4 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        self.pg_enable_capture(self.pg_interfaces)
        collector_if = self.pg2

        self.vapi.set_ipfix_exporter(collector_address=collector_if.remote_ip4n,
                                     src_address=collector_if.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        self.vapi.flowperpkt_tx_interface_add_del(is_add=1, which=2,
                                                  record_l2=True,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)
        self.vapi.cli("trace add flowperpkt-l2 10")
        pkts = create_stream_ip4(self, self.pg0, self.pg1,
                                 self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        self.vapi.cli("ipfix flush")
        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))

        capture = collector_if.get_capture(4)
        ipfix = IPFIXDecoder()
        foundtemplate = False
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                foundtemplate = True
        self.assertTrue(foundtemplate, "No template packet received")
        founddata = False
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_l2_ip4(data)
                founddata = True
        self.assertTrue(founddata, "No data packet received")

        self.vapi.flowperpkt_tx_interface_add_del(is_add=0, which=2,
                                                  record_l2=True,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)

    def test_l2_ip6_fpp(self):
        """ Flow per packet L2/IP6 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        self.pg_enable_capture(self.pg_interfaces)
        collector_if = self.pg2

        self.vapi.set_ipfix_exporter(collector_address=collector_if.remote_ip4n,
                                     src_address=collector_if.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        self.vapi.flowperpkt_tx_interface_add_del(is_add=1, which=2,
                                                  record_l2=True,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)
        self.vapi.cli("trace add flowperpkt-l2 10")
        pkts = create_stream_ip6(self, self.pg0, self.pg1,
                                 self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        self.vapi.cli("ipfix flush")
        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))

        capture = collector_if.get_capture(4)
        ipfix = IPFIXDecoder()
        foundtemplate = False
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                foundtemplate = True
        self.assertTrue(foundtemplate, "No template packet received")
        founddata = False
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_l2_ip6(data)
                founddata = True
        self.assertTrue(founddata, "No data packet received")

        self.vapi.flowperpkt_tx_interface_add_del(is_add=0, which=2,
                                                  record_l2=True,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)

    def test_l2_only_fpp(self):
        """ Flow per packet L2 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        self.pg_enable_capture(self.pg_interfaces)
        collector_if = self.pg2

        self.vapi.set_ipfix_exporter(collector_address=collector_if.remote_ip4n,
                                     src_address=collector_if.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        self.vapi.flowperpkt_tx_interface_add_del(is_add=1, which=2,
                                                  record_l2=True,
                                                  sw_if_index=self.pg1.sw_if_index)
        self.vapi.cli("trace add flowperpkt-l2 10")
        pkts = create_stream_ip4(self, self.pg0, self.pg1,
                                 self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        self.vapi.cli("ipfix flush")
        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))

        capture = collector_if.get_capture(2)
        ipfix = IPFIXDecoder()
        foundtemplate = False
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                foundtemplate = True
        self.assertTrue(foundtemplate, "No template packet received")
        founddata = False
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_l2_only(data)
                founddata = True
        self.assertTrue(founddata, "No data packet received")

        self.vapi.flowperpkt_tx_interface_add_del(is_add=0, which=2,
                                                  record_l2=True,
                                                  sw_if_index=self.pg1.sw_if_index)


class TestIP6Flowperpkt(VppTestCase):
    """ Flow-per-packet plugin: test IP6 reporting """

    def setUp(self):
        """
       Set up

        **Config:**
            - create three PG interfaces
        """
        super(TestIP6Flowperpkt, self).setUp()
        try:
            self.create_pg_interfaces(range(3))
            self.pg_if_packet_sizes = [150]
            self.interfaces = list(self.pg_interfaces)
            for intf in self.interfaces:
                intf.config_ip4()
                intf.config_ip6()
                intf.admin_up()
                intf.resolve_arp()
                intf.resolve_ndp()
            self.pg2.configure_ipv4_neighbors()
        except Exception:
            super(TestIP6Flowperpkt, self.tearDown())
            raise

    def verify_ipfix_ip6_only(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)

    def test_ip6_fpp(self):
        """ Flow per packet IP6 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        # Have to wait so we don't pick up MLD messages
        import time
        time.sleep(1)

        self.pg_enable_capture(self.pg_interfaces)
        collector_if = self.pg2

        self.vapi.set_ipfix_exporter(collector_address=collector_if.remote_ip4n,
                                     src_address=collector_if.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        self.vapi.flowperpkt_tx_interface_add_del(is_add=1, which=1,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)
        self.vapi.cli("trace add flowperpkt-l2 10")
        pkts = create_stream_ip6(self, self.pg0, self.pg1,
                                 self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        self.vapi.cli("ipfix flush")
        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))

        capture = collector_if.get_capture(2)
        ipfix = IPFIXDecoder()
        foundtemplate = False
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                foundtemplate = True
        self.assertTrue(foundtemplate, "No template packet received")
        founddata = False
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_ip6_only(data)
                founddata = True
        self.assertTrue(founddata, "No data packet received")

        self.vapi.flowperpkt_tx_interface_add_del(is_add=0, which=1,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)

class TestIP4Flowperpkt(VppTestCase):
    """ Flow-per-packet plugin: test IP4 reporting """

    def setUp(self):
        """
       Set up

        **Config:**
            - create three PG interfaces
        """
        super(TestIP4Flowperpkt, self).setUp()
        try:
            self.create_pg_interfaces(range(3))
            self.pg_if_packet_sizes = [150]
            self.interfaces = list(self.pg_interfaces)
            for intf in self.interfaces:
                intf.config_ip4()
                intf.admin_up()
                intf.resolve_arp()
            self.pg2.configure_ipv4_neighbors()
        except Exception:
            super(TestIP4Flowperpkt, self.tearDown())
            raise

    def verify_ipfix_ip4_only(self, data):
        self.assertEqual(1, len(data))
        for record in data:
            self.assertEqual(pack("!I", 1), record[10])     # InputInt: 1 (10)
            self.assertEqual(pack("!I", 2), record[14])     # OutputInt: 2 (14)
            self.assertEqual(pack("!H", 146), record[312])  # Data Link Frame Size: 146 (312)

    def test_ip4_fpp(self):
        """ Flow per packet IP4 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        # Have to wait so we don't pick up MLD messages
        import time
        time.sleep(1)

        self.pg_enable_capture(self.pg_interfaces)
        collector_if = self.pg2

        self.vapi.set_ipfix_exporter(collector_address=collector_if.remote_ip4n,
                                     src_address=collector_if.local_ip4n,
                                     path_mtu=1450,
                                     template_interval=1)

        self.vapi.flowperpkt_tx_interface_add_del(is_add=1, which=0,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)
        self.vapi.cli("trace add flowperpkt-l2 10")
        pkts = create_stream_ip4(self, self.pg0, self.pg1,
                                 self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        self.vapi.cli("ipfix flush")
        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))

        capture = collector_if.get_capture(2)
        ipfix = IPFIXDecoder()
        foundtemplate = False
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
                foundtemplate = True
        self.assertTrue(foundtemplate, "No template packet received")
        founddata = False
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_ip4_only(data)
                founddata = True
        self.assertTrue(founddata, "No data packet received")

        self.vapi.flowperpkt_tx_interface_add_del(is_add=0, which=0,
                                                  record_l3=True,
                                                  sw_if_index=self.pg1.sw_if_index)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
