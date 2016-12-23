#!/usr/bin/env python

import unittest
import socket
import binascii
import time

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.utils import hexdump
from util import ppp

class TestFlowperpkt(VppTestCase):
    """ Flow-per-packet plugin: test both L2 and IP4 reporting """

    def setUp(self):
        """
        Set up

        **Config:**
            - create three PG interfaces
            - create a couple of loopback interfaces
        """
        super(TestFlowperpkt, self).setUp()

        self.create_pg_interfaces(range(3))

        self.pg_if_packet_sizes = [150]

        self.interfaces = list(self.pg_interfaces)

        for intf in self.interfaces:
            intf.admin_up()
            intf.config_ip4()
            intf.resolve_arp()

    def tearDown(self):
        """Run standard test teardown"""
        super(TestFlowperpkt, self).tearDown()


    def create_stream(self, src_if, dst_if, packet_sizes):
        """Create a packet stream to tickle the plugin

        :param VppInterface src_if: Source interface for packet stream
        :param VppInterface src_if: Dst interface for packet stream
        :param list packet_sizes: Sizes to test
        """
        pkts = []
        for size in packet_sizes:
            info = self.create_packet_info(src_if.sw_if_index, 
                                           dst_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(src=src_if.local_mac, dst=dst_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=4321) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_ipfix(self, collector_if):
        """Check the ipfix capture"""
        found_data_packet = 0
        found_template_packet = 0
        found_l2_data_packet = 0
        found_l2_template_packet = 0

        # Scapy, of course, understands ipfix not at all...
        # These data vetted by manual inspection in wireshark
        # X'ed out fields are timestamps, which will absolutely
        # fail to compare. At L2, kill the pg src MAC address, which
        # is random.
        
        data_udp_string = "1283128300370000000a002fXXXXXXXX00000000000000010100001f0000000100000002ac100102ac10020200XXXXXXXXXXXXXXXX0092"

        template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000000010002002401000007000a0004000e000400080004000c000400050001009c000801380002"

        l2_data_udp_string =  "12831283003c0000000a0034XXXXXXXX0000000100000001010100240000000100000002XXXXXXXXXXXX02020000ff020008XXXXXXXXXXXXXXXX0092"

        l2_template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000000010002002401010007000a0004000e0004003800060050000601000002009c000801380002"

        cap_x = "X"
        data_udp_len = len(data_udp_string)
        template_udp_len = len(template_udp_string)
        l2_data_udp_len = len(l2_data_udp_string)
        l2_template_udp_len = len(l2_template_udp_string)

        self.logger.info("Look for ipfix packets on %s sw_if_index %d " 
                         % (collector_if.name, collector_if.sw_if_index))
        capture = collector_if.get_capture()

        for p in capture:
            data_result = ""
            template_result = ""
            l2_data_result = ""
            l2_template_result = ""
            unmasked_result = ""
            ip = p[IP]
            udp = p[UDP]
            self.logger.info("src %s dst %s" % (ip.src, ip.dst))
            self.logger.info(" udp src_port %s dst_port %s" 
                             % (udp.sport, udp.dport))

            # Hex-dump the UDP datagram 4 ways in parallel
            # X'ing out incomparable fields
            # Python completely bites at this sort of thing, of course

            x = str(udp)
            l = len(x)
            i = 0
            while i < l:
                # If current index within range
                if i < data_udp_len/2:
                    # See if we're supposed to don't care the data
                    if ord(data_udp_string[i*2]) == ord(cap_x[0]):
                        data_result = data_result + "XX"
                    else:
                        data_result = data_result + ("%02x" % ord(x[i]))
                else:
                    # index out of range, emit actual data
                    # The test will fail, but it may help debug, etc.
                    data_result = data_result + ("%02x" % ord(x[i]))
                    
                if i < template_udp_len/2:
                    if ord(template_udp_string[i*2]) == ord(cap_x[0]):
                        template_result = template_result + "XX"
                    else:
                        template_result = template_result + ("%02x" % ord(x[i]))
                else:
                    template_result = template_result + ("%02x" % ord(x[i]))

                if i < l2_data_udp_len/2:
                    # See if we're supposed to don't care the data
                    if ord(l2_data_udp_string[i*2]) == ord(cap_x[0]):
                        l2_data_result = l2_data_result + "XX"
                    else:
                        l2_data_result = l2_data_result + ("%02x" % ord(x[i]))
                else:
                    # index out of range, emit actual data
                    # The test will fail, but it may help debug, etc.
                    l2_data_result = l2_data_result + ("%02x" % ord(x[i]))
                
                if i < l2_template_udp_len/2:
                    if ord(l2_template_udp_string[i*2]) == ord(cap_x[0]):
                        l2_template_result = l2_template_result + "XX"
                    else:
                        l2_template_result = l2_template_result + ("%02x" % ord(x[i]))
                else:
                    l2_template_result = l2_template_result + ("%02x" % ord(x[i]))
                # In case we need to 
                unmasked_result = unmasked_result + ("%02x" % ord(x[i]))

                i = i + 1

            if data_result == data_udp_string:
                self.logger.info ("found ip4 data packet")
                found_data_packet = 1
            elif template_result == template_udp_string:
                self.logger.info ("found ip4 template packet")
                found_template_packet = 1
            elif l2_data_result == l2_data_udp_string:
                self.logger.info ("found l2 data packet")
                found_l2_data_packet = 1
            elif l2_template_result == l2_template_udp_string:
                self.logger.info ("found l2 template packet")
                found_l2_template_packet = 1
            else:
                self.logger.info ("unknown pkt '%s'" % unmasked_result)
                
        self.assertTrue (found_data_packet == 1)
        self.assertTrue (found_template_packet == 1)
        self.assertTrue (found_l2_data_packet == 1)
        self.assertTrue (found_l2_template_packet == 1)

    def test_L3_fpp(self):
        """ Flow per packet L3 test """

        # Configure an ipfix report on the [nonexistent] collector
        # 172.16.3.2, as if it was connected to the pg2 interface
        # Install a FIB entry, so the exporter's work won't turn into
        # an ARP request

        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.cli("set ip arp pg2 172.16.3.2 dead.beef.0002")
        self.logger.info(self.vapi.cli("set ipfix exporter collector 172.16.3.2 src 172.16.3.1 path-mtu 1450 template-interval 1"))

        # Export flow records for all pkts transmitted on pg1

        self.logger.info(self.vapi.cli("flowperpkt feature add-del pg1"))
        self.logger.info(self.vapi.cli("flowperpkt feature add-del pg1 l2"))

        # Arrange to minimally trace generated ipfix packets
        self.logger.info(self.vapi.cli("trace add flowperpkt-ipv4 10"))
        self.logger.info(self.vapi.cli("trace add flowperpkt-l2 10"))

        # Create a stream from pg0 -> pg1, which causes
        # an ipfix packet to be transmitted on pg2
        
        pkts = self.create_stream(self.pg0, self.pg1, 
                                  self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)
        self.pg_start()
        
        # Flush the ipfix collector, so we don't need any
        # asinine time.sleep(5) action

        self.logger.info(self.vapi.cli("ipfix flush"))
        
        # Make sure the 4 pkts we expect actually showed up
        self.verify_ipfix(self.pg2)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
            
        
    
        
