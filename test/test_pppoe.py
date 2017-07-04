#!/usr/bin/env python

import unittest
from logging import *

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi_provider import L2_VTR_OP

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoE, PPPoED, PPP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.volatile import RandMAC, RandIP

from util import ppp, ppc, mactobinary
import socket


class TestPPPoE(VppTestCase):
    """ PPPoE Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPPPoE, cls).setUpClass()

        cls.client_ip = "100.1.2.1"
        cls.client_ipn = socket.inet_pton(socket.AF_INET, cls.client_ip)
        cls.session_id = 1
        cls.client_mac = "00:11:01:00:00:01"
        cls.dst_ip = "100.1.1.100"
        cls.dst_ipn = socket.inet_pton(socket.AF_INET, cls.dst_ip)

    def setUp(self):
        super(TestPPPoE, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestPPPoE, self).tearDown()

        self.logger.info(self.vapi.cli("show int"))
        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))
        self.logger.info(self.vapi.cli("show trace"))

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def add_pppoe_session(self):
        r = self.vapi.pppoe_add_del_session(self.client_ipn,
                                            mactobinary(self.client_mac),
                                            session_id=self.session_id)

    def del_pppoe_session(self):
        r = self.vapi.pppoe_add_del_session(self.client_ipn,
                                            mactobinary(self.client_mac),
                                            session_id=self.session_id,
                                            is_add=0)

    def create_stream_pppoe_discovery(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=self.client_mac) /
                 PPPoED(sessionid=0) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_pppoe_lcp(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=self.client_mac) /
                 PPPoE(sessionid=self.session_id) /
                 PPP(proto=0xc021) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_pppoe_ip4(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=self.client_mac) /
                 PPPoE(sessionid=self.session_id) /
                 PPP(proto=0x0021) /
                 IP(src=self.client_ip, dst=self.dst_ip) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)

        # return the created packet list
        return packets

    def create_stream_ip4(self, src_if, dst_if, count):
        pkts = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=self.dst_ip, dst=self.client_ip) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            pkts.append(p)

        # return the created packet list
        return pkts

    def verify_decapped_pppoe(self, src_if, capture, sent):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_encaped_pppoe(self, src_if, capture, sent):

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

                rx_pppoe = rx[PPPoE]

                self.assertEqual(rx_pppoe.sessionid, self.session_id)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def test_PPPoE_Decap(self):
        """ PPPoE Decap Test """

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(self, "100.1.1.100", 32,
                                     [VppRoutePath(self.pg1.remote_ip4,
                                                   self.pg1.sw_if_index)])
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(self.pg0, self.pg1, 1)
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(self.pg0, self.pg1, 1)
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        self.add_pppoe_session()

        #
        # Send tunneled packets that match the created tunnel and
        # are decapped and forwarded
        #
        tx2 = self.create_stream_pppoe_ip4(self.pg0, self.pg1, 1)
        self.pg0.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg1.get_capture(len(tx2))
        self.verify_decapped_pppoe(self.pg0, rx2, tx2)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        self.del_pppoe_session()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

    def test_PPPoE_Encap(self):
        """ PPPoE Encap Test """

        self.vapi.cli("clear trace")

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(self, "100.1.1.100", 32,
                                     [VppRoutePath(self.pg1.remote_ip4,
                                                   self.pg1.sw_if_index)])
        route_sever_dst.add_vpp_config()

        # Send PPPoE Discovery
        tx0 = self.create_stream_pppoe_discovery(self.pg0, self.pg1, 1)
        self.pg0.add_stream(tx0)
        self.pg_start()

        # Send PPPoE PPP LCP
        tx1 = self.create_stream_pppoe_lcp(self.pg0, self.pg1, 1)
        self.pg0.add_stream(tx1)
        self.pg_start()

        # Create PPPoE session
        self.add_pppoe_session()

        #
        # Send a packet stream that is routed into the session
        #  - packets are PPPoE encapped
        #
        self.vapi.cli("clear trace")
        tx2 = self.create_stream_ip4(self.pg1, self.pg0, 1)
        self.pg1.add_stream(tx2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx2 = self.pg0.get_capture(len(tx2))
        self.verify_encaped_pppoe(self.pg1, rx2, tx2)

        self.logger.info(self.vapi.cli("show pppoe fib"))
        self.logger.info(self.vapi.cli("show pppoe session"))
        self.logger.info(self.vapi.cli("show ip fib"))

        #
        # test case cleanup
        #

        # Delete PPPoE session
        self.del_pppoe_session()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
