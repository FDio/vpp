#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import IpRoute, RoutePath
from vpp_lo_interface import VppLoInterface

from scapy.layers.l2 import Ether, getmacbyip
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import DHCP, BOOTP
from socket import AF_INET, AF_INET6

class TestDHCP(VppTestCase):
    """ DHCP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestDHCP, cls).setUpClass()

    def setUp(self):
        super(TestDHCP, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(4))

        # pg0 and 1 are IP configured in VRF 0 and 1.
        # pg2 and 3 are non IP-confgured in VRF 0 and 1
        table_id = 0
        for i in self.pg_interfaces[:1]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

        table_id = 0
        for i in self.pg_interfaces[2:]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            table_id += 1

        self.pg3 = self.pg_interfaces[3]

    def tearDown(self):
        super(TestDHCP, self).tearDown()

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        intf.assert_nothing_captured(remark=remark)

    def validate_option_82(self, pkt, intf, ip_addr):
        dhcp = pkt[DHCP]
        found = 0
        data = []
        print dhcp.options

        for i in dhcp.options:
            if type(i) is tuple:
                if i[0] == "relay_agent_Information":
                    #
                    # First sub-optin is num 1, len 4, then encoded 
                    #  sw_if_index = 3 (pg2)
                    #
                    data = i[1];
                    self.assertEqual(len(data), 12)

                    print type(data[0])
                    self.assertEqual(ord(data[0]), 1)
                    self.assertEqual(ord(data[1]), 4)
                    self.assertEqual(ord(data[2]), 0)
                    self.assertEqual(ord(data[3]), 0)
                    self.assertEqual(ord(data[4]), 0)
                    self.assertEqual(ord(data[5]), intf._sw_if_index)

                    #
                    # next sub-option is the IP address of the clinet side interface
                    #
                    claddr = socket.inet_pton(AF_INET, ip_addr)

                    self.assertEqual(ord(data[6]), 5)
                    self.assertEqual(ord(data[7]), 4)
                    self.assertEqual(data[8], claddr[0])
                    self.assertEqual(data[9], claddr[1])
                    self.assertEqual(data[10], claddr[2])
                    self.assertEqual(data[11], claddr[3])

                    found = 1
        self.assertTrue(found)

        return data

    def verify_dhcp_offer(self, pkt, intf, check_option_82=True):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, "255.255.255.255")
        self.assertEqual(ip.src, intf.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, 68)
        self.assertEqual(udp.sport, 67)

        # TODO check it's an offer
        if check_option_82:
            data = self.validate_option_82(pkt, intf, intf.local_ip4)

    def verify_dhcp_request(self, pkt, intf, src_intf=None, option_82_present=True):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, self.pg0.remote_mac)
        self.assertEqual(ether.src, self.pg0.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, self.pg0.remote_ip4)
        self.assertEqual(ip.src, self.pg0.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, 67)
        self.assertEqual(udp.sport, 68)

        dhcp = pkt[DHCP]

        if option_82_present:
             data = self.validate_option_82(pkt, src_intf, src_intf.local_ip4)
             return data
        else:
            for i in dhcp.options:
                if type(i) is tuple:
                    self.assertNotEqual(i[0], "relay_agent_Information")

    def test_dhcp_proxy(self):
        """ DHCP tests """

        #
        # Verify no response to DHCP request without DHCP config
        #
        p_disc = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
                  IP(src="0.0.0.0", dst="255.255.255.255") /
                  UDP(sport=68, dport=67) /
                  BOOTP(op=1) /
                  DHCP(options=[('message-type','discover'), ('end')]))
        pkts_disc = [p_disc]

        self.send_and_assert_no_replies(self.pg2, pkts_disc,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg3, pkts_disc,
                                        "DHCP with no configuration")

        #
        # Enable DHCP proxy in VRF 0
        #
        server_addr = socket.inet_pton(AF_INET, self.pg0.remote_ip4)
        src_addr = socket.inet_pton(AF_INET, self.pg0.local_ip4)

        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0)

        #
        # Now a DHCP request on pg2, which is in the same VRF
        # as the DHCP config, will result in a relayed DHCP
        # message to the [fake] server
        #
        self.pg2.add_stream(pkts_disc)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]

        #
        # Rx'd packet should be to the server address and from the configured
        # source address
        # UDP source ports are unchanged
        # we've no option 82 config so that should be absent
        #
        self.verify_dhcp_request(rx, self.pg0, option_82_present=False)

        #
        # Inject a response from the server
        #  VPP will only relay the offer if option 82 is present.
        #  so this one is dropped
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=67, dport=67) /
             BOOTP(op=1) /
             DHCP(options=[('message-type','offer'), ('end')]))
        pkts = [p]

        self.send_and_assert_no_replies(self.pg2, pkts,
                                        "DHCP offer no option 82")
        self.send_and_assert_no_replies(self.pg3, pkts,
                                        "DHCP offer no option 82")

        #
        # Configure sending option 82 in relayed messages
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0,
                                    insert_circuit_id=1)

        #
        # Send a request:
        #  again dropped, but ths time because there is no IP addrees on the
        #  clinet interfce to fill in the option.
        #
        self.pg2.add_stream(pkts_disc)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "DHCP no relay address")

        #
        # configure an IP address on the client facing interface
        #
        self.pg2.config_ip4()

        #
        # Try again with a discover packet
        # Rx'd packet should be to the server address and from the configured
        # source address
        # UDP source ports are unchanged
        # we've no option 82 config so that should be absent
        #
        self.pg2.add_stream(pkts_disc)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]

        option_82 = self.verify_dhcp_request(rx, self.pg0, src_intf=self.pg2)

        #
        # Create an DHCP offer reply from the server with a correctly formatted
        # option 82. i.e. send back what we just captured
        # The offer, sent mcast to the client, still has option 82.
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=67, dport=67) /
             BOOTP(op=1) /
             DHCP(options=[('message-type','offer'),
                           ('relay_agent_Information',option_82),
                           ('end')]))
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        rx = rx[0]

        self.verify_dhcp_offer(rx, self.pg2)

        #
        # Bogus Option 82:
        #
        # 1. not our IP address = not checked by VPP? so offer is replayed to client
        bad_ip = option_82[0:8] + chr(33) + option_82[9:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=67, dport=67) /
             BOOTP(op=1) /
             DHCP(options=[('message-type','offer'),
                           ('relay_agent_Information',bad_ip),
                           ('end')]))
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg2.get_capture(1)
        rx = rx[0]

        self.verify_dhcp_offer(rx, self.pg2, check_option_82=False)

        # 2. Not a sw_if_index VPP knows
        bad_if_index = option_82[0:2] + chr(33) + option_82[3:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=67, dport=67) /
             BOOTP(op=1) /
             DHCP(options=[('message-type','offer'),
                           ('relay_agent_Information',bad_if_index),
                           ('end')]))
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.send_and_assert_no_replies(self.pg2, pkts,
                                        "DHCP offer option 82 bad if index")

        #
        # Send a DHCP request in VRF 1. should be dropped.
        #
        p_disc = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg1.remote_mac) /
                  IP(src="0.0.0.0", dst="255.255.255.255") /
                  UDP(sport=68, dport=67) /
                  BOOTP(op=1) /
                  DHCP(options=[('message-type','discover'), ('end')]))
        pkts_disc = [p_disc]

        self.pg0.add_stream(pkts_disc)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.send_and_assert_no_replies(self.pg2, pkts_disc,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg3, pkts_disc,
                                        "DHCP with no configuration")

        #
        # Delete the DHCP config in VRF 0
        # Should now drop requests.
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0,
                                    is_add=0,
                                    insert_circuit_id=1)

        p_disc = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
                  IP(src="0.0.0.0", dst="255.255.255.255") /
                  UDP(sport=68, dport=67) /
                  BOOTP(op=1) /
                  DHCP(options=[('message-type','discover'), ('end')]))
        pkts_disc = [p_disc]

        self.pg0.add_stream(pkts_disc)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.send_and_assert_no_replies(self.pg2, pkts_disc,
                                        "DHCP config removed")
        self.send_and_assert_no_replies(self.pg3, pkts_disc,
                                        "DHCP config removed")

        #
        # Add DHCP config for VRF 1
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    insert_circuit_id=1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
