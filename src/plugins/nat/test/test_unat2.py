#!/usr/bin/env python3
"""IP4 UNAT functional tests"""

import unittest
from scapy.layers.inet import ICMP, TCP, Ether, IP, UDP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from socket import AF_INET, inet_pton
from util import reassemble4
from scapy.packet import Raw
from vpp_papi import mac_pton, VppEnum
from scapy.layers.dhcp import DHCP, BOOTP, DHCPTypes
from vpp_dhcp import VppDHCPClient
from vpp_ip_route import find_route, VppIpTable
from scapy.layers.l2 import Ether, getmacbyip, ARP, Dot1Q

""" Test_unat2 is a subclass of VPPTestCase classes.
    UNAT tests.
"""

DHCP4_CLIENT_PORT = 68
DHCP4_SERVER_PORT = 67


class TestUNAT(VppTestCase):
    """ UNAT Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestUNAT, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestUNAT, cls).tearDownClass()

    def setUp(self):
        super(TestUNAT, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.cli(f"set interface unat in {self.interfaces[0]}")
        self.vapi.cli(f"set interface unat out {self.interfaces[1]}")
        self.vapi.cli(f"set unat prefix-pool interface pg1")

    def tearDown(self):
        super(TestUNAT, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                #i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        print('RECIVED: ')
        rx.show2()
        print('EXPECTED: ')
        expected.show2()
        expected.id = rx.id
        self.assertEqual(rx, expected.__class__(expected))


    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def verify_dhcp_msg_type(self, pkt, name):
        dhcp = pkt[DHCP]
        found = False
        for o in dhcp.options:
            if isinstance(o, tuple):
                if o[0] == "message-type" \
                   and DHCPTypes[o[1]] == name:
                    found = True
        self.assertTrue(found)

    def verify_dhcp_has_option(self, pkt, option, value):
        dhcp = pkt[DHCP]
        found = False

        for i in dhcp.options:
            if isinstance(i, tuple):
                if i[0] == option:
                    self.assertEqual(i[1], value)
                    found = True

        self.assertTrue(found)

    def verify_orig_dhcp_request(self, pkt, intf, hostname, ip,
                                 broadcast=True,
                                 l2_bc=True,
                                 dscp=0):
        self.verify_orig_dhcp_pkt(pkt, intf, dscp, l2_bc=l2_bc)

        self.verify_dhcp_msg_type(pkt, "request")
        self.verify_dhcp_has_option(pkt, "hostname",
                                    hostname.encode('ascii'))
        self.verify_dhcp_has_option(pkt, "requested_addr", ip)
        bootp = pkt[BOOTP]

        if l2_bc:
            self.assertEqual(bootp.ciaddr, "0.0.0.0")
        else:
            self.assertEqual(bootp.ciaddr, intf.local_ip4)
        self.assertEqual(bootp.giaddr, "0.0.0.0")

        if broadcast:
            self.assertEqual(bootp.flags, 0x8000)
        else:
            self.assertEqual(bootp.flags, 0x0000)

    def verify_orig_dhcp_pkt(self, pkt, intf, dscp, l2_bc=True):
        ether = pkt[Ether]
        if l2_bc:
            self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        else:
            self.assertEqual(ether.dst, intf.remote_mac)
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]

        if (l2_bc):
            self.assertEqual(ip.dst, "255.255.255.255")
            self.assertEqual(ip.src, "0.0.0.0")
        else:
            self.assertEqual(ip.dst, intf.remote_ip4)
            self.assertEqual(ip.src, intf.local_ip4)
        self.assertEqual(ip.tos, dscp)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP4_CLIENT_PORT)

    def verify_orig_dhcp_discover(self, pkt, intf, hostname, client_id=None,
                                  broadcast=True, dscp=0):
        self.verify_orig_dhcp_pkt(pkt, intf, dscp)

        self.verify_dhcp_msg_type(pkt, "discover")
        self.verify_dhcp_has_option(pkt, "hostname",
                                    hostname.encode('ascii'))
        if client_id:
            client_id = '\x00' + client_id
            self.verify_dhcp_has_option(pkt, "client_id",
                                        client_id.encode('ascii'))
        bootp = pkt[BOOTP]
        self.assertEqual(bootp.ciaddr, "0.0.0.0")
        self.assertEqual(bootp.giaddr, "0.0.0.0")
        if broadcast:
            self.assertEqual(bootp.flags, 0x8000)
        else:
            self.assertEqual(bootp.flags, 0x0000)

    def test_in2out_bypass(self):
        """ IP4 in2out bypass test """

        print(self.vapi.cli("show unat summary"))

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) / ICMP()
        p_payload = Raw(b'\x0a' * 18)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4) / ICMP(type='echo-reply') / p_payload

        rx = self.send_and_expect(self.pg0, p4*1, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

    def test_out2in_bypass(self):
        """ IP4 out2in bypass test """

        print(self.vapi.cli("show unat summary"))

        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) / ICMP()
        p_payload = Raw(b'\x0a' * 18)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = IP(src=self.pg1.local_ip4, dst=self.pg1.remote_ip4) / ICMP(type='echo-reply') / p_payload

        rx = self.send_and_expect(self.pg1, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

    def test_tcp_single_session(self):
        """ IP4 out2in bypass test """

        print(self.vapi.cli("show unat summary"))

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) / TCP()

        p4 = p_ether / p_ip4
        p4_reply = IP(src=self.pg1.local_ip4, dst=self.pg1.remote_ip4) / TCP()

        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        print(self.vapi.cli("show unat sessions"))
        for p in rx:
            self.validate(p[1], p4_reply)

    def wait_for_no_route(self, address, length,
                          n_tries=50, s_time=1):
        while (n_tries):
            if not find_route(self, address, length):
                return True
            n_tries = n_tries - 1
            self.sleep(s_time)

        return False

    def test_dhcp_client(self):
        """ DHCP Client"""

        vdscp = VppEnum.vl_api_ip_dscp_t
        hostname = 'universal-dp'

        self.pg_enable_capture(self.pg_interfaces)

        #
        # Configure DHCP client on PG1 and capture the discover sent
        #
        Client = VppDHCPClient(self, self.pg1.sw_if_index, hostname)
        Client.add_vpp_config()
        self.assertTrue(Client.query_vpp_config())

        rx = self.pg1.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg1, hostname)

        #
        # Send back on offer, expect the request
        #
        p_offer = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst="255.255.255.255") /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1,
                         yiaddr=self.pg1.local_ip4,
                         chaddr=mac_pton(self.pg1.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg1.remote_ip4),
                                 'end']))

        self.pg1.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg1, hostname,
                                      self.pg1.local_ip4)

        #
        # Send an acknowledgment
        #
        p_ack = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst="255.255.255.255") /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg1.local_ip4,
                       chaddr=mac_pton(self.pg1.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg1.remote_ip4),
                               ('server_id', self.pg1.remote_ip4),
                               ('lease_time', 43200),
                               'end']))

        self.pg1.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        '''
        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg1.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)
        '''
        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg1.local_ip4, 24))
        self.assertTrue(find_route(self, self.pg1.local_ip4, 32))

        #
        # remove the DHCP config
        #
        Client.remove_vpp_config()

        #
        # and now the route should be gone
        #
        self.assertFalse(find_route(self, self.pg1.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg1.local_ip4, 24))

        #
        # Start the procedure again. this time have VPP send the client-ID
        # and set the DSCP value
        #
        self.pg1.admin_down()
        self.sleep(1)
        self.pg1.admin_up()
        Client.set_client(self.pg1.sw_if_index, hostname,
                          id=self.pg1.local_mac,
                          dscp=vdscp.IP_API_DSCP_EF)
        Client.add_vpp_config()

        rx = self.pg1.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg1, hostname,
                                       self.pg1.local_mac,
                                       dscp=vdscp.IP_API_DSCP_EF)

        # TODO: VPP DHCP client should not accept DHCP OFFER message with
        # the XID (Transaction ID) not matching the XID of the most recent
        # DHCP DISCOVERY message.
        # Such DHCP OFFER message must be silently discarded - RFC2131.
        # Reported in Jira ticket: VPP-99
        self.pg1.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg1, hostname,
                                      self.pg1.local_ip4,
                                      dscp=vdscp.IP_API_DSCP_EF)

        #
        # unicast the ack to the offered address
        #
        p_ack = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg1.local_ip4,
                       chaddr=mac_pton(self.pg1.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg1.remote_ip4),
                               ('server_id', self.pg1.remote_ip4),
                               ('lease_time', 43200),
                               'end']))

        self.pg1.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg1.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg1.local_ip4, 32))
        self.assertTrue(find_route(self, self.pg1.local_ip4, 24))

        #
        # remove the DHCP config
        #
        Client.remove_vpp_config()

        self.assertFalse(find_route(self, self.pg1.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg1.local_ip4, 24))

        #
        # Rince and repeat, this time with VPP configured not to set
        # the braodcast flag in the discover and request messages,
        # and for the server to unicast the responses.
        #
        # Configure DHCP client on PG3 and capture the discover sent
        #
        Client.set_client(
            self.pg1.sw_if_index,
            hostname,
            set_broadcast_flag=False)
        Client.add_vpp_config()

        rx = self.pg1.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg1, hostname,
                                       broadcast=False)

        #
        # Send back on offer, unicasted to the offered address.
        # Expect the request.
        #
        p_offer = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1, yiaddr=self.pg1.local_ip4,
                         chaddr=mac_pton(self.pg1.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg1.remote_ip4),
                                 'end']))

        self.pg1.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg1, hostname,
                                      self.pg1.local_ip4,
                                      broadcast=False)

        #
        # Send an acknowledgment, the lease renewal time is 2 seconds
        # so we should expect the renew straight after
        #
        p_ack = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg1.local_ip4,
                       chaddr=mac_pton(self.pg1.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg1.remote_ip4),
                               ('server_id', self.pg1.remote_ip4),
                               ('lease_time', 43200),
                               ('renewal_time', 2),
                               'end']))

        self.pg1.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg1.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg1.local_ip4, 24))
        self.assertTrue(find_route(self, self.pg1.local_ip4, 32))

        #
        # read the DHCP client details from a dump
        #
        clients = self.vapi.dhcp_client_dump()

        self.assertEqual(clients[0].client.sw_if_index,
                         self.pg1.sw_if_index)
        self.assertEqual(clients[0].lease.sw_if_index,
                         self.pg1.sw_if_index)
        self.assertEqual(clients[0].client.hostname, hostname)
        self.assertEqual(clients[0].lease.hostname, hostname)
        # 0 = DISCOVER, 1 = REQUEST, 2 = BOUND
        self.assertEqual(clients[0].lease.state, 2)
        self.assertEqual(clients[0].lease.mask_width, 24)
        self.assertEqual(str(clients[0].lease.router_address),
                         self.pg1.remote_ip4)
        self.assertEqual(str(clients[0].lease.host_address),
                         self.pg1.local_ip4)

        #
        # wait for the unicasted renewal
        #  the first attempt will be an ARP packet, since we have not yet
        #  responded to VPP's request
        #
        self.logger.info(self.vapi.cli("sh dhcp client intfc pg1 verbose"))
        rx = self.pg1.get_capture(1, timeout=10)

        self.assertEqual(rx[0][ARP].pdst, self.pg1.remote_ip4)

        # respond to the arp
        p_arp = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 ARP(op="is-at",
                     hwdst=self.pg1.local_mac,
                     hwsrc=self.pg1.remote_mac,
                     pdst=self.pg1.local_ip4,
                     psrc=self.pg1.remote_ip4))
        self.pg1.add_stream(p_arp)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # the next packet is the unicasted renewal
        rx = self.pg1.get_capture(1, timeout=10)
        self.verify_orig_dhcp_request(rx[0], self.pg1, hostname,
                                      self.pg1.local_ip4,
                                      l2_bc=False,
                                      broadcast=False)

        # send an ACK with different data from the original offer *
        self.pg1.generate_remote_hosts(4)
        p_ack = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg1.remote_hosts[3].ip4,
                       chaddr=mac_pton(self.pg1.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg1.remote_hosts[1].ip4),
                               ('server_id', self.pg1.remote_hosts[2].ip4),
                               ('lease_time', 43200),
                               ('renewal_time', 2),
                               'end']))

        self.pg1.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # read the DHCP client details from a dump
        #
        clients = self.vapi.dhcp_client_dump()

        self.assertEqual(clients[0].client.sw_if_index,
                         self.pg1.sw_if_index)
        self.assertEqual(clients[0].lease.sw_if_index,
                         self.pg1.sw_if_index)
        self.assertEqual(clients[0].client.hostname, hostname)
        self.assertEqual(clients[0].lease.hostname, hostname)
        # 0 = DISCOVER, 1 = REQUEST, 2 = BOUND
        self.assertEqual(clients[0].lease.state, 2)
        self.assertEqual(clients[0].lease.mask_width, 24)
        self.assertEqual(str(clients[0].lease.router_address),
                         self.pg1.remote_hosts[1].ip4)
        self.assertEqual(str(clients[0].lease.host_address),
                         self.pg1.remote_hosts[3].ip4)

        #
        # remove the DHCP config
        #
        Client.remove_vpp_config()

        #
        # and now the route should be gone
        #
        self.assertFalse(find_route(self, self.pg1.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg1.local_ip4, 24))

        #
        # Start the procedure again. Use requested lease time option.
        # this time wait for the lease to expire and the client to
        # self-destruct
        #
        hostname += "-2"
        self.pg1.admin_down()
        self.sleep(1)
        self.pg1.admin_up()
        self.pg_enable_capture(self.pg_interfaces)
        Client.set_client(self.pg1.sw_if_index, hostname)
        Client.add_vpp_config()

        rx = self.pg1.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg1, hostname)

        #
        # Send back on offer with requested lease time, expect the request
        #
        lease_time = 1
        p_offer = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst='255.255.255.255') /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1,
                         yiaddr=self.pg1.local_ip4,
                         chaddr=mac_pton(self.pg1.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg1.remote_ip4),
                                 ('lease_time', lease_time),
                                 'end']))

        self.pg1.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg1, hostname,
                                      self.pg1.local_ip4)

        #
        # Send an acknowledgment
        #
        p_ack = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst='255.255.255.255') /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg1.local_ip4,
                       chaddr=mac_pton(self.pg1.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', '255.255.255.0'),
                               ('router', self.pg1.remote_ip4),
                               ('server_id', self.pg1.remote_ip4),
                               ('lease_time', lease_time),
                               'end']))

        self.pg1.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg1.remote_ip4)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg1.local_ip4, 32))
        self.assertTrue(find_route(self, self.pg1.local_ip4, 24))

        #
        # the route should be gone after the lease expires
        #
        self.assertTrue(self.wait_for_no_route(self.pg1.local_ip4, 32))
        self.assertTrue(self.wait_for_no_route(self.pg1.local_ip4, 24))

        #
        # remove the DHCP config
        #
        Client.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
