#!/usr/bin/env python

import unittest
import socket
import struct

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_neighbor import VppNeighbor
from vpp_ip_route import find_route, VppIpTable
from util import mk_ll_addr

from scapy.layers.l2 import Ether, getmacbyip, ARP
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, in6_getnsmac
from scapy.utils6 import in6_mactoifaceid
from scapy.layers.dhcp import DHCP, BOOTP, DHCPTypes
from scapy.layers.dhcp6 import DHCP6, DHCP6_Solicit, DHCP6_RelayForward, \
    DHCP6_RelayReply, DHCP6_Advertise, DHCP6OptRelayMsg, DHCP6OptIfaceId, \
    DHCP6OptStatusCode, DHCP6OptVSS, DHCP6OptClientLinkLayerAddr, DHCP6_Request
from socket import AF_INET, AF_INET6
from scapy.utils import inet_pton, inet_ntop
from scapy.utils6 import in6_ptop
from util import mactobinary

DHCP4_CLIENT_PORT = 68
DHCP4_SERVER_PORT = 67
DHCP6_CLIENT_PORT = 547
DHCP6_SERVER_PORT = 546


class TestDHCP(VppTestCase):
    """ DHCP Test Case """

    def setUp(self):
        super(TestDHCP, self).setUp()

        # create 6 pg interfaces for pg0 to pg5
        self.create_pg_interfaces(range(6))
        self.tables = []

        # pg0 to 2 are IP configured in VRF 0, 1 and 2.
        # pg3 to 5 are non IP-configured in VRF 0, 1 and 2.
        table_id = 0
        for table_id in range(1, 4):
            tbl4 = VppIpTable(self, table_id)
            tbl4.add_vpp_config()
            self.tables.append(tbl4)
            tbl6 = VppIpTable(self, table_id, is_ip6=1)
            tbl6.add_vpp_config()
            self.tables.append(tbl6)

        table_id = 0
        for i in self.pg_interfaces[:3]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

        table_id = 0
        for i in self.pg_interfaces[3:]:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            table_id += 1

    def tearDown(self):
        for i in self.pg_interfaces[:3]:
            i.unconfig_ip4()
            i.unconfig_ip6()

        for i in self.pg_interfaces:
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.admin_down()
        super(TestDHCP, self).tearDown()

    def verify_dhcp_has_option(self, pkt, option, value):
        dhcp = pkt[DHCP]
        found = False

        for i in dhcp.options:
            if type(i) is tuple:
                if i[0] == option:
                    self.assertEqual(i[1], value)
                    found = True

        self.assertTrue(found)

    def validate_relay_options(self, pkt, intf, ip_addr, vpn_id, fib_id, oui):
        dhcp = pkt[DHCP]
        found = 0
        data = []
        id_len = len(vpn_id)

        for i in dhcp.options:
            if type(i) is tuple:
                if i[0] == "relay_agent_Information":
                    #
                    # There are two sb-options present - each of length 6.
                    #
                    data = i[1]
                    if oui != 0:
                        self.assertEqual(len(data), 24)
                    elif len(vpn_id) > 0:
                        self.assertEqual(len(data), len(vpn_id)+17)
                    else:
                        self.assertEqual(len(data), 12)

                    #
                    # First sub-option is ID 1, len 4, then encoded
                    #  sw_if_index. This test uses low valued indicies
                    # so [2:4] are 0.
                    # The ID space is VPP internal - so no matching value
                    # scapy
                    #
                    self.assertEqual(ord(data[0]), 1)
                    self.assertEqual(ord(data[1]), 4)
                    self.assertEqual(ord(data[2]), 0)
                    self.assertEqual(ord(data[3]), 0)
                    self.assertEqual(ord(data[4]), 0)
                    self.assertEqual(ord(data[5]), intf._sw_if_index)

                    #
                    # next sub-option is the IP address of the client side
                    # interface.
                    # sub-option ID=5, length (of a v4 address)=4
                    #
                    claddr = socket.inet_pton(AF_INET, ip_addr)

                    self.assertEqual(ord(data[6]), 5)
                    self.assertEqual(ord(data[7]), 4)
                    self.assertEqual(data[8], claddr[0])
                    self.assertEqual(data[9], claddr[1])
                    self.assertEqual(data[10], claddr[2])
                    self.assertEqual(data[11], claddr[3])

                    if oui != 0:
                        # sub-option 151 encodes vss_type 1,
                        # the 3 byte oui and the 4 byte fib_id
                        self.assertEqual(id_len, 0)
                        self.assertEqual(ord(data[12]), 151)
                        self.assertEqual(ord(data[13]), 8)
                        self.assertEqual(ord(data[14]), 1)
                        self.assertEqual(ord(data[15]), 0)
                        self.assertEqual(ord(data[16]), 0)
                        self.assertEqual(ord(data[17]), oui)
                        self.assertEqual(ord(data[18]), 0)
                        self.assertEqual(ord(data[19]), 0)
                        self.assertEqual(ord(data[20]), 0)
                        self.assertEqual(ord(data[21]), fib_id)

                        # VSS control sub-option
                        self.assertEqual(ord(data[22]), 152)
                        self.assertEqual(ord(data[23]), 0)

                    if id_len > 0:
                        # sub-option 151 encode vss_type of 0
                        # followerd by vpn_id in ascii
                        self.assertEqual(oui, 0)
                        self.assertEqual(ord(data[12]), 151)
                        self.assertEqual(ord(data[13]), id_len+1)
                        self.assertEqual(ord(data[14]), 0)
                        self.assertEqual(data[15:15+id_len], vpn_id)

                        # VSS control sub-option
                        self.assertEqual(ord(data[15+len(vpn_id)]), 152)
                        self.assertEqual(ord(data[16+len(vpn_id)]), 0)

                    found = 1
        self.assertTrue(found)

        return data

    def verify_dhcp_msg_type(self, pkt, name):
        dhcp = pkt[DHCP]
        found = False
        for o in dhcp.options:
            if type(o) is tuple:
                if o[0] == "message-type" \
                   and DHCPTypes[o[1]] == name:
                    found = True
        self.assertTrue(found)

    def verify_dhcp_offer(self, pkt, intf, vpn_id="", fib_id=0, oui=0):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, "255.255.255.255")
        self.assertEqual(ip.src, intf.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_CLIENT_PORT)
        self.assertEqual(udp.sport, DHCP4_SERVER_PORT)

        self.verify_dhcp_msg_type(pkt, "offer")
        data = self.validate_relay_options(pkt, intf, intf.local_ip4,
                                           vpn_id, fib_id, oui)

    def verify_orig_dhcp_pkt(self, pkt, intf):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, "255.255.255.255")
        self.assertEqual(ip.src, "0.0.0.0")

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP4_CLIENT_PORT)

    def verify_orig_dhcp_discover(self, pkt, intf, hostname, client_id=None,
                                  broadcast=1):
        self.verify_orig_dhcp_pkt(pkt, intf)

        self.verify_dhcp_msg_type(pkt, "discover")
        self.verify_dhcp_has_option(pkt, "hostname", hostname)
        if client_id:
            self.verify_dhcp_has_option(pkt, "client_id", client_id)
        bootp = pkt[BOOTP]
        self.assertEqual(bootp.ciaddr, "0.0.0.0")
        self.assertEqual(bootp.giaddr, "0.0.0.0")
        if broadcast:
            self.assertEqual(bootp.flags, 0x8000)
        else:
            self.assertEqual(bootp.flags, 0x0000)

    def verify_orig_dhcp_request(self, pkt, intf, hostname, ip,
                                 broadcast=1):
        self.verify_orig_dhcp_pkt(pkt, intf)

        self.verify_dhcp_msg_type(pkt, "request")
        self.verify_dhcp_has_option(pkt, "hostname", hostname)
        self.verify_dhcp_has_option(pkt, "requested_addr", ip)
        bootp = pkt[BOOTP]
        self.assertEqual(bootp.ciaddr, "0.0.0.0")
        self.assertEqual(bootp.giaddr, "0.0.0.0")
        if broadcast:
            self.assertEqual(bootp.flags, 0x8000)
        else:
            self.assertEqual(bootp.flags, 0x0000)

    def verify_relayed_dhcp_discover(self, pkt, intf, src_intf=None,
                                     fib_id=0, oui=0,
                                     vpn_id="",
                                     dst_mac=None, dst_ip=None):
        if not dst_mac:
            dst_mac = intf.remote_mac
        if not dst_ip:
            dst_ip = intf.remote_ip4

        ether = pkt[Ether]
        self.assertEqual(ether.dst, dst_mac)
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IP]
        self.assertEqual(ip.dst, dst_ip)
        self.assertEqual(ip.src, intf.local_ip4)

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP4_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP4_CLIENT_PORT)

        dhcp = pkt[DHCP]

        is_discover = False
        for o in dhcp.options:
            if type(o) is tuple:
                if o[0] == "message-type" \
                   and DHCPTypes[o[1]] == "discover":
                    is_discover = True
        self.assertTrue(is_discover)

        data = self.validate_relay_options(pkt, src_intf,
                                           src_intf.local_ip4,
                                           vpn_id,
                                           fib_id, oui)
        return data

    def verify_dhcp6_solicit(self, pkt, intf,
                             peer_ip, peer_mac,
                             vpn_id="",
                             fib_id=0,
                             oui=0,
                             dst_mac=None,
                             dst_ip=None):
        if not dst_mac:
            dst_mac = intf.remote_mac
        if not dst_ip:
            dst_ip = in6_ptop(intf.remote_ip6)

        ether = pkt[Ether]
        self.assertEqual(ether.dst, dst_mac)
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IPv6]
        self.assertEqual(in6_ptop(ip.dst), dst_ip)
        self.assertEqual(in6_ptop(ip.src), in6_ptop(intf.local_ip6))

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP6_CLIENT_PORT)
        self.assertEqual(udp.sport, DHCP6_SERVER_PORT)

        relay = pkt[DHCP6_RelayForward]
        self.assertEqual(in6_ptop(relay.peeraddr), in6_ptop(peer_ip))
        oid = pkt[DHCP6OptIfaceId]
        cll = pkt[DHCP6OptClientLinkLayerAddr]
        self.assertEqual(cll.optlen, 8)
        self.assertEqual(cll.lltype, 1)
        self.assertEqual(cll.clladdr, peer_mac)

        id_len = len(vpn_id)

        if fib_id != 0:
            self.assertEqual(id_len, 0)
            vss = pkt[DHCP6OptVSS]
            self.assertEqual(vss.optlen, 8)
            self.assertEqual(vss.type, 1)
            # the OUI and FIB-id are really 3 and 4 bytes resp.
            # but the tested range is small
            self.assertEqual(ord(vss.data[0]), 0)
            self.assertEqual(ord(vss.data[1]), 0)
            self.assertEqual(ord(vss.data[2]), oui)
            self.assertEqual(ord(vss.data[3]), 0)
            self.assertEqual(ord(vss.data[4]), 0)
            self.assertEqual(ord(vss.data[5]), 0)
            self.assertEqual(ord(vss.data[6]), fib_id)

        if id_len > 0:
            self.assertEqual(oui, 0)
            vss = pkt[DHCP6OptVSS]
            self.assertEqual(vss.optlen, id_len+1)
            self.assertEqual(vss.type, 0)
            self.assertEqual(vss.data[0:id_len], vpn_id)

        # the relay message should be an encoded Solicit
        msg = pkt[DHCP6OptRelayMsg]
        sol = DHCP6_Solicit()
        self.assertEqual(msg.optlen, len(str(sol)))
        self.assertEqual(str(sol), (str(msg[1]))[:msg.optlen])

    def verify_dhcp6_advert(self, pkt, intf, peer):
        ether = pkt[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, intf.local_mac)

        ip = pkt[IPv6]
        self.assertEqual(in6_ptop(ip.dst), in6_ptop(peer))
        self.assertEqual(in6_ptop(ip.src), in6_ptop(intf.local_ip6))

        udp = pkt[UDP]
        self.assertEqual(udp.dport, DHCP6_SERVER_PORT)
        self.assertEqual(udp.sport, DHCP6_CLIENT_PORT)

        # not sure why this is not decoding
        # adv = pkt[DHCP6_Advertise]

    def test_dhcp_proxy(self):
        """ DHCPv4 Proxy """

        #
        # Verify no response to DHCP request without DHCP config
        #
        p_disc_vrf0 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                             src=self.pg3.remote_mac) /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=DHCP4_CLIENT_PORT,
                           dport=DHCP4_SERVER_PORT) /
                       BOOTP(op=1) /
                       DHCP(options=[('message-type', 'discover'), ('end')]))
        pkts_disc_vrf0 = [p_disc_vrf0]
        p_disc_vrf1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                             src=self.pg4.remote_mac) /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=DHCP4_CLIENT_PORT,
                           dport=DHCP4_SERVER_PORT) /
                       BOOTP(op=1) /
                       DHCP(options=[('message-type', 'discover'), ('end')]))
        pkts_disc_vrf1 = [p_disc_vrf1]
        p_disc_vrf2 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                             src=self.pg5.remote_mac) /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=DHCP4_CLIENT_PORT,
                           dport=DHCP4_SERVER_PORT) /
                       BOOTP(op=1) /
                       DHCP(options=[('message-type', 'discover'), ('end')]))
        pkts_disc_vrf2 = [p_disc_vrf2]

        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg4, pkts_disc_vrf1,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg5, pkts_disc_vrf2,
                                        "DHCP with no configuration")

        #
        # Enable DHCP proxy in VRF 0
        #
        server_addr = self.pg0.remote_ip4n
        src_addr = self.pg0.local_ip4n

        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0)

        #
        # Discover packets from the client are dropped because there is no
        # IP address configured on the client facing interface
        #
        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf0,
                                        "Discover DHCP no relay address")

        #
        # Inject a response from the server
        #  dropped, because there is no IP addrees on the
        #  client interfce to fill in the option.
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'), ('end')]))
        pkts = [p]

        self.send_and_assert_no_replies(self.pg3, pkts,
                                        "Offer DHCP no relay address")

        #
        # configure an IP address on the client facing interface
        #
        self.pg3.config_ip4()

        #
        # Try again with a discover packet
        # Rx'd packet should be to the server address and from the configured
        # source address
        # UDP source ports are unchanged
        # we've no option 82 config so that should be absent
        #
        self.pg3.add_stream(pkts_disc_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]

        option_82 = self.verify_relayed_dhcp_discover(rx, self.pg0,
                                                      src_intf=self.pg3)

        #
        # Create an DHCP offer reply from the server with a correctly formatted
        # option 82. i.e. send back what we just captured
        # The offer, sent mcast to the client, still has option 82.
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', option_82),
                           ('end')]))
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        rx = rx[0]

        self.verify_dhcp_offer(rx, self.pg3)

        #
        # Bogus Option 82:
        #
        # 1. not our IP address = not checked by VPP? so offer is replayed
        #    to client
        bad_ip = option_82[0:8] + chr(33) + option_82[9:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', bad_ip),
                           ('end')]))
        pkts = [p]
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "DHCP offer option 82 bad address")

        # 2. Not a sw_if_index VPP knows
        bad_if_index = option_82[0:2] + chr(33) + option_82[3:]

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
             BOOTP(op=1) /
             DHCP(options=[('message-type', 'offer'),
                           ('relay_agent_Information', bad_if_index),
                           ('end')]))
        pkts = [p]
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "DHCP offer option 82 bad if index")

        #
        # Send a DHCP request in VRF 1. should be dropped.
        #
        self.send_and_assert_no_replies(self.pg4, pkts_disc_vrf1,
                                        "DHCP with no configuration VRF 1")

        #
        # Delete the DHCP config in VRF 0
        # Should now drop requests.
        #
        self.vapi.dhcp_proxy_config(server_addr,
                                    src_addr,
                                    rx_table_id=0,
                                    is_add=0)

        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf0,
                                        "DHCP config removed VRF 0")
        self.send_and_assert_no_replies(self.pg4, pkts_disc_vrf1,
                                        "DHCP config removed VRF 1")

        #
        # Add DHCP config for VRF 1 & 2
        #
        server_addr1 = self.pg1.remote_ip4n
        src_addr1 = self.pg1.local_ip4n
        self.vapi.dhcp_proxy_config(server_addr1,
                                    src_addr1,
                                    rx_table_id=1,
                                    server_table_id=1)
        server_addr2 = self.pg2.remote_ip4n
        src_addr2 = self.pg2.local_ip4n
        self.vapi.dhcp_proxy_config(server_addr2,
                                    src_addr2,
                                    rx_table_id=2,
                                    server_table_id=2)

        #
        # Confim DHCP requests ok in VRF 1 & 2.
        #  - dropped on IP config on client interface
        #
        self.send_and_assert_no_replies(self.pg4, pkts_disc_vrf1,
                                        "DHCP config removed VRF 1")
        self.send_and_assert_no_replies(self.pg5, pkts_disc_vrf2,
                                        "DHCP config removed VRF 2")

        #
        # configure an IP address on the client facing interface
        #
        self.pg4.config_ip4()
        self.pg4.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg1, src_intf=self.pg4)

        self.pg5.config_ip4()
        self.pg5.add_stream(pkts_disc_vrf2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg2.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg2, src_intf=self.pg5)

        #
        # Add VSS config
        #  table=1, vss_type=1, vpn_index=1, oui=4
        #  table=2, vss_type=0, vpn_id = "ip4-table-2"
        self.vapi.dhcp_proxy_set_vss(1, 1, vpn_index=1, oui=4, is_add=1)
        self.vapi.dhcp_proxy_set_vss(2, 0, "ip4-table-2", is_add=1)

        self.pg4.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg1,
                                          src_intf=self.pg4,
                                          fib_id=1, oui=4)

        self.pg5.add_stream(pkts_disc_vrf2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg2,
                                          src_intf=self.pg5,
                                          vpn_id="ip4-table-2")

        #
        # Add a second DHCP server in VRF 1
        #  expect clients messages to be relay to both configured servers
        #
        self.pg1.generate_remote_hosts(2)
        server_addr12 = socket.inet_pton(AF_INET, self.pg1.remote_hosts[1].ip4)

        self.vapi.dhcp_proxy_config(server_addr12,
                                    src_addr1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_add=1)

        #
        # We'll need an ARP entry for the server to send it packets
        #
        arp_entry = VppNeighbor(self,
                                self.pg1.sw_if_index,
                                self.pg1.remote_hosts[1].mac,
                                self.pg1.remote_hosts[1].ip4)
        arp_entry.add_vpp_config()

        #
        # Send a discover from the client. expect two relayed messages
        # The frist packet is sent to the second server
        # We're not enforcing that here, it's just the way it is.
        #
        self.pg4.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(2)

        option_82 = self.verify_relayed_dhcp_discover(
            rx[0], self.pg1,
            src_intf=self.pg4,
            dst_mac=self.pg1.remote_hosts[1].mac,
            dst_ip=self.pg1.remote_hosts[1].ip4,
            fib_id=1, oui=4)
        self.verify_relayed_dhcp_discover(rx[1], self.pg1,
                                          src_intf=self.pg4,
                                          fib_id=1, oui=4)

        #
        # Send both packets back. Client gets both.
        #
        p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
              UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
              BOOTP(op=1) /
              DHCP(options=[('message-type', 'offer'),
                            ('relay_agent_Information', option_82),
                            ('end')]))
        p2 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IP(src=self.pg1.remote_hosts[1].ip4, dst=self.pg1.local_ip4) /
              UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
              BOOTP(op=1) /
              DHCP(options=[('message-type', 'offer'),
                            ('relay_agent_Information', option_82),
                            ('end')]))
        pkts = [p1, p2]

        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg4.get_capture(2)

        self.verify_dhcp_offer(rx[0], self.pg4, fib_id=1, oui=4)
        self.verify_dhcp_offer(rx[1], self.pg4, fib_id=1, oui=4)

        #
        # Ensure offers from non-servers are dropeed
        #
        p2 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IP(src="8.8.8.8", dst=self.pg1.local_ip4) /
              UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_SERVER_PORT) /
              BOOTP(op=1) /
              DHCP(options=[('message-type', 'offer'),
                            ('relay_agent_Information', option_82),
                            ('end')]))
        self.send_and_assert_no_replies(self.pg1, p2,
                                        "DHCP offer from non-server")

        #
        # Ensure only the discover is sent to multiple servers
        #
        p_req_vrf1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                            src=self.pg4.remote_mac) /
                      IP(src="0.0.0.0", dst="255.255.255.255") /
                      UDP(sport=DHCP4_CLIENT_PORT,
                          dport=DHCP4_SERVER_PORT) /
                      BOOTP(op=1) /
                      DHCP(options=[('message-type', 'request'),
                                    ('end')]))

        self.pg4.add_stream(p_req_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        #
        # Remove the second DHCP server
        #
        self.vapi.dhcp_proxy_config(server_addr12,
                                    src_addr1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_add=0)

        #
        # Test we can still relay with the first
        #
        self.pg4.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg1,
                                          src_intf=self.pg4,
                                          fib_id=1, oui=4)

        #
        # Remove the VSS config
        #  relayed DHCP has default vlaues in the option.
        #
        self.vapi.dhcp_proxy_set_vss(1, is_add=0)
        self.vapi.dhcp_proxy_set_vss(2, is_add=0)

        self.pg4.add_stream(pkts_disc_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]
        self.verify_relayed_dhcp_discover(rx, self.pg1, src_intf=self.pg4)

        #
        # remove DHCP config to cleanup
        #
        self.vapi.dhcp_proxy_config(server_addr1,
                                    src_addr1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_add=0)
        self.vapi.dhcp_proxy_config(server_addr2,
                                    src_addr2,
                                    rx_table_id=2,
                                    server_table_id=2,
                                    is_add=0)

        self.send_and_assert_no_replies(self.pg3, pkts_disc_vrf0,
                                        "DHCP cleanup VRF 0")
        self.send_and_assert_no_replies(self.pg4, pkts_disc_vrf1,
                                        "DHCP cleanup VRF 1")
        self.send_and_assert_no_replies(self.pg5, pkts_disc_vrf2,
                                        "DHCP cleanup VRF 2")

        self.pg3.unconfig_ip4()
        self.pg4.unconfig_ip4()
        self.pg5.unconfig_ip4()

    def test_dhcp6_proxy(self):
        """ DHCPv6 Proxy"""
        #
        # Verify no response to DHCP request without DHCP config
        #
        dhcp_solicit_dst = "ff02::1:2"
        dhcp_solicit_src_vrf0 = mk_ll_addr(self.pg3.remote_mac)
        dhcp_solicit_src_vrf1 = mk_ll_addr(self.pg4.remote_mac)
        dhcp_solicit_src_vrf2 = mk_ll_addr(self.pg5.remote_mac)
        server_addr_vrf0 = self.pg0.remote_ip6n
        src_addr_vrf0 = self.pg0.local_ip6n
        server_addr_vrf1 = self.pg1.remote_ip6n
        src_addr_vrf1 = self.pg1.local_ip6n
        server_addr_vrf2 = self.pg2.remote_ip6n
        src_addr_vrf2 = self.pg2.local_ip6n

        dmac = in6_getnsmac(inet_pton(socket.AF_INET6, dhcp_solicit_dst))
        p_solicit_vrf0 = (Ether(dst=dmac, src=self.pg3.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf0,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Solicit())
        p_solicit_vrf1 = (Ether(dst=dmac, src=self.pg4.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf1,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Solicit())
        p_solicit_vrf2 = (Ether(dst=dmac, src=self.pg5.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf2,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Solicit())

        self.send_and_assert_no_replies(self.pg3, p_solicit_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg4, p_solicit_vrf1,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg5, p_solicit_vrf2,
                                        "DHCP with no configuration")

        #
        # DHCPv6 config in VRF 0.
        # Packets still dropped because the client facing interface has no
        # IPv6 config
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf0,
                                    src_addr_vrf0,
                                    rx_table_id=0,
                                    server_table_id=0,
                                    is_ipv6=1)

        self.send_and_assert_no_replies(self.pg3, p_solicit_vrf0,
                                        "DHCP with no configuration")
        self.send_and_assert_no_replies(self.pg4, p_solicit_vrf1,
                                        "DHCP with no configuration")

        #
        # configure an IP address on the client facing interface
        #
        self.pg3.config_ip6()

        #
        # Now the DHCP requests are relayed to the server
        #
        self.pg3.add_stream(p_solicit_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg0,
                                  dhcp_solicit_src_vrf0,
                                  self.pg3.remote_mac)

        #
        # Exception cases for rejected relay responses
        #

        # 1 - not a relay reply
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_Advertise())
        self.send_and_assert_no_replies(self.pg3, p_adv_vrf0,
                                        "DHCP6 not a relay reply")

        # 2 - no relay message option
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6_Advertise())
        self.send_and_assert_no_replies(self.pg3, p_adv_vrf0,
                                        "DHCP not a relay message")

        # 3 - no circuit ID
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise())
        self.send_and_assert_no_replies(self.pg3, p_adv_vrf0,
                                        "DHCP6 no circuit ID")
        # 4 - wrong circuit ID
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise())
        self.send_and_assert_no_replies(self.pg3, p_adv_vrf0,
                                        "DHCP6 wrong circuit ID")

        #
        # Send the relay response (the advertisement)
        #   - no peer address
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply() /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x04') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf0 = [p_adv_vrf0]

        self.pg0.add_stream(pkts_adv_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)

        self.verify_dhcp6_advert(rx[0], self.pg3, "::")

        #
        # Send the relay response (the advertisement)
        #   - with peer address
        p_adv_vrf0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                      IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf0) /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x04') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf0 = [p_adv_vrf0]

        self.pg0.add_stream(pkts_adv_vrf0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)

        self.verify_dhcp6_advert(rx[0], self.pg3, dhcp_solicit_src_vrf0)

        #
        # Add all the config for VRF 1 & 2
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf1,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1)
        self.pg4.config_ip6()

        self.vapi.dhcp_proxy_config(server_addr_vrf2,
                                    src_addr_vrf2,
                                    rx_table_id=2,
                                    server_table_id=2,
                                    is_ipv6=1)
        self.pg5.config_ip6()

        #
        # VRF 1 solicit
        #
        self.pg4.add_stream(p_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac)

        #
        # VRF 2 solicit
        #
        self.pg5.add_stream(p_solicit_vrf2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg2,
                                  dhcp_solicit_src_vrf2,
                                  self.pg5.remote_mac)

        #
        # VRF 1 Advert
        #
        p_adv_vrf1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                      IPv6(dst=self.pg1.local_ip6, src=self.pg1.remote_ip6) /
                      UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
                      DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf1) /
                      DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
                      DHCP6OptRelayMsg(optlen=0) /
                      DHCP6_Advertise(trid=1) /
                      DHCP6OptStatusCode(statuscode=0))
        pkts_adv_vrf1 = [p_adv_vrf1]

        self.pg1.add_stream(pkts_adv_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg4.get_capture(1)

        self.verify_dhcp6_advert(rx[0], self.pg4, dhcp_solicit_src_vrf1)

        #
        # Add VSS config
        #  table=1, vss_type=1, vpn_index=1, oui=4
        #  table=2, vss_type=0, vpn_id = "ip6-table-2"
        self.vapi.dhcp_proxy_set_vss(1, 1, oui=4, vpn_index=1, is_ip6=1)
        self.vapi.dhcp_proxy_set_vss(2, 0, "IPv6-table-2", is_ip6=1)

        self.pg4.add_stream(p_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac,
                                  fib_id=1,
                                  oui=4)

        self.pg5.add_stream(p_solicit_vrf2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg2,
                                  dhcp_solicit_src_vrf2,
                                  self.pg5.remote_mac,
                                  vpn_id="IPv6-table-2")

        #
        # Remove the VSS config
        #  relayed DHCP has default vlaues in the option.
        #
        self.vapi.dhcp_proxy_set_vss(1, is_ip6=1, is_add=0)

        self.pg4.add_stream(p_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac)

        #
        # Add a second DHCP server in VRF 1
        #  expect clients messages to be relay to both configured servers
        #
        self.pg1.generate_remote_hosts(2)
        server_addr12 = socket.inet_pton(AF_INET6,
                                         self.pg1.remote_hosts[1].ip6)

        self.vapi.dhcp_proxy_config(server_addr12,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1)

        #
        # We'll need an ND entry for the server to send it packets
        #
        nd_entry = VppNeighbor(self,
                               self.pg1.sw_if_index,
                               self.pg1.remote_hosts[1].mac,
                               self.pg1.remote_hosts[1].ip6)
        nd_entry.add_vpp_config()

        #
        # Send a discover from the client. expect two relayed messages
        # The frist packet is sent to the second server
        # We're not enforcing that here, it's just the way it is.
        #
        self.pg4.add_stream(p_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(2)

        self.verify_dhcp6_solicit(rx[0], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac)
        self.verify_dhcp6_solicit(rx[1], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac,
                                  dst_mac=self.pg1.remote_hosts[1].mac,
                                  dst_ip=self.pg1.remote_hosts[1].ip6)

        #
        # Send both packets back. Client gets both.
        #
        p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IPv6(dst=self.pg1.local_ip6, src=self.pg1.remote_ip6) /
              UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
              DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf1) /
              DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
              DHCP6OptRelayMsg(optlen=0) /
              DHCP6_Advertise(trid=1) /
              DHCP6OptStatusCode(statuscode=0))
        p2 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_hosts[1].mac) /
              IPv6(dst=self.pg1.local_ip6, src=self.pg1._remote_hosts[1].ip6) /
              UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
              DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf1) /
              DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
              DHCP6OptRelayMsg(optlen=0) /
              DHCP6_Advertise(trid=1) /
              DHCP6OptStatusCode(statuscode=0))

        pkts = [p1, p2]

        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg4.get_capture(2)

        self.verify_dhcp6_advert(rx[0], self.pg4, dhcp_solicit_src_vrf1)
        self.verify_dhcp6_advert(rx[1], self.pg4, dhcp_solicit_src_vrf1)

        #
        # Ensure only solicit messages are duplicated
        #
        p_request_vrf1 = (Ether(dst=dmac, src=self.pg4.remote_mac) /
                          IPv6(src=dhcp_solicit_src_vrf1,
                               dst=dhcp_solicit_dst) /
                          UDP(sport=DHCP6_SERVER_PORT,
                              dport=DHCP6_CLIENT_PORT) /
                          DHCP6_Request())

        self.pg4.add_stream(p_request_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        #
        # Test we drop DHCP packets from addresses that are not configured as
        # DHCP servers
        #
        p2 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_hosts[1].mac) /
              IPv6(dst=self.pg1.local_ip6, src="3001::1") /
              UDP(sport=DHCP6_SERVER_PORT, dport=DHCP6_SERVER_PORT) /
              DHCP6_RelayReply(peeraddr=dhcp_solicit_src_vrf1) /
              DHCP6OptIfaceId(optlen=4, ifaceid='\x00\x00\x00\x05') /
              DHCP6OptRelayMsg(optlen=0) /
              DHCP6_Advertise(trid=1) /
              DHCP6OptStatusCode(statuscode=0))
        self.send_and_assert_no_replies(self.pg1, p2,
                                        "DHCP6 not from server")

        #
        # Remove the second DHCP server
        #
        self.vapi.dhcp_proxy_config(server_addr12,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1,
                                    is_add=0)

        #
        # Test we can still relay with the first
        #
        self.pg4.add_stream(p_solicit_vrf1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_dhcp6_solicit(rx[0], self.pg1,
                                  dhcp_solicit_src_vrf1,
                                  self.pg4.remote_mac)

        #
        # Cleanup
        #
        self.vapi.dhcp_proxy_config(server_addr_vrf2,
                                    src_addr_vrf2,
                                    rx_table_id=2,
                                    server_table_id=2,
                                    is_ipv6=1,
                                    is_add=0)
        self.vapi.dhcp_proxy_config(server_addr_vrf1,
                                    src_addr_vrf1,
                                    rx_table_id=1,
                                    server_table_id=1,
                                    is_ipv6=1,
                                    is_add=0)
        self.vapi.dhcp_proxy_config(server_addr_vrf0,
                                    src_addr_vrf0,
                                    rx_table_id=0,
                                    server_table_id=0,
                                    is_ipv6=1,
                                    is_add=0)

        # duplicate delete
        self.vapi.dhcp_proxy_config(server_addr_vrf0,
                                    src_addr_vrf0,
                                    rx_table_id=0,
                                    server_table_id=0,
                                    is_ipv6=1,
                                    is_add=0)
        self.pg3.unconfig_ip6()
        self.pg4.unconfig_ip6()
        self.pg5.unconfig_ip6()

    def test_dhcp_client(self):
        """ DHCP Client"""

        hostname = 'universal-dp'

        self.pg_enable_capture(self.pg_interfaces)

        #
        # Configure DHCP client on PG3 and capture the discover sent
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname)

        rx = self.pg3.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg3, hostname)

        #
        # Send back on offer, expect the request
        #
        p_offer = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                   IP(src=self.pg3.remote_ip4, dst="255.255.255.255") /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1,
                         yiaddr=self.pg3.local_ip4,
                         chaddr=mactobinary(self.pg3.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg3.remote_ip4),
                                 'end']))

        self.pg3.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg3, hostname,
                                      self.pg3.local_ip4)

        #
        # Send an acknowledgment
        #
        p_ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                 IP(src=self.pg3.remote_ip4, dst="255.255.255.255") /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg3.local_ip4,
                       chaddr=mactobinary(self.pg3.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg3.remote_ip4),
                               ('server_id', self.pg3.remote_ip4),
                               ('lease_time', 43200),
                               'end']))

        self.pg3.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg3.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg3.local_ip4, 24))
        self.assertTrue(find_route(self, self.pg3.local_ip4, 32))

        # remove the left over ARP entry
        self.vapi.ip_neighbor_add_del(self.pg3.sw_if_index,
                                      mactobinary(self.pg3.remote_mac),
                                      self.pg3.remote_ip4,
                                      is_add=0)
        #
        # remove the DHCP config
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname, is_add=0)

        #
        # and now the route should be gone
        #
        self.assertFalse(find_route(self, self.pg3.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg3.local_ip4, 24))

        #
        # Start the procedure again. this time have VPP send the client-ID
        #
        self.pg3.admin_down()
        self.sleep(1)
        self.pg3.admin_up()
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname,
                              client_id=self.pg3.local_mac)

        rx = self.pg3.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg3, hostname,
                                       self.pg3.local_mac)

        # TODO: VPP DHCP client should not accept DHCP OFFER message with
        # the XID (Transaction ID) not matching the XID of the most recent
        # DHCP DISCOVERY message.
        # Such DHCP OFFER message must be silently discarded - RFC2131.
        # Reported in Jira ticket: VPP-99
        self.pg3.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg3, hostname,
                                      self.pg3.local_ip4)

        #
        # unicast the ack to the offered address
        #
        p_ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                 IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg3.local_ip4,
                       chaddr=mactobinary(self.pg3.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg3.remote_ip4),
                               ('server_id', self.pg3.remote_ip4),
                               ('lease_time', 43200),
                               'end']))

        self.pg3.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg3.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg3.local_ip4, 32))
        self.assertTrue(find_route(self, self.pg3.local_ip4, 24))

        #
        # remove the DHCP config
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname, is_add=0)

        self.assertFalse(find_route(self, self.pg3.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg3.local_ip4, 24))

        #
        # Rince and repeat, this time with VPP configured not to set
        # the braodcast flag in the discover and request messages,
        # and for the server to unicast the responses.
        #
        # Configure DHCP client on PG3 and capture the discover sent
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname,
                              set_broadcast_flag=0)

        rx = self.pg3.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg3, hostname,
                                       broadcast=0)

        #
        # Send back on offer, unicasted to the offered address.
        # Expect the request.
        #
        p_offer = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                   IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1, yiaddr=self.pg3.local_ip4,
                         chaddr=mactobinary(self.pg3.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg3.remote_ip4),
                                 'end']))

        self.pg3.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg3, hostname,
                                      self.pg3.local_ip4,
                                      broadcast=0)

        #
        # Send an acknowledgment
        #
        p_ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                 IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg3.local_ip4,
                       chaddr=mactobinary(self.pg3.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', "255.255.255.0"),
                               ('router', self.pg3.remote_ip4),
                               ('server_id', self.pg3.remote_ip4),
                               ('lease_time', 43200),
                               'end']))

        self.pg3.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg3.remote_ip4)
        self.pg_enable_capture(self.pg_interfaces)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg3.local_ip4, 24))
        self.assertTrue(find_route(self, self.pg3.local_ip4, 32))

        # remove the left over ARP entry
        self.vapi.ip_neighbor_add_del(self.pg3.sw_if_index,
                                      mactobinary(self.pg3.remote_mac),
                                      self.pg3.remote_ip4,
                                      is_add=0)

        #
        # read the DHCP client details from a dump
        #
        clients = self.vapi.dhcp_client_dump()

        self.assertEqual(clients[0].client.sw_if_index,
                         self.pg3.sw_if_index)
        self.assertEqual(clients[0].lease.sw_if_index,
                         self.pg3.sw_if_index)
        self.assertEqual(clients[0].client.hostname.rstrip('\0'),
                         hostname)
        self.assertEqual(clients[0].lease.hostname.rstrip('\0'),
                         hostname)
        self.assertEqual(clients[0].lease.is_ipv6, 0)
        # 0 = DISCOVER, 1 = REQUEST, 2 = BOUND
        self.assertEqual(clients[0].lease.state, 2)
        self.assertEqual(clients[0].lease.mask_width, 24)
        self.assertEqual(clients[0].lease.router_address.rstrip('\0'),
                         self.pg3.remote_ip4n)
        self.assertEqual(clients[0].lease.host_address.rstrip('\0'),
                         self.pg3.local_ip4n)

        #
        # remove the DHCP config
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname, is_add=0)

        #
        # and now the route should be gone
        #
        self.assertFalse(find_route(self, self.pg3.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg3.local_ip4, 24))

        #
        # Start the procedure again. Use requested lease time option.
        #
        self.pg3.admin_down()
        self.sleep(1)
        self.pg3.admin_up()
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname)

        rx = self.pg3.get_capture(1)

        self.verify_orig_dhcp_discover(rx[0], self.pg3, hostname)

        #
        # Send back on offer with requested lease time, expect the request
        #
        lease_time = 1
        p_offer = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                   IP(src=self.pg3.remote_ip4, dst='255.255.255.255') /
                   UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                   BOOTP(op=1,
                         yiaddr=self.pg3.local_ip4,
                         chaddr=mactobinary(self.pg3.local_mac)) /
                   DHCP(options=[('message-type', 'offer'),
                                 ('server_id', self.pg3.remote_ip4),
                                 ('lease_time', lease_time),
                                 'end']))

        self.pg3.add_stream(p_offer)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)
        self.verify_orig_dhcp_request(rx[0], self.pg3, hostname,
                                      self.pg3.local_ip4)

        #
        # Send an acknowledgment
        #
        p_ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
                 IP(src=self.pg3.remote_ip4, dst='255.255.255.255') /
                 UDP(sport=DHCP4_SERVER_PORT, dport=DHCP4_CLIENT_PORT) /
                 BOOTP(op=1, yiaddr=self.pg3.local_ip4,
                       chaddr=mactobinary(self.pg3.local_mac)) /
                 DHCP(options=[('message-type', 'ack'),
                               ('subnet_mask', '255.255.255.0'),
                               ('router', self.pg3.remote_ip4),
                               ('server_id', self.pg3.remote_ip4),
                               ('lease_time', lease_time),
                               'end']))

        self.pg3.add_stream(p_ack)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # We'll get an ARP request for the router address
        #
        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][ARP].pdst, self.pg3.remote_ip4)

        #
        # At the end of this procedure there should be a connected route
        # in the FIB
        #
        self.assertTrue(find_route(self, self.pg3.local_ip4, 32))
        self.assertTrue(find_route(self, self.pg3.local_ip4, 24))

        # remove the left over ARP entry
        self.vapi.ip_neighbor_add_del(self.pg3.sw_if_index,
                                      mactobinary(self.pg3.remote_mac),
                                      self.pg3.remote_ip4,
                                      is_add=0)

        #
        # Sleep for the lease time
        #
        self.sleep(lease_time+1)

        #
        # And now the route should be gone
        #
        self.assertFalse(find_route(self, self.pg3.local_ip4, 32))
        self.assertFalse(find_route(self, self.pg3.local_ip4, 24))

        #
        # remove the DHCP config
        #
        self.vapi.dhcp_client(self.pg3.sw_if_index, hostname, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
