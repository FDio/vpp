#!/usr/bin/env python

import unittest
import binascii
from socket import AF_INET6

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable
from vpp_srv6 import SRv6LocalSIDBehaviors, VppSRv6LocalSID, VppSRv6Policy, \
    SRv6PolicyType, VppSRv6Steering, SRv6PolicySteeringTypes

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, IPv6ExtHdrSegmentRouting
from scapy.layers.inet import IP, UDP

from scapy.utils import inet_pton, inet_ntop

from util import ppp


class TestSRv6(VppTestCase):
    """ SRv6 Dynamic Proxy plugin Test Case """

    @classmethod
    def setUpClass(self):
        super(TestSRv6, self).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSRv6, cls).tearDownClass()

    def setUp(self):
        """ Perform test setup before each test case.
        """
        super(TestSRv6, self).setUp()

        # packet sizes, inclusive L2 overhead
        self.pg_packet_sizes = [64, 512, 1518, 9018]

        # reset packet_infos
        self.reset_packet_infos()

    def tearDown(self):
        """ Clean up test setup after each test case.
        """
        self.teardown_interfaces()

        super(TestSRv6, self).tearDown()

    def configure_interface(self,
                            interface,
                            ipv6=False, ipv4=False,
                            ipv6_table_id=0, ipv4_table_id=0):
        """ Configure interface.
        :param ipv6: configure IPv6 on interface
        :param ipv4: configure IPv4 on interface
        :param ipv6_table_id: FIB table_id for IPv6
        :param ipv4_table_id: FIB table_id for IPv4
        """
        self.logger.debug("Configuring interface %s" % (interface.name))
        if ipv6:
            self.logger.debug("Configuring IPv6")
            interface.set_table_ip6(ipv6_table_id)
            interface.config_ip6()
            interface.resolve_ndp(timeout=5)
        if ipv4:
            self.logger.debug("Configuring IPv4")
            interface.set_table_ip4(ipv4_table_id)
            interface.config_ip4()
            interface.resolve_arp()
        interface.admin_up()

    def setup_interfaces(self, ipv6=[], ipv4=[],
                         ipv6_table_id=[], ipv4_table_id=[]):
        """ Create and configure interfaces.

        :param ipv6: list of interface IPv6 capabilities
        :param ipv4: list of interface IPv4 capabilities
        :param ipv6_table_id: list of intf IPv6 FIB table_ids
        :param ipv4_table_id: list of intf IPv4 FIB table_ids
        :returns: List of created interfaces.
        """
        # how many interfaces?
        if len(ipv6):
            count = len(ipv6)
        else:
            count = len(ipv4)
        self.logger.debug("Creating and configuring %d interfaces" % (count))

        # fill up ipv6 and ipv4 lists if needed
        # not enabled (False) is the default
        if len(ipv6) < count:
            ipv6 += (count - len(ipv6)) * [False]
        if len(ipv4) < count:
            ipv4 += (count - len(ipv4)) * [False]

        # fill up table_id lists if needed
        # table_id 0 (global) is the default
        if len(ipv6_table_id) < count:
            ipv6_table_id += (count - len(ipv6_table_id)) * [0]
        if len(ipv4_table_id) < count:
            ipv4_table_id += (count - len(ipv4_table_id)) * [0]

        # create 'count' pg interfaces
        self.create_pg_interfaces(range(count))

        # setup all interfaces
        for i in range(count):
            intf = self.pg_interfaces[i]
            self.configure_interface(intf,
                                     ipv6[i], ipv4[i],
                                     ipv6_table_id[i], ipv4_table_id[i])

        if any(ipv6):
            self.logger.debug(self.vapi.cli("show ip6 neighbors"))
        if any(ipv4):
            self.logger.debug(self.vapi.cli("show ip arp"))
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show hardware"))

        return self.pg_interfaces

    def teardown_interfaces(self):
        """ Unconfigure and bring down interface.
        """
        self.logger.debug("Tearing down interfaces")
        # tear down all interfaces
        # AFAIK they cannot be deleted
        for i in self.pg_interfaces:
            self.logger.debug("Tear down interface %s" % (i.name))
            i.admin_down()
            i.unconfig()
            i.set_table_ip4(0)
            i.set_table_ip6(0)

    def test_SRv6_End_AD_IPv6(self):
        """ Test SRv6 End.AD behavior with IPv6 traffic.
        """
        self.src_addr = 'a0::'
        self.sid_list = ['a1::', 'a2::a6', 'a3::']
        self.test_sid_index = 1

        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure route to next segment
        route = VppIpRoute(self, self.sid_list[self.test_sid_index + 1], 128,
                           [VppRoutePath(self.pg0.remote_ip6,
                                         self.pg0.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID behavior
        cli_str = "sr localsid address " + \
                  self.sid_list[self.test_sid_index] + \
                  " behavior end.ad" + \
                  " nh " + self.pg1.remote_ip6 + \
                  " oif " + self.pg1.name + \
                  " iif " + self.pg1.name
        self.vapi.cli(cli_str)

        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare IPv6 in SRv6 headers
        packet_header1 = self.create_packet_header_IPv6_SRH_IPv6(
            srcaddr=self.src_addr,
            sidlist=self.sid_list[::-1],
            segleft=len(self.sid_list) - self.test_sid_index - 1)

        # generate packets (pg0->pg1)
        pkts1 = self.create_stream(self.pg0, self.pg1, packet_header1,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts1, self.pg1,
                                  self.compare_rx_tx_packet_End_AD_IPv6_out)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # prepare IPv6 header for returning packets
        packet_header2 = self.create_packet_header_IPv6()

        # generate returning packets (pg1->pg0)
        pkts2 = self.create_stream(self.pg1, self.pg0, packet_header2,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg1, pkts2, self.pg0,
                                  self.compare_rx_tx_packet_End_AD_IPv6_in)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        cli_str = "sr localsid del address " + \
                  self.sid_list[self.test_sid_index]
        self.vapi.cli(cli_str)

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_End_AD_IPv6_out(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD with IPv6

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_ip2 = tx_pkt.getlayer(IPv6, 2)

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # the whole rx_ip pkt should be equal to tx_ip2
        # except for the hlim field
        #   -> adjust tx'ed hlim to expected hlim
        tx_ip2.hlim = tx_ip2.hlim - 1

        self.assertEqual(rx_ip, tx_ip2)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_AD_IPv6_in(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to expected sidlist next segment
        self.assertEqual(rx_ip.dst, self.sid_list[self.test_sid_index + 1])

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed seglist should be equal to SID-list in reversed order
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to previous segleft value minus 1
        self.assertEqual(rx_srh.segleft,
                         len(self.sid_list) - self.test_sid_index - 2)
        # lastentry should be equal to the SID-list length minus 1
        self.assertEqual(rx_srh.lastentry, len(self.sid_list) - 1)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the hop-limit field
        tx_ip = tx_pkt.getlayer(IPv6)
        #   -> update tx'ed hlim to the expected hlim
        tx_ip.hlim -= 1
        #   -> check payload
        self.assertEqual(rx_srh.payload, tx_ip)

        self.logger.debug("packet verification: SUCCESS")

    def test_SRv6_End_AD_IPv4(self):
        """ Test SRv6 End.AD behavior with IPv4 traffic.
        """
        self.src_addr = 'a0::'
        self.sid_list = ['a1::', 'a2::a4', 'a3::']
        self.test_sid_index = 1

        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, False], ipv4=[False, True])

        # configure route to next segment
        route = VppIpRoute(self, self.sid_list[self.test_sid_index + 1], 128,
                           [VppRoutePath(self.pg0.remote_ip6,
                                         self.pg0.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID behavior
        cli_str = "sr localsid address " + \
                  self.sid_list[self.test_sid_index] + \
                  " behavior end.ad" + \
                  " nh " + self.pg1.remote_ip4 + \
                  " oif " + self.pg1.name + \
                  " iif " + self.pg1.name
        self.vapi.cli(cli_str)

        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare IPv4 in SRv6 headers
        packet_header1 = self.create_packet_header_IPv6_SRH_IPv4(
            srcaddr=self.src_addr,
            sidlist=self.sid_list[::-1],
            segleft=len(self.sid_list) - self.test_sid_index - 1)

        # generate packets (pg0->pg1)
        pkts1 = self.create_stream(self.pg0, self.pg1, packet_header1,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts1, self.pg1,
                                  self.compare_rx_tx_packet_End_AD_IPv4_out)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # prepare IPv6 header for returning packets
        packet_header2 = self.create_packet_header_IPv4()

        # generate returning packets (pg1->pg0)
        pkts2 = self.create_stream(self.pg1, self.pg0, packet_header2,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg1, pkts2, self.pg0,
                                  self.compare_rx_tx_packet_End_AD_IPv4_in)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        cli_str = "sr localsid del address " + \
                  self.sid_list[self.test_sid_index]
        self.vapi.cli(cli_str)

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_End_AD_IPv4_out(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD with IPv4

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get IPv4 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IP)

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_ip2 = tx_pkt.getlayer(IP)

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # the whole rx_ip pkt should be equal to tx_ip2
        # except for the ttl field and ip checksum
        #   -> adjust tx'ed ttl to expected ttl
        tx_ip2.ttl = tx_ip2.ttl - 1
        #   -> set tx'ed ip checksum to None and let scapy recompute
        tx_ip2.chksum = None
        # read back the pkt (with str()) to force computing these fields
        # probably other ways to accomplish this are possible
        tx_ip2 = IP(scapy.compat.raw(tx_ip2))

        self.assertEqual(rx_ip, tx_ip2)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_AD_IPv4_in(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to expected sidlist next segment
        self.assertEqual(rx_ip.dst, self.sid_list[self.test_sid_index + 1])

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed seglist should be equal to SID-list in reversed order
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to previous segleft value minus 1
        self.assertEqual(rx_srh.segleft,
                         len(self.sid_list) - self.test_sid_index - 2)
        # lastentry should be equal to the SID-list length minus 1
        self.assertEqual(rx_srh.lastentry, len(self.sid_list) - 1)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the ttl field and ip checksum
        tx_ip = tx_pkt.getlayer(IP)
        #   -> adjust tx'ed ttl to expected ttl
        tx_ip.ttl = tx_ip.ttl - 1
        #   -> set tx'ed ip checksum to None and let scapy recompute
        tx_ip.chksum = None
        #   -> read back the pkt (with str()) to force computing these fields
        # probably other ways to accomplish this are possible
        self.assertEqual(rx_srh.payload, IP(scapy.compat.raw(tx_ip)))

        self.logger.debug("packet verification: SUCCESS")

    def test_SRv6_End_AD_L2(self):
        """ Test SRv6 End.AD behavior with L2 traffic.
        """
        self.src_addr = 'a0::'
        self.sid_list = ['a1::', 'a2::a4', 'a3::']
        self.test_sid_index = 1

        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, False])

        # configure route to next segment
        route = VppIpRoute(self, self.sid_list[self.test_sid_index + 1], 128,
                           [VppRoutePath(self.pg0.remote_ip6,
                                         self.pg0.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID behavior
        cli_str = "sr localsid address " + \
                  self.sid_list[self.test_sid_index] + \
                  " behavior end.ad" + \
                  " oif " + self.pg1.name + \
                  " iif " + self.pg1.name
        self.vapi.cli(cli_str)

        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare L2 in SRv6 headers
        packet_header1 = self.create_packet_header_IPv6_SRH_L2(
            srcaddr=self.src_addr,
            sidlist=self.sid_list[::-1],
            segleft=len(self.sid_list) - self.test_sid_index - 1,
            vlan=0)

        # generate packets (pg0->pg1)
        pkts1 = self.create_stream(self.pg0, self.pg1, packet_header1,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts1, self.pg1,
                                  self.compare_rx_tx_packet_End_AD_L2_out)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # prepare L2 header for returning packets
        packet_header2 = self.create_packet_header_L2()

        # generate returning packets (pg1->pg0)
        pkts2 = self.create_stream(self.pg1, self.pg0, packet_header2,
                                   self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg1, pkts2, self.pg0,
                                  self.compare_rx_tx_packet_End_AD_L2_in)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        cli_str = "sr localsid del address " + \
                  self.sid_list[self.test_sid_index]
        self.vapi.cli(cli_str)

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_End_AD_L2_out(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD with L2

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get IPv4 header of rx'ed packet
        rx_eth = rx_pkt.getlayer(Ether)

        tx_ip = tx_pkt.getlayer(IPv6)
        # we can't just get the 2nd Ether layer
        # get the Raw content and dissect it as Ether
        tx_eth1 = Ether(scapy.compat.raw(tx_pkt[Raw]))

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # the whole rx_eth pkt should be equal to tx_eth1
        self.assertEqual(rx_eth, tx_eth1)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_AD_L2_in(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.AD

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        ####
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to expected sidlist next segment
        self.assertEqual(rx_ip.dst, self.sid_list[self.test_sid_index + 1])

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed seglist should be equal to SID-list in reversed order
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to previous segleft value minus 1
        self.assertEqual(rx_srh.segleft,
                         len(self.sid_list) - self.test_sid_index - 2)
        # lastentry should be equal to the SID-list length minus 1
        self.assertEqual(rx_srh.lastentry, len(self.sid_list) - 1)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        tx_ether = tx_pkt.getlayer(Ether)
        self.assertEqual(Ether(scapy.compat.raw(rx_srh.payload)), tx_ether)

        self.logger.debug("packet verification: SUCCESS")

    def create_stream(self, src_if, dst_if, packet_header, packet_sizes,
                      count):
        """Create SRv6 input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for
        :param VppInterface dst_if: destination interface of packet stream
        :param packet_header: Layer3 scapy packet headers,
                L2 is added when not provided,
                Raw(payload) with packet_info is added
        :param list packet_sizes: packet stream pckt sizes,sequentially applied
               to packets in stream have
        :param int count: number of packets in packet stream
        :return: list of packets
        """
        self.logger.info("Creating packets")
        pkts = []
        for i in range(0, count - 1):
            payload_info = self.create_packet_info(src_if, dst_if)
            self.logger.debug(
                "Creating packet with index %d" % (payload_info.index))
            payload = self.info_to_payload(payload_info)
            # add L2 header if not yet provided in packet_header
            if packet_header.getlayer(0).name == 'Ethernet':
                p = packet_header / Raw(payload)
            else:
                p = Ether(dst=src_if.local_mac, src=src_if.remote_mac) / \
                    packet_header / Raw(payload)
            size = packet_sizes[i % len(packet_sizes)]
            self.logger.debug("Packet size %d" % (size))
            self.extend_packet(p, size)
            # we need to store the packet with the automatic fields computed
            # read back the dumped packet (with str())
            # to force computing these fields
            # probably other ways are possible
            p = Ether(scapy.compat.raw(p))
            payload_info.data = p.copy()
            self.logger.debug(ppp("Created packet:", p))
            pkts.append(p)
        self.logger.info("Done creating packets")
        return pkts

    def send_and_verify_pkts(self, input, pkts, output, compare_func):
        """Send packets and verify received packets using compare_func

        :param input: ingress interface of DUT
        :param pkts: list of packets to transmit
        :param output: egress interface of DUT
        :param compare_func: function to compare in and out packets
        """
        # add traffic stream to input interface
        input.add_stream(pkts)

        # enable capture on all interfaces
        self.pg_enable_capture(self.pg_interfaces)

        # start traffic
        self.logger.info("Starting traffic")
        self.pg_start()

        # get output capture
        self.logger.info("Getting packet capture")
        capture = output.get_capture()

        # assert nothing was captured on input interface
        # input.assert_nothing_captured()

        # verify captured packets
        self.verify_captured_pkts(output, capture, compare_func)

    def create_packet_header_IPv6(self):
        """Create packet header: IPv6 header, UDP header

        :param dst: IPv6 destination address

        IPv6 source address is 1234::1
        IPv6 destination address is 4321::1
        UDP source port and destination port are 1234
        """

        p = IPv6(src='1234::1', dst='4321::1') / UDP(sport=1234, dport=1234)
        return p

    def create_packet_header_IPv6_SRH_IPv6(self, srcaddr, sidlist, segleft):
        """Create packet header: IPv6 encapsulated in SRv6:
        IPv6 header with SRH, IPv6 header, UDP header

        :param int srcaddr: outer source address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH

        Outer IPv6 source address is set to srcaddr
        Outer IPv6 destination address is set to sidlist[segleft]
        Inner IPv6 source addresses is 1234::1
        Inner IPv6 destination address is 4321::1
        UDP source port and destination port are 1234
        """

        p = IPv6(src=srcaddr, dst=sidlist[segleft]) / \
            IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                     segleft=segleft, nh=41) / \
            IPv6(src='1234::1', dst='4321::1') / \
            UDP(sport=1234, dport=1234)
        return p

    def create_packet_header_IPv4(self):
        """Create packet header: IPv4 header, UDP header

        :param dst: IPv4 destination address

        IPv4 source address is 123.1.1.1
        IPv4 destination address is 124.1.1.1
        UDP source port and destination port are 1234
        """

        p = IP(src='123.1.1.1', dst='124.1.1.1') / UDP(sport=1234, dport=1234)
        return p

    def create_packet_header_IPv6_SRH_IPv4(self, srcaddr, sidlist, segleft):
        """Create packet header: IPv4 encapsulated in SRv6:
        IPv6 header with SRH, IPv4 header, UDP header

        :param int srcaddr: outer source address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH

        Outer IPv6 source address is set to srcaddr
        Outer IPv6 destination address is set to sidlist[segleft]
        Inner IPv4 source address is 123.1.1.1
        Inner IPv4 destination address is 124.1.1.1
        UDP source port and destination port are 1234
        """

        p = IPv6(src=srcaddr, dst=sidlist[segleft]) / \
            IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                     segleft=segleft, nh=4) / \
            IP(src='123.1.1.1', dst='124.1.1.1') / \
            UDP(sport=1234, dport=1234)
        return p

    def create_packet_header_L2(self, vlan=0):
        """Create packet header: L2 header

        :param vlan: if vlan!=0 then add 802.1q header
        """
        # Note: the dst addr ('00:55:44:33:22:11') is used in
        # the compare function compare_rx_tx_packet_T_Encaps_L2
        # to detect presence of L2 in SRH payload
        p = Ether(src='00:11:22:33:44:55', dst='00:55:44:33:22:11')
        etype = 0x8137  # IPX
        if vlan:
            # add 802.1q layer
            p /= Dot1Q(vlan=vlan, type=etype)
        else:
            p.type = etype
        return p

    def create_packet_header_IPv6_SRH_L2(self, srcaddr, sidlist, segleft,
                                         vlan=0):
        """Create packet header: L2 encapsulated in SRv6:
        IPv6 header with SRH, L2

        :param int srcaddr: IPv6 source address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH
        :param vlan: L2 vlan; if vlan!=0 then add 802.1q header

        IPv6 source address is set to srcaddr
        IPv6 destination address is set to sidlist[segleft]
        """
        eth = Ether(src='00:11:22:33:44:55', dst='00:55:44:33:22:11')
        etype = 0x8137  # IPX
        if vlan:
            # add 802.1q layer
            eth /= Dot1Q(vlan=vlan, type=etype)
        else:
            eth.type = etype

        p = IPv6(src=srcaddr, dst=sidlist[segleft]) / \
            IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                     segleft=segleft, nh=59) / \
            eth
        return p

    def get_payload_info(self, packet):
        """ Extract the payload_info from the packet
        """
        # in most cases, payload_info is in packet[Raw]
        # but packet[Raw] gives the complete payload
        # (incl L2 header) for the T.Encaps L2 case
        try:
            payload_info = self.payload_to_info(packet[Raw])

        except:
            # remote L2 header from packet[Raw]:
            # take packet[Raw], convert it to an Ether layer
            # and then extract Raw from it
            payload_info = self.payload_to_info(
                Ether(scapy.compat.raw(packet[Raw]))[Raw])

        return payload_info

    def verify_captured_pkts(self, dst_if, capture, compare_func):
        """
        Verify captured packet stream for specified interface.
        Compare ingress with egress packets using the specified compare fn

        :param dst_if: egress interface of DUT
        :param capture: captured packets
        :param compare_func: function to compare in and out packet
        """
        self.logger.info("Verifying capture on interface %s using function %s"
                         % (dst_if.name, compare_func.__name__))

        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index

        for packet in capture:
            try:
                # extract payload_info from packet's payload
                payload_info = self.get_payload_info(packet)
                packet_index = payload_info.index

                self.logger.debug("Verifying packet with index %d"
                                  % (packet_index))
                # packet should have arrived on the expected interface
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on interface %s: src=%u (idx=%u)" %
                    (dst_if.name, payload_info.src, packet_index))

                # search for payload_info with same src and dst if_index
                # this will give us the transmitted packet
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                # next_info should not be None
                self.assertTrue(next_info is not None)
                # index of tx and rx packets should be equal
                self.assertEqual(packet_index, next_info.index)
                # data field of next_info contains the tx packet
                txed_packet = next_info.data

                self.logger.debug(ppp("Transmitted packet:",
                                      txed_packet))  # ppp=Pretty Print Packet

                self.logger.debug(ppp("Received packet:", packet))

                # compare rcvd packet with expected packet using compare_func
                compare_func(txed_packet, packet)

            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # have all expected packets arrived?
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
