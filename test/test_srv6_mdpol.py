#!/usr/bin/env python

import unittest
import binascii
from socket import AF_INET6

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto, VppIpTable
from vpp_srv6 import SRv6LocalSIDBehaviors, VppSRv6LocalSID, VppSRv6Policy, \
    SRv6PolicyType, VppSRv6Steering, SRv6PolicySteeringTypes

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, IPv6ExtHdrSegmentRouting, \
    IPv6ExtHdrSegmentRoutingTLV
from scapy.layers.inet import IP, UDP

from scapy.utils import inet_pton, inet_ntop

from util import ppp


# class IPv6ExtHdrSegmentRoutingTLVOpaque(IPv6ExtHdrSegmentRoutingTLV):
#     name = "IPv6 Option Header Segment Routing - Opaque Metadata TLV"
#     fields_desc = [ByteField("type", 6),
#                    ByteField("len", 14),
#                    ByteListField("value", [],
#  length_from=lambda pkt: pkt.len)]


class TestSRv6MDPol(VppTestCase):
    """ SRv6 Metadata Policies plugin Test Case """

    @classmethod
    def setUpClass(self):
        super(TestSRv6MDPol, self).setUpClass()

    def setUp(self):
        """ Perform test setup before each test case.
        """
        super(TestSRv6MDPol, self).setUp()

        # packet sizes, inclusive L2 overhead
        self.pg_packet_sizes = [64, 512, 1518, 9018]

        # reset packet_infos
        self.reset_packet_infos()

    def tearDown(self):
        """ Clean up test setup after each test case.
        """
        self.teardown_interfaces()

        super(TestSRv6MDPol, self).tearDown()

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

    def test_SRv6_MDPol_IPv4(self):
        """ Test SRv6 MDPol transit behavior with IPv4 traffic.
        """
        self.run_SRv6_MDPol_IPv4(dscp=0x5, sid_list=['b:2:d4::'])

    def test_SRv6_MDPol_IPv6(self):
        """ Test SRv6 MDPol transit behavior with IPv6 traffic.
        """
        self.run_SRv6_MDPol_IPv6(dscp=0x5, sid_list=['b:2:d4::'])

    def test_SRv6_MDPol_BSID(self):
        """ Test SRv6 MDPol Binding SID behavior (IPv6 traffic).
        """
        self.run_SRv6_MDPol_BSID(dscp=0x5, sid_list=['b:2:d4::'])

    def run_SRv6_MDPol_IPv4(self, dscp, sid_list, bsid='b:1:b1::',
                            src='a:1::', dst_in='10.0.0.4'):
        """ Run SRv6 MDPol transit test with IPv4 traffic.
        """
        self.dscp = dscp
        self.src_addr = src
        self.sid_list = sid_list

        # inbound traffic is IPv4; outbound traffic is IPv6
        self.setup_interfaces(ipv6=[False, True], ipv4=[True, False])

        # configure route to first segment via outgoing interface
        route = VppIpRoute(self, sid_list[0], 128,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 policy
        cli_str = "srv6 mdpol " + bsid + " source " + src
        for s in sid_list:
            cli_str += " next " + s
        self.vapi.cli(cli_str)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # configure per-destination steering
        self.vapi.cli("sr steer l3 " + dst_in + "/32 via bsid " + bsid)

        # show configured steering rules
        self.logger.debug(self.vapi.cli("show sr steering-policies"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare IPv4 packet header
        hdr = self.create_header_IPv4_UDP(dst=dst_in, dscp=dscp)

        # generate packet stream from pg0 to pg1
        pkts = self.create_stream(self.pg0, self.pg1, hdr,
                                  self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_MDPol_IPv4)

        # remove steering rule
        self.vapi.cli("sr steer del l3 " + dst_in + "/32 via bsid " + bsid)

        # show configured steering rules
        self.logger.debug(self.vapi.cli("show sr steering-policies"))

        # remove policy
        self.vapi.cli("sr policy del bsid " + bsid)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # cleanup interfaces
        self.teardown_interfaces()

    def run_SRv6_MDPol_IPv6(self, dscp, sid_list, bsid='b:1:b1::',
                            src='a:1::', dst_in='a:4::'):
        """ Run SRv6 MDPol transit test with IPv6 traffic.
        """
        self.dscp = dscp
        self.src_addr = src
        self.sid_list = sid_list

        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure route to first segment via outgoing interface
        route = VppIpRoute(self, sid_list[0], 128,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 policy
        cli_str = "srv6 mdpol " + bsid + " source " + src
        for s in sid_list:
            cli_str += " next " + s
        self.vapi.cli(cli_str)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # configure per-destination steering
        self.vapi.cli("sr steer l3 " + dst_in + "/128 via bsid " + bsid)

        # show configured steering rules
        self.logger.debug(self.vapi.cli("show sr steering-policies"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare IPv6 packet header
        hdr = self.create_header_IPv6_UDP(dst=dst_in, dscp=dscp)

        # generate packet stream from pg0 to pg1
        pkts = self.create_stream(self.pg0, self.pg1, hdr,
                                  self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_MDPol_IPv6)

        # remove steering rule
        self.vapi.cli("sr steer del l3 " + dst_in + "/128 via bsid " + bsid)

        # show configured steering rules
        self.logger.debug(self.vapi.cli("show sr steering-policies"))

        # remove policy
        self.vapi.cli("sr policy del bsid " + bsid)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # cleanup interfaces
        self.teardown_interfaces()

    def run_SRv6_MDPol_BSID(self, dscp, sid_list, bsid='b:1:b1::',
                            src='a:1::', dst_in='a:4::'):
        """ Run SRv6 MDPol BSID test.
        """
        self.dscp = dscp
        self.src_addr = src
        self.sid_list = sid_list

        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure route to first segment via outgoing interface
        route = VppIpRoute(self, sid_list[0], 128,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DpoProto.DPO_PROTO_IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 policy
        cli_str = "srv6 mdpol " + bsid + " source " + src
        for s in sid_list:
            cli_str += " next " + s
        self.vapi.cli(cli_str)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)

        # prepare IPv6 packet header
        hdr = self.create_header_IPv6_SRH_UDP(dst=bsid,
                                              sid_list=[bsid, dst_in], sl=1,
                                              dscp=dscp)

        # generate packet stream from pg0 to pg1
        pkts = self.create_stream(self.pg0, self.pg1, hdr,
                                  self.pg_packet_sizes, count)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_MDPol_BSID)

        # remove policy
        self.vapi.cli("sr policy del bsid " + bsid)

        # show configured policies
        self.logger.debug(self.vapi.cli("show sr policies"))

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_MDPol_IPv4(self, tx_pkt, rx_pkt):
        """ Compare in and out packet after steering IPv4 into SRv6 MD policy.

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        # also get the IPv4 header of tx'ed packet
        tx_ip = tx_pkt.getlayer(IP)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to the first segment in the SID-list
        self.assertEqual(rx_ip.dst, self.sid_list[0])

        # rx'ed packet should have SRH and IPv4 header
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertTrue(rx_ip.payload.haslayer(IP))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed segment list should be equal to policy's SID-list in rev order
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to SID-list length minus 1
        self.assertEqual(rx_srh.segleft, len(self.sid_list)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        # rx'ed SRH should have exactly one TLV
        self.assertEqual(len(rx_srh.tlv_objects), 1)
        # TLV type should be 6
        self.assertEqual(rx_srh.tlv_objects[0].type, 6)
        # TLV length should be 14
        self.assertEqual(rx_srh.tlv_objects[0].len, 14)
        # First byte of TLV value should be equal to the DSCP value
        # FIXME: fix Scapy; there is no such field as 'reserved'
        self.assertEqual(rx_srh.tlv_objects[0].reserved, self.dscp)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the ttl field and ip checksum
        #   -> adjust tx'ed ttl to expected ttl
        tx_ip.ttl = tx_ip.ttl - 1
        #   -> set tx'ed ip checksum to None and let scapy recompute
        tx_ip.chksum = None
        # read back the pkt (with str()) to force computing these fields
        # probably other ways to accomplish this are possible
        self.assertEqual(rx_srh.payload, IP(str(tx_ip)))

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_MDPol_IPv6(self, tx_pkt, rx_pkt):
        """ Compare in and out packet after steering IPv6 into SRv6 MD policy.

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)

        tx_ip = tx_pkt.getlayer(IPv6)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to expected sidlist[lastentry]
        self.assertEqual(rx_ip.dst, self.sid_list[0])

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed seglist should be equal to expected seglist
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to size expected seglist-1
        self.assertEqual(rx_srh.segleft, len(self.sid_list)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        # rx'ed SRH should have exactly one TLV
        self.assertEqual(len(rx_srh.tlv_objects), 1)
        # TLV type should be 6
        self.assertEqual(rx_srh.tlv_objects[0].type, 6)
        # TLV length should be 14
        self.assertEqual(rx_srh.tlv_objects[0].len, 14)
        # First byte of TLV value should be equal to the DSCP value
        # FIXME: fix Scapy; there is no such field as 'reserved'
        self.assertEqual(rx_srh.tlv_objects[0].reserved, self.dscp)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the hop-limit field
        #   -> update tx'ed hlim to the expected hlim
        tx_ip.hlim = tx_ip.hlim - 1

        self.assertEqual(rx_srh.payload, tx_ip)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_MDPol_BSID(self, tx_pkt, rx_pkt):
        """ Compare in and out packet after steering IPv6 into SRv6 MD policy.

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_srh = tx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, self.src_addr)
        # received ip.dst should be equal to expected sidlist[lastentry]
        self.assertEqual(rx_ip.dst, self.sid_list[0])

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # rx'ed seglist should be equal to expected seglist
        self.assertEqual(rx_srh.addresses, self.sid_list[::-1])
        # segleft should be equal to size expected seglist-1
        self.assertEqual(rx_srh.segleft, len(self.sid_list)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        # rx'ed SRH should have exactly one TLV
        self.assertEqual(len(rx_srh.tlv_objects), 1)
        # TLV type should be 6
        self.assertEqual(rx_srh.tlv_objects[0].type, 6)
        # TLV length should be 14
        self.assertEqual(rx_srh.tlv_objects[0].len, 14)
        # First byte of TLV value should be equal to the DSCP value
        # FIXME: fix Scapy; there is no such field as 'reserved'
        self.assertEqual(rx_srh.tlv_objects[0].reserved, self.dscp)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the DA, the hop-limit field and the SL value
        #   -> update DA to the next segment
        tx_ip.dst = tx_srh.addresses[tx_srh.segleft-1]
        #   -> update tx'ed hlim to the expected hlim
        tx_ip.hlim = tx_ip.hlim - 1
        #   -> decrement SL
        tx_srh.segleft -= 1

        self.assertEqual(rx_srh.payload, tx_ip)

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
        for i in range(0, count-1):
            payload_info = self.create_packet_info(src_if, dst_if)
            self.logger.debug(
                "Creating packet with index %d" % (payload_info.index))
            payload = self.info_to_payload(payload_info)
            # add L2 header if not yet provided in packet_header
            if packet_header.getlayer(0).name == 'Ethernet':
                p = (packet_header /
                     Raw(payload))
            else:
                p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                     packet_header /
                     Raw(payload))
            size = packet_sizes[i % len(packet_sizes)]
            self.logger.debug("Packet size %d" % (size))
            self.extend_packet(p, size)
            # we need to store the packet with the automatic fields computed
            # read back the dumped packet (with str())
            # to force computing these fields
            # probably other ways are possible
            p = Ether(str(p))
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
        input.assert_nothing_captured()

        # verify captured packets
        self.verify_captured_pkts(output, capture, compare_func)

    def create_header_IPv4_UDP(self, src='123.1.1.1', dst='124.1.1.1',
                               dscp=0x0, sport=1234, dport=1234):
        """Create packet header: IPv4 header, UDP header

        :param src: IPv4 source address
        :param dst: IPv4 destination address
        :param dscp: IPv4 DSCP value
        :param sport: UDP source port
        :param dport: UDP destination port
        """

        return (IP(src=src, dst=dst, tos=dscp) / UDP(sport=sport, dport=dport))

    def create_header_IPv6_UDP(self, src='a:1234::', dst='a:4321::',
                               dscp=0x0, sport=1234, dport=1234):
        """Create packet header: IPv6 header, UDP header

        :param src: IPv6 source address
        :param dst: IPv6 destination address
        :param dscp: IPv6 DSCP value
        :param sport: UDP source port
        :param dport: UDP destination port
        """

        p = (IPv6(src=src, dst=dst, tc=dscp) /
             UDP(sport=sport, dport=dport))
        return p

    def create_header_IPv6_SRH_UDP(self, src='a:1234::', dst='a:4321::',
                                   dscp=0x0, sid_list=[], sl=0, sport=1234,
                                   dport=1234):
        """Create packet header: IPv4 encapsulated in SRv6:
        IPv6 header with SRH, IPv4 header, UDP header

        :param src: IPv6 source address
        :param dst: IPv6 destination address
        :param dscp: IPv6 DSCP value
        :param sport: UDP source port
        :param dport: UDP destination port
        :param list sid_list: SRH SID-list
        :param int sl: SRH Segments Left value
        """

        p = (IPv6(src=src, dst=dst, tc=dscp) /
             IPv6ExtHdrSegmentRouting(addresses=sid_list[::-1],
                                      segleft=sl, nh=17) /
             UDP(sport=sport, dport=dport))
        return p

    def get_payload_info(self, packet):
        """ Extract the payload_info from the packet
        """
        # in most cases, payload_info is in packet[Raw]
        # but packet[Raw] gives the complete payload
        # (incl L2 header) for the T.Encaps L2 case
        try:
            payload_info = self.payload_to_info(str(packet[Raw]))

        except:
            # remote L2 header from packet[Raw]:
            # take packet[Raw], convert it to an Ether layer
            # and then extract Raw from it
            payload_info = self.payload_to_info(
                str(Ether(str(packet[Raw]))[Raw]))

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
                         % (dst_if.name, compare_func.func_name))

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
                print packet.command()
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
