#!/usr/bin/env python

import unittest
from socket import AF_INET6

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint
from vpp_pg_interface import is_ipv6_misc
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route, VppIpMRoute, \
    VppMRoutePath, MRouteItfFlags, MRouteEntryFlags
from vpp_neighbor import find_nbr, VppNeighbor
from vpp_srv6 import SRv6LocalSIDBehaviors, VppSRv6LocalSID, VppSRv6Policy, \
    SRv6PolicyType, VppSRv6Steering, SRv6PolicySteeringTypes

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, ICMPv6ND_NS, ICMPv6ND_RS, \
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, getmacbyip6, ICMPv6MRD_Solicitation, \
    ICMPv6NDOptMTU, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, \
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6DestUnreach, icmp6types
from scapy.layers.inet6 import *

from util import ppp
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ptop, in6_islladdr, \
    in6_mactoifaceid, in6_ismaddr
from scapy.utils import inet_pton, inet_ntop


class TestSRv6(VppTestCase):
    """ SRv6 Test Case """

    @classmethod
    def setUpClass(self):
        super(TestSRv6, self).setUpClass()

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

    def setup_interfaces(self, count,
                         src_ipv6=False, dst_ipv6=False,
                         src_ipv4=False, dst_ipv4=False):
        """ Setup interfaces with IPv6 and/or IPv4 capability.
        Create and configure the interfaces.

        :param count: number of interfaces (1 src intf, count-1 dst intfs)
        :param src_ipv6: source interface has IPv6 enabled
        :param dst_ipv6: destination interface has IPv6 enabled
        :param src_ipv4: source interface has IPv4 enabled
        :param dst_ipv4: destination interface has IPv4 enabled
        :returns: List of creates interfaces.
        """
        self.logger.debug("Creating and configuring interfaces")

        # create 'count' pg interfaces
        # first one (pg0) will be source interface
        # others (pg1-pg(count-1)) will be destination interfaces
        self.create_pg_interfaces(range(count))

        # setup all interfaces
        for i in self.pg_interfaces:
            self.logger.debug("configured interface %s" % (i.name))
            i.admin_up()
            if (i.pg_index == 0 and src_ipv6) or (i.pg_index and dst_ipv6):
                i.config_ip6()
                # self.logger.debug(self.vapi.cli("show ip6 neighbors"))
                i.resolve_ndp(timeout=5)
                # self.logger.debug(self.vapi.cli("show ip6 neighbors"))
            if (i.pg_index == 0 and src_ipv4) or (i.pg_index and dst_ipv4):
                i.config_ip4()
                # self.logger.debug(self.vapi.cli("show ip arp"))
                i.resolve_arp()
                # self.logger.debug(self.vapi.cli("show ip arp"))
        self.logger.debug(self.vapi.cli("show ip6 neighbors"))
        self.logger.debug(self.vapi.cli("show ip arp"))
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show hardware"))

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

    def test_SRv6_T_Encaps(self):
        """ Test SRv6 Transit.Encaps behavior for IPv6.
        """
        # TODO: L2 encaps variant
        # send traffic to one destination interface
        # source and destination are IPv6 only
        self.setup_interfaces(count=2, src_ipv6=True, dst_ipv6=True)

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         is_ip6=1)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure encaps IPv6 source address
        # needs to be done before SR Policy config
        # TODO: API?
        # self.vapi.cli("set sr encaps source addr " + inet_ntop(AF_INET6,
        #    sr_policy.source))
        self.vapi.cli("set sr encaps source addr a3::")

        bsid = 'a3::9999:1'
        # configure SRv6 Policy
        # Note: segment list order: first -> last
        sr_policy = VppSRv6Policy(
            self, bsid=bsid,
            is_encap=1,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1, fib_table=0,
            segments=['a4::', 'a5::', 'a6::c7'],
            source='a3::')
        sr_policy.add_vpp_config()
        self.sr_policy = sr_policy

        # log the sr policies
        self.logger.info(self.vapi.cli("show sr policies"))

        # steer IPv6 traffic to a7::/64 into SRv6 Policy
        # use the bsid of the above self.sr_policy
        pol_steering = VppSRv6Steering(
                        self,
                        bsid=inet_ntop(AF_INET6, self.sr_policy.bsid),
                        prefix="a7::", mask_width=64,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_IPV6,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=0)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))
        # self.logger.debug(self.vapi.cli("show ip6 fib"))

        # create packets
        count = len(self.pg_packet_sizes)
        dst_inner = 'a7::1234'
        pkts = []

        # create IPv6 packets without SRH
        packet_header = self.create_packet_header_IPv6(dst_inner)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # create IPv6 packets with SRH
        # packets with segments-left 1, active segment a7::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                                                dst_inner,
                                                sidlist=['a8::', 'a7::',
                                                         'a6::'],
                                                segleft=1)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # steer packets to the bsid, DA == BSID
        # TODO: packets without SRH sent to bsid are dropped, expected?
        # create IPv6 packets without SRH
        # packet_header = self.create_packet_header_IPv6(bsid)
        # create traffic stream pg0->pg1
        # pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
        #    self.pg_packet_sizes, count))

        # create IPv6 packets with SRH with active segment == BSID
        # TODO: update packet verification function for this case
        # packets with segments-left 1, active segment bsid
        # packet_header = self.create_packet_header_IPv6_SRH_IPv6(bsid,
        #    sidlist = ['a8::', bsid, 'a6::'], segleft = 1)
        # create traffic stream pg0->pg1
        # pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
        #    self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_T_Encaps)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SR steering
        pol_steering.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # remove SR Policies
        self.sr_policy.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr policies"))

        # remove FIB entries
        route.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_T_Encaps_IPv4(self):
        """ Test SRv6 Transit.Encaps behavior for IPv4.
        """
        # TODO: L2 encaps
        # send traffic to one destination interface
        # source interface is IPv4 only
        # destination interface is IPv6 only
        self.setup_interfaces(count=2, src_ipv4=True, dst_ipv6=True)

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         is_ip6=1)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure encaps IPv6 source address
        # needs to be done before SR Policy config
        # TODO: API?
        self.vapi.cli("set sr encaps source addr a3::")

        bsid = 'a3::9999:1'
        # configure SRv6 Policy
        # Note: segment list order: first -> last
        sr_policy = VppSRv6Policy(
            self, bsid=bsid,
            is_encap=1,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1, fib_table=0,
            segments=['a4::', 'a5::', 'a6::c7'],
            source='a3::')
        sr_policy.add_vpp_config()
        self.sr_policy = sr_policy

        # log the sr policies
        self.logger.info(self.vapi.cli("show sr policies"))

        # steer IPv4 traffic to 7.1.1.0/24 into SRv6 Policy
        # use the bsid of the above self.sr_policy
        pol_steering = VppSRv6Steering(
                        self,
                        bsid=inet_ntop(AF_INET6, self.sr_policy.bsid),
                        prefix="7.1.1.0", mask_width=24,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_IPV4,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=0)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))
        # self.logger.debug(self.vapi.cli("show ip fib"))

        # create packets
        count = len(self.pg_packet_sizes)
        dst_inner = '7.1.1.123'
        pkts = []

        # create IPv4 packets
        packet_header = self.create_packet_header_IPv4(dst_inner)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_T_Encaps_IPv4)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SR steering
        pol_steering.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # remove SR Policies
        self.sr_policy.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr policies"))

        # remove FIB entries
        route.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End(self):
        """ Test SRv6 End (without PSP) behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(count=2, src_ipv6=True, dst_ipv6=True)

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         is_ip6=1)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID End without PSP behavior
        localsid = VppSRv6LocalSID(
                        self, localsid_addr='A3::0',
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_END,
                        nh_addr='::',
                        end_psp=0,
                        sw_if_index=0,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # create IPv6 packets with SRH (SL=2, SL=1, SL=0)
        # send one packet per SL value per packet size
        # SL=0 packet with localSID End with USP needs 2nd SRH
        count = len(self.pg_packet_sizes)
        dst_inner = 'a4::1234'
        pkts = []

        # packets with segments-left 2, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                dst_inner,
                sidlist=['a5::', 'a4::', 'a3::'],
                segleft=2)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets with segments-left 1, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                dst_inner,
                sidlist=['a4::', 'a3::', 'a2::'],
                segleft=1)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # TODO: End behavior with USP pops SRH if SL=0 and NH(SRH)=SRH
        # TODO: need to generate packets with 2 SRHs for this
        # TODO: supported?
        # packets with segments-left 0, active segment a3::
        # packet_header = self.create_packet_header_IPv6_SRH_IPv6(dst_inner,
        #        sidlist = ['a3::', 'a2::', 'a1::'], segleft = 0)
        # add to traffic stream pg0->pg1
        # pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
        #    self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        route.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_with_PSP(self):
        """ Test SRv6 End with PSP behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(count=2, src_ipv6=True, dst_ipv6=True)

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index, is_ip6=1)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID End with PSP behavior
        localsid = VppSRv6LocalSID(
                        self, localsid_addr='A3::0',
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_END,
                        nh_addr='::',
                        end_psp=1,
                        sw_if_index=0,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # create IPv6 packets with SRH (SL=2, SL=1)
        # send one packet per SL value per packet size
        # SL=0 packet with localSID End with PSP is dropped
        count = len(self.pg_packet_sizes)
        dst_inner = 'a4::1234'
        pkts = []

        # packets with segments-left 2, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                    dst_inner,
                    sidlist=['a5::', 'a4::', 'a3::'],
                    segleft=2)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets with segments-left 1, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                    dst_inner,
                    sidlist=['a4::', 'a3::', 'a2::'],
                    segleft=1)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # SL=0 packet with localSID End with PSP is dropped
        # packets with segments-left 0, active segment a3::
        # packet_header = self.create_packet_header_IPv6_SRH_IPv6(dst_inner,
        #        sidlist = ['a3::', 'a2::', 'a1::'], segleft = 0)
        # add to traffic stream pg0->pg1
        # pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
        #    self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_PSP)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        route.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_DX6(self):
        """ Test SRv6 End.DX6 behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(count=2, src_ipv6=True, dst_ipv6=True)

        # configure SRv6 localSID End.DX6 behavior
        localsid = VppSRv6LocalSID(
                        self, localsid_addr='a3::c4',
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX6,
                        nh_addr=self.pg1.remote_ip6,
                        end_psp=0,
                        sw_if_index=self.pg1.sw_if_index,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # create IPv6 packets with SRH (SL=0)
        # send one packet per packet size
        count = len(self.pg_packet_sizes)
        dst_inner = 'a4::1234'  # inner header destination address
        pkts = []

        # packets with SRH, segments-left 0, active segment a3::c4
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                        dst_inner,
                        sidlist=['a3::c4', 'a2::', 'a1::'],
                        segleft=0)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, IPv6 in IPv6
        # outer IPv6 dest addr is the localsid End.DX6
        packet_header = self.create_packet_header_IPv6_IPv6(
                                            dst_inner,
                                            dst_outer='a3::c4')
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_DX6)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_DX4(self):
        """ Test SRv6 End.DX4 behavior.
        """
        # send traffic to one destination interface
        # source interface is IPv6 only
        # destination interface is IPv4 only
        self.setup_interfaces(count=2, src_ipv6=True, dst_ipv4=True)

        # configure SRv6 localSID End.DX4 behavior
        localsid = VppSRv6LocalSID(
                        self, localsid_addr='a3::c4',
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX4,
                        nh_addr=self.pg1.remote_ip4,
                        end_psp=0,
                        sw_if_index=self.pg1.sw_if_index,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)
        dst_inner = '4.1.1.123'  # inner header destination address
        pkts = []

        # packets with SRH, segments-left 0, active segment a3::c4
        packet_header = self.create_packet_header_IPv6_SRH_IPv4(
                        dst_inner,
                        sidlist=['a3::c4', 'a2::', 'a1::'],
                        segleft=0)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, IPv4 in IPv6
        # outer IPv6 dest addr is the localsid End.DX4
        packet_header = self.create_packet_header_IPv6_IPv4(
                                            dst_inner,
                                            dst_outer='a3::c4')
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_DX4)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_T_Encaps(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Encaps

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None
        rx_ip2 = None
        rx_srh2 = None
        rx_ip3 = None
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_srh = None
        tx_ip2 = None
        # some packets have been tx'ed with an SRH, some without it
        # get SRH if tx'ed packet has it
        if tx_pkt.haslayer(IPv6ExtHdrSegmentRouting):
            tx_srh = tx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # get inner IPv6 header if tx'ed packet has it
        if tx_ip.payload.haslayer(IPv6):
            # get second (inner) IPv6 header
            tx_ip2 = tx_pkt.getlayer(IPv6, 2)
        tx_udp = tx_pkt[UDP]

        # expected segment-list
        # TODO: do it once on a class level instead of per packet
        seglist = []
        for i in range(self.sr_policy.n_segments):
            addr = self.sr_policy.segments[i*16:(i+1)*16]
            seglist.append(inet_ntop(AF_INET6, ''.join(addr)))
        # reverse list
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = inet_ntop(AF_INET6, self.sr_policy.source)

        # checks common to cases tx with and without SRH
        # rx'ed packet should have SRH and 2nd IPv6 header
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertTrue(rx_ip.payload.haslayer(IPv6))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # get second IPv6 header
        rx_ip2 = rx_pkt.getlayer(IPv6, 2)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, sr_policy_source)
        # received ip.dst should be equal to sidlist[lastentry]
        self.assertEqual(rx_ip.dst, tx_seglist[-1])
        # rx'ed seglist should be equal to seglist
        self.assertEqual(rx_srh.addresses, tx_seglist)
        # segleft should be equal to size seglist-1
        self.assertEqual(rx_srh.segleft, len(tx_seglist)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        if tx_srh:
            # packet was tx'ed with SRH
            # verify if rx'ed packet has 2 SRH and 3 IPv6
            self.assertTrue(rx_ip2.payload.haslayer(IPv6ExtHdrSegmentRouting))
            self.assertTrue(rx_ip2.payload.haslayer(IPv6))

            # get inner SRH and IPv6 header
            rx_srh2 = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting, 2)
            rx_ip3 = rx_pkt.getlayer(IPv6, 3)

            # rx'ed ip2.src should be equal to tx'ed ip.src
            self.assertEqual(rx_ip2.src, tx_ip.src)
            # rx'ed ip2.dst should be equal to tx'ed ip.dst
            self.assertEqual(rx_ip2.dst, tx_ip.dst)

            # rx'ed ip3.src should be equal to tx'ed ip2.src
            self.assertEqual(rx_ip3.src, tx_ip2.src)
            # rx'ed ip3.dst should be equal to tx'ed ip2.dst
            self.assertEqual(rx_ip3.dst, tx_ip2.dst)

            # rx'ed srh2.addresses should be equal to tx'ed srh.addresses
            self.assertEqual(rx_srh2.addresses, tx_srh.addresses)
            # rx'ed srh2.segleft should be equal to tx'ed srh.segleft
            self.assertEqual(rx_srh2.segleft, tx_srh.segleft)
            # rx'ed srh2.lastentry should be equal to tx'ed srh.lastentry
            self.assertEqual(rx_srh2.lastentry, tx_srh.lastentry)

        else:  # packet was tx'ed without SRH
            # rx_ip2.src should be equal to tx_ip.src
            self.assertEqual(rx_ip2.src, tx_ip.src)
            # rx_ip2.dst should be equal to tx_ip.dst
            self.assertEqual(rx_ip2.dst, tx_ip.dst)

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_T_Encaps_IPv4(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Encaps for IPv4

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None
        rx_ip2 = None
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IP)
        tx_udp = tx_pkt[UDP]

        # expected segment-list
        # TODO: do it once on a class level instead of per packet
        seglist = []
        for i in range(self.sr_policy.n_segments):
            addr = self.sr_policy.segments[i*16:(i+1)*16]
            seglist.append(inet_ntop(AF_INET6, ''.join(addr)))
        # reverse list
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = inet_ntop(AF_INET6, self.sr_policy.source)

        # checks common to cases tx with and without SRH
        # rx'ed packet should have SRH and IPv4 header
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertTrue(rx_ip.payload.haslayer(IP))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        # get IPv4 header
        rx_ip2 = rx_pkt.getlayer(IP)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, sr_policy_source)
        # received ip.dst should be equal to sidlist[lastentry]
        self.assertEqual(rx_ip.dst, tx_seglist[-1])
        # rx'ed seglist should be equal to seglist
        self.assertEqual(rx_srh.addresses, tx_seglist)
        # segleft should be equal to size seglist-1
        self.assertEqual(rx_srh.segleft, len(tx_seglist)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        # rx_ip2.src should be equal to tx_ip.src
        self.assertEqual(rx_ip2.src, tx_ip.src)
        # rx_ip2.dst should be equal to tx_ip.dst
        self.assertEqual(rx_ip2.dst, tx_ip.dst)

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End (without PSP)

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None
        rx_ip2 = None
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IPv6)
        # we know the packet has been tx'ed
        # with an inner IPv6 header and an SRH
        tx_ip2 = tx_pkt.getlayer(IPv6, 2)
        tx_srh = tx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        tx_udp = tx_pkt[UDP]

        # common checks, regardless of tx segleft value
        # rx'ed packet should have 2nd IPv6 header
        self.assertTrue(rx_ip.payload.haslayer(IPv6))
        # get second (inner) IPv6 header
        rx_ip2 = rx_pkt.getlayer(IPv6, 2)

        if tx_ip.segleft > 0:
            # SRH should NOT have been popped:
            #   End SID without PSP does not pop SRH if segleft>0
            self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
            rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

            # received ip.src should be equal to expected ip.src
            self.assertEqual(rx_ip.src, tx_ip.src)
            # sidlist should be unchanged
            self.assertEqual(rx_srh.addresses, tx_srh.addresses)
            # segleft should have been decremented
            self.assertEqual(rx_srh.segleft, tx_srh.segleft-1)
            # received ip.dst should be equal to sidlist[segleft]
            self.assertEqual(rx_ip.dst, rx_srh.addresses[rx_srh.segleft])
            # lastentry should be unchanged
            self.assertEqual(rx_srh.lastentry, tx_srh.lastentry)
            # inner IPv6 packet (ip2) should be unchanged
            self.assertEqual(rx_ip2.src, tx_ip2.src)
            self.assertEqual(rx_ip2.dst, tx_ip2.dst)
        # else:  # tx_ip.segleft == 0
            # TODO: End with USP pops SRH if SL=0 and NH=SRH
            # TODO: generate packets with 2 SRHs for this
            # SRH should have been popped:
            #   End SID without PSP and segleft=0
            # outer SRH is removed
            # IPv6 packet is forwarded with inner SRH

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_PSP(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End with PSP

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None
        rx_ip2 = None
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IPv6)
        # we know the packet has been tx'ed
        # with an inner IPv6 header and an SRH
        tx_ip2 = tx_pkt.getlayer(IPv6, 2)
        tx_srh = tx_pkt.getlayer(IPv6ExtHdrSegmentRouting)
        tx_udp = tx_pkt[UDP]

        # common checks, regardless of tx segleft value
        self.assertTrue(rx_ip.payload.haslayer(IPv6))
        rx_ip2 = rx_pkt.getlayer(IPv6, 2)
        # inner IPv6 packet (ip2) should be unchanged
        self.assertEqual(rx_ip2.src, tx_ip2.src)
        self.assertEqual(rx_ip2.dst, tx_ip2.dst)

        if tx_ip.segleft > 1:
            # SRH should NOT have been popped:
            #   End SID with PSP does not pop SRH if segleft>1
            # rx'ed packet should have SRH
            self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
            rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

            # received ip.src should be equal to expected ip.src
            self.assertEqual(rx_ip.src, tx_ip.src)
            # sidlist should be unchanged
            self.assertEqual(rx_srh.addresses, tx_srh.addresses)
            # segleft should have been decremented
            self.assertEqual(rx_srh.segleft, tx_srh.segleft-1)
            # received ip.dst should be equal to sidlist[segleft]
            self.assertEqual(rx_ip.dst, rx_srh.addresses[rx_srh.segleft])
            # lastentry should be unchanged
            self.assertEqual(rx_srh.lastentry, tx_srh.lastentry)

        else:  # tx_ip.segleft <= 1
            # SRH should have been popped:
            #   End SID with PSP and segleft=1 pops SRH
            # the two IPv6 headers are still present
            # outer IPv6 header has DA == last segment of popped SRH
            # SRH should not be present
            self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
            # outer IPv6 header ip.src should be equal to tx'ed ip.src
            self.assertEqual(rx_ip.src, tx_ip.src)
            # outer IPv6 header ip.dst should be = to tx'ed sidlist[segleft-1]
            self.assertEqual(rx_ip.dst, tx_srh.addresses[tx_srh.segleft-1])

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_DX6(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.DX6

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_ip2 = tx_pkt.getlayer(IPv6, 2)
        tx_udp = tx_pkt[UDP]

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # rx'ed ip.src should be equal to tx'ed ip2.src
        self.assertEqual(rx_ip.src, tx_ip2.src)
        # rx'ed ip.dst should be equal to tx'ed ip2.dst
        self.assertEqual(rx_ip.dst, tx_ip2.dst)

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_DX4(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.DX4

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # get IPv4 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IP)
        rx_udp = rx_pkt[UDP]

        tx_ip = tx_pkt.getlayer(IPv6)
        tx_ip2 = tx_pkt.getlayer(IP)
        tx_udp = tx_pkt[UDP]

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # rx'ed ip.src should be equal to tx'ed ip2.src
        self.assertEqual(rx_ip.src, tx_ip2.src)
        # rx'ed ip.dst should be equal to tx'ed ip2.dst
        self.assertEqual(rx_ip.dst, tx_ip2.dst)

        # UDP layer should be unchanged
        self.assertEqual(rx_udp.sport, tx_udp.sport)
        self.assertEqual(rx_udp.dport, tx_udp.dport)

        self.logger.debug("packet verification: SUCCESS")

    def create_stream(self, src_if, dst_if, packet_header, packet_sizes,
                      count):
        """Create SRv6 input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for
        :param VppInterface dst_if: destination interface of packet stream
        :param packet_header: Layer3 scapy packet headers (excl L2),
        :param packet_header: L2 and Raw(payload) with packet_info are added
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

        :param input: ingress interface
        :param pkts: list of packets to transmit
        :param output: egress interface
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

    def create_packet_header_IPv6(self, dst):
        """Create packet header: IPv6 header, UDP header

        :param dst: IPv6 destination address

        IPv6 source address is 1234::1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=dst) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_SRH(self, sidlist, segleft):
        """Create packet header: IPv6 header with SRH, UDP header

        :param list sidlist: segment list
        :param int segleft: segments-left field value

        IPv6 destination address is set to sidlist[segleft]
        IPv6 source addresses are 1234::1 and 4321::1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=sidlist[segleft]) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_SRH_IPv6(self, dst, sidlist, segleft):
        """Create packet header: IPv6 encapsulated in SRv6:
        IPv6 header with SRH, IPv6 header, UDP header

        :param ipv6address dst: inner IPv6 destination address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH

        Outer IPv6 destination address is set to sidlist[segleft]
        IPv6 source addresses are 1234::1 and 4321::1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=sidlist[segleft]) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                      segleft=segleft, nh=41) /
             IPv6(src='4321::1', dst=dst) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_IPv6(self, dst_inner, dst_outer):
        """Create packet header: IPv6 encapsulated in IPv6:
        IPv6 header, IPv6 header, UDP header

        :param ipv6address dst_inner: inner IPv6 destination address
        :param ipv6address dst_outer: outer IPv6 destination address

        IPv6 source addresses are 1234::1 and 4321::1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=dst_outer) /
             IPv6(src='4321::1', dst=dst_inner) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_SRH_SRH_IPv6(self, dst, sidlist1, segleft1,
                                               sidlist2, segleft2):
        # TODO: make one create_packet function for any stack of SRH (1, 2, ..)
        """Create packet header: IPv6 encapsulated in SRv6 with 2 SRH:
        IPv6 header with SRH, 2nd SRH, IPv6 header, UDP header

        :param ipv6address dst: inner IPv6 destination address
        :param list sidlist1: segment list of outer IPv6 SRH
        :param int segleft1: segments-left field of outer IPv6 SRH
        :param list sidlist2: segment list of inner IPv6 SRH
        :param int segleft2: segments-left field of inner IPv6 SRH

        Outer IPv6 destination address is set to sidlist[segleft]
        IPv6 source addresses are 1234::1 and 4321::1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=sidlist1[segleft1]) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist1,
                                      segleft=segleft1, nh=43) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist2,
                                      segleft=segleft2, nh=41) /
             IPv6(src='4321::1', dst=dst) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv4(self, dst):
        """Create packet header: IPv4 header, UDP header

        :param dst: IPv4 destination address

        IPv4 source address is 123.1.1.1
        UDP source port and destination port are 1234
        """

        p = (IP(src='123.1.1.1', dst=dst) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_IPv4(self, dst_inner, dst_outer):
        """Create packet header: IPv4 encapsulated in IPv6:
        IPv6 header, IPv4 header, UDP header

        :param ipv4address dst_inner: inner IPv4 destination address
        :param ipv6address dst_outer: outer IPv6 destination address

        IPv6 source address is 1234::1
        IPv4 source address is 123.1.1.1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=dst_outer) /
             IP(src='123.1.1.1', dst=dst_inner) /
             UDP(sport=1234, dport=1234))
        return p

    def create_packet_header_IPv6_SRH_IPv4(self, dst, sidlist, segleft):
        """Create packet header: IPv4 encapsulated in SRv6:
        IPv6 header with SRH, IPv4 header, UDP header

        :param ipv4address dst: inner IPv4 destination address
        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH

        Outer IPv6 destination address is set to sidlist[segleft]
        IPv6 source address is 1234::1
        IPv4 source address is 123.1.1.1
        UDP source port and destination port are 1234
        """

        p = (IPv6(src='1234::1', dst=sidlist[segleft]) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                      segleft=segleft, nh=4) /
             IP(src='123.1.1.1', dst=dst) /
             UDP(sport=1234, dport=1234))
        return p

    def verify_captured_pkts(self, dst_if, capture, compare_func):
        """
        Verify captured packet stream for specified interface.
        Compare ingress with egress packets using the specified compare fn

        :param dst_if: destination interface
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
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index

                self.logger.debug("Verifying packet with index %d"
                                  % (packet_index))
                # packet should have arrived on the expected interface
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (idx=%u)" %
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
