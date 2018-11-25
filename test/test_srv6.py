#!/usr/bin/env python

import unittest
import binascii
from socket import AF_INET6

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, DPO_PROTO, VppIpTable
from vpp_srv6 import SRv6LocalSIDBehaviors, VppSRv6LocalSID, VppSRv6Policy, \
    SRv6PolicyType, VppSRv6Steering, SRv6PolicySteeringTypes

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, IPv6ExtHdrSegmentRouting
from scapy.layers.inet import IP, UDP

from scapy.utils import inet_pton, inet_ntop

from util import ppp


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

    @unittest.skipUnless(0, "PC to fix")
    def test_SRv6_T_Encaps(self):
        """ Test SRv6 Transit.Encaps behavior for IPv6.
        """
        # send traffic to one destination interface
        # source and destination are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
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

        # steer IPv6 traffic to a7::/64 into SRv6 Policy
        # use the bsid of the above self.sr_policy
        pol_steering = VppSRv6Steering(
                        self,
                        bsid=self.sr_policy.bsid,
                        prefix="a7::", mask_width=64,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_IPV6,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=0)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))

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
        packet_header = self.create_packet_header_IPv6_SRH(
            sidlist=['a8::', 'a7::', 'a6::'],
            segleft=1)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # create IPv6 packets with SRH and IPv6
        # packets with segments-left 1, active segment a7::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
            dst_inner,
            sidlist=['a8::', 'a7::', 'a6::'],
            segleft=1)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

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
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    @unittest.skipUnless(0, "PC to fix")
    def test_SRv6_T_Insert(self):
        """ Test SRv6 Transit.Insert behavior (IPv6 only).
        """
        # send traffic to one destination interface
        # source and destination are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
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
            is_encap=0,
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
                        bsid=self.sr_policy.bsid,
                        prefix="a7::", mask_width=64,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_IPV6,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=0)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))

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
        packet_header = self.create_packet_header_IPv6_SRH(
            sidlist=['a8::', 'a7::', 'a6::'],
            segleft=1)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_T_Insert)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SR steering
        pol_steering.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # remove SR Policies
        self.sr_policy.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr policies"))

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    @unittest.skipUnless(0, "PC to fix")
    def test_SRv6_T_Encaps_IPv4(self):
        """ Test SRv6 Transit.Encaps behavior for IPv4.
        """
        # send traffic to one destination interface
        # source interface is IPv4 only
        # destination interface is IPv6 only
        self.setup_interfaces(ipv6=[False, True], ipv4=[True, False])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
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
                        bsid=self.sr_policy.bsid,
                        prefix="7.1.1.0", mask_width=24,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_IPV4,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=0)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))

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
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    @unittest.skip("VPP crashes after running this test")
    def test_SRv6_T_Encaps_L2(self):
        """ Test SRv6 Transit.Encaps behavior for L2.
        """
        # send traffic to one destination interface
        # source interface is IPv4 only TODO?
        # destination interface is IPv6 only
        self.setup_interfaces(ipv6=[False, True], ipv4=[False, False])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
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

        # steer L2 traffic into SRv6 Policy
        # use the bsid of the above self.sr_policy
        pol_steering = VppSRv6Steering(
                        self,
                        bsid=self.sr_policy.bsid,
                        prefix="::", mask_width=0,
                        traffic_type=SRv6PolicySteeringTypes.SR_STEER_L2,
                        sr_policy_index=0, table_id=0,
                        sw_if_index=self.pg0.sw_if_index)
        pol_steering.add_vpp_config()

        # log the sr steering policies
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # create packets
        count = len(self.pg_packet_sizes)
        pkts = []

        # create L2 packets without dot1q header
        packet_header = self.create_packet_header_L2()
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # create L2 packets with dot1q header
        packet_header = self.create_packet_header_L2(vlan=123)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_T_Encaps_L2)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SR steering
        pol_steering.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # remove SR Policies
        self.sr_policy.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr policies"))

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End(self):
        """ Test SRv6 End (without PSP) behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID End without PSP behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::0'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_END,
                        nh_addr4='0.0.0.0',
                        nh_addr6='::',
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

        # TODO: test behavior with SL=0 packet (needs 2*SRH?)

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_with_PSP(self):
        """ Test SRv6 End with PSP behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID End with PSP behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::0'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_END,
                        nh_addr4='0.0.0.0',
                        nh_addr6='::',
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

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_PSP)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_X(self):
        """ Test SRv6 End.X (without PSP) behavior.
        """
        # create three interfaces (1 source, 2 destinations)
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True, True])

        # configure FIB entries
        # a4::/64 via pg1 and pg2
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6),
                            VppRoutePath(self.pg2.remote_ip6,
                                         self.pg2.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
                           is_ip6=1)
        route.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip6 fib"))

        # configure SRv6 localSID End.X without PSP behavior
        # End.X points to interface pg1
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_X,
                        nh_addr4='0.0.0.0',
                        nh_addr6=self.pg1.remote_ip6,
                        end_psp=0,
                        sw_if_index=self.pg1.sw_if_index,
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

        # packets with segments-left 2, active segment a3::c4
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                    dst_inner,
                    sidlist=['a5::', 'a4::', 'a3::c4'],
                    segleft=2)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets with segments-left 1, active segment a3::c4
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                    dst_inner,
                    sidlist=['a4::', 'a3::c4', 'a2::'],
                    segleft=1)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        # using same comparison function as End (no PSP)
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End)

        # assert nothing was received on the other interface (pg2)
        self.pg2.assert_nothing_captured("mis-directed packet(s)")

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_X_with_PSP(self):
        """ Test SRv6 End.X with PSP behavior.
        """
        # create three interfaces (1 source, 2 destinations)
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True, True])

        # configure FIB entries
        # a4::/64 via pg1 and pg2
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg1.remote_ip6,
                                         self.pg1.sw_if_index,
                                         proto=DPO_PROTO.IP6),
                            VppRoutePath(self.pg2.remote_ip6,
                                         self.pg2.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
                           is_ip6=1)
        route.add_vpp_config()

        # configure SRv6 localSID End with PSP behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_X,
                        nh_addr4='0.0.0.0',
                        nh_addr6=self.pg1.remote_ip6,
                        end_psp=1,
                        sw_if_index=self.pg1.sw_if_index,
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
                    sidlist=['a5::', 'a4::', 'a3::c4'],
                    segleft=2)
        # create traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets with segments-left 1, active segment a3::
        packet_header = self.create_packet_header_IPv6_SRH_IPv6(
                    dst_inner,
                    sidlist=['a4::', 'a3::c4', 'a2::'],
                    segleft=1)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        # using same comparison function as End with PSP
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_PSP)

        # assert nothing was received on the other interface (pg2)
        self.pg2.assert_nothing_captured("mis-directed packet(s)")

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_DX6(self):
        """ Test SRv6 End.DX6 behavior.
        """
        # send traffic to one destination interface
        # source and destination interfaces are IPv6 only
        self.setup_interfaces(ipv6=[True, True])

        # configure SRv6 localSID End.DX6 behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX6,
                        nh_addr4='0.0.0.0',
                        nh_addr6=self.pg1.remote_ip6,
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

    def test_SRv6_End_DT6(self):
        """ Test SRv6 End.DT6 behavior.
        """
        # create three interfaces (1 source, 2 destinations)
        # all interfaces are IPv6 only
        # source interface in global FIB (0)
        # destination interfaces in global and vrf
        vrf_1 = 1
        ipt = VppIpTable(self, vrf_1, is_ip6=True)
        ipt.add_vpp_config()
        self.setup_interfaces(ipv6=[True, True, True],
                              ipv6_table_id=[0, 0, vrf_1])

        # configure FIB entries
        # a4::/64 is reachable
        #     via pg1 in table 0 (global)
        #     and via pg2 in table vrf_1
        route0 = VppIpRoute(self, "a4::", 64,
                            [VppRoutePath(self.pg1.remote_ip6,
                                          self.pg1.sw_if_index,
                                          proto=DPO_PROTO.IP6,
                                          nh_table_id=0)],
                            table_id=0,
                            is_ip6=1)
        route0.add_vpp_config()
        route1 = VppIpRoute(self, "a4::", 64,
                            [VppRoutePath(self.pg2.remote_ip6,
                                          self.pg2.sw_if_index,
                                          proto=DPO_PROTO.IP6,
                                          nh_table_id=vrf_1)],
                            table_id=vrf_1,
                            is_ip6=1)
        route1.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip6 fib"))

        # configure SRv6 localSID End.DT6 behavior
        # Note:
        # fib_table: where the localsid is installed
        # sw_if_index: in T-variants of localsid this is the vrf table_id
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DT6,
                        nh_addr4='0.0.0.0',
                        nh_addr6='::',
                        end_psp=0,
                        sw_if_index=vrf_1,
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
        pkts.extend(self.create_stream(self.pg0, self.pg2, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, IPv6 in IPv6
        # outer IPv6 dest addr is the localsid End.DT6
        packet_header = self.create_packet_header_IPv6_IPv6(
                                            dst_inner,
                                            dst_outer='a3::c4')
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg2, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        # using same comparison function as End.DX6
        self.send_and_verify_pkts(self.pg0, pkts, self.pg2,
                                  self.compare_rx_tx_packet_End_DX6)

        # assert nothing was received on the other interface (pg2)
        self.pg1.assert_nothing_captured("mis-directed packet(s)")

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_DX4(self):
        """ Test SRv6 End.DX4 behavior.
        """
        # send traffic to one destination interface
        # source interface is IPv6 only
        # destination interface is IPv4 only
        self.setup_interfaces(ipv6=[True, False], ipv4=[False, True])

        # configure SRv6 localSID End.DX4 behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX4,
                        nh_addr4=self.pg1.remote_ip4,
                        nh_addr6='::',
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

    def test_SRv6_End_DT4(self):
        """ Test SRv6 End.DT4 behavior.
        """
        # create three interfaces (1 source, 2 destinations)
        # source interface is IPv6-only
        # destination interfaces are IPv4 only
        # source interface in global FIB (0)
        # destination interfaces in global and vrf
        vrf_1 = 1
        ipt = VppIpTable(self, vrf_1)
        ipt.add_vpp_config()
        self.setup_interfaces(ipv6=[True, False, False],
                              ipv4=[False, True, True],
                              ipv6_table_id=[0, 0, 0],
                              ipv4_table_id=[0, 0, vrf_1])

        # configure FIB entries
        # 4.1.1.0/24 is reachable
        #     via pg1 in table 0 (global)
        #     and via pg2 in table vrf_1
        route0 = VppIpRoute(self, "4.1.1.0", 24,
                            [VppRoutePath(self.pg1.remote_ip4,
                                          self.pg1.sw_if_index,
                                          nh_table_id=0)],
                            table_id=0,
                            is_ip6=0)
        route0.add_vpp_config()
        route1 = VppIpRoute(self, "4.1.1.0", 24,
                            [VppRoutePath(self.pg2.remote_ip4,
                                          self.pg2.sw_if_index,
                                          nh_table_id=vrf_1)],
                            table_id=vrf_1,
                            is_ip6=0)
        route1.add_vpp_config()
        self.logger.debug(self.vapi.cli("show ip fib"))

        # configure SRv6 localSID End.DT6 behavior
        # Note:
        # fib_table: where the localsid is installed
        # sw_if_index: in T-variants of localsid: vrf table_id
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DT4,
                        nh_addr4='0.0.0.0',
                        nh_addr6='::',
                        end_psp=0,
                        sw_if_index=vrf_1,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # create IPv6 packets with SRH (SL=0)
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
        pkts.extend(self.create_stream(self.pg0, self.pg2, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, IPv6 in IPv6
        # outer IPv6 dest addr is the localsid End.DX4
        packet_header = self.create_packet_header_IPv6_IPv4(
                                            dst_inner,
                                            dst_outer='a3::c4')
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg2, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        # using same comparison function as End.DX4
        self.send_and_verify_pkts(self.pg0, pkts, self.pg2,
                                  self.compare_rx_tx_packet_End_DX4)

        # assert nothing was received on the other interface (pg2)
        self.pg1.assert_nothing_captured("mis-directed packet(s)")

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def test_SRv6_End_DX2(self):
        """ Test SRv6 End.DX2 behavior.
        """
        # send traffic to one destination interface
        # source interface is IPv6 only
        self.setup_interfaces(ipv6=[True, False], ipv4=[False, False])

        # configure SRv6 localSID End.DX2 behavior
        localsid = VppSRv6LocalSID(
                        self, localsid={'addr': 'A3::C4'},
                        behavior=SRv6LocalSIDBehaviors.SR_BEHAVIOR_DX2,
                        nh_addr4='0.0.0.0',
                        nh_addr6='::',
                        end_psp=0,
                        sw_if_index=self.pg1.sw_if_index,
                        vlan_index=0,
                        fib_table=0)
        localsid.add_vpp_config()
        # log the localsids
        self.logger.debug(self.vapi.cli("show sr localsid"))

        # send one packet per packet size
        count = len(self.pg_packet_sizes)
        pkts = []

        # packets with SRH, segments-left 0, active segment a3::c4
        # L2 has no dot1q header
        packet_header = self.create_packet_header_IPv6_SRH_L2(
                            sidlist=['a3::c4', 'a2::', 'a1::'],
                            segleft=0,
                            vlan=0)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets with SRH, segments-left 0, active segment a3::c4
        # L2 has dot1q header
        packet_header = self.create_packet_header_IPv6_SRH_L2(
                            sidlist=['a3::c4', 'a2::', 'a1::'],
                            segleft=0,
                            vlan=123)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, L2 in IPv6
        # outer IPv6 dest addr is the localsid End.DX2
        # L2 has no dot1q header
        packet_header = self.create_packet_header_IPv6_L2(
                                            dst_outer='a3::c4',
                                            vlan=0)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # packets without SRH, L2 in IPv6
        # outer IPv6 dest addr is the localsid End.DX2
        # L2 has dot1q header
        packet_header = self.create_packet_header_IPv6_L2(
                                            dst_outer='a3::c4',
                                            vlan=123)
        # add to traffic stream pg0->pg1
        pkts.extend(self.create_stream(self.pg0, self.pg1, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg0, pkts, self.pg1,
                                  self.compare_rx_tx_packet_End_DX2)

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove SRv6 localSIDs
        localsid.remove_vpp_config()

        # cleanup interfaces
        self.teardown_interfaces()

    @unittest.skipUnless(0, "PC to fix")
    def test_SRv6_T_Insert_Classifier(self):
        """ Test SRv6 Transit.Insert behavior (IPv6 only).
            steer packets using the classifier
        """
        # send traffic to one destination interface
        # source and destination are IPv6 only
        self.setup_interfaces(ipv6=[False, False, False, True, True])

        # configure FIB entries
        route = VppIpRoute(self, "a4::", 64,
                           [VppRoutePath(self.pg4.remote_ip6,
                                         self.pg4.sw_if_index,
                                         proto=DPO_PROTO.IP6)],
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
            is_encap=0,
            sr_type=SRv6PolicyType.SR_POLICY_TYPE_DEFAULT,
            weight=1, fib_table=0,
            segments=['a4::', 'a5::', 'a6::c7'],
            source='a3::')
        sr_policy.add_vpp_config()
        self.sr_policy = sr_policy

        # log the sr policies
        self.logger.info(self.vapi.cli("show sr policies"))

        # add classify table
        # mask on dst ip address prefix a7::/8
        mask = '{:0<16}'.format('ff')
        r = self.vapi.classify_add_del_table(
            1,
            binascii.unhexlify(mask),
            match_n_vectors=(len(mask) - 1) // 32 + 1,
            current_data_flag=1,
            skip_n_vectors=2)  # data offset
        self.assertIsNotNone(r, msg='No response msg for add_del_table')
        table_index = r.new_table_index

        # add the source routign node as a ip6 inacl netxt node
        r = self.vapi.add_node_next('ip6-inacl',
                                    'sr-pl-rewrite-insert')
        inacl_next_node_index = r.node_index

        match = '{:0<16}'.format('a7')
        r = self.vapi.classify_add_del_session(
            1,
            table_index,
            binascii.unhexlify(match),
            hit_next_index=inacl_next_node_index,
            action=3,
            metadata=0)  # sr policy index
        self.assertIsNotNone(r, msg='No response msg for add_del_session')

        # log the classify table used in the steering policy
        self.logger.info(self.vapi.cli("show classify table"))

        r = self.vapi.input_acl_set_interface(
            is_add=1,
            sw_if_index=self.pg3.sw_if_index,
            ip6_table_index=table_index)
        self.assertIsNotNone(r,
                             msg='No response msg for input_acl_set_interface')

        # log the ip6 inacl
        self.logger.info(self.vapi.cli("show inacl type ip6"))

        # create packets
        count = len(self.pg_packet_sizes)
        dst_inner = 'a7::1234'
        pkts = []

        # create IPv6 packets without SRH
        packet_header = self.create_packet_header_IPv6(dst_inner)
        # create traffic stream pg3->pg4
        pkts.extend(self.create_stream(self.pg3, self.pg4, packet_header,
                                       self.pg_packet_sizes, count))

        # create IPv6 packets with SRH
        # packets with segments-left 1, active segment a7::
        packet_header = self.create_packet_header_IPv6_SRH(
            sidlist=['a8::', 'a7::', 'a6::'],
            segleft=1)
        # create traffic stream pg3->pg4
        pkts.extend(self.create_stream(self.pg3, self.pg4, packet_header,
                                       self.pg_packet_sizes, count))

        # send packets and verify received packets
        self.send_and_verify_pkts(self.pg3, pkts, self.pg4,
                                  self.compare_rx_tx_packet_T_Insert)

        # remove the interface l2 input feature
        r = self.vapi.input_acl_set_interface(
            is_add=0,
            sw_if_index=self.pg3.sw_if_index,
            ip6_table_index=table_index)
        self.assertIsNotNone(r,
                             msg='No response msg for input_acl_set_interface')

        # log the ip6 inacl after cleaning
        self.logger.info(self.vapi.cli("show inacl type ip6"))

        # log the localsid counters
        self.logger.info(self.vapi.cli("show sr localsid"))

        # remove classifier SR steering
        # classifier_steering.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr steering policies"))

        # remove SR Policies
        self.sr_policy.remove_vpp_config()
        self.logger.info(self.vapi.cli("show sr policies"))

        # remove classify session and table
        r = self.vapi.classify_add_del_session(
            0,
            table_index,
            binascii.unhexlify(match))
        self.assertIsNotNone(r, msg='No response msg for add_del_session')

        r = self.vapi.classify_add_del_table(
            0,
            binascii.unhexlify(mask),
            table_index=table_index)
        self.assertIsNotNone(r, msg='No response msg for add_del_table')

        self.logger.info(self.vapi.cli("show classify table"))

        # remove FIB entries
        # done by tearDown

        # cleanup interfaces
        self.teardown_interfaces()

    def compare_rx_tx_packet_T_Encaps(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Encaps

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # T.Encaps updates the headers as follows:
        # SR Policy seglist (S3, S2, S1)
        # SR Policy source C
        # IPv6:
        # in: IPv6(A, B2)
        # out: IPv6(C, S1)SRH(S3, S2, S1; SL=2)IPv6(A, B2)
        # IPv6 + SRH:
        # in: IPv6(A, B2)SRH(B3, B2, B1; SL=1)
        # out: IPv6(C, S1)SRH(S3, S2, S1; SL=2)IPv6(a, B2)SRH(B3, B2, B1; SL=1)

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None

        tx_ip = tx_pkt.getlayer(IPv6)

        # expected segment-list
        seglist = self.sr_policy.segments
        # reverse list to get order as in SRH
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = self.sr_policy.source

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

        # received ip.src should be equal to SR Policy source
        self.assertEqual(rx_ip.src, sr_policy_source)
        # received ip.dst should be equal to expected sidlist[lastentry]
        self.assertEqual(rx_ip.dst, tx_seglist[-1])
        # rx'ed seglist should be equal to expected seglist
        self.assertEqual(rx_srh.addresses, tx_seglist)
        # segleft should be equal to size expected seglist-1
        self.assertEqual(rx_srh.segleft, len(tx_seglist)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the hop-limit field
        #   -> update tx'ed hlim to the expected hlim
        tx_ip.hlim = tx_ip.hlim - 1

        self.assertEqual(rx_srh.payload, tx_ip)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_T_Encaps_IPv4(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Encaps for IPv4

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # T.Encaps for IPv4 updates the headers as follows:
        # SR Policy seglist (S3, S2, S1)
        # SR Policy source C
        # IPv4:
        # in: IPv4(A, B2)
        # out: IPv6(C, S1)SRH(S3, S2, S1; SL=2)IPv4(A, B2)

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None

        tx_ip = tx_pkt.getlayer(IP)

        # expected segment-list
        seglist = self.sr_policy.segments
        # reverse list to get order as in SRH
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = self.sr_policy.source

        # checks common to cases tx with and without SRH
        # rx'ed packet should have SRH and IPv4 header
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertTrue(rx_ip.payload.haslayer(IP))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

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

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        # except for the ttl field and ip checksum
        #   -> adjust tx'ed ttl to expected ttl
        tx_ip.ttl = tx_ip.ttl - 1
        #   -> set tx'ed ip checksum to None and let scapy recompute
        tx_ip.chksum = None
        # read back the pkt (with str()) to force computing these fields
        # probably other ways to accomplish this are possible
        tx_ip = IP(str(tx_ip))

        self.assertEqual(rx_srh.payload, tx_ip)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_T_Encaps_L2(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Encaps for L2

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # T.Encaps for L2 updates the headers as follows:
        # SR Policy seglist (S3, S2, S1)
        # SR Policy source C
        # L2:
        # in: L2
        # out: IPv6(C, S1)SRH(S3, S2, S1; SL=2)L2

        # get first (outer) IPv6 header of rx'ed packet
        rx_ip = rx_pkt.getlayer(IPv6)
        rx_srh = None

        tx_ether = tx_pkt.getlayer(Ether)

        # expected segment-list
        seglist = self.sr_policy.segments
        # reverse list to get order as in SRH
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = self.sr_policy.source

        # rx'ed packet should have SRH
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

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
        # nh should be "No Next Header" (59)
        self.assertEqual(rx_srh.nh, 59)

        # the whole rx'ed pkt beyond SRH should be equal to tx'ed pkt
        self.assertEqual(Ether(str(rx_srh.payload)), tx_ether)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_T_Insert(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing T.Insert

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # T.Insert updates the headers as follows:
        # IPv6:
        # in: IPv6(A, B2)
        # out: IPv6(A, S1)SRH(B2, S3, S2, S1; SL=3)
        # IPv6 + SRH:
        # in: IPv6(A, B2)SRH(B3, B2, B1; SL=1)
        # out: IPv6(A, S1)SRH(B2, S3, S2, S1; SL=3)SRH(B3, B2, B1; SL=1)

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
            tx_ip2 = tx_pkt.getlayer(IPv6, 2)
        tx_udp = tx_pkt[UDP]

        # expected segment-list (make copy of SR Policy segment list)
        seglist = self.sr_policy.segments[:]
        # expected seglist has initial dest addr as last segment
        seglist.append(tx_ip.dst)
        # reverse list to get order as in SRH
        tx_seglist = seglist[::-1]

        # get source address of SR Policy
        sr_policy_source = self.sr_policy.source

        # checks common to cases tx with and without SRH
        # rx'ed packet should have SRH and only one IPv6 header
        self.assertTrue(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))
        self.assertFalse(rx_ip.payload.haslayer(IPv6))
        # get SRH
        rx_srh = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting)

        # rx'ed ip.src should be equal to tx'ed ip.src
        self.assertEqual(rx_ip.src, tx_ip.src)
        # rx'ed ip.dst should be equal to sidlist[lastentry]
        self.assertEqual(rx_ip.dst, tx_seglist[-1])

        # rx'ed seglist should be equal to expected seglist
        self.assertEqual(rx_srh.addresses, tx_seglist)
        # segleft should be equal to size(expected seglist)-1
        self.assertEqual(rx_srh.segleft, len(tx_seglist)-1)
        # segleft should be equal to lastentry
        self.assertEqual(rx_srh.segleft, rx_srh.lastentry)

        if tx_srh:  # packet was tx'ed with SRH
            # packet should have 2nd SRH
            self.assertTrue(rx_srh.payload.haslayer(IPv6ExtHdrSegmentRouting))
            # get 2nd SRH
            rx_srh2 = rx_pkt.getlayer(IPv6ExtHdrSegmentRouting, 2)

            # rx'ed srh2.addresses should be equal to tx'ed srh.addresses
            self.assertEqual(rx_srh2.addresses, tx_srh.addresses)
            # rx'ed srh2.segleft should be equal to tx'ed srh.segleft
            self.assertEqual(rx_srh2.segleft, tx_srh.segleft)
            # rx'ed srh2.lastentry should be equal to tx'ed srh.lastentry
            self.assertEqual(rx_srh2.lastentry, tx_srh.lastentry)

        else:  # packet was tx'ed without SRH
            # rx packet should have no other SRH
            self.assertFalse(rx_srh.payload.haslayer(IPv6ExtHdrSegmentRouting))

        # UDP layer should be unchanged
        self.assertEqual(rx_udp, tx_udp)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End (without PSP)

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # End (no PSP) updates the headers as follows:
        # IPv6 + SRH:
        # in: IPv6(A, S1)SRH(S3, S2, S1; SL=2)
        # out: IPv6(A, S2)SRH(S3, S2, S1; SL=1)

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
            # TODO: Does this work with 2 SRHs in ingress packet?

        # UDP layer should be unchanged
        self.assertEqual(rx_udp, tx_udp)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_PSP(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End with PSP

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # End (PSP) updates the headers as follows:
        # IPv6 + SRH (SL>1):
        # in: IPv6(A, S1)SRH(S3, S2, S1; SL=2)
        # out: IPv6(A, S2)SRH(S3, S2, S1; SL=1)
        # IPv6 + SRH (SL=1):
        # in: IPv6(A, S2)SRH(S3, S2, S1; SL=1)
        # out: IPv6(A, S3)

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
        self.assertEqual(rx_udp, tx_udp)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_DX6(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.DX6

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # End.DX6 updates the headers as follows:
        # IPv6 + SRH (SL=0):
        # in: IPv6(A, S3)SRH(S3, S2, S1; SL=0)IPv6(B, D)
        # out: IPv6(B, D)
        # IPv6:
        # in: IPv6(A, S3)IPv6(B, D)
        # out: IPv6(B, D)

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

    def compare_rx_tx_packet_End_DX4(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.DX4

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # End.DX4 updates the headers as follows:
        # IPv6 + SRH (SL=0):
        # in: IPv6(A, S3)SRH(S3, S2, S1; SL=0)IPv4(B, D)
        # out: IPv4(B, D)
        # IPv6:
        # in: IPv6(A, S3)IPv4(B, D)
        # out: IPv4(B, D)

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
        tx_ip2 = IP(str(tx_ip2))

        self.assertEqual(rx_ip, tx_ip2)

        self.logger.debug("packet verification: SUCCESS")

    def compare_rx_tx_packet_End_DX2(self, tx_pkt, rx_pkt):
        """ Compare input and output packet after passing End.DX2

        :param tx_pkt: transmitted packet
        :param rx_pkt: received packet
        """
        # End.DX2 updates the headers as follows:
        # IPv6 + SRH (SL=0):
        # in: IPv6(A, S3)SRH(S3, S2, S1; SL=0)L2
        # out: L2
        # IPv6:
        # in: IPv6(A, S3)L2
        # out: L2

        # get IPv4 header of rx'ed packet
        rx_eth = rx_pkt.getlayer(Ether)

        tx_ip = tx_pkt.getlayer(IPv6)
        # we can't just get the 2nd Ether layer
        # get the Raw content and dissect it as Ether
        tx_eth1 = Ether(str(tx_pkt[Raw]))

        # verify if rx'ed packet has no SRH
        self.assertFalse(rx_pkt.haslayer(IPv6ExtHdrSegmentRouting))

        # the whole rx_eth pkt should be equal to tx_eth1
        self.assertEqual(rx_eth, tx_eth1)

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

    def create_packet_header_IPv6_SRH_L2(self, sidlist, segleft, vlan=0):
        """Create packet header: L2 encapsulated in SRv6:
        IPv6 header with SRH, L2

        :param list sidlist: segment list of outer IPv6 SRH
        :param int segleft: segments-left field of outer IPv6 SRH
        :param vlan: L2 vlan; if vlan!=0 then add 802.1q header

        Outer IPv6 destination address is set to sidlist[segleft]
        IPv6 source address is 1234::1
        """
        eth = Ether(src='00:11:22:33:44:55', dst='00:55:44:33:22:11')
        etype = 0x8137  # IPX
        if vlan:
            # add 802.1q layer
            eth /= Dot1Q(vlan=vlan, type=etype)
        else:
            eth.type = etype

        p = (IPv6(src='1234::1', dst=sidlist[segleft]) /
             IPv6ExtHdrSegmentRouting(addresses=sidlist,
                                      segleft=segleft, nh=59) /
             eth)
        return p

    def create_packet_header_IPv6_L2(self, dst_outer, vlan=0):
        """Create packet header: L2 encapsulated in IPv6:
        IPv6 header, L2

        :param ipv6address dst_outer: outer IPv6 destination address
        :param vlan: L2 vlan; if vlan!=0 then add 802.1q header
        """
        eth = Ether(src='00:11:22:33:44:55', dst='00:55:44:33:22:11')
        etype = 0x8137  # IPX
        if vlan:
            # add 802.1q layer
            eth /= Dot1Q(vlan=vlan, type=etype)
        else:
            eth.type = etype

        p = (IPv6(src='1234::1', dst=dst_outer, nh=59) / eth)
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
