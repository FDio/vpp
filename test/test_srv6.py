#!/usr/bin/env python

import unittest
from socket import AF_INET6

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint
from vpp_pg_interface import is_ipv6_misc
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route, VppIpMRoute, \
    VppMRoutePath, MRouteItfFlags, MRouteEntryFlags
from vpp_neighbor import find_nbr, VppNeighbor

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, ICMPv6ND_NS, ICMPv6ND_RS, \
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, getmacbyip6, ICMPv6MRD_Solicitation, \
    ICMPv6NDOptMTU, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, \
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6DestUnreach, icmp6types

from util import ppp
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ptop, in6_islladdr, \
    in6_mactoifaceid, in6_ismaddr
from scapy.utils import inet_pton, inet_ntop
from vpp_srv6 import VppSRv6Policy, VppSRv6Steering
from vpp_ioam_trace import VppiOAMTrace

class TestSRv6PolicySteer(VppTestCase):
    """ SRv6 Policy-steering """

    def setUp(self):
        super(TestSRv6PolicySteer, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestSRv6PolicySteer, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def send_and_expect_policy_steering(self, input, pkts, outputs):
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for oo in outputs:
            rx = oo._get_capture(1)
            #self.assertNotEqual(0, len(rx))

    def test_srv6_policy_steering(self):
        """ SRv6 Policy-Steering-Encap """

        #
        # An array of packets that differ only in the destination port
        #
        test_pkts = []



        for ii in range(1):
            test_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IPv6(dst="db01::1", src="3000:1::1") /
                              UDP(sport=7785, dport=7784 + ii) /
                              Raw('\xa5' * 100)))

        route_3000_1 = VppIpRoute(self, "A32B::", 64,
                                  [VppRoutePath(self.pg1.remote_ip6,
                                                self.pg1.sw_if_index,
                                                is_ip6=1)],
                                  is_ip6=1)
        route_3000_1.add_vpp_config()
        #self.vapi.cli("set ioam-trace profile trace-type 0x1f trace-elts 2 trace-tsp 1 node-id 0x2 app-data 0xcafec0ff")

        #ioam_trace_obj = VppiOAMTrace(self, ioam_trace_type=31, num_elts=2, trace_tsp=1, node_id=2, app_data=0xcafec0ff)
        ioam_trace_obj = VppiOAMTrace(self, 31, 2, 1, 0xc19902, 0xcafec0ff)
        ioam_trace_obj.add_vpp_config()

        sr_policy_1 = VppSRv6Policy(self, bsid="C1::99:2", num_segments=3, segment_i=['A32B::', 'B1B2::',  'CACD::'])
        sr_policy_1.add_vpp_config()

        sr_steer_1 = VppSRv6Steering(self, bsid="C1::99:2", mask_width=64, prefix="db01::0")
        sr_steer_1.add_vpp_config()

        self.logger.info(self.vapi.cli("show ioam-trace profile"))
        self.logger.info(self.vapi.cli("show int addr"))
        self.logger.info(self.vapi.cli("show ip6 fib"))
        self.logger.info(self.vapi.cli("show ip6 nei"))
        self.logger.info(self.vapi.cli("show sr policies"))
        self.logger.info(self.vapi.cli("show sr steering policies"))
        self.send_and_expect_policy_steering(self.pg0, test_pkts,
                                            [self.pg1])

        self.vapi.cli("show trace")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
