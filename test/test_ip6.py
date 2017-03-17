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


def mk_ll_addr(mac):
    euid = in6_mactoifaceid(mac)
    addr = "fe80::" + euid
    return addr


class TestIPv6ND(VppTestCase):
    def validate_ra(self, intf, rx, dst_ip=None):
        if not dst_ip:
            dst_ip = intf.remote_ip6

        # unicasted packets must come to the unicast mac
        self.assertEqual(rx[Ether].dst, intf.remote_mac)

        # and from the router's MAC
        self.assertEqual(rx[Ether].src, intf.local_mac)

        # the rx'd RA should be addressed to the sender's source
        self.assertTrue(rx.haslayer(ICMPv6ND_RA))
        self.assertEqual(in6_ptop(rx[IPv6].dst),
                         in6_ptop(dst_ip))

        # and come from the router's link local
        self.assertTrue(in6_islladdr(rx[IPv6].src))
        self.assertEqual(in6_ptop(rx[IPv6].src),
                         in6_ptop(mk_ll_addr(intf.local_mac)))

    def validate_na(self, intf, rx, dst_ip=None, tgt_ip=None):
        if not dst_ip:
            dst_ip = intf.remote_ip6
        if not tgt_ip:
            dst_ip = intf.local_ip6

        # unicasted packets must come to the unicast mac
        self.assertEqual(rx[Ether].dst, intf.remote_mac)

        # and from the router's MAC
        self.assertEqual(rx[Ether].src, intf.local_mac)

        # the rx'd NA should be addressed to the sender's source
        self.assertTrue(rx.haslayer(ICMPv6ND_NA))
        self.assertEqual(in6_ptop(rx[IPv6].dst),
                         in6_ptop(dst_ip))

        # and come from the target address
        self.assertEqual(in6_ptop(rx[IPv6].src), in6_ptop(tgt_ip))

        # Dest link-layer options should have the router's MAC
        dll = rx[ICMPv6NDOptDstLLAddr]
        self.assertEqual(dll.lladdr, intf.local_mac)

    def send_and_expect_ra(self, intf, pkts, remark, dst_ip=None,
                           filter_out_fn=is_ipv6_misc):
        intf.add_stream(pkts)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = intf.get_capture(1, filter_out_fn=filter_out_fn)

        self.assertEqual(len(rx), 1)
        rx = rx[0]
        self.validate_ra(intf, rx, dst_ip)

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        intf.assert_nothing_captured(remark=remark)


class TestIPv6(TestIPv6ND):
    """ IPv6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6, cls).setUpClass()

    def setUp(self):
        """
        Perform test setup before test case.

        **Config:**
            - create 3 pg interfaces
                - untagged pg0 interface
                - Dot1Q subinterface on pg1
                - Dot1AD subinterface on pg2
            - setup interfaces:
                - put it into UP state
                - set IPv6 addresses
                - resolve neighbor address using NDP
            - configure 200 fib entries

        :ivar list interfaces: pg interfaces and subinterfaces.
        :ivar dict flows: IPv4 packet flows in test.
        :ivar list pg_if_packet_sizes: packet sizes in test.

        *TODO:* Create AD sub interface
        """
        super(TestIPv6, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # create 2 subinterfaces for p1 and pg2
        self.sub_interfaces = [
            VppDot1QSubint(self, self.pg1, 100),
            VppDot1QSubint(self, self.pg2, 200)
            # TODO: VppDot1ADSubint(self, self.pg2, 200, 300, 400)
        ]

        # packet flows mapping pg0 -> pg1.sub, pg2.sub, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1.sub_if, self.pg2.sub_if]
        self.flows[self.pg1.sub_if] = [self.pg0, self.pg2.sub_if]
        self.flows[self.pg2.sub_if] = [self.pg0, self.pg1.sub_if]

        # packet sizes
        self.pg_if_packet_sizes = [64, 512, 1518, 9018]
        self.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

        self.interfaces = list(self.pg_interfaces)
        self.interfaces.extend(self.sub_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

        # config 2M FIB entries
        self.config_fib_entries(200)

    def tearDown(self):
        """Run standard test teardown and log ``show ip6 neighbors``."""
        for i in self.sub_interfaces:
            i.unconfig_ip6()
            i.ip6_disable()
            i.admin_down()
            i.remove_vpp_config()

        super(TestIPv6, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show ip6 neighbors"))
            # info(self.vapi.cli("show ip6 fib"))  # many entries

    def config_fib_entries(self, count):
        """For each interface add to the FIB table *count* routes to
        "fd02::1/128" destination with interface's local address as next-hop
        address.

        :param int count: Number of FIB entries.

        - *TODO:* check if the next-hop address shouldn't be remote address
          instead of local address.
        """
        n_int = len(self.interfaces)
        percent = 0
        counter = 0.0
        dest_addr = inet_pton(AF_INET6, "fd02::1")
        dest_addr_len = 128
        for i in self.interfaces:
            next_hop_address = i.local_ip6n
            for j in range(count / n_int):
                self.vapi.ip_add_del_route(
                    dest_addr, dest_addr_len, next_hop_address, is_ipv6=1)
                counter += 1
                if counter / count * 100 > percent:
                    self.logger.info("Configure %d FIB entries .. %d%% done" %
                                     (count, percent))
                    percent += 1

    def create_stream(self, src_if, packet_sizes):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        :param list packet_sizes: Required packet sizes.
        """
        pkts = []
        for i in range(0, 257):
            dst_if = self.flows[src_if][i % 2]
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            if isinstance(src_if, VppSubInterface):
                p = src_if.add_dot1_layer(p)
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
                                    for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        is_sub_if = False
        dst_sw_if_index = dst_if.sw_if_index
        if hasattr(dst_if, 'parent'):
            is_sub_if = True
        for packet in capture:
            if is_sub_if:
                # Check VLAN tags and Ethernet header
                packet = dst_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IPv6]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IPv6].src)
                self.assertEqual(ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))

    def test_fib(self):
        """ IPv6 FIB test

        Test scenario:
            - Create IPv6 stream for pg0 interface
            - Create IPv6 tagged streams for pg1's and pg2's subinterface.
            - Send and verify received packets on each interface.
        """

        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i, self.sub_if_packet_sizes)
            i.parent.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts)

        for i in self.sub_interfaces:
            pkts = i.parent.get_capture()
            self.verify_capture(i, pkts)

    def test_ns(self):
        """ IPv6 Neighbour Solicitation Exceptions

        Test scenario:
           - Send an NS Sourced from an address not covered by the link sub-net
           - Send an NS to an mcast address the router has not joined
           - Send NS for a target address the router does not onn.
        """

        #
        # An NS from a non link source address
        #
        nsma = in6_getnsma(inet_pton(AF_INET6, self.pg0.local_ip6))
        d = inet_ntop(AF_INET6, nsma)

        p = (Ether(dst=in6_getnsmac(nsma)) /
             IPv6(dst=d, src="2002::2") /
             ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
             ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
        pkts = [p]

        self.send_and_assert_no_replies(
            self.pg0, pkts,
            "No response to NS source by address not on sub-net")

        #
        # An NS for sent to a solicited mcast group the router is
        # not a member of FAILS
        #
        if 0:
            nsma = in6_getnsma(inet_pton(AF_INET6, "fd::ffff"))
            d = inet_ntop(AF_INET6, nsma)

            p = (Ether(dst=in6_getnsmac(nsma)) /
                 IPv6(dst=d, src=self.pg0.remote_ip6) /
                 ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
                 ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
            pkts = [p]

            self.send_and_assert_no_replies(
                self.pg0, pkts,
                "No response to NS sent to unjoined mcast address")

        #
        # An NS whose target address is one the router does not own
        #
        nsma = in6_getnsma(inet_pton(AF_INET6, self.pg0.local_ip6))
        d = inet_ntop(AF_INET6, nsma)

        p = (Ether(dst=in6_getnsmac(nsma)) /
             IPv6(dst=d, src=self.pg0.remote_ip6) /
             ICMPv6ND_NS(tgt="fd::ffff") /
             ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
        pkts = [p]

        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "No response to NS for unknown target")

        #
        # A neighbor entry that has no associated FIB-entry
        #
        self.pg0.generate_remote_hosts(4)
        nd_entry = VppNeighbor(self,
                               self.pg0.sw_if_index,
                               self.pg0.remote_hosts[2].mac,
                               self.pg0.remote_hosts[2].ip6,
                               af=AF_INET6,
                               is_no_fib_entry=1)
        nd_entry.add_vpp_config()

        #
        # check we have the neighbor, but no route
        #
        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0._remote_hosts[2].ip6,
                                 inet=AF_INET6))
        self.assertFalse(find_route(self,
                                    self.pg0._remote_hosts[2].ip6,
                                    128,
                                    inet=AF_INET6))

    def validate_ra(self, intf, rx, dst_ip=None, mtu=9000, pi_opt=None):
        if not dst_ip:
            dst_ip = intf.remote_ip6

        # unicasted packets must come to the unicast mac
        self.assertEqual(rx[Ether].dst, intf.remote_mac)

        # and from the router's MAC
        self.assertEqual(rx[Ether].src, intf.local_mac)

        # the rx'd RA should be addressed to the sender's source
        self.assertTrue(rx.haslayer(ICMPv6ND_RA))
        self.assertEqual(in6_ptop(rx[IPv6].dst),
                         in6_ptop(dst_ip))

        # and come from the router's link local
        self.assertTrue(in6_islladdr(rx[IPv6].src))
        self.assertEqual(in6_ptop(rx[IPv6].src),
                         in6_ptop(mk_ll_addr(intf.local_mac)))

        # it should contain the links MTU
        ra = rx[ICMPv6ND_RA]
        self.assertEqual(ra[ICMPv6NDOptMTU].mtu, mtu)

        # it should contain the source's link layer address option
        sll = ra[ICMPv6NDOptSrcLLAddr]
        self.assertEqual(sll.lladdr, intf.local_mac)

        if not pi_opt:
            # the RA should not contain prefix information
            self.assertFalse(ra.haslayer(ICMPv6NDOptPrefixInfo))
        else:
            raos = rx.getlayer(ICMPv6NDOptPrefixInfo, 1)

            # the options are nested in the scapy packet in way that i cannot
            # decipher how to decode. this 1st layer of option always returns
            # nested classes, so a direct obj1=obj2 comparison always fails.
            # however, the getlayer(.., 2) does give one instnace.
            # so we cheat here and construct a new opt instnace for comparison
            rd = ICMPv6NDOptPrefixInfo(prefixlen=raos.prefixlen,
                                       prefix=raos.prefix,
                                       L=raos.L,
                                       A=raos.A)
            if type(pi_opt) is list:
                for ii in range(len(pi_opt)):
                    self.assertEqual(pi_opt[ii], rd)
                    rd = rx.getlayer(ICMPv6NDOptPrefixInfo, ii+2)
            else:
                self.assertEqual(pi_opt, raos)

    def send_and_expect_ra(self, intf, pkts, remark, dst_ip=None,
                           filter_out_fn=is_ipv6_misc,
                           opt=None):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = intf.get_capture(1, filter_out_fn=filter_out_fn)

        self.assertEqual(len(rx), 1)
        rx = rx[0]
        self.validate_ra(intf, rx, dst_ip, pi_opt=opt)

    def test_rs(self):
        """ IPv6 Router Solicitation Exceptions

        Test scenario:
        """

        #
        # Before we begin change the IPv6 RA responses to use the unicast
        # address - that way we will not confuse them with the periodic
        # RAs which go to the mcast address
        # Sit and wait for the first periodic RA.
        #
        # TODO
        #
        self.pg0.ip6_ra_config(send_unicast=1)

        #
        # An RS from a link source address
        #  - expect an RA in return
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
             ICMPv6ND_RS())
        pkts = [p]
        self.send_and_expect_ra(self.pg0, pkts, "Genuine RS")

        #
        # For the next RS sent the RA should be rate limited
        #
        self.send_and_assert_no_replies(self.pg0, pkts, "RA rate limited")

        #
        # When we reconfiure the IPv6 RA config, we reset the RA rate limiting,
        # so we need to do this before each test below so as not to drop
        # packets for rate limiting reasons. Test this works here.
        #
        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, pkts, "Rate limit reset RS")

        #
        # An RS sent from a non-link local source
        #
        self.pg0.ip6_ra_config(send_unicast=1)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0.local_ip6, src="2002::ffff") /
             ICMPv6ND_RS())
        pkts = [p]
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "RS from non-link source")

        #
        # Source an RS from a link local address
        #
        self.pg0.ip6_ra_config(send_unicast=1)
        ll = mk_ll_addr(self.pg0.remote_mac)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0.local_ip6, src=ll) /
             ICMPv6ND_RS())
        pkts = [p]
        self.send_and_expect_ra(self.pg0, pkts,
                                "RS sourced from link-local",
                                dst_ip=ll)

        #
        # Send the RS multicast
        #
        self.pg0.ip6_ra_config(send_unicast=1)
        dmac = in6_getnsmac(inet_pton(AF_INET6, "ff02::2"))
        ll = mk_ll_addr(self.pg0.remote_mac)
        p = (Ether(dst=dmac, src=self.pg0.remote_mac) /
             IPv6(dst="ff02::2", src=ll) /
             ICMPv6ND_RS())
        pkts = [p]
        self.send_and_expect_ra(self.pg0, pkts,
                                "RS sourced from link-local",
                                dst_ip=ll)

        #
        # Source from the unspecified address ::. This happens when the RS
        # is sent before the host has a configured address/sub-net,
        # i.e. auto-config. Since the sender has no IP address, the reply
        # comes back mcast - so the capture needs to not filter this.
        # If we happen to pick up the periodic RA at this point then so be it,
        # it's not an error.
        #
        self.pg0.ip6_ra_config(send_unicast=1, suppress=1)
        p = (Ether(dst=dmac, src=self.pg0.remote_mac) /
             IPv6(dst="ff02::2", src="::") /
             ICMPv6ND_RS())
        pkts = [p]
        self.send_and_expect_ra(self.pg0, pkts,
                                "RS sourced from unspecified",
                                dst_ip="ff02::1",
                                filter_out_fn=None)

        #
        # Configure The RA to announce the links prefix
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len)

        #
        # RAs should now contain the prefix information option
        #
        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=1,
                                    A=1)

        self.pg0.ip6_ra_config(send_unicast=1)
        ll = mk_ll_addr(self.pg0.remote_mac)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0.local_ip6, src=ll) /
             ICMPv6ND_RS())
        self.send_and_expect_ra(self.pg0, p,
                                "RA with prefix-info",
                                dst_ip=ll,
                                opt=opt)

        #
        # Change the prefix info to not off-link
        #  L-flag is clear
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len,
                               off_link=1)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=0,
                                    A=1)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix info with L-flag=0",
                                dst_ip=ll,
                                opt=opt)

        #
        # Change the prefix info to not off-link, no-autoconfig
        #  L and A flag are clear in the advert
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len,
                               off_link=1,
                               no_autoconfig=1)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=0,
                                    A=0)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix info with A & L-flag=0",
                                dst_ip=ll,
                                opt=opt)

        #
        # Change the flag settings back to the defaults
        #  L and A flag are set in the advert
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=1,
                                    A=1)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix info",
                                dst_ip=ll,
                                opt=opt)

        #
        # Change the prefix info to not off-link, no-autoconfig
        #  L and A flag are clear in the advert
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len,
                               off_link=1,
                               no_autoconfig=1)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=0,
                                    A=0)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix info with A & L-flag=0",
                                dst_ip=ll,
                                opt=opt)

        #
        # Use the reset to defults option to revert to defaults
        #  L and A flag are clear in the advert
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len,
                               use_default=1)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                    prefix=self.pg0.local_ip6,
                                    L=1,
                                    A=1)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix reverted to defaults",
                                dst_ip=ll,
                                opt=opt)

        #
        # Advertise Another prefix. With no L-flag/A-flag
        #
        self.pg0.ip6_ra_prefix(self.pg1.local_ip6n,
                               self.pg1.local_ip6_prefix_len,
                               off_link=1,
                               no_autoconfig=1)

        opt = [ICMPv6NDOptPrefixInfo(prefixlen=self.pg0.local_ip6_prefix_len,
                                     prefix=self.pg0.local_ip6,
                                     L=1,
                                     A=1),
               ICMPv6NDOptPrefixInfo(prefixlen=self.pg1.local_ip6_prefix_len,
                                     prefix=self.pg1.local_ip6,
                                     L=0,
                                     A=0)]

        self.pg0.ip6_ra_config(send_unicast=1)
        ll = mk_ll_addr(self.pg0.remote_mac)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0.local_ip6, src=ll) /
             ICMPv6ND_RS())
        self.send_and_expect_ra(self.pg0, p,
                                "RA with multiple Prefix infos",
                                dst_ip=ll,
                                opt=opt)

        #
        # Remove the first refix-info - expect the second is still in the
        # advert
        #
        self.pg0.ip6_ra_prefix(self.pg0.local_ip6n,
                               self.pg0.local_ip6_prefix_len,
                               is_no=1)

        opt = ICMPv6NDOptPrefixInfo(prefixlen=self.pg1.local_ip6_prefix_len,
                                    prefix=self.pg1.local_ip6,
                                    L=0,
                                    A=0)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix reverted to defaults",
                                dst_ip=ll,
                                opt=opt)

        #
        # Remove the second prefix-info - expect no prefix-info i nthe adverts
        #
        self.pg0.ip6_ra_prefix(self.pg1.local_ip6n,
                               self.pg1.local_ip6_prefix_len,
                               is_no=1)

        self.pg0.ip6_ra_config(send_unicast=1)
        self.send_and_expect_ra(self.pg0, p,
                                "RA with Prefix reverted to defaults",
                                dst_ip=ll)

        #
        # Reset the periodic advertisements back to default values
        #
        self.pg0.ip6_ra_config(no=1, suppress=1, send_unicast=0)


class IPv6NDProxyTest(TestIPv6ND):
    """ IPv6 ND ProxyTest Case """

    def setUp(self):
        super(IPv6NDProxyTest, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # pg0 is the master interface, with the configured subnet
        self.pg0.admin_up()
        self.pg0.config_ip6()
        self.pg0.resolve_ndp()

        self.pg1.ip6_enable()
        self.pg2.ip6_enable()

    def tearDown(self):
        super(IPv6NDProxyTest, self).tearDown()

    def test_nd_proxy(self):
        """ IPv6 Proxy ND """

        #
        # Generate some hosts in the subnet that we are proxying
        #
        self.pg0.generate_remote_hosts(8)

        nsma = in6_getnsma(inet_pton(AF_INET6, self.pg0.local_ip6))
        d = inet_ntop(AF_INET6, nsma)

        #
        # Send an NS for one of those remote hosts on one of the proxy links
        # expect no response since it's from an address that is not
        # on the link that has the prefix configured
        #
        ns_pg1 = (Ether(dst=in6_getnsmac(nsma), src=self.pg1.remote_mac) /
                  IPv6(dst=d, src=self.pg0._remote_hosts[2].ip6) /
                  ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.pg0._remote_hosts[2].mac))

        self.send_and_assert_no_replies(self.pg1, ns_pg1, "Off link NS")

        #
        # Add proxy support for the host
        #
        self.vapi.ip6_nd_proxy(
            inet_pton(AF_INET6, self.pg0._remote_hosts[2].ip6),
            self.pg1.sw_if_index)

        #
        # try that NS again. this time we expect an NA back
        #
        self.pg1.add_stream(ns_pg1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        self.validate_na(self.pg1, rx[0],
                         dst_ip=self.pg0._remote_hosts[2].ip6,
                         tgt_ip=self.pg0.local_ip6)

        #
        # ... and that we have an entry in the ND cache
        #
        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg0._remote_hosts[2].ip6,
                                 inet=AF_INET6))

        #
        # ... and we can route traffic to it
        #
        t = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(dst=self.pg0._remote_hosts[2].ip6,
                  src=self.pg0.remote_ip6) /
             UDP(sport=10000, dport=20000) /
             Raw('\xa5' * 100))

        self.pg0.add_stream(t)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        rx = rx[0]

        self.assertEqual(rx[Ether].dst, self.pg0._remote_hosts[2].mac)
        self.assertEqual(rx[Ether].src, self.pg1.local_mac)

        self.assertEqual(rx[IPv6].src, t[IPv6].src)
        self.assertEqual(rx[IPv6].dst, t[IPv6].dst)

        #
        # Test we proxy for the host on the main interface
        #
        ns_pg0 = (Ether(dst=in6_getnsmac(nsma), src=self.pg0.remote_mac) /
                  IPv6(dst=d, src=self.pg0.remote_ip6) /
                  ICMPv6ND_NS(tgt=self.pg0._remote_hosts[2].ip6) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))

        self.pg0.add_stream(ns_pg0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        self.validate_na(self.pg0, rx[0],
                         tgt_ip=self.pg0._remote_hosts[2].ip6,
                         dst_ip=self.pg0.remote_ip6)

        #
        # Setup and resolve proxy for another host on another interface
        #
        ns_pg2 = (Ether(dst=in6_getnsmac(nsma), src=self.pg2.remote_mac) /
                  IPv6(dst=d, src=self.pg0._remote_hosts[3].ip6) /
                  ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.pg0._remote_hosts[2].mac))

        self.vapi.ip6_nd_proxy(
            inet_pton(AF_INET6, self.pg0._remote_hosts[3].ip6),
            self.pg2.sw_if_index)

        self.pg2.add_stream(ns_pg2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg2.get_capture(1)

        self.validate_na(self.pg2, rx[0],
                         dst_ip=self.pg0._remote_hosts[3].ip6,
                         tgt_ip=self.pg0.local_ip6)

        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg0._remote_hosts[3].ip6,
                                 inet=AF_INET6))

        #
        # hosts can communicate. pg2->pg1
        #
        t2 = (Ether(dst=self.pg2.local_mac,
                    src=self.pg0.remote_hosts[3].mac) /
              IPv6(dst=self.pg0._remote_hosts[2].ip6,
                   src=self.pg0._remote_hosts[3].ip6) /
              UDP(sport=10000, dport=20000) /
              Raw('\xa5' * 100))

        self.pg2.add_stream(t2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        rx = rx[0]

        self.assertEqual(rx[Ether].dst, self.pg0._remote_hosts[2].mac)
        self.assertEqual(rx[Ether].src, self.pg1.local_mac)

        self.assertEqual(rx[IPv6].src, t2[IPv6].src)
        self.assertEqual(rx[IPv6].dst, t2[IPv6].dst)

        #
        # remove the proxy configs
        #
        self.vapi.ip6_nd_proxy(
            inet_pton(AF_INET6, self.pg0._remote_hosts[2].ip6),
            self.pg1.sw_if_index,
            is_del=1)
        self.vapi.ip6_nd_proxy(
            inet_pton(AF_INET6, self.pg0._remote_hosts[3].ip6),
            self.pg2.sw_if_index,
            is_del=1)

        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg0._remote_hosts[3].ip6,
                                  inet=AF_INET6))
        self.assertFalse(find_nbr(self,
                                  self.pg1.sw_if_index,
                                  self.pg0._remote_hosts[2].ip6,
                                  inet=AF_INET6))

        #
        # no longer proxy-ing...
        #
        self.send_and_assert_no_replies(self.pg0, ns_pg0, "Proxy unconfigured")
        self.send_and_assert_no_replies(self.pg1, ns_pg1, "Proxy unconfigured")
        self.send_and_assert_no_replies(self.pg2, ns_pg2, "Proxy unconfigured")

        #
        # no longer forwarding. traffic generates NS out of the glean/main
        # interface
        #
        self.pg2.add_stream(t2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        self.assertTrue(rx[0].haslayer(ICMPv6ND_NS))


class TestIPNull(VppTestCase):
    """ IPv6 routes via NULL """

    def setUp(self):
        super(TestIPNull, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIPNull, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_ip_null(self):
        """ IP NULL route """

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="2001::1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        #
        # A route via IP NULL that will reply with ICMP unreachables
        #
        ip_unreach = VppIpRoute(self, "2001::", 64, [], is_unreach=1, is_ip6=1)
        ip_unreach.add_vpp_config()

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        icmp = rx[ICMPv6DestUnreach]

        # 0 = "No route to destination"
        self.assertEqual(icmp.code, 0)

        # ICMP is rate limited. pause a bit
        self.sleep(1)

        #
        # A route via IP NULL that will reply with ICMP prohibited
        #
        ip_prohibit = VppIpRoute(self, "2001::1", 128, [],
                                 is_prohibit=1, is_ip6=1)
        ip_prohibit.add_vpp_config()

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        icmp = rx[ICMPv6DestUnreach]

        # 1 = "Communication with destination administratively prohibited"
        self.assertEqual(icmp.code, 1)


class TestIPDisabled(VppTestCase):
    """ IPv6 disabled """

    def setUp(self):
        super(TestIPDisabled, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # PG0 is IP enalbed
        self.pg0.admin_up()
        self.pg0.config_ip6()
        self.pg0.resolve_ndp()

        # PG 1 is not IP enabled
        self.pg1.admin_up()

    def tearDown(self):
        super(TestIPDisabled, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for i in self.pg_interfaces:
            i.get_capture(0)
            i.assert_nothing_captured(remark=remark)

    def test_ip_disabled(self):
        """ IP Disabled """

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_ff_01 = VppIpMRoute(
            self,
            "::",
            "ffef::1", 128,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_ITF_FLAG_FORWARD)],
            is_ip6=1)
        route_ff_01.add_vpp_config()

        pu = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IPv6(src="2001::1", dst=self.pg0.remote_ip6) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        pm = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IPv6(src="2001::1", dst="ffef::1") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, pu, "IPv6 disabled")
        self.send_and_assert_no_replies(self.pg1, pm, "IPv6 disabled")

        #
        # IP enable PG1
        #
        self.pg1.config_ip6()

        #
        # Now we get packets through
        #
        self.pg1.add_stream(pu)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        self.pg1.add_stream(pm)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        #
        # Disable PG1
        #
        self.pg1.unconfig_ip6()

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, pu, "IPv6 disabled")
        self.send_and_assert_no_replies(self.pg1, pm, "IPv6 disabled")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
