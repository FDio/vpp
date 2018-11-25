#!/usr/bin/env python

import socket
import unittest

from parameterized import parameterized
import scapy.layers.inet6 as inet6
from scapy.contrib.mpls import MPLS
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_RS, \
    ICMPv6ND_RA, ICMPv6NDOptMTU, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, \
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6DestUnreach, icmp6types, \
    ICMPv6TimeExceeded, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Raw
from scapy.utils import inet_pton, inet_ntop
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ptop, in6_islladdr, \
    in6_mactoifaceid
from six import moves

from framework import VppTestCase, VppTestRunner
from util import ppp, ip6_normalize
from vpp_ip import DPO_PROTO
from vpp_sub_interface import VppSubInterface, VppDot1QSubint
from vpp_pg_interface import is_ipv6_misc
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route, VppIpMRoute, \
    VppMRoutePath, MFIB_ITF_FLAG, MFIB_ENTRY_FLAG, VppMplsIpBind, \
    VppMplsRoute, VppMplsTable, VppIpTable
from vpp_neighbor import find_nbr, VppNeighbor
from vpp_pg_interface import is_ipv6_misc
from vpp_sub_interface import VppSubInterface, VppDot1QSubint

AF_INET6 = socket.AF_INET6


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
        self.assertEqual(
            in6_ptop(rx[IPv6].src), in6_ptop(tgt_ip))

        # Dest link-layer options should have the router's MAC
        dll = rx[ICMPv6NDOptDstLLAddr]
        self.assertEqual(dll.lladdr, intf.local_mac)

    def validate_ns(self, intf, rx, tgt_ip):
        nsma = in6_getnsma(inet_pton(AF_INET6, tgt_ip))
        dst_ip = inet_ntop(AF_INET6, nsma)

        # NS is broadcast
        self.assertEqual(rx[Ether].dst, in6_getnsmac(nsma))

        # and from the router's MAC
        self.assertEqual(rx[Ether].src, intf.local_mac)

        # the rx'd NS should be addressed to an mcast address
        # derived from the target address
        self.assertEqual(
            in6_ptop(rx[IPv6].dst), in6_ptop(dst_ip))

        # expect the tgt IP in the NS header
        ns = rx[ICMPv6ND_NS]
        self.assertEqual(in6_ptop(ns.tgt), in6_ptop(tgt_ip))

        # packet is from the router's local address
        self.assertEqual(
            in6_ptop(rx[IPv6].src), intf.local_ip6)

        # Src link-layer options should have the router's MAC
        sll = rx[ICMPv6NDOptSrcLLAddr]
        self.assertEqual(sll.lladdr, intf.local_mac)

    def send_and_expect_ra(self, intf, pkts, remark, dst_ip=None,
                           filter_out_fn=is_ipv6_misc):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = intf.get_capture(1, filter_out_fn=filter_out_fn)

        self.assertEqual(len(rx), 1)
        rx = rx[0]
        self.validate_ra(intf, rx, dst_ip)

    def send_and_expect_na(self, intf, pkts, remark, dst_ip=None,
                           tgt_ip=None,
                           filter_out_fn=is_ipv6_misc):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = intf.get_capture(1, filter_out_fn=filter_out_fn)

        self.assertEqual(len(rx), 1)
        rx = rx[0]
        self.validate_na(intf, rx, dst_ip, tgt_ip)

    def send_and_expect_ns(self, tx_intf, rx_intf, pkts, tgt_ip,
                           filter_out_fn=is_ipv6_misc):
        tx_intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = rx_intf.get_capture(1, filter_out_fn=filter_out_fn)

        self.assertEqual(len(rx), 1)
        rx = rx[0]
        self.validate_ns(rx_intf, rx, tgt_ip)

    def verify_ip(self, rx, smac, dmac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, dmac)
        self.assertEqual(ether.src, smac)

        ip = rx[IPv6]
        self.assertEqual(ip.src, sip)
        self.assertEqual(ip.dst, dip)


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
        self.pg_if_packet_sizes = [64, 1500, 9020]

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
        for i in self.interfaces:
            i.unconfig_ip6()
            i.ip6_disable()
            i.admin_down()
        for i in self.sub_interfaces:
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

    def modify_packet(self, src_if, packet_size, pkt):
        """Add load, set destination IP and extend packet to required packet
        size for defined interface.

        :param VppInterface src_if: Interface to create packet for.
        :param int packet_size: Required packet size.
        :param Scapy pkt: Packet to be modified.
        """
        dst_if_idx = packet_size / 10 % 2
        dst_if = self.flows[src_if][dst_if_idx]
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        p = pkt / Raw(payload)
        p[IPv6].dst = dst_if.remote_ip6
        info.data = p.copy()
        if isinstance(src_if, VppSubInterface):
            p = src_if.add_dot1_layer(p)
        self.extend_packet(p, packet_size)

        return p

    def create_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        hdr_ext = 4 if isinstance(src_if, VppSubInterface) else 0
        pkt_tmpl = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IPv6(src=src_if.remote_ip6) /
                    inet6.UDP(sport=1234, dport=1234))

        pkts = [self.modify_packet(src_if, i, pkt_tmpl)
                for i in moves.range(self.pg_if_packet_sizes[0],
                                     self.pg_if_packet_sizes[1], 10)]
        pkts_b = [self.modify_packet(src_if, i, pkt_tmpl)
                  for i in moves.range(self.pg_if_packet_sizes[1] + hdr_ext,
                                       self.pg_if_packet_sizes[2] + hdr_ext,
                                       50)]
        pkts.extend(pkts_b)

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
                udp = packet[inet6.UDP]
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
                self.assertEqual(
                    ip.src, saved_packet[IPv6].src)
                self.assertEqual(
                    ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(
                    udp.sport, saved_packet[inet6.UDP].sport)
                self.assertEqual(
                    udp.dport, saved_packet[inet6.UDP].dport)
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

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i)
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
             ICMPv6NDOptSrcLLAddr(
                 lladdr=self.pg0.remote_mac))
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
                 ICMPv6NDOptSrcLLAddr(
                     lladdr=self.pg0.remote_mac))
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
             ICMPv6NDOptSrcLLAddr(
                 lladdr=self.pg0.remote_mac))
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

        #
        # send an NS from a link local address to the interface's global
        # address
        #
        p = (Ether(dst=in6_getnsmac(nsma), src=self.pg0.remote_mac) /
             IPv6(
                 dst=d, src=self.pg0._remote_hosts[2].ip6_ll) /
             ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
             ICMPv6NDOptSrcLLAddr(
                 lladdr=self.pg0.remote_mac))

        self.send_and_expect_na(self.pg0, p,
                                "NS from link-local",
                                dst_ip=self.pg0._remote_hosts[2].ip6_ll,
                                tgt_ip=self.pg0.local_ip6)

        #
        # we should have learned an ND entry for the peer's link-local
        # but not inserted a route to it in the FIB
        #
        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0._remote_hosts[2].ip6_ll,
                                 inet=AF_INET6))
        self.assertFalse(find_route(self,
                                    self.pg0._remote_hosts[2].ip6_ll,
                                    128,
                                    inet=AF_INET6))

        #
        # An NS to the router's own Link-local
        #
        p = (Ether(dst=in6_getnsmac(nsma), src=self.pg0.remote_mac) /
             IPv6(
                 dst=d, src=self.pg0._remote_hosts[3].ip6_ll) /
             ICMPv6ND_NS(tgt=self.pg0.local_ip6_ll) /
             ICMPv6NDOptSrcLLAddr(
                 lladdr=self.pg0.remote_mac))

        self.send_and_expect_na(self.pg0, p,
                                "NS to/from link-local",
                                dst_ip=self.pg0._remote_hosts[3].ip6_ll,
                                tgt_ip=self.pg0.local_ip6_ll)

        #
        # we should have learned an ND entry for the peer's link-local
        # but not inserted a route to it in the FIB
        #
        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0._remote_hosts[3].ip6_ll,
                                 inet=AF_INET6))
        self.assertFalse(find_route(self,
                                    self.pg0._remote_hosts[3].ip6_ll,
                                    128,
                                    inet=AF_INET6))

    def test_ns_duplicates(self):
        """ ND Duplicates"""

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(3)

        #
        # Add host 1 on pg1 and pg2
        #
        ns_pg1 = VppNeighbor(self,
                             self.pg1.sw_if_index,
                             self.pg1.remote_hosts[1].mac,
                             self.pg1.remote_hosts[1].ip6,
                             af=AF_INET6)
        ns_pg1.add_vpp_config()
        ns_pg2 = VppNeighbor(self,
                             self.pg2.sw_if_index,
                             self.pg2.remote_mac,
                             self.pg1.remote_hosts[1].ip6,
                             af=AF_INET6)
        ns_pg2.add_vpp_config()

        #
        # IP packet destined for pg1 remote host arrives on pg1 again.
        #
        p = (Ether(dst=self.pg0.local_mac,
                   src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6,
                  dst=self.pg1.remote_hosts[1].ip6) /
             inet6.UDP(sport=1234, dport=1234) /
             Raw())

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

        self.verify_ip(rx1[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip6,
                       self.pg1.remote_hosts[1].ip6)

        #
        # remove the duplicate on pg1
        # packet stream shoud generate NSs out of pg1
        #
        ns_pg1.remove_vpp_config()

        self.send_and_expect_ns(self.pg0, self.pg1,
                                p, self.pg1.remote_hosts[1].ip6)

        #
        # Add it back
        #
        ns_pg1.add_vpp_config()

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

        self.verify_ip(rx1[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip6,
                       self.pg1.remote_hosts[1].ip6)

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
            self.assertFalse(ra.haslayer(
                ICMPv6NDOptPrefixInfo))
        else:
            raos = rx.getlayer(ICMPv6NDOptPrefixInfo, 1)

            # the options are nested in the scapy packet in way that i cannot
            # decipher how to decode. this 1st layer of option always returns
            # nested classes, so a direct obj1=obj2 comparison always fails.
            # however, the getlayer(.., 2) does give one instnace.
            # so we cheat here and construct a new opt instnace for comparison
            rd = ICMPv6NDOptPrefixInfo(
                prefixlen=raos.prefixlen,
                prefix=raos.prefix,
                L=raos.L,
                A=raos.A)
            if type(pi_opt) is list:
                for ii in range(len(pi_opt)):
                    self.assertEqual(pi_opt[ii], rd)
                    rd = rx.getlayer(
                        ICMPv6NDOptPrefixInfo, ii + 2)
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
             IPv6(
                 dst=self.pg0.local_ip6, src=self.pg0.remote_ip6) /
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
             IPv6(dst=self.pg0.local_ip6,
                  src="2002::ffff") /
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
        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
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

        opt = [ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg0.local_ip6_prefix_len,
            prefix=self.pg0.local_ip6,
            L=1,
            A=1),
            ICMPv6NDOptPrefixInfo(
                prefixlen=self.pg1.local_ip6_prefix_len,
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

        opt = ICMPv6NDOptPrefixInfo(
            prefixlen=self.pg1.local_ip6_prefix_len,
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


class TestICMPv6Echo(VppTestCase):
    """ ICMPv6 Echo Test Case """

    def setUp(self):
        super(TestICMPv6Echo, self).setUp()

        # create 1 pg interface
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestICMPv6Echo, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.ip6_disable()
            i.admin_down()

    def test_icmpv6_echo(self):
        """ VPP replies to ICMPv6 Echo Request

        Test scenario:

            - Receive ICMPv6 Echo Request message on pg0 interface.
            - Check outgoing ICMPv6 Echo Reply message on pg0 interface.
        """

        icmpv6_id = 0xb
        icmpv6_seq = 5
        icmpv6_data = '\x0a' * 18
        p_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IPv6(src=self.pg0.remote_ip6,
                               dst=self.pg0.local_ip6) /
                          ICMPv6EchoRequest(
                              id=icmpv6_id,
                              seq=icmpv6_seq,
                              data=icmpv6_data))

        self.pg0.add_stream(p_echo_request)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        ether = rx[Ether]
        ipv6 = rx[IPv6]
        icmpv6 = rx[ICMPv6EchoReply]

        self.assertEqual(ether.src, self.pg0.local_mac)
        self.assertEqual(ether.dst, self.pg0.remote_mac)

        self.assertEqual(ipv6.src, self.pg0.local_ip6)
        self.assertEqual(ipv6.dst, self.pg0.remote_ip6)

        self.assertEqual(
            icmp6types[icmpv6.type], "Echo Reply")
        self.assertEqual(icmpv6.id, icmpv6_id)
        self.assertEqual(icmpv6.seq, icmpv6_seq)
        self.assertEqual(icmpv6.data, icmpv6_data)


class TestIPv6RD(TestIPv6ND):
    """ IPv6 Router Discovery Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6RD, cls).setUpClass()

    def setUp(self):
        super(TestIPv6RD, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        self.interfaces = list(self.pg_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()

    def tearDown(self):
        for i in self.interfaces:
            i.unconfig_ip6()
            i.admin_down()
        super(TestIPv6RD, self).tearDown()

    def test_rd_send_router_solicitation(self):
        """ Verify router solicitation packets """

        count = 2
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.vapi.ip6nd_send_router_solicitation(self.pg1.sw_if_index,
                                                 mrc=count)
        rx_list = self.pg1.get_capture(count, timeout=3)
        self.assertEqual(len(rx_list), count)
        for packet in rx_list:
            self.assertEqual(packet.haslayer(IPv6), 1)
            self.assertEqual(packet[IPv6].haslayer(
                ICMPv6ND_RS), 1)
            dst = ip6_normalize(packet[IPv6].dst)
            dst2 = ip6_normalize("ff02::2")
            self.assert_equal(dst, dst2)
            src = ip6_normalize(packet[IPv6].src)
            src2 = ip6_normalize(self.pg1.local_ip6_ll)
            self.assert_equal(src, src2)
            self.assertTrue(
                bool(packet[ICMPv6ND_RS].haslayer(
                    ICMPv6NDOptSrcLLAddr)))
            self.assert_equal(
                packet[ICMPv6NDOptSrcLLAddr].lladdr,
                self.pg1.local_mac)

    def verify_prefix_info(self, reported_prefix, prefix_option):
        prefix = socket.inet_pton(socket.AF_INET6,
                                  prefix_option.getfieldval("prefix"))
        self.assert_equal(reported_prefix.dst_address, prefix)
        self.assert_equal(reported_prefix.dst_address_length,
                          prefix_option.getfieldval("prefixlen"))
        L = prefix_option.getfieldval("L")
        A = prefix_option.getfieldval("A")
        option_flags = (L << 7) | (A << 6)
        self.assert_equal(reported_prefix.flags, option_flags)
        self.assert_equal(reported_prefix.valid_time,
                          prefix_option.getfieldval("validlifetime"))
        self.assert_equal(reported_prefix.preferred_time,
                          prefix_option.getfieldval("preferredlifetime"))

    def test_rd_receive_router_advertisement(self):
        """ Verify events triggered by received RA packets """

        self.vapi.want_ip6_ra_events()

        prefix_info_1 = ICMPv6NDOptPrefixInfo(
            prefix="1::2",
            prefixlen=50,
            validlifetime=200,
            preferredlifetime=500,
            L=1,
            A=1,
        )

        prefix_info_2 = ICMPv6NDOptPrefixInfo(
            prefix="7::4",
            prefixlen=20,
            validlifetime=70,
            preferredlifetime=1000,
            L=1,
            A=0,
        )

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=self.pg1.local_ip6_ll,
                  src=mk_ll_addr(self.pg1.remote_mac)) /
             ICMPv6ND_RA() /
             prefix_info_1 /
             prefix_info_2)
        self.pg1.add_stream([p])
        self.pg_start()

        ev = self.vapi.wait_for_event(10, "ip6_ra_event")

        self.assert_equal(ev.current_hop_limit, 0)
        self.assert_equal(ev.flags, 8)
        self.assert_equal(ev.router_lifetime_in_sec, 1800)
        self.assert_equal(ev.neighbor_reachable_time_in_msec, 0)
        self.assert_equal(
            ev.time_in_msec_between_retransmitted_neighbor_solicitations, 0)

        self.assert_equal(ev.n_prefixes, 2)

        self.verify_prefix_info(ev.prefixes[0], prefix_info_1)
        self.verify_prefix_info(ev.prefixes[1], prefix_info_2)


class TestIPv6RDControlPlane(TestIPv6ND):
    """ IPv6 Router Discovery Control Plane Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6RDControlPlane, cls).setUpClass()

    def setUp(self):
        super(TestIPv6RDControlPlane, self).setUp()

        # create 1 pg interface
        self.create_pg_interfaces(range(1))

        self.interfaces = list(self.pg_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip6()

    def tearDown(self):
        super(TestIPv6RDControlPlane, self).tearDown()

    @staticmethod
    def create_ra_packet(pg, routerlifetime=None):
        src_ip = pg.remote_ip6_ll
        dst_ip = pg.local_ip6
        if routerlifetime is not None:
            ra = ICMPv6ND_RA(routerlifetime=routerlifetime)
        else:
            ra = ICMPv6ND_RA()
        p = (Ether(dst=pg.local_mac, src=pg.remote_mac) /
             IPv6(dst=dst_ip, src=src_ip) / ra)
        return p

    @staticmethod
    def get_default_routes(fib):
        list = []
        for entry in fib:
            if entry.address_length == 0:
                for path in entry.path:
                    if path.sw_if_index != 0xFFFFFFFF:
                        defaut_route = {}
                        defaut_route['sw_if_index'] = path.sw_if_index
                        defaut_route['next_hop'] = path.next_hop
                        list.append(defaut_route)
        return list

    @staticmethod
    def get_interface_addresses(fib, pg):
        list = []
        for entry in fib:
            if entry.address_length == 128:
                path = entry.path[0]
                if path.sw_if_index == pg.sw_if_index:
                    list.append(entry.address)
        return list

    def test_all(self):
        """ Test handling of SLAAC addresses and default routes """

        fib = self.vapi.ip6_fib_dump()
        default_routes = self.get_default_routes(fib)
        initial_addresses = set(self.get_interface_addresses(fib, self.pg0))
        self.assertEqual(default_routes, [])
        router_address = self.pg0.remote_ip6n_ll

        self.vapi.ip6_nd_address_autoconfig(self.pg0.sw_if_index, 1, 1)

        self.sleep(0.1)

        # send RA
        packet = (self.create_ra_packet(
            self.pg0) / ICMPv6NDOptPrefixInfo(
            prefix="1::",
            prefixlen=64,
            validlifetime=2,
            preferredlifetime=2,
            L=1,
            A=1,
        ) / ICMPv6NDOptPrefixInfo(
            prefix="7::",
            prefixlen=20,
            validlifetime=1500,
            preferredlifetime=1000,
            L=1,
            A=0,
        ))
        self.pg0.add_stream([packet])
        self.pg_start()

        self.sleep(0.1)

        fib = self.vapi.ip6_fib_dump()

        # check FIB for new address
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 1)
        prefix = list(new_addresses)[0][:8] + '\0\0\0\0\0\0\0\0'
        self.assertEqual(inet_ntop(AF_INET6, prefix), '1::')

        # check FIB for new default route
        default_routes = self.get_default_routes(fib)
        self.assertEqual(len(default_routes), 1)
        dr = default_routes[0]
        self.assertEqual(dr['sw_if_index'], self.pg0.sw_if_index)
        self.assertEqual(dr['next_hop'], router_address)

        # send RA to delete default route
        packet = self.create_ra_packet(self.pg0, routerlifetime=0)
        self.pg0.add_stream([packet])
        self.pg_start()

        self.sleep(0.1)

        # check that default route is deleted
        fib = self.vapi.ip6_fib_dump()
        default_routes = self.get_default_routes(fib)
        self.assertEqual(len(default_routes), 0)

        self.sleep(0.1)

        # send RA
        packet = self.create_ra_packet(self.pg0)
        self.pg0.add_stream([packet])
        self.pg_start()

        self.sleep(0.1)

        # check FIB for new default route
        fib = self.vapi.ip6_fib_dump()
        default_routes = self.get_default_routes(fib)
        self.assertEqual(len(default_routes), 1)
        dr = default_routes[0]
        self.assertEqual(dr['sw_if_index'], self.pg0.sw_if_index)
        self.assertEqual(dr['next_hop'], router_address)

        # send RA, updating router lifetime to 1s
        packet = self.create_ra_packet(self.pg0, 1)
        self.pg0.add_stream([packet])
        self.pg_start()

        self.sleep(0.1)

        # check that default route still exists
        fib = self.vapi.ip6_fib_dump()
        default_routes = self.get_default_routes(fib)
        self.assertEqual(len(default_routes), 1)
        dr = default_routes[0]
        self.assertEqual(dr['sw_if_index'], self.pg0.sw_if_index)
        self.assertEqual(dr['next_hop'], router_address)

        self.sleep(1)

        # check that default route is deleted
        fib = self.vapi.ip6_fib_dump()
        default_routes = self.get_default_routes(fib)
        self.assertEqual(len(default_routes), 0)

        # check FIB still contains the SLAAC address
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 1)
        prefix = list(new_addresses)[0][:8] + '\0\0\0\0\0\0\0\0'
        self.assertEqual(inet_ntop(AF_INET6, prefix), '1::')

        self.sleep(1)

        # check that SLAAC address is deleted
        fib = self.vapi.ip6_fib_dump()
        addresses = set(self.get_interface_addresses(fib, self.pg0))
        new_addresses = addresses.difference(initial_addresses)
        self.assertEqual(len(new_addresses), 0)


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
                  IPv6(dst=d,
                       src=self.pg0._remote_hosts[2].ip6) /
                  ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
                  ICMPv6NDOptSrcLLAddr(
                      lladdr=self.pg0._remote_hosts[2].mac))

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
        self.send_and_expect_na(self.pg1, ns_pg1,
                                "NS to proxy entry",
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
             inet6.UDP(sport=10000, dport=20000) /
             Raw('\xa5' * 100))

        self.pg0.add_stream(t)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        rx = rx[0]

        self.assertEqual(rx[Ether].dst, self.pg0._remote_hosts[2].mac)
        self.assertEqual(rx[Ether].src, self.pg1.local_mac)

        self.assertEqual(rx[IPv6].src,
                         t[IPv6].src)
        self.assertEqual(rx[IPv6].dst,
                         t[IPv6].dst)

        #
        # Test we proxy for the host on the main interface
        #
        ns_pg0 = (Ether(dst=in6_getnsmac(nsma), src=self.pg0.remote_mac) /
                  IPv6(dst=d, src=self.pg0.remote_ip6) /
                  ICMPv6ND_NS(
                      tgt=self.pg0._remote_hosts[2].ip6) /
                  ICMPv6NDOptSrcLLAddr(
                      lladdr=self.pg0.remote_mac))

        self.send_and_expect_na(self.pg0, ns_pg0,
                                "NS to proxy entry on main",
                                tgt_ip=self.pg0._remote_hosts[2].ip6,
                                dst_ip=self.pg0.remote_ip6)

        #
        # Setup and resolve proxy for another host on another interface
        #
        ns_pg2 = (Ether(dst=in6_getnsmac(nsma), src=self.pg2.remote_mac) /
                  IPv6(dst=d,
                       src=self.pg0._remote_hosts[3].ip6) /
                  ICMPv6ND_NS(tgt=self.pg0.local_ip6) /
                  ICMPv6NDOptSrcLLAddr(
                      lladdr=self.pg0._remote_hosts[2].mac))

        self.vapi.ip6_nd_proxy(
            inet_pton(AF_INET6, self.pg0._remote_hosts[3].ip6),
            self.pg2.sw_if_index)

        self.send_and_expect_na(self.pg2, ns_pg2,
                                "NS to proxy entry other interface",
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
              inet6.UDP(sport=10000, dport=20000) /
              Raw('\xa5' * 100))

        self.pg2.add_stream(t2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        rx = rx[0]

        self.assertEqual(rx[Ether].dst, self.pg0._remote_hosts[2].mac)
        self.assertEqual(rx[Ether].src, self.pg1.local_mac)

        self.assertEqual(rx[IPv6].src,
                         t2[IPv6].src)
        self.assertEqual(rx[IPv6].dst,
                         t2[IPv6].dst)

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
             inet6.UDP(sport=1234, dport=1234) /
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
            MFIB_ENTRY_FLAG.NONE,
            [VppMRoutePath(self.pg1.sw_if_index,
                           MFIB_ITF_FLAG.ACCEPT),
             VppMRoutePath(self.pg0.sw_if_index,
                           MFIB_ITF_FLAG.FORWARD)],
            is_ip6=1)
        route_ff_01.add_vpp_config()

        pu = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IPv6(src="2001::1", dst=self.pg0.remote_ip6) /
              inet6.UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        pm = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IPv6(src="2001::1", dst="ffef::1") /
              inet6.UDP(sport=1234, dport=1234) /
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


class TestIP6LoadBalance(VppTestCase):
    """ IPv6 Load-Balancing """

    def setUp(self):
        super(TestIP6LoadBalance, self).setUp()

        self.create_pg_interfaces(range(5))

        mpls_tbl = VppMplsTable(self, 0)
        mpls_tbl.add_vpp_config()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()
            i.disable_mpls()
        super(TestIP6LoadBalance, self).tearDown()

    def send_and_expect_load_balancing(self, input, pkts, outputs):
        self.vapi.cli("clear trace")
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx))

    def send_and_expect_one_itf(self, input, pkts, itf):
        self.vapi.cli("clear trace")
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = itf.get_capture(len(pkts))

    def test_ip6_load_balance(self):
        """ IPv6 Load-Balancing """

        #
        # An array of packets that differ only in the destination port
        #  - IP only
        #  - MPLS EOS
        #  - MPLS non-EOS
        #  - MPLS non-EOS with an entropy label
        #
        port_ip_pkts = []
        port_mpls_pkts = []
        port_mpls_neos_pkts = []
        port_ent_pkts = []

        #
        # An array of packets that differ only in the source address
        #
        src_ip_pkts = []
        src_mpls_pkts = []

        for ii in range(65):
            port_ip_hdr = (
                IPv6(dst="3000::1", src="3000:1::1") /
                inet6.UDP(sport=1234, dport=1234 + ii) /
                Raw('\xa5' * 100))
            port_ip_pkts.append((Ether(src=self.pg0.remote_mac,
                                       dst=self.pg0.local_mac) /
                                 port_ip_hdr))
            port_mpls_pkts.append((Ether(src=self.pg0.remote_mac,
                                         dst=self.pg0.local_mac) /
                                   MPLS(label=66, ttl=2) /
                                   port_ip_hdr))
            port_mpls_neos_pkts.append((Ether(src=self.pg0.remote_mac,
                                              dst=self.pg0.local_mac) /
                                        MPLS(label=67, ttl=2) /
                                        MPLS(label=77, ttl=2) /
                                        port_ip_hdr))
            port_ent_pkts.append((Ether(src=self.pg0.remote_mac,
                                        dst=self.pg0.local_mac) /
                                  MPLS(label=67, ttl=2) /
                                  MPLS(label=14, ttl=2) /
                                  MPLS(label=999, ttl=2) /
                                  port_ip_hdr))
            src_ip_hdr = (
                IPv6(dst="3000::1", src="3000:1::%d" % ii) /
                inet6.UDP(sport=1234, dport=1234) /
                Raw('\xa5' * 100))
            src_ip_pkts.append((Ether(src=self.pg0.remote_mac,
                                      dst=self.pg0.local_mac) /
                                src_ip_hdr))
            src_mpls_pkts.append((Ether(src=self.pg0.remote_mac,
                                        dst=self.pg0.local_mac) /
                                  MPLS(label=66, ttl=2) /
                                  src_ip_hdr))

        #
        # A route for the IP pacekts
        #
        route_3000_1 = VppIpRoute(self, "3000::1", 128,
                                  [VppRoutePath(self.pg1.remote_ip6,
                                                self.pg1.sw_if_index,
                                                proto=DPO_PROTO.IP6),
                                   VppRoutePath(self.pg2.remote_ip6,
                                                self.pg2.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_3000_1.add_vpp_config()

        #
        # a local-label for the EOS packets
        #
        binding = VppMplsIpBind(self, 66, "3000::1", 128, is_ip6=1)
        binding.add_vpp_config()

        #
        # An MPLS route for the non-EOS packets
        #
        route_67 = VppMplsRoute(self, 67, 0,
                                [VppRoutePath(self.pg1.remote_ip6,
                                              self.pg1.sw_if_index,
                                              labels=[67],
                                              proto=DPO_PROTO.IP6),
                                 VppRoutePath(self.pg2.remote_ip6,
                                              self.pg2.sw_if_index,
                                              labels=[67],
                                              proto=DPO_PROTO.IP6)])
        route_67.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across the 2 paths
        #  - since the default hash config is to use IP src,dst and port
        #    src,dst
        # We are not going to ensure equal amounts of packets across each link,
        # since the hash algorithm is statistical and therefore this can never
        # be guaranteed. But wuth 64 different packets we do expect some
        # balancing. So instead just ensure there is traffic on each link.
        #
        self.send_and_expect_load_balancing(self.pg0, port_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, port_mpls_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, port_mpls_neos_pkts,
                                            [self.pg1, self.pg2])

        #
        # The packets with Entropy label in should not load-balance,
        # since the Entorpy value is fixed.
        #
        self.send_and_expect_one_itf(self.pg0, port_ent_pkts, self.pg1)

        #
        # change the flow hash config so it's only IP src,dst
        #  - now only the stream with differing source address will
        #    load-balance
        #
        self.vapi.set_ip_flow_hash(0, is_ip6=1, src=1, dst=1, sport=0, dport=0)

        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_one_itf(self.pg0, port_ip_pkts, self.pg2)

        #
        # change the flow hash config back to defaults
        #
        self.vapi.set_ip_flow_hash(0, is_ip6=1, src=1, dst=1, sport=1, dport=1)

        #
        # Recursive prefixes
        #  - testing that 2 stages of load-balancing occurs and there is no
        #    polarisation (i.e. only 2 of 4 paths are used)
        #
        port_pkts = []
        src_pkts = []

        for ii in range(257):
            port_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IPv6(dst="4000::1",
                                   src="4000:1::1") /
                              inet6.UDP(sport=1234,
                                        dport=1234 + ii) /
                              Raw('\xa5' * 100)))
            src_pkts.append((Ether(src=self.pg0.remote_mac,
                                   dst=self.pg0.local_mac) /
                             IPv6(dst="4000::1",
                                  src="4000:1::%d" % ii) /
                             inet6.UDP(sport=1234, dport=1234) /
                             Raw('\xa5' * 100)))

        route_3000_2 = VppIpRoute(self, "3000::2", 128,
                                  [VppRoutePath(self.pg3.remote_ip6,
                                                self.pg3.sw_if_index,
                                                proto=DPO_PROTO.IP6),
                                   VppRoutePath(self.pg4.remote_ip6,
                                                self.pg4.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_3000_2.add_vpp_config()

        route_4000_1 = VppIpRoute(self, "4000::1", 128,
                                  [VppRoutePath("3000::1",
                                                0xffffffff,
                                                proto=DPO_PROTO.IP6),
                                   VppRoutePath("3000::2",
                                                0xffffffff,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_4000_1.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across all 4 paths
        #
        self.vapi.cli("clear trace")
        self.send_and_expect_load_balancing(self.pg0, port_pkts,
                                            [self.pg1, self.pg2,
                                             self.pg3, self.pg4])
        self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                            [self.pg1, self.pg2,
                                             self.pg3, self.pg4])

        #
        # Recursive prefixes
        #  - testing that 2 stages of load-balancing no choices
        #
        port_pkts = []

        for ii in range(257):
            port_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IPv6(dst="6000::1",
                                   src="6000:1::1") /
                              inet6.UDP(sport=1234,
                                        dport=1234 + ii) /
                              Raw('\xa5' * 100)))

        route_5000_2 = VppIpRoute(self, "5000::2", 128,
                                  [VppRoutePath(self.pg3.remote_ip6,
                                                self.pg3.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_5000_2.add_vpp_config()

        route_6000_1 = VppIpRoute(self, "6000::1", 128,
                                  [VppRoutePath("5000::2",
                                                0xffffffff,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_6000_1.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across all 4 paths
        #
        self.vapi.cli("clear trace")
        self.send_and_expect_one_itf(self.pg0, port_pkts, self.pg3)


class TestIP6Punt(VppTestCase):
    """ IPv6 Punt Police/Redirect """

    def setUp(self):
        super(TestIP6Punt, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIP6Punt, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_ip_punt(self):
        """ IP6 punt police and redirect """

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6,
                  dst=self.pg0.local_ip6) /
             inet6.TCP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        pkts = p * 1025

        #
        # Configure a punt redirect via pg1.
        #
        nh_addr = self.pg1.remote_ip6
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg1.sw_if_index,
                                   nh_addr)

        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # add a policer
        #
        policer = self.vapi.policer_add_del("ip6-punt", 400, 0, 10, 0,
                                            rate_type=1)
        self.vapi.ip_punt_police(policer.policer_index, is_ip6=1)

        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # the number of packet recieved should be greater than 0,
        # but not equal to the number sent, since some were policed
        #
        rx = self.pg1._get_capture(1)
        self.assertGreater(len(rx), 0)
        self.assertLess(len(rx), len(pkts))

        #
        # remove the poilcer. back to full rx
        #
        self.vapi.ip_punt_police(policer.policer_index, is_add=0, is_ip6=1)
        self.vapi.policer_add_del("ip6-punt", 400, 0, 10, 0,
                                  rate_type=1, is_add=0)
        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # remove the redirect. expect full drop.
        #
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg1.sw_if_index,
                                   nh_addr,
                                   is_add=0)
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "IP no punt config")

        #
        # Add a redirect that is not input port selective
        #
        self.vapi.ip_punt_redirect(0xffffffff,
                                   self.pg1.sw_if_index,
                                   nh_addr)
        self.send_and_expect(self.pg0, pkts, self.pg1)

        self.vapi.ip_punt_redirect(0xffffffff,
                                   self.pg1.sw_if_index,
                                   nh_addr,
                                   is_add=0)

    def test_ip_punt_dump(self):
        """ IP6 punt redirect dump"""

        #
        # Configure a punt redirects
        #
        nh_addr = self.pg3.remote_ip6
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg3.sw_if_index,
                                   nh_addr)
        self.vapi.ip_punt_redirect(self.pg1.sw_if_index,
                                   self.pg3.sw_if_index,
                                   nh_addr)
        self.vapi.ip_punt_redirect(self.pg2.sw_if_index,
                                   self.pg3.sw_if_index,
                                   '0::0')

        #
        # Dump pg0 punt redirects
        #
        punts = self.vapi.ip_punt_redirect_dump(self.pg0.sw_if_index,
                                                is_ipv6=1)
        for p in punts:
            self.assertEqual(p.punt.rx_sw_if_index, self.pg0.sw_if_index)

        #
        # Dump punt redirects for all interfaces
        #
        punts = self.vapi.ip_punt_redirect_dump(0xffffffff, is_ipv6=1)
        self.assertEqual(len(punts), 3)
        for p in punts:
            self.assertEqual(p.punt.tx_sw_if_index, self.pg3.sw_if_index)
        self.assertNotEqual(punts[1].punt.nh, self.pg3.remote_ip6)
        self.assertEqual(str(punts[2].punt.nh), '::')


class TestIPDeag(VppTestCase):
    """ IPv6 Deaggregate Routes """

    def setUp(self):
        super(TestIPDeag, self).setUp()

        self.create_pg_interfaces(range(3))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIPDeag, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_ip_deag(self):
        """ IP Deag Routes """

        #
        # Create a table to be used for:
        #  1 - another destination address lookup
        #  2 - a source address lookup
        #
        table_dst = VppIpTable(self, 1, is_ip6=1)
        table_src = VppIpTable(self, 2, is_ip6=1)
        table_dst.add_vpp_config()
        table_src.add_vpp_config()

        #
        # Add a route in the default table to point to a deag/
        # second lookup in each of these tables
        #
        route_to_dst = VppIpRoute(self, "1::1", 128,
                                  [VppRoutePath("::",
                                                0xffffffff,
                                                nh_table_id=1,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_to_src = VppIpRoute(self, "1::2", 128,
                                  [VppRoutePath("::",
                                                0xffffffff,
                                                nh_table_id=2,
                                                is_source_lookup=1,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_to_dst.add_vpp_config()
        route_to_src.add_vpp_config()

        #
        # packets to these destination are dropped, since they'll
        # hit the respective default routes in the second table
        #
        p_dst = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="5::5", dst="1::1") /
                 inet6.TCP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        p_src = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="2::2", dst="1::2") /
                 inet6.TCP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
        pkts_dst = p_dst * 257
        pkts_src = p_src * 257

        self.send_and_assert_no_replies(self.pg0, pkts_dst,
                                        "IP in dst table")
        self.send_and_assert_no_replies(self.pg0, pkts_src,
                                        "IP in src table")

        #
        # add a route in the dst table to forward via pg1
        #
        route_in_dst = VppIpRoute(self, "1::1", 128,
                                  [VppRoutePath(self.pg1.remote_ip6,
                                                self.pg1.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1,
                                  table_id=1)
        route_in_dst.add_vpp_config()

        self.send_and_expect(self.pg0, pkts_dst, self.pg1)

        #
        # add a route in the src table to forward via pg2
        #
        route_in_src = VppIpRoute(self, "2::2", 128,
                                  [VppRoutePath(self.pg2.remote_ip6,
                                                self.pg2.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1,
                                  table_id=2)
        route_in_src.add_vpp_config()
        self.send_and_expect(self.pg0, pkts_src, self.pg2)

        #
        # loop in the lookup DP
        #
        route_loop = VppIpRoute(self, "3::3", 128,
                                [VppRoutePath("::",
                                              0xffffffff,
                                              proto=DPO_PROTO.IP6)],
                                is_ip6=1)
        route_loop.add_vpp_config()

        p_l = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IPv6(src="3::4", dst="3::3") /
               inet6.TCP(sport=1234, dport=1234) /
               Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, p_l * 257,
                                        "IP lookup loop")


class TestIP6Input(VppTestCase):
    """ IPv6 Input Exception Test Cases """

    def setUp(self):
        super(TestIP6Input, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIP6Input, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_ip_input_icmp_reply(self):
        """ IP6 Input Exception - Return ICMP (3,0) """
        #
        # hop limit - ICMP replies
        #
        p_version = (Ether(src=self.pg0.remote_mac,
                           dst=self.pg0.local_mac) /
                     IPv6(src=self.pg0.remote_ip6,
                          dst=self.pg1.remote_ip6,
                          hlim=1) /
                     inet6.UDP(sport=1234, dport=1234) /
                     Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_version * 65, self.pg0)
        rx = rx[0]
        icmp = rx[ICMPv6TimeExceeded]

        # 0: "hop limit exceeded in transit",
        self.assertEqual((icmp.type, icmp.code), (3, 0))

    icmpv6_data = '\x0a' * 18
    all_0s = "::"
    all_1s = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"

    @parameterized.expand([
        # Name, src, dst, l4proto, msg, timeout
        ("src='iface',   dst='iface'", None, None,
         inet6.UDP(sport=1234, dport=1234), "funky version", None),
        ("src='All 0's', dst='iface'", all_0s, None,
         ICMPv6EchoRequest(id=0xb, seq=5, data=icmpv6_data), None, 0.1),
        ("src='iface',   dst='All 0's'", None, all_0s,
         ICMPv6EchoRequest(id=0xb, seq=5, data=icmpv6_data), None, 0.1),
        ("src='All 1's', dst='iface'", all_1s, None,
         ICMPv6EchoRequest(id=0xb, seq=5, data=icmpv6_data), None, 0.1),
        ("src='iface',   dst='All 1's'", None, all_1s,
         ICMPv6EchoRequest(id=0xb, seq=5, data=icmpv6_data), None, 0.1),
        ("src='All 1's', dst='All 1's'", all_1s, all_1s,
         ICMPv6EchoRequest(id=0xb, seq=5, data=icmpv6_data), None, 0.1),

    ])
    def test_ip_input_no_replies(self, name, src, dst, l4, msg, timeout):

        self._testMethodDoc = 'IPv6 Input Exception - %s' % name

        p_version = (Ether(src=self.pg0.remote_mac,
                           dst=self.pg0.local_mac) /
                     IPv6(src=src or self.pg0.remote_ip6,
                          dst=dst or self.pg1.remote_ip6,
                          version=3) /
                     l4 /
                     Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, p_version * 65,
                                        remark=msg or "",
                                        timeout=timeout)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
