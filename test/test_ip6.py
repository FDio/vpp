#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint
from vpp_pg_interface import is_ipv6_misc

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP, ICMPv6ND_NS, ICMPv6ND_RS, \
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, getmacbyip6, ICMPv6MRD_Solicitation
from util import ppp
from scapy.utils6 import in6_getnsma, in6_getnsmac, in6_ptop, in6_islladdr, \
    in6_mactoifaceid, in6_ismaddr
from scapy.utils import inet_pton, inet_ntop


def mk_ll_addr(mac):
    euid = in6_mactoifaceid(mac)
    addr = "fe80::" + euid
    return addr


class TestIPv6(VppTestCase):
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
        dest_addr = socket.inet_pton(socket.AF_INET6, "fd02::1")
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

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        intf.assert_nothing_captured(remark=remark)

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
        nsma = in6_getnsma(inet_pton(socket.AF_INET6, self.pg0.local_ip6))
        d = inet_ntop(socket.AF_INET6, nsma)

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
            nsma = in6_getnsma(inet_pton(socket.AF_INET6, "fd::ffff"))
            d = inet_ntop(socket.AF_INET6, nsma)

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
        nsma = in6_getnsma(inet_pton(socket.AF_INET6, self.pg0.local_ip6))
        d = inet_ntop(socket.AF_INET6, nsma)

        p = (Ether(dst=in6_getnsmac(nsma)) /
             IPv6(dst=d, src=self.pg0.remote_ip6) /
             ICMPv6ND_NS(tgt="fd::ffff") /
             ICMPv6NDOptSrcLLAddr(lladdr=self.pg0.remote_mac))
        pkts = [p]

        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "No response to NS for unknown target")

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
        dmac = in6_getnsmac(inet_pton(socket.AF_INET6, "ff02::2"))
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
        # Reset the periodic advertisements back to default values
        #
        self.pg0.ip6_ra_config(no=1, suppress=1, send_unicast=0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
