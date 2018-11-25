#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, \
    VppMplsIpBind, VppIpMRoute, VppMRoutePath, \
    MFIB_ITF_FLAG, MFIB_ENTRY_FLAG, VppIpTable, VppMplsTable, \
    VppMplsLabel, MPLS_LSP_MODE, find_mpls_route
from vpp_mpls_tunnel_interface import VppMPLSTunnelInterface

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded
from scapy.contrib.mpls import MPLS


def verify_filter(capture, sent):
    if not len(capture) == len(sent):
        # filter out any IPv6 RAs from the capture
        for p in capture:
            if p.haslayer(IPv6):
                capture.remove(p)
    return capture


def verify_mpls_stack(tst, rx, mpls_labels):
    # the rx'd packet has the MPLS label popped
    eth = rx[Ether]
    tst.assertEqual(eth.type, 0x8847)

    rx_mpls = rx[MPLS]

    for ii in range(len(mpls_labels)):
        tst.assertEqual(rx_mpls.label, mpls_labels[ii].value)
        tst.assertEqual(rx_mpls.cos, mpls_labels[ii].exp)
        tst.assertEqual(rx_mpls.ttl, mpls_labels[ii].ttl)

        if ii == len(mpls_labels) - 1:
            tst.assertEqual(rx_mpls.s, 1)
        else:
            # not end of stack
            tst.assertEqual(rx_mpls.s, 0)
            # pop the label to expose the next
            rx_mpls = rx_mpls[MPLS].payload


class TestMPLS(VppTestCase):
    """ MPLS Test Case """

    def setUp(self):
        super(TestMPLS, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        # setup both interfaces
        # assign them different tables.
        table_id = 0
        self.tables = []

        tbl = VppMplsTable(self, 0)
        tbl.add_vpp_config()
        self.tables.append(tbl)

        for i in self.pg_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                self.tables.append(tbl)
                tbl = VppIpTable(self, table_id, is_ip6=1)
                tbl.add_vpp_config()
                self.tables.append(tbl)

            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.enable_mpls()
            table_id += 1

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.disable_mpls()
            i.admin_down()
        super(TestMPLS, self).tearDown()

    # the default of 64 matches the IP packet TTL default
    def create_stream_labelled_ip4(
            self,
            src_if,
            mpls_labels,
            ping=0,
            ip_itf=None,
            dst_ip=None,
            chksum=None,
            ip_ttl=64,
            n=257):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, n):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = Ether(dst=src_if.local_mac, src=src_if.remote_mac)

            for ii in range(len(mpls_labels)):
                p = p / MPLS(label=mpls_labels[ii].value,
                             ttl=mpls_labels[ii].ttl,
                             cos=mpls_labels[ii].exp)
            if not ping:
                if not dst_ip:
                    p = (p / IP(src=src_if.local_ip4,
                                dst=src_if.remote_ip4,
                                ttl=ip_ttl) /
                         UDP(sport=1234, dport=1234) /
                         Raw(payload))
                else:
                    p = (p / IP(src=src_if.local_ip4, dst=dst_ip, ttl=ip_ttl) /
                         UDP(sport=1234, dport=1234) /
                         Raw(payload))
            else:
                p = (p / IP(src=ip_itf.remote_ip4,
                            dst=ip_itf.local_ip4,
                            ttl=ip_ttl) /
                     ICMP())

            if chksum:
                p[IP].chksum = chksum
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_ip4(self, src_if, dst_ip, ip_ttl=64, ip_dscp=0):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_ip,
                    ttl=ip_ttl, tos=ip_dscp) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_ip6(self, src_if, dst_ip, ip_ttl=64, ip_dscp=0):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IPv6(src=src_if.remote_ip6, dst=dst_ip,
                      hlim=ip_ttl, tc=ip_dscp) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_labelled_ip6(self, src_if, mpls_labels,
                                   hlim=64, dst_ip=None):
        if dst_ip is None:
            dst_ip = src_if.remote_ip6
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            for l in mpls_labels:
                p = p / MPLS(label=l.value, ttl=l.ttl, cos=l.exp)

            p = p / (IPv6(src=src_if.remote_ip6, dst=dst_ip, hlim=hlim) /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def verify_capture_ip4(self, src_if, capture, sent, ping_resp=0,
                           ip_ttl=None, ip_dscp=0):
        try:
            capture = verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                # the rx'd packet has the MPLS label popped
                eth = rx[Ether]
                self.assertEqual(eth.type, 0x800)

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                if not ping_resp:
                    self.assertEqual(rx_ip.src, tx_ip.src)
                    self.assertEqual(rx_ip.dst, tx_ip.dst)
                    self.assertEqual(rx_ip.tos, ip_dscp)
                    if not ip_ttl:
                        # IP processing post pop has decremented the TTL
                        self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)
                    else:
                        self.assertEqual(rx_ip.ttl, ip_ttl)
                else:
                    self.assertEqual(rx_ip.src, tx_ip.dst)
                    self.assertEqual(rx_ip.dst, tx_ip.src)

        except:
            raise

    def verify_capture_labelled_ip4(self, src_if, capture, sent,
                                    mpls_labels, ip_ttl=None):
        try:
            capture = verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]
                tx_ip = tx[IP]
                rx_ip = rx[IP]

                verify_mpls_stack(self, rx, mpls_labels)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                if not ip_ttl:
                    # IP processing post pop has decremented the TTL
                    self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)
                else:
                    self.assertEqual(rx_ip.ttl, ip_ttl)

        except:
            raise

    def verify_capture_labelled_ip6(self, src_if, capture, sent,
                                    mpls_labels, ip_ttl=None):
        try:
            capture = verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]
                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]

                verify_mpls_stack(self, rx, mpls_labels)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                if not ip_ttl:
                    # IP processing post pop has decremented the TTL
                    self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)
                else:
                    self.assertEqual(rx_ip.hlim, ip_ttl)

        except:
            raise

    def verify_capture_tunneled_ip4(self, src_if, capture, sent, mpls_labels):
        try:
            capture = verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]
                tx_ip = tx[IP]
                rx_ip = rx[IP]

                verify_mpls_stack(self, rx, mpls_labels)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

        except:
            raise

    def verify_capture_labelled(self, src_if, capture, sent,
                                mpls_labels):
        try:
            capture = verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                rx = capture[i]
                verify_mpls_stack(self, rx, mpls_labels)
        except:
            raise

    def verify_capture_ip6(self, src_if, capture, sent,
                           ip_hlim=None, ip_dscp=0):
        try:
            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                # the rx'd packet has the MPLS label popped
                eth = rx[Ether]
                self.assertEqual(eth.type, 0x86DD)

                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                self.assertEqual(rx_ip.tc,  ip_dscp)
                # IP processing post pop has decremented the TTL
                if not ip_hlim:
                    self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)
                else:
                    self.assertEqual(rx_ip.hlim, ip_hlim)

        except:
            raise

    def verify_capture_ip6_icmp(self, src_if, capture, sent):
        try:
            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                # the rx'd packet has the MPLS label popped
                eth = rx[Ether]
                self.assertEqual(eth.type, 0x86DD)

                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]

                self.assertEqual(rx_ip.dst, tx_ip.src)
                # ICMP sourced from the interface's address
                self.assertEqual(rx_ip.src, src_if.local_ip6)
                # hop-limit reset to 255 for IMCP packet
                self.assertEqual(rx_ip.hlim, 255)

                icmp = rx[ICMPv6TimeExceeded]

        except:
            raise

    def test_swap(self):
        """ MPLS label swap tests """

        #
        # A simple MPLS xconnect - eos label in label out
        #
        route_32_eos = VppMplsRoute(self, 32, 1,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[VppMplsLabel(33)])])
        route_32_eos.add_vpp_config()

        self.assertTrue(
            find_mpls_route(self, 0, 32, 1,
                            [VppRoutePath(self.pg0.remote_ip4,
                                          self.pg0.sw_if_index,
                                          labels=[VppMplsLabel(33)])]))

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(32, ttl=32, exp=1)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(33, ttl=31, exp=1)])

        self.assertEqual(route_32_eos.get_stats_to()['packets'], 257)

        #
        # A simple MPLS xconnect - non-eos label in label out
        #
        route_32_neos = VppMplsRoute(self, 32, 0,
                                     [VppRoutePath(self.pg0.remote_ip4,
                                                   self.pg0.sw_if_index,
                                                   labels=[VppMplsLabel(33)])])
        route_32_neos.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(32, ttl=21, exp=7),
                                              VppMplsLabel(99)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(33, ttl=20, exp=7),
                                      VppMplsLabel(99)])
        self.assertEqual(route_32_neos.get_stats_to()['packets'], 257)

        #
        # A simple MPLS xconnect - non-eos label in label out, uniform mode
        #
        route_42_neos = VppMplsRoute(
            self, 42, 0,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(43, MPLS_LSP_MODE.UNIFORM)])])
        route_42_neos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(42, ttl=21, exp=7),
                                              VppMplsLabel(99)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(43, ttl=20, exp=7),
                                      VppMplsLabel(99)])

        #
        # An MPLS xconnect - EOS label in IP out
        #
        route_33_eos = VppMplsRoute(self, 33, 1,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[])])
        route_33_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(33)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip4(self.pg0, rx, tx)

        #
        # disposed packets have an invalid IPv4 checkusm
        #
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(33)],
                                             dst_ip=self.pg0.remote_ip4,
                                             n=65,
                                             chksum=1)
        self.send_and_assert_no_replies(self.pg0, tx, "Invalid Checksum")

        #
        # An MPLS xconnect - EOS label in IP out, uniform mode
        #
        route_3333_eos = VppMplsRoute(
            self, 3333, 1,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(3, MPLS_LSP_MODE.UNIFORM)])])
        route_3333_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(
            self.pg0,
            [VppMplsLabel(3333, ttl=55, exp=3)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip4(self.pg0, rx, tx, ip_ttl=54, ip_dscp=0x60)
        tx = self.create_stream_labelled_ip4(
            self.pg0,
            [VppMplsLabel(3333, ttl=66, exp=4)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip4(self.pg0, rx, tx, ip_ttl=65, ip_dscp=0x80)

        #
        # An MPLS xconnect - EOS label in IPv6 out
        #
        route_333_eos = VppMplsRoute(
            self, 333, 1,
            [VppRoutePath(self.pg0.remote_ip6,
                          self.pg0.sw_if_index,
                          labels=[],
                          proto=DPO_PROTO.IP6)])
        route_333_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip6(self.pg0, [VppMplsLabel(333)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6(self.pg0, rx, tx)

        #
        # disposed packets have an TTL expired
        #
        tx = self.create_stream_labelled_ip6(self.pg0,
                                             [VppMplsLabel(333, ttl=64)],
                                             dst_ip=self.pg1.remote_ip6,
                                             hlim=1)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6_icmp(self.pg0, rx, tx)

        #
        # An MPLS xconnect - EOS label in IPv6 out w imp-null
        #
        route_334_eos = VppMplsRoute(
            self, 334, 1,
            [VppRoutePath(self.pg0.remote_ip6,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(3)],
                          proto=DPO_PROTO.IP6)])
        route_334_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip6(self.pg0,
                                             [VppMplsLabel(334, ttl=64)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6(self.pg0, rx, tx)

        #
        # An MPLS xconnect - EOS label in IPv6 out w imp-null in uniform mode
        #
        route_335_eos = VppMplsRoute(
            self, 335, 1,
            [VppRoutePath(self.pg0.remote_ip6,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(3, MPLS_LSP_MODE.UNIFORM)],
                          proto=DPO_PROTO.IP6)])
        route_335_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip6(
            self.pg0,
            [VppMplsLabel(335, ttl=27, exp=4)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6(self.pg0, rx, tx, ip_hlim=26, ip_dscp=0x80)

        #
        # disposed packets have an TTL expired
        #
        tx = self.create_stream_labelled_ip6(self.pg0, [VppMplsLabel(334)],
                                             dst_ip=self.pg1.remote_ip6,
                                             hlim=0)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6_icmp(self.pg0, rx, tx)

        #
        # An MPLS xconnect - non-EOS label in IP out - an invalid configuration
        # so this traffic should be dropped.
        #
        route_33_neos = VppMplsRoute(self, 33, 0,
                                     [VppRoutePath(self.pg0.remote_ip4,
                                                   self.pg0.sw_if_index,
                                                   labels=[])])
        route_33_neos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(33),
                                              VppMplsLabel(99)])
        self.send_and_assert_no_replies(
            self.pg0, tx,
            "MPLS non-EOS packets popped and forwarded")

        #
        # A recursive EOS x-connect, which resolves through another x-connect
        # in pipe mode
        #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_via_label=32,
                                                  labels=[VppMplsLabel(44),
                                                          VppMplsLabel(45)])])
        route_34_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(34, ttl=3)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(33),
                                      VppMplsLabel(44),
                                      VppMplsLabel(45, ttl=2)])

        self.assertEqual(route_34_eos.get_stats_to()['packets'], 257)
        self.assertEqual(route_32_neos.get_stats_via()['packets'], 257)

        #
        # A recursive EOS x-connect, which resolves through another x-connect
        # in uniform mode
        #
        route_35_eos = VppMplsRoute(
            self, 35, 1,
            [VppRoutePath("0.0.0.0",
                          0xffffffff,
                          nh_via_label=42,
                          labels=[VppMplsLabel(44)])])
        route_35_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(35, ttl=3)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(43, ttl=2),
                                      VppMplsLabel(44, ttl=2)])

        #
        # A recursive non-EOS x-connect, which resolves through another
        # x-connect
        #
        route_34_neos = VppMplsRoute(self, 34, 0,
                                     [VppRoutePath("0.0.0.0",
                                                   0xffffffff,
                                                   nh_via_label=32,
                                                   labels=[VppMplsLabel(44),
                                                           VppMplsLabel(46)])])
        route_34_neos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(34, ttl=45),
                                              VppMplsLabel(99)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        # it's the 2nd (counting from 0) label in the stack that is swapped
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(33),
                                      VppMplsLabel(44),
                                      VppMplsLabel(46, ttl=44),
                                      VppMplsLabel(99)])

        #
        # an recursive IP route that resolves through the recursive non-eos
        # x-connect
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_via_label=34,
                                               labels=[VppMplsLabel(55)])])
        ip_10_0_0_1.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(33),
                                          VppMplsLabel(44),
                                          VppMplsLabel(46),
                                          VppMplsLabel(55)])
        self.assertEqual(ip_10_0_0_1.get_stats_to()['packets'], 257)

        ip_10_0_0_1.remove_vpp_config()
        route_34_neos.remove_vpp_config()
        route_34_eos.remove_vpp_config()
        route_33_neos.remove_vpp_config()
        route_33_eos.remove_vpp_config()
        route_32_neos.remove_vpp_config()
        route_32_eos.remove_vpp_config()

    def test_bind(self):
        """ MPLS Local Label Binding test """

        #
        # Add a non-recursive route with a single out label
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[VppMplsLabel(45)])])
        route_10_0_0_1.add_vpp_config()

        # bind a local label to the route
        binding = VppMplsIpBind(self, 44, "10.0.0.1", 32)
        binding.add_vpp_config()

        # non-EOS stream
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(44),
                                              VppMplsLabel(99)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(45, ttl=63),
                                      VppMplsLabel(99)])

        # EOS stream
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(44)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled(self.pg0, rx, tx,
                                     [VppMplsLabel(45, ttl=63)])

        # IP stream
        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [VppMplsLabel(45)])

        #
        # cleanup
        #
        binding.remove_vpp_config()
        route_10_0_0_1.remove_vpp_config()

    def test_imposition(self):
        """ MPLS label imposition test """

        #
        # Add a non-recursive route with a single out label
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[VppMplsLabel(32)])])
        route_10_0_0_1.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [VppMplsLabel(32)])

        #
        # Add a non-recursive route with a 3 out labels
        #
        route_10_0_0_2 = VppIpRoute(self, "10.0.0.2", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[VppMplsLabel(32),
                                                          VppMplsLabel(33),
                                                          VppMplsLabel(34)])])
        route_10_0_0_2.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "10.0.0.2",
                                    ip_ttl=44, ip_dscp=0xff)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34)],
                                         ip_ttl=43)

        #
        # Add a non-recursive route with a single out label in uniform mode
        #
        route_10_0_0_3 = VppIpRoute(
            self, "10.0.0.3", 32,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(32,
                                               mode=MPLS_LSP_MODE.UNIFORM)])])
        route_10_0_0_3.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "10.0.0.3",
                                    ip_ttl=54, ip_dscp=0xbe)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32, ttl=53, exp=5)])

        #
        # Add a IPv6 non-recursive route with a single out label in
        # uniform mode
        #
        route_2001_3 = VppIpRoute(
            self, "2001::3", 128,
            [VppRoutePath(self.pg0.remote_ip6,
                          self.pg0.sw_if_index,
                          proto=DPO_PROTO.IP6,
                          labels=[VppMplsLabel(32,
                                               mode=MPLS_LSP_MODE.UNIFORM)])],
            is_ip6=1)
        route_2001_3.add_vpp_config()

        tx = self.create_stream_ip6(self.pg0, "2001::3",
                                    ip_ttl=54, ip_dscp=0xbe)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip6(self.pg0, rx, tx,
                                         [VppMplsLabel(32, ttl=53, exp=5)])

        #
        # add a recursive path, with output label, via the 1 label route
        #
        route_11_0_0_1 = VppIpRoute(self, "11.0.0.1", 32,
                                    [VppRoutePath("10.0.0.1",
                                                  0xffffffff,
                                                  labels=[VppMplsLabel(44)])])
        route_11_0_0_1.add_vpp_config()

        #
        # a stream that matches the route for 11.0.0.1, should pick up
        # the label stack for 11.0.0.1 and 10.0.0.1
        #
        tx = self.create_stream_ip4(self.pg0, "11.0.0.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(44)])

        self.assertEqual(route_11_0_0_1.get_stats_to()['packets'], 257)

        #
        # add a recursive path, with 2 labels, via the 3 label route
        #
        route_11_0_0_2 = VppIpRoute(self, "11.0.0.2", 32,
                                    [VppRoutePath("10.0.0.2",
                                                  0xffffffff,
                                                  labels=[VppMplsLabel(44),
                                                          VppMplsLabel(45)])])
        route_11_0_0_2.add_vpp_config()

        #
        # a stream that matches the route for 11.0.0.1, should pick up
        # the label stack for 11.0.0.1 and 10.0.0.1
        #
        tx = self.create_stream_ip4(self.pg0, "11.0.0.2")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34),
                                          VppMplsLabel(44),
                                          VppMplsLabel(45)])

        self.assertEqual(route_11_0_0_2.get_stats_to()['packets'], 257)

        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34),
                                          VppMplsLabel(44),
                                          VppMplsLabel(45)])

        self.assertEqual(route_11_0_0_2.get_stats_to()['packets'], 514)

        #
        # cleanup
        #
        route_11_0_0_2.remove_vpp_config()
        route_11_0_0_1.remove_vpp_config()
        route_10_0_0_2.remove_vpp_config()
        route_10_0_0_1.remove_vpp_config()

    def test_tunnel_pipe(self):
        """ MPLS Tunnel Tests - Pipe """

        #
        # Create a tunnel with a single out label
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(44),
                                  VppMplsLabel(46)])])
        mpls_tun.add_vpp_config()
        mpls_tun.admin_up()

        #
        # add an unlabelled route through the new tunnel
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun._sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.3")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(44),
                                          VppMplsLabel(46)])

        #
        # add a labelled route through the new tunnel
        #
        route_10_0_0_4 = VppIpRoute(self, "10.0.0.4", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun._sw_if_index,
                                                  labels=[33])])
        route_10_0_0_4.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.4")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(44),
                                          VppMplsLabel(46),
                                          VppMplsLabel(33, ttl=255)])

    def test_tunnel_uniform(self):
        """ MPLS Tunnel Tests - Uniform """

        #
        # Create a tunnel with a single out label
        # The label stack is specified here from outer to inner
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(44, ttl=32),
                                  VppMplsLabel(46, MPLS_LSP_MODE.UNIFORM)])])
        mpls_tun.add_vpp_config()
        mpls_tun.admin_up()

        #
        # add an unlabelled route through the new tunnel
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun._sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.3", ip_ttl=24)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(44, ttl=32),
                                          VppMplsLabel(46, ttl=23)])

        #
        # add a labelled route through the new tunnel
        #
        route_10_0_0_4 = VppIpRoute(
            self, "10.0.0.4", 32,
            [VppRoutePath("0.0.0.0",
                          mpls_tun._sw_if_index,
                          labels=[VppMplsLabel(33, ttl=47)])])
        route_10_0_0_4.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.4")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(44, ttl=32),
                                          VppMplsLabel(46, ttl=47),
                                          VppMplsLabel(33, ttl=47)])

    def test_mpls_tunnel_many(self):
        """ Multiple Tunnels """

        for ii in range(10):
            mpls_tun = VppMPLSTunnelInterface(
                self,
                [VppRoutePath(self.pg0.remote_ip4,
                              self.pg0.sw_if_index,
                              labels=[VppMplsLabel(44, ttl=32),
                                      VppMplsLabel(46, MPLS_LSP_MODE.UNIFORM)
                                      ])])
            mpls_tun.add_vpp_config()
            mpls_tun.admin_up()

    def test_v4_exp_null(self):
        """ MPLS V4 Explicit NULL test """

        #
        # The first test case has an MPLS TTL of 0
        # all packet should be dropped
        #
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(0, ttl=0)])
        self.send_and_assert_no_replies(self.pg0, tx,
                                        "MPLS TTL=0 packets forwarded")

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(0)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip4(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        tx = self.create_stream_labelled_ip4(self.pg1, [VppMplsLabel(0)])
        rx = self.send_and_expect(self.pg1, tx, self.pg1)
        self.verify_capture_ip4(self.pg1, rx, tx)

    def test_v6_exp_null(self):
        """ MPLS V6 Explicit NULL test """

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip6(self.pg0, [VppMplsLabel(2)])
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        tx = self.create_stream_labelled_ip6(self.pg1, [VppMplsLabel(2)])
        rx = self.send_and_expect(self.pg1, tx, self.pg1)
        self.verify_capture_ip6(self.pg0, rx, tx)

    def test_deag(self):
        """ MPLS Deagg """

        #
        # A de-agg route - next-hop lookup in default table
        #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_table_id=0)])
        route_34_eos.add_vpp_config()

        #
        # ping an interface in the default table
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(34)],
                                             ping=1,
                                             ip_itf=self.pg0)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip4(self.pg0, rx, tx, ping_resp=1)

        #
        # A de-agg route - next-hop lookup in non-default table
        #
        route_35_eos = VppMplsRoute(self, 35, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_table_id=1)])
        route_35_eos.add_vpp_config()

        #
        # ping an interface in the non-default table
        # PG0 is in the default table. packet arrive labelled in the
        # default table and egress unlabelled in the non-default
        #
        tx = self.create_stream_labelled_ip4(
            self.pg0, [VppMplsLabel(35)], ping=1, ip_itf=self.pg1)
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_capture_ip4(self.pg1, rx, tx, ping_resp=1)

        #
        # Double pop
        #
        route_36_neos = VppMplsRoute(self, 36, 0,
                                     [VppRoutePath("0.0.0.0",
                                                   0xffffffff)])
        route_36_neos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(36),
                                              VppMplsLabel(35)],
                                             ping=1, ip_itf=self.pg1)
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_capture_ip4(self.pg1, rx, tx, ping_resp=1)

        route_36_neos.remove_vpp_config()
        route_35_eos.remove_vpp_config()
        route_34_eos.remove_vpp_config()

    def test_interface_rx(self):
        """ MPLS Interface Receive """

        #
        # Add a non-recursive route that will forward the traffic
        # post-interface-rx
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    table_id=1,
                                    paths=[VppRoutePath(self.pg1.remote_ip4,
                                                        self.pg1.sw_if_index)])
        route_10_0_0_1.add_vpp_config()

        #
        # An interface receive label that maps traffic to RX on interface
        # pg1
        # by injecting the packet in on pg0, which is in table 0
        # doing an interface-rx on pg1 and matching a route in table 1
        # if the packet egresses, then we must have swapped to pg1
        # so as to have matched the route in table 1
        #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  self.pg1.sw_if_index,
                                                  is_interface_rx=1)])
        route_34_eos.add_vpp_config()

        #
        # ping an interface in the default table
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(34)],
                                             dst_ip="10.0.0.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_capture_ip4(self.pg1, rx, tx)

    def test_mcast_mid_point(self):
        """ MPLS Multicast Mid Point """

        #
        # Add a non-recursive route that will forward the traffic
        # post-interface-rx
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    table_id=1,
                                    paths=[VppRoutePath(self.pg1.remote_ip4,
                                                        self.pg1.sw_if_index)])
        route_10_0_0_1.add_vpp_config()

        #
        # Add a mcast entry that replicate to pg2 and pg3
        # and replicate to a interface-rx (like a bud node would)
        #
        route_3400_eos = VppMplsRoute(
            self, 3400, 1,
            [VppRoutePath(self.pg2.remote_ip4,
                          self.pg2.sw_if_index,
                          labels=[VppMplsLabel(3401)]),
             VppRoutePath(self.pg3.remote_ip4,
                          self.pg3.sw_if_index,
                          labels=[VppMplsLabel(3402)]),
             VppRoutePath("0.0.0.0",
                          self.pg1.sw_if_index,
                          is_interface_rx=1)],
            is_multicast=1)
        route_3400_eos.add_vpp_config()

        #
        # ping an interface in the default table
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0,
                                             [VppMplsLabel(3400, ttl=64)],
                                             n=257,
                                             dst_ip="10.0.0.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(257)
        self.verify_capture_ip4(self.pg1, rx, tx)

        rx = self.pg2.get_capture(257)
        self.verify_capture_labelled(self.pg2, rx, tx,
                                     [VppMplsLabel(3401, ttl=63)])
        rx = self.pg3.get_capture(257)
        self.verify_capture_labelled(self.pg3, rx, tx,
                                     [VppMplsLabel(3402, ttl=63)])

    def test_mcast_head(self):
        """ MPLS Multicast Head-end """

        #
        # Create a multicast tunnel with two replications
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath(self.pg2.remote_ip4,
                          self.pg2.sw_if_index,
                          labels=[VppMplsLabel(42)]),
             VppRoutePath(self.pg3.remote_ip4,
                          self.pg3.sw_if_index,
                          labels=[VppMplsLabel(43)])],
            is_multicast=1)
        mpls_tun.add_vpp_config()
        mpls_tun.admin_up()

        #
        # add an unlabelled route through the new tunnel
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun._sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.3")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(257)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx, [VppMplsLabel(42)])
        rx = self.pg3.get_capture(257)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx, [VppMplsLabel(43)])

        #
        # An an IP multicast route via the tunnel
        # A (*,G).
        # one accepting interface, pg0, 1 forwarding interface via the tunnel
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MFIB_ENTRY_FLAG.NONE,
            [VppMRoutePath(self.pg0.sw_if_index,
                           MFIB_ITF_FLAG.ACCEPT),
             VppMRoutePath(mpls_tun._sw_if_index,
                           MFIB_ITF_FLAG.FORWARD)])
        route_232_1_1_1.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(257)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx, [VppMplsLabel(42)])
        rx = self.pg3.get_capture(257)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx, [VppMplsLabel(43)])

    def test_mcast_ip4_tail(self):
        """ MPLS IPv4 Multicast Tail """

        #
        # Add a multicast route that will forward the traffic
        # post-disposition
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MFIB_ENTRY_FLAG.NONE,
            table_id=1,
            paths=[VppMRoutePath(self.pg1.sw_if_index,
                                 MFIB_ITF_FLAG.FORWARD)])
        route_232_1_1_1.add_vpp_config()

        #
        # An interface receive label that maps traffic to RX on interface
        # pg1
        # by injecting the packet in on pg0, which is in table 0
        # doing an rpf-id  and matching a route in table 1
        # if the packet egresses, then we must have matched the route in
        # table 1
        #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  self.pg1.sw_if_index,
                                                  nh_table_id=1,
                                                  rpf_id=55)],
                                    is_multicast=1)

        route_34_eos.add_vpp_config()

        #
        # Drop due to interface lookup miss
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="232.1.1.1", n=1)
        self.send_and_assert_no_replies(self.pg0, tx, "RPF-ID drop none")

        #
        # set the RPF-ID of the enrtry to match the input packet's
        #
        route_232_1_1_1.update_rpf_id(55)

        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="232.1.1.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_capture_ip4(self.pg1, rx, tx)

        #
        # disposed packets have an invalid IPv4 checkusm
        #
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="232.1.1.1", n=65,
                                             chksum=1)
        self.send_and_assert_no_replies(self.pg0, tx, "Invalid Checksum")

        #
        # set the RPF-ID of the entry to not match the input packet's
        #
        route_232_1_1_1.update_rpf_id(56)
        tx = self.create_stream_labelled_ip4(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="232.1.1.1")
        self.send_and_assert_no_replies(self.pg0, tx, "RPF-ID drop 56")

    def test_mcast_ip6_tail(self):
        """ MPLS IPv6 Multicast Tail """

        #
        # Add a multicast route that will forward the traffic
        # post-disposition
        #
        route_ff = VppIpMRoute(
            self,
            "::",
            "ff01::1", 32,
            MFIB_ENTRY_FLAG.NONE,
            table_id=1,
            paths=[VppMRoutePath(self.pg1.sw_if_index,
                                 MFIB_ITF_FLAG.FORWARD)],
            is_ip6=1)
        route_ff.add_vpp_config()

        #
        # An interface receive label that maps traffic to RX on interface
        # pg1
        # by injecting the packet in on pg0, which is in table 0
        # doing an rpf-id  and matching a route in table 1
        # if the packet egresses, then we must have matched the route in
        # table 1
        #
        route_34_eos = VppMplsRoute(
            self, 34, 1,
            [VppRoutePath("::",
                          self.pg1.sw_if_index,
                          nh_table_id=1,
                          rpf_id=55,
                          proto=DPO_PROTO.IP6)],
            is_multicast=1)

        route_34_eos.add_vpp_config()

        #
        # Drop due to interface lookup miss
        #
        tx = self.create_stream_labelled_ip6(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="ff01::1")
        self.send_and_assert_no_replies(self.pg0, tx, "RPF Miss")

        #
        # set the RPF-ID of the enrtry to match the input packet's
        #
        route_ff.update_rpf_id(55)

        tx = self.create_stream_labelled_ip6(self.pg0, [VppMplsLabel(34)],
                                             dst_ip="ff01::1")
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_capture_ip6(self.pg1, rx, tx)

        #
        # disposed packets have hop-limit = 1
        #
        tx = self.create_stream_labelled_ip6(self.pg0,
                                             [VppMplsLabel(34)],
                                             dst_ip="ff01::1",
                                             hlim=1)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_capture_ip6_icmp(self.pg0, rx, tx)

        #
        # set the RPF-ID of the enrtry to not match the input packet's
        #
        route_ff.update_rpf_id(56)
        tx = self.create_stream_labelled_ip6(self.pg0,
                                             [VppMplsLabel(34)],
                                             dst_ip="ff01::1")
        self.send_and_assert_no_replies(self.pg0, tx, "RPF-ID drop 56")


class TestMPLSDisabled(VppTestCase):
    """ MPLS disabled """

    def setUp(self):
        super(TestMPLSDisabled, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        self.tbl = VppMplsTable(self, 0)
        self.tbl.add_vpp_config()

        # PG0 is MPLS enalbed
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg0.enable_mpls()

        # PG 1 is not MPLS enabled
        self.pg1.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

        self.pg0.disable_mpls()
        super(TestMPLSDisabled, self).tearDown()

    def test_mpls_disabled(self):
        """ MPLS Disabled """

        tx = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              MPLS(label=32, ttl=64) /
              IPv6(src="2001::1", dst=self.pg0.remote_ip6) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        #
        # A simple MPLS xconnect - eos label in label out
        #
        route_32_eos = VppMplsRoute(self, 32, 1,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[33])])
        route_32_eos.add_vpp_config()

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, tx, "MPLS disabled")

        #
        # MPLS enable PG1
        #
        self.pg1.enable_mpls()

        #
        # Now we get packets through
        #
        self.pg1.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        #
        # Disable PG1
        #
        self.pg1.disable_mpls()

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, tx, "IPv6 disabled")
        self.send_and_assert_no_replies(self.pg1, tx, "IPv6 disabled")


class TestMPLSPIC(VppTestCase):
    """ MPLS PIC edge convergence """

    def setUp(self):
        super(TestMPLSPIC, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        mpls_tbl = VppMplsTable(self, 0)
        mpls_tbl.add_vpp_config()
        tbl4 = VppIpTable(self, 1)
        tbl4.add_vpp_config()
        tbl6 = VppIpTable(self, 1, is_ip6=1)
        tbl6.add_vpp_config()

        # core links
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg0.enable_mpls()
        self.pg1.admin_up()
        self.pg1.config_ip4()
        self.pg1.resolve_arp()
        self.pg1.enable_mpls()

        # VRF (customer facing) link
        self.pg2.admin_up()
        self.pg2.set_table_ip4(1)
        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg2.set_table_ip6(1)
        self.pg2.config_ip6()
        self.pg2.resolve_ndp()
        self.pg3.admin_up()
        self.pg3.set_table_ip4(1)
        self.pg3.config_ip4()
        self.pg3.resolve_arp()
        self.pg3.set_table_ip6(1)
        self.pg3.config_ip6()
        self.pg3.resolve_ndp()

    def tearDown(self):
        self.pg0.disable_mpls()
        self.pg1.disable_mpls()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.admin_down()
        super(TestMPLSPIC, self).tearDown()

    def test_mpls_ibgp_pic(self):
        """ MPLS iBGP PIC edge convergence

        1) setup many iBGP VPN routes via a pair of iBGP peers.
        2) Check EMCP forwarding to these peers
        3) withdraw the IGP route to one of these peers.
        4) check forwarding continues to the remaining peer
        """

        #
        # IGP+LDP core routes
        #
        core_10_0_0_45 = VppIpRoute(self, "10.0.0.45", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[45])])
        core_10_0_0_45.add_vpp_config()

        core_10_0_0_46 = VppIpRoute(self, "10.0.0.46", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index,
                                                  labels=[46])])
        core_10_0_0_46.add_vpp_config()

        #
        # Lot's of VPN routes. We need more the 64 so VPP will build
        # the fast convergence indirection
        #
        vpn_routes = []
        pkts = []
        for ii in range(64):
            dst = "192.168.1.%d" % ii
            vpn_routes.append(VppIpRoute(self, dst, 32,
                                         [VppRoutePath("10.0.0.45",
                                                       0xffffffff,
                                                       labels=[145],
                                                       is_resolve_host=1),
                                          VppRoutePath("10.0.0.46",
                                                       0xffffffff,
                                                       labels=[146],
                                                       is_resolve_host=1)],
                                         table_id=1))
            vpn_routes[ii].add_vpp_config()

            pkts.append(Ether(dst=self.pg2.local_mac,
                              src=self.pg2.remote_mac) /
                        IP(src=self.pg2.remote_ip4, dst=dst) /
                        UDP(sport=1234, dport=1234) /
                        Raw('\xa5' * 100))

        #
        # Send the packet stream (one pkt to each VPN route)
        #  - expect a 50-50 split of the traffic
        #
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg0._get_capture(1)
        rx1 = self.pg1._get_capture(1)

        # not testig the LB hashing algorithm so we're not concerned
        # with the split ratio, just as long as neither is 0
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))

        #
        # use a test CLI command to stop the FIB walk process, this
        # will prevent the FIB converging the VPN routes and thus allow
        # us to probe the interim (psot-fail, pre-converge) state
        #
        self.vapi.ppcli("test fib-walk-process disable")

        #
        # Withdraw one of the IGP routes
        #
        core_10_0_0_46.remove_vpp_config()

        #
        # now all packets should be forwarded through the remaining peer
        #
        self.vapi.ppcli("clear trace")
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg0.get_capture(len(pkts))

        #
        # enable the FIB walk process to converge the FIB
        #
        self.vapi.ppcli("test fib-walk-process enable")

        #
        # packets should still be forwarded through the remaining peer
        #
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg0.get_capture(64)

        #
        # Add the IGP route back and we return to load-balancing
        #
        core_10_0_0_46.add_vpp_config()

        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg0._get_capture(1)
        rx1 = self.pg1._get_capture(1)
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))

    def test_mpls_ebgp_pic(self):
        """ MPLS eBGP PIC edge convergence

        1) setup many eBGP VPN routes via a pair of eBGP peers
        2) Check EMCP forwarding to these peers
        3) withdraw one eBGP path - expect LB across remaining eBGP
        """

        #
        # Lot's of VPN routes. We need more the 64 so VPP will build
        # the fast convergence indirection
        #
        vpn_routes = []
        vpn_bindings = []
        pkts = []
        for ii in range(64):
            dst = "192.168.1.%d" % ii
            local_label = 1600 + ii
            vpn_routes.append(VppIpRoute(self, dst, 32,
                                         [VppRoutePath(self.pg2.remote_ip4,
                                                       0xffffffff,
                                                       nh_table_id=1,
                                                       is_resolve_attached=1),
                                          VppRoutePath(self.pg3.remote_ip4,
                                                       0xffffffff,
                                                       nh_table_id=1,
                                                       is_resolve_attached=1)],
                                         table_id=1))
            vpn_routes[ii].add_vpp_config()

            vpn_bindings.append(VppMplsIpBind(self, local_label, dst, 32,
                                              ip_table_id=1))
            vpn_bindings[ii].add_vpp_config()

            pkts.append(Ether(dst=self.pg0.local_mac,
                              src=self.pg0.remote_mac) /
                        MPLS(label=local_label, ttl=64) /
                        IP(src=self.pg0.remote_ip4, dst=dst) /
                        UDP(sport=1234, dport=1234) /
                        Raw('\xa5' * 100))

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg2._get_capture(1)
        rx1 = self.pg3._get_capture(1)
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))

        #
        # use a test CLI command to stop the FIB walk process, this
        # will prevent the FIB converging the VPN routes and thus allow
        # us to probe the interim (psot-fail, pre-converge) state
        #
        self.vapi.ppcli("test fib-walk-process disable")

        #
        # withdraw the connected prefix on the interface.
        #
        self.pg2.unconfig_ip4()

        #
        # now all packets should be forwarded through the remaining peer
        #
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg3.get_capture(len(pkts))

        #
        # enable the FIB walk process to converge the FIB
        #
        self.vapi.ppcli("test fib-walk-process enable")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg3.get_capture(len(pkts))

        #
        # put the connecteds back
        #
        self.pg2.config_ip4()

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg2._get_capture(1)
        rx1 = self.pg3._get_capture(1)
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))

    def test_mpls_v6_ebgp_pic(self):
        """ MPLSv6 eBGP PIC edge convergence

        1) setup many eBGP VPNv6 routes via a pair of eBGP peers
        2) Check EMCP forwarding to these peers
        3) withdraw one eBGP path - expect LB across remaining eBGP
        """

        #
        # Lot's of VPN routes. We need more the 64 so VPP will build
        # the fast convergence indirection
        #
        vpn_routes = []
        vpn_bindings = []
        pkts = []
        for ii in range(64):
            dst = "3000::%d" % ii
            local_label = 1600 + ii
            vpn_routes.append(VppIpRoute(
                self, dst, 128,
                [VppRoutePath(self.pg2.remote_ip6,
                              0xffffffff,
                              nh_table_id=1,
                              is_resolve_attached=1,
                              proto=DPO_PROTO.IP6),
                 VppRoutePath(self.pg3.remote_ip6,
                              0xffffffff,
                              nh_table_id=1,
                              proto=DPO_PROTO.IP6,
                              is_resolve_attached=1)],
                table_id=1,
                is_ip6=1))
            vpn_routes[ii].add_vpp_config()

            vpn_bindings.append(VppMplsIpBind(self, local_label, dst, 128,
                                              ip_table_id=1,
                                              is_ip6=1))
            vpn_bindings[ii].add_vpp_config()

            pkts.append(Ether(dst=self.pg0.local_mac,
                              src=self.pg0.remote_mac) /
                        MPLS(label=local_label, ttl=64) /
                        IPv6(src=self.pg0.remote_ip6, dst=dst) /
                        UDP(sport=1234, dport=1234) /
                        Raw('\xa5' * 100))

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg2._get_capture(1)
        rx1 = self.pg3._get_capture(1)
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))

        #
        # use a test CLI command to stop the FIB walk process, this
        # will prevent the FIB converging the VPN routes and thus allow
        # us to probe the interim (psot-fail, pre-converge) state
        #
        self.vapi.ppcli("test fib-walk-process disable")

        #
        # withdraw the connected prefix on the interface.
        # and shutdown the interface so the ND cache is flushed.
        #
        self.pg2.unconfig_ip6()
        self.pg2.admin_down()

        #
        # now all packets should be forwarded through the remaining peer
        #
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg3.get_capture(len(pkts))

        #
        # enable the FIB walk process to converge the FIB
        #
        self.vapi.ppcli("test fib-walk-process enable")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg3.get_capture(len(pkts))

        #
        # put the connecteds back
        #
        self.pg2.admin_up()
        self.pg2.config_ip6()

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg2._get_capture(1)
        rx1 = self.pg3._get_capture(1)
        self.assertNotEqual(0, len(rx0))
        self.assertNotEqual(0, len(rx1))


class TestMPLSL2(VppTestCase):
    """ MPLS-L2 """

    def setUp(self):
        super(TestMPLSL2, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # create the default MPLS table
        self.tables = []
        tbl = VppMplsTable(self, 0)
        tbl.add_vpp_config()
        self.tables.append(tbl)

        # use pg0 as the core facing interface
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg0.enable_mpls()

        # use the other 2 for customer facing L2 links
        for i in self.pg_interfaces[1:]:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces[1:]:
            i.admin_down()

        self.pg0.disable_mpls()
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(TestMPLSL2, self).tearDown()

    def verify_capture_tunneled_ethernet(self, capture, sent, mpls_labels):
        capture = verify_filter(capture, sent)

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            tx = sent[i]
            rx = capture[i]

            # the MPLS TTL is 255 since it enters a new tunnel
            verify_mpls_stack(self, rx, mpls_labels)

            tx_eth = tx[Ether]
            rx_eth = Ether(str(rx[MPLS].payload))

            self.assertEqual(rx_eth.src, tx_eth.src)
            self.assertEqual(rx_eth.dst, tx_eth.dst)

    def test_vpws(self):
        """ Virtual Private Wire Service """

        #
        # Create an MPLS tunnel that pushes 1 label
        # For Ethernet over MPLS the uniform mode is irrelevant since ttl/cos
        # information is not in the packet, but we test it works anyway
        #
        mpls_tun_1 = VppMPLSTunnelInterface(
            self,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(42, MPLS_LSP_MODE.UNIFORM)])],
            is_l2=1)
        mpls_tun_1.add_vpp_config()
        mpls_tun_1.admin_up()

        #
        # Create a label entry to for 55 that does L2 input to the tunnel
        #
        route_55_eos = VppMplsRoute(
            self, 55, 1,
            [VppRoutePath("0.0.0.0",
                          mpls_tun_1.sw_if_index,
                          is_interface_rx=1,
                          proto=DPO_PROTO.ETHERNET)])
        route_55_eos.add_vpp_config()

        #
        # Cross-connect the tunnel with one of the customers L2 interfaces
        #
        self.vapi.sw_interface_set_l2_xconnect(self.pg1.sw_if_index,
                                               mpls_tun_1.sw_if_index,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(mpls_tun_1.sw_if_index,
                                               self.pg1.sw_if_index,
                                               enable=1)

        #
        # inject a packet from the core
        #
        pcore = (Ether(dst=self.pg0.local_mac,
                       src=self.pg0.remote_mac) /
                 MPLS(label=55, ttl=64) /
                 Ether(dst="00:00:de:ad:ba:be",
                       src="00:00:de:ad:be:ef") /
                 IP(src="10.10.10.10", dst="11.11.11.11") /
                 UDP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))

        tx0 = pcore * 65
        rx0 = self.send_and_expect(self.pg0, tx0, self.pg1)
        payload = pcore[MPLS].payload

        self.assertEqual(rx0[0][Ether].dst, payload[Ether].dst)
        self.assertEqual(rx0[0][Ether].src, payload[Ether].src)

        #
        # Inject a packet from the custoer/L2 side
        #
        tx1 = pcore[MPLS].payload * 65
        rx1 = self.send_and_expect(self.pg1, tx1, self.pg0)

        self.verify_capture_tunneled_ethernet(rx1, tx1, [VppMplsLabel(42)])

    def test_vpls(self):
        """ Virtual Private LAN Service """
        #
        # Create an L2 MPLS tunnel
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath(self.pg0.remote_ip4,
                          self.pg0.sw_if_index,
                          labels=[VppMplsLabel(42)])],
            is_l2=1)
        mpls_tun.add_vpp_config()
        mpls_tun.admin_up()

        #
        # Create a label entry to for 55 that does L2 input to the tunnel
        #
        route_55_eos = VppMplsRoute(
            self, 55, 1,
            [VppRoutePath("0.0.0.0",
                          mpls_tun.sw_if_index,
                          is_interface_rx=1,
                          proto=DPO_PROTO.ETHERNET)])
        route_55_eos.add_vpp_config()

        #
        # add to tunnel to the customers bridge-domain
        #
        self.vapi.sw_interface_set_l2_bridge(mpls_tun.sw_if_index,
                                             bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index,
                                             bd_id=1)

        #
        # Packet from the customer interface and from the core
        #
        p_cust = (Ether(dst="00:00:de:ad:ba:be",
                        src="00:00:de:ad:be:ef") /
                  IP(src="10.10.10.10", dst="11.11.11.11") /
                  UDP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))
        p_core = (Ether(src="00:00:de:ad:ba:be",
                        dst="00:00:de:ad:be:ef") /
                  IP(dst="10.10.10.10", src="11.11.11.11") /
                  UDP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))

        #
        # The BD is learning, so send in one of each packet to learn
        #
        p_core_encap = (Ether(dst=self.pg0.local_mac,
                              src=self.pg0.remote_mac) /
                        MPLS(label=55, ttl=64) /
                        p_core)

        self.pg1.add_stream(p_cust)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.add_stream(p_core_encap)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # we've learnt this so expect it be be forwarded
        rx0 = self.pg1.get_capture(1)

        self.assertEqual(rx0[0][Ether].dst, p_core[Ether].dst)
        self.assertEqual(rx0[0][Ether].src, p_core[Ether].src)

        #
        # now a stream in each direction
        #
        self.pg1.add_stream(p_cust * 65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg0.get_capture(65)

        self.verify_capture_tunneled_ethernet(rx0, p_cust*65,
                                              [VppMplsLabel(42)])

        #
        # remove interfaces from customers bridge-domain
        #
        self.vapi.sw_interface_set_l2_bridge(mpls_tun.sw_if_index,
                                             bd_id=1,
                                             enable=0)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index,
                                             bd_id=1,
                                             enable=0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
