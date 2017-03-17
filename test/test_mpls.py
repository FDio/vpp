#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, \
    VppMplsIpBind

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS


class TestMPLS(VppTestCase):
    """ MPLS Test Case """

    def setUp(self):
        super(TestMPLS, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # setup both interfaces
        # assign them different tables.
        table_id = 0

        for i in self.pg_interfaces:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.enable_mpls()
            table_id += 1

    def tearDown(self):
        super(TestMPLS, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.admin_down()

    # the default of 64 matches the IP packet TTL default
    def create_stream_labelled_ip4(
            self,
            src_if,
            mpls_labels,
            mpls_ttl=255,
            ping=0,
            ip_itf=None):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = Ether(dst=src_if.local_mac, src=src_if.remote_mac)

            for ii in range(len(mpls_labels)):
                if ii == len(mpls_labels) - 1:
                    p = p / MPLS(label=mpls_labels[ii], ttl=mpls_ttl, s=1)
                else:
                    p = p / MPLS(label=mpls_labels[ii], ttl=mpls_ttl, s=0)
            if not ping:
                p = (p / IP(src=src_if.local_ip4, dst=src_if.remote_ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
            else:
                p = (p / IP(src=ip_itf.remote_ip4,
                            dst=ip_itf.local_ip4) /
                     ICMP())

            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_ip4(self, src_if, dst_ip):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_labelled_ip6(self, src_if, mpls_label, mpls_ttl):
        self.reset_packet_infos()
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 MPLS(label=mpls_label, ttl=mpls_ttl) /
                 IPv6(src=src_if.remote_ip6, dst=src_if.remote_ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    @staticmethod
    def verify_filter(capture, sent):
        if not len(capture) == len(sent):
            # filter out any IPv6 RAs from the capture
            for p in capture:
                if p.haslayer(IPv6):
                    capture.remove(p)
        return capture

    def verify_capture_ip4(self, src_if, capture, sent, ping_resp=0):
        try:
            capture = self.verify_filter(capture, sent)

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
                    # IP processing post pop has decremented the TTL
                    self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)
                else:
                    self.assertEqual(rx_ip.src, tx_ip.dst)
                    self.assertEqual(rx_ip.dst, tx_ip.src)

        except:
            raise

    def verify_mpls_stack(self, rx, mpls_labels, ttl=255, num=0):
        # the rx'd packet has the MPLS label popped
        eth = rx[Ether]
        self.assertEqual(eth.type, 0x8847)

        rx_mpls = rx[MPLS]

        for ii in range(len(mpls_labels)):
            self.assertEqual(rx_mpls.label, mpls_labels[ii])
            self.assertEqual(rx_mpls.cos, 0)
            if ii == num:
                self.assertEqual(rx_mpls.ttl, ttl)
            else:
                self.assertEqual(rx_mpls.ttl, 255)

            if ii == len(mpls_labels) - 1:
                self.assertEqual(rx_mpls.s, 1)
            else:
                # not end of stack
                self.assertEqual(rx_mpls.s, 0)
                # pop the label to expose the next
                rx_mpls = rx_mpls[MPLS].payload

    def verify_capture_labelled_ip4(self, src_if, capture, sent,
                                    mpls_labels):
        try:
            capture = self.verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]
                tx_ip = tx[IP]
                rx_ip = rx[IP]

                # the MPLS TTL is copied from the IP
                self.verify_mpls_stack(
                    rx, mpls_labels, rx_ip.ttl, len(mpls_labels) - 1)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

        except:
            raise

    def verify_capture_tunneled_ip4(self, src_if, capture, sent, mpls_labels):
        try:
            capture = self.verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]
                tx_ip = tx[IP]
                rx_ip = rx[IP]

                # the MPLS TTL is 255 since it enters a new tunnel
                self.verify_mpls_stack(
                    rx, mpls_labels, 255, len(mpls_labels) - 1)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

        except:
            raise

    def verify_capture_labelled(self, src_if, capture, sent,
                                mpls_labels, ttl=254, num=0):
        try:
            capture = self.verify_filter(capture, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                rx = capture[i]
                self.verify_mpls_stack(rx, mpls_labels, ttl, num)
        except:
            raise

    def verify_capture_ip6(self, src_if, capture, sent):
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
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

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
                                                  labels=[33])])
        route_32_eos.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [32])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [33])

        #
        # A simple MPLS xconnect - non-eos label in label out
        #
        route_32_neos = VppMplsRoute(self, 32, 0,
                                     [VppRoutePath(self.pg0.remote_ip4,
                                                   self.pg0.sw_if_index,
                                                   labels=[33])])
        route_32_neos.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [32, 99])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled(self.pg0, rx, tx, [33, 99])

        #
        # An MPLS xconnect - EOS label in IP out
        #
        route_33_eos = VppMplsRoute(self, 33, 1,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[])])
        route_33_eos.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [33])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_ip4(self.pg0, rx, tx)

        #
        # An MPLS xconnect - non-EOS label in IP out - an invalid configuration
        # so this traffic should be dropped.
        #
        route_33_neos = VppMplsRoute(self, 33, 0,
                                     [VppRoutePath(self.pg0.remote_ip4,
                                                   self.pg0.sw_if_index,
                                                   labels=[])])
        route_33_neos.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [33, 99])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured(
            remark="MPLS non-EOS packets popped and forwarded")

        #
        # A recursive EOS x-connect, which resolves through another x-connect
        #
        route_34_eos = VppMplsRoute(self, 34, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_via_label=32,
                                                  labels=[44, 45])])
        route_34_eos.add_vpp_config()

        tx = self.create_stream_labelled_ip4(self.pg0, [34])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [33, 44, 45])

        #
        # A recursive non-EOS x-connect, which resolves through another
        # x-connect
        #
        route_34_neos = VppMplsRoute(self, 34, 0,
                                     [VppRoutePath("0.0.0.0",
                                                   0xffffffff,
                                                   nh_via_label=32,
                                                   labels=[44, 46])])
        route_34_neos.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [34, 99])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        # it's the 2nd (counting from 0) label in the stack that is swapped
        self.verify_capture_labelled(self.pg0, rx, tx, [33, 44, 46, 99], num=2)

        #
        # an recursive IP route that resolves through the recursive non-eos
        # x-connect
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_via_label=34,
                                               labels=[55])])
        ip_10_0_0_1.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [33, 44, 46, 55])

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
                                                  labels=[45])])
        route_10_0_0_1.add_vpp_config()

        # bind a local label to the route
        binding = VppMplsIpBind(self, 44, "10.0.0.1", 32)
        binding.add_vpp_config()

        # non-EOS stream
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [44, 99])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled(self.pg0, rx, tx, [45, 99])

        # EOS stream
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [44])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled(self.pg0, rx, tx, [45])

        # IP stream
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [45])

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
                                                  labels=[32])])
        route_10_0_0_1.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [32])

        #
        # Add a non-recursive route with a 3 out labels
        #
        route_10_0_0_2 = VppIpRoute(self, "10.0.0.2", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[32, 33, 34])])
        route_10_0_0_2.add_vpp_config()

        #
        # a stream that matches the route for 10.0.0.1
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.2")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [32, 33, 34])

        #
        # add a recursive path, with output label, via the 1 label route
        #
        route_11_0_0_1 = VppIpRoute(self, "11.0.0.1", 32,
                                    [VppRoutePath("10.0.0.1",
                                                  0xffffffff,
                                                  labels=[44])])
        route_11_0_0_1.add_vpp_config()

        #
        # a stream that matches the route for 11.0.0.1, should pick up
        # the label stack for 11.0.0.1 and 10.0.0.1
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "11.0.0.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(self.pg0, rx, tx, [32, 44])

        #
        # add a recursive path, with 2 labels, via the 3 label route
        #
        route_11_0_0_2 = VppIpRoute(self, "11.0.0.2", 32,
                                    [VppRoutePath("10.0.0.2",
                                                  0xffffffff,
                                                  labels=[44, 45])])
        route_11_0_0_2.add_vpp_config()

        #
        # a stream that matches the route for 11.0.0.1, should pick up
        # the label stack for 11.0.0.1 and 10.0.0.1
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "11.0.0.2")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_labelled_ip4(
            self.pg0, rx, tx, [32, 33, 34, 44, 45])

        #
        # cleanup
        #
        route_11_0_0_2.remove_vpp_config()
        route_11_0_0_1.remove_vpp_config()
        route_10_0_0_2.remove_vpp_config()
        route_10_0_0_1.remove_vpp_config()

    def test_tunnel(self):
        """ MPLS Tunnel Tests """

        #
        # Create a tunnel with a single out label
        #
        nh_addr = socket.inet_pton(socket.AF_INET, self.pg0.remote_ip4)

        reply = self.vapi.mpls_tunnel_add_del(
            0xffffffff,  # don't know the if index yet
            1,  # IPv4 next-hop
            nh_addr,
            self.pg0.sw_if_index,
            0,  # next-hop-table-id
            1,  # next-hop-weight
            2,  # num-out-labels,
            [44, 46])
        self.vapi.sw_interface_set_flags(reply.sw_if_index, admin_up_down=1)

        #
        # add an unlabelled route through the new tunnel
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  reply.sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "10.0.0.3")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx, [44, 46])

    def test_v4_exp_null(self):
        """ MPLS V4 Explicit NULL test """

        #
        # The first test case has an MPLS TTL of 0
        # all packet should be dropped
        #
        tx = self.create_stream_labelled_ip4(self.pg0, [0], 0)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.assert_nothing_captured(remark="MPLS TTL=0 packets forwarded")

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        tx = self.create_stream_labelled_ip4(self.pg0, [0])
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_ip4(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg1, [0])
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture()
        self.verify_capture_ip4(self.pg0, rx, tx)

    def test_v6_exp_null(self):
        """ MPLS V6 Explicit NULL test """

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip6(self.pg0, 2, 2)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_ip6(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip6(self.pg1, 2, 2)
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture()
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
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(self.pg0, [34], ping=1,
                                             ip_itf=self.pg0)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
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
        self.vapi.cli("clear trace")
        tx = self.create_stream_labelled_ip4(
            self.pg0, [35], ping=1, ip_itf=self.pg1)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        packet_count = self.get_packet_count_for_if_idx(self.pg0.sw_if_index)
        rx = self.pg1.get_capture(packet_count)
        self.verify_capture_ip4(self.pg1, rx, tx, ping_resp=1)

        route_35_eos.remove_vpp_config()
        route_34_eos.remove_vpp_config()


class TestMPLSDisabled(VppTestCase):
    """ MPLS disabled """

    def setUp(self):
        super(TestMPLSDisabled, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # PG0 is MPLS enalbed
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg0.enable_mpls()

        # PG 1 is not MPLS enabled
        self.pg1.admin_up()

    def tearDown(self):
        super(TestMPLSDisabled, self).tearDown()
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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
