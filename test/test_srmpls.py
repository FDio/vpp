#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, \
    VppIpTable, VppMplsTable, VppMplsLabel
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


class TestSRMPLS(VppTestCase):
    """ SR-MPLS Test Case """

    def setUp(self):
        super(TestSRMPLS, self).setUp()

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
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.disable_mpls()
            i.admin_down()
        super(TestSRMPLS, self).tearDown()

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

    def test_sr_mpls(self):
        """ SR MPLS """

        #
        # A simple MPLS xconnect - neos label in label out
        #
        route_32_eos = VppMplsRoute(self, 32, 0,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index,
                                                  labels=[VppMplsLabel(32)])])
        route_32_eos.add_vpp_config()

        #
        # A binding SID with only one label
        #
        self.vapi.sr_mpls_policy_add(999, 1, 0, [32])

        #
        # A labeled IP route that resolves thru the binding SID
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_via_label=999,
                                               labels=[VppMplsLabel(55)])])
        ip_10_0_0_1.add_vpp_config()

        tx = self.create_stream_ip4(self.pg1, "10.0.0.1")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(55)])

        #
        # An unlabeled IP route that resolves thru the binding SID
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.2", 32,
                                 [VppRoutePath("0.0.0.0",
                                               0xffffffff,
                                               nh_via_label=999)])
        ip_10_0_0_1.add_vpp_config()

        tx = self.create_stream_ip4(self.pg1, "10.0.0.2")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32)])

        self.vapi.sr_mpls_policy_del(999)

        #
        # this time the SID has many labels pushed
        #
        self.vapi.sr_mpls_policy_add(999, 1, 0, [32, 33, 34])

        tx = self.create_stream_ip4(self.pg1, "10.0.0.1")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34),
                                          VppMplsLabel(55)])
        tx = self.create_stream_ip4(self.pg1, "10.0.0.2")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_labelled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34)])

        #
        # Resolve an MPLS tunnel via the SID
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath("0.0.0.0",
                          0xffffffff,
                          nh_via_label=999,
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
        self.logger.info(self.vapi.cli("sh mpls tun 0"))
        self.logger.info(self.vapi.cli("sh adj 21"))

        tx = self.create_stream_ip4(self.pg1, "10.0.0.3")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34),
                                          VppMplsLabel(44),
                                          VppMplsLabel(46)])

        #
        # add a labelled route through the new tunnel
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.4", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun._sw_if_index,
                                                  labels=[VppMplsLabel(55)])])
        route_10_0_0_3.add_vpp_config()

        tx = self.create_stream_ip4(self.pg1, "10.0.0.4")
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_capture_tunneled_ip4(self.pg0, rx, tx,
                                         [VppMplsLabel(32),
                                          VppMplsLabel(33),
                                          VppMplsLabel(34),
                                          VppMplsLabel(44),
                                          VppMplsLabel(46),
                                          VppMplsLabel(55)])

        self.vapi.sr_mpls_policy_del(999)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
