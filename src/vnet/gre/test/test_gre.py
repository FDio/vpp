#!/usr/bin/env python3

import unittest

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, GRE
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.volatile import RandMAC, RandIP

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint
from vpp_gre_interface import VppGreInterface
from vpp_teib import VppTeib
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, FibPathProto, \
    VppMplsLabel
from vpp_mpls_tunnel_interface import VppMPLSTunnelInterface
from util import ppp, ppc
from vpp_papi import VppEnum


@tag_fixme_vpp_workers
class TestGREInputNodes(VppTestCase):
    """ GRE Input Nodes Test Case """

    def setUp(self):
        super(TestGREInputNodes, self).setUp()

        # create 3 pg interfaces - set one in a non-default table.
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestGREInputNodes, self).tearDown()

    def test_gre_input_node(self):
        """ GRE gre input nodes not registerd unless configured """
        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               GRE())

        self.pg0.add_stream(pkt)
        self.pg_start()
        # no tunnel created, gre-input not registered
        err = self.statistics.get_counter(
            '/err/ip4-local/unknown ip protocol')[0]
        self.assertEqual(err, 1)
        err_count = err

        # create gre tunnel
        gre_if = VppGreInterface(self, self.pg0.local_ip4, "1.1.1.2")
        gre_if.add_vpp_config()

        self.pg0.add_stream(pkt)
        self.pg_start()
        # tunnel created, gre-input registered
        err = self.statistics.get_counter(
            '/err/ip4-local/unknown ip protocol')[0]
        # expect no new errors
        self.assertEqual(err, err_count)


class TestGRE(VppTestCase):
    """ GRE Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestGRE, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestGRE, cls).tearDownClass()

    def setUp(self):
        super(TestGRE, self).setUp()

        # create 3 pg interfaces - set one in a non-default table.
        self.create_pg_interfaces(range(5))

        self.tbl = VppIpTable(self, 1)
        self.tbl.add_vpp_config()
        self.pg1.set_table_ip4(1)

        for i in self.pg_interfaces:
            i.admin_up()

        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg1.config_ip4()
        self.pg1.resolve_arp()
        self.pg2.config_ip6()
        self.pg2.resolve_ndp()
        self.pg3.config_ip4()
        self.pg3.resolve_arp()
        self.pg4.config_ip4()
        self.pg4.resolve_arp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        self.pg1.set_table_ip4(0)
        super(TestGRE, self).tearDown()

    def create_stream_ip4(self, src_if, src_ip, dst_ip, dscp=0, ecn=0):
        pkts = []
        tos = (dscp << 2) | ecn
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_ip, dst=dst_ip, tos=tos) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_ip6(self, src_if, src_ip, dst_ip, dscp=0, ecn=0):
        pkts = []
        tc = (dscp << 2) | ecn
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IPv6(src=src_ip, dst=dst_ip, tc=tc) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_tunnel_stream_4o4(self, src_if,
                                 tunnel_src, tunnel_dst,
                                 src_ip, dst_ip):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=tunnel_src, dst=tunnel_dst) /
                 GRE() /
                 IP(src=src_ip, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_tunnel_stream_6o4(self, src_if,
                                 tunnel_src, tunnel_dst,
                                 src_ip, dst_ip):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=tunnel_src, dst=tunnel_dst) /
                 GRE() /
                 IPv6(src=src_ip, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_tunnel_stream_6o6(self, src_if,
                                 tunnel_src, tunnel_dst,
                                 src_ip, dst_ip):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IPv6(src=tunnel_src, dst=tunnel_dst) /
                 GRE() /
                 IPv6(src=src_ip, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_tunnel_stream_l2o4(self, src_if,
                                  tunnel_src, tunnel_dst):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=tunnel_src, dst=tunnel_dst) /
                 GRE() /
                 Ether(dst=RandMAC('*:*:*:*:*:*'),
                       src=RandMAC('*:*:*:*:*:*')) /
                 IP(src=scapy.compat.raw(RandIP()),
                    dst=scapy.compat.raw(RandIP())) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_tunnel_stream_vlano4(self, src_if,
                                    tunnel_src, tunnel_dst, vlan):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=tunnel_src, dst=tunnel_dst) /
                 GRE() /
                 Ether(dst=RandMAC('*:*:*:*:*:*'),
                       src=RandMAC('*:*:*:*:*:*')) /
                 Dot1Q(vlan=vlan) /
                 IP(src=scapy.compat.raw(RandIP()),
                    dst=scapy.compat.raw(RandIP())) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def verify_tunneled_4o4(self, src_if, capture, sent,
                            tunnel_src, tunnel_dst,
                            dscp=0, ecn=0):

        self.assertEqual(len(capture), len(sent))
        tos = (dscp << 2) | ecn

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)
                self.assertEqual(rx_ip.tos, tos)
                self.assertEqual(rx_ip.len, len(rx_ip))

                rx_gre = rx[GRE]
                rx_ip = rx_gre[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_tunneled_6o6(self, src_if, capture, sent,
                            tunnel_src, tunnel_dst,
                            dscp=0, ecn=0):

        self.assertEqual(len(capture), len(sent))
        tc = (dscp << 2) | ecn

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)
                self.assertEqual(rx_ip.tc, tc)

                rx_gre = GRE(scapy.compat.raw(rx_ip[IPv6].payload))

                self.assertEqual(rx_ip.plen, len(rx_gre))

                rx_ip = rx_gre[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_tunneled_4o6(self, src_if, capture, sent,
                            tunnel_src, tunnel_dst):

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                rx_ip = rx[IPv6]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)

                rx_gre = GRE(scapy.compat.raw(rx_ip[IPv6].payload))

                self.assertEqual(rx_ip.plen, len(rx_gre))

                tx_ip = tx[IP]
                rx_ip = rx_gre[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_tunneled_6o4(self, src_if, capture, sent,
                            tunnel_src, tunnel_dst):

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)
                self.assertEqual(rx_ip.len, len(rx_ip))

                rx_gre = GRE(scapy.compat.raw(rx_ip[IP].payload))
                rx_ip = rx_gre[IPv6]
                tx_ip = tx[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_tunneled_l2o4(self, src_if, capture, sent,
                             tunnel_src, tunnel_dst):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)
                self.assertEqual(rx_ip.len, len(rx_ip))

                rx_gre = rx[GRE]
                rx_l2 = rx_gre[Ether]
                rx_ip = rx_l2[IP]
                tx_gre = tx[GRE]
                tx_l2 = tx_gre[Ether]
                tx_ip = tx_l2[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # bridged, not L3 forwarded, so no TTL decrement
                self.assertEqual(rx_ip.ttl, tx_ip.ttl)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_tunneled_vlano4(self, src_if, capture, sent,
                               tunnel_src, tunnel_dst, vlan):
        try:
            self.assertEqual(len(capture), len(sent))
        except:
            ppc("Unexpected packets captured:", capture)
            raise

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tunnel_src)
                self.assertEqual(rx_ip.dst, tunnel_dst)

                rx_gre = rx[GRE]
                rx_l2 = rx_gre[Ether]
                rx_vlan = rx_l2[Dot1Q]
                rx_ip = rx_l2[IP]

                self.assertEqual(rx_vlan.vlan, vlan)

                tx_gre = tx[GRE]
                tx_l2 = tx_gre[Ether]
                tx_ip = tx_l2[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # bridged, not L3 forwarded, so no TTL decrement
                self.assertEqual(rx_ip.ttl, tx_ip.ttl)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_decapped_4o4(self, src_if, capture, sent):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IP]
                tx_gre = tx[GRE]
                tx_ip = tx_gre[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_decapped_6o4(self, src_if, capture, sent):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IP]
                rx_ip = rx[IPv6]
                tx_gre = tx[GRE]
                tx_ip = tx_gre[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def verify_decapped_6o6(self, src_if, capture, sent):
        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            try:
                tx = sent[i]
                rx = capture[i]

                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]
                tx_gre = tx[GRE]
                tx_ip = tx_gre[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

            except:
                self.logger.error(ppp("Rx:", rx))
                self.logger.error(ppp("Tx:", tx))
                raise

    def test_gre(self):
        """ GRE IPv4 tunnel Tests """

        #
        # Create an L3 GRE tunnel.
        #  - set it admin up
        #  - assign an IP Addres
        #  - Add a route via the tunnel
        #
        gre_if = VppGreInterface(self,
                                 self.pg0.local_ip4,
                                 "1.1.1.2")
        gre_if.add_vpp_config()

        #
        # The double create (create the same tunnel twice) should fail,
        # and we should still be able to use the original
        #
        try:
            gre_if.add_vpp_config()
        except Exception:
            pass
        else:
            self.fail("Double GRE tunnel add does not fail")

        gre_if.admin_up()
        gre_if.config_ip4()

        route_via_tun = VppIpRoute(self, "4.4.4.4", 32,
                                   [VppRoutePath("0.0.0.0",
                                                 gre_if.sw_if_index)])

        route_via_tun.add_vpp_config()

        #
        # Send a packet stream that is routed into the tunnel
        #  - they are all dropped since the tunnel's destintation IP
        #    is unresolved - or resolves via the default route - which
        #    which is a drop.
        #
        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "4.4.4.4")

        self.send_and_assert_no_replies(self.pg0, tx)

        #
        # Add a route that resolves the tunnel's destination
        #
        route_tun_dst = VppIpRoute(self, "1.1.1.2", 32,
                                   [VppRoutePath(self.pg0.remote_ip4,
                                                 self.pg0.sw_if_index)])
        route_tun_dst.add_vpp_config()

        #
        # Send a packet stream that is routed into the tunnel
        #  - packets are GRE encapped
        #
        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "4.4.4.4")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_4o4(self.pg0, rx, tx,
                                 self.pg0.local_ip4, "1.1.1.2")

        #
        # Send tunneled packets that match the created tunnel and
        # are decapped and forwarded
        #
        tx = self.create_tunnel_stream_4o4(self.pg0,
                                           "1.1.1.2",
                                           self.pg0.local_ip4,
                                           self.pg0.local_ip4,
                                           self.pg0.remote_ip4)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_decapped_4o4(self.pg0, rx, tx)

        #
        # Send tunneled packets that do not match the tunnel's src
        #
        self.vapi.cli("clear trace")
        tx = self.create_tunnel_stream_4o4(self.pg0,
                                           "1.1.1.3",
                                           self.pg0.local_ip4,
                                           self.pg0.local_ip4,
                                           self.pg0.remote_ip4)
        self.send_and_assert_no_replies(
            self.pg0, tx,
            remark="GRE packets forwarded despite no SRC address match")

        #
        # Configure IPv6 on the PG interface so we can route IPv6
        # packets
        #
        self.pg0.config_ip6()
        self.pg0.resolve_ndp()

        #
        # Send IPv6 tunnel encapslated packets
        #  - dropped since IPv6 is not enabled on the tunnel
        #
        tx = self.create_tunnel_stream_6o4(self.pg0,
                                           "1.1.1.2",
                                           self.pg0.local_ip4,
                                           self.pg0.local_ip6,
                                           self.pg0.remote_ip6)
        self.send_and_assert_no_replies(self.pg0, tx,
                                        "IPv6 GRE packets forwarded "
                                        "despite IPv6 not enabled on tunnel")

        #
        # Enable IPv6 on the tunnel
        #
        gre_if.config_ip6()

        #
        # Send IPv6 tunnel encapslated packets
        #  - forwarded since IPv6 is enabled on the tunnel
        #
        tx = self.create_tunnel_stream_6o4(self.pg0,
                                           "1.1.1.2",
                                           self.pg0.local_ip4,
                                           self.pg0.local_ip6,
                                           self.pg0.remote_ip6)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_decapped_6o4(self.pg0, rx, tx)

        #
        # Send v6 packets for v4 encap
        #
        route6_via_tun = VppIpRoute(
            self, "2001::1", 128,
            [VppRoutePath("::",
                          gre_if.sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP6)])
        route6_via_tun.add_vpp_config()

        tx = self.create_stream_ip6(self.pg0, "2001::2", "2001::1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)

        self.verify_tunneled_6o4(self.pg0, rx, tx,
                                 self.pg0.local_ip4, "1.1.1.2")

        #
        # add a labelled route through the tunnel
        #
        label_via_tun = VppIpRoute(self, "5.4.3.2", 32,
                                   [VppRoutePath("0.0.0.0",
                                                 gre_if.sw_if_index,
                                                 labels=[VppMplsLabel(33)])])
        label_via_tun.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "5.4.3.2")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_4o4(self.pg0, rx, tx,
                                 self.pg0.local_ip4, "1.1.1.2")

        #
        # an MPLS tunnel over the GRE tunnel add a route through
        # the mpls tunnel
        #
        mpls_tun = VppMPLSTunnelInterface(
            self,
            [VppRoutePath("0.0.0.0",
                          gre_if.sw_if_index,
                          labels=[VppMplsLabel(44),
                                  VppMplsLabel(46)])])
        mpls_tun.add_vpp_config()
        mpls_tun.admin_up()

        label_via_mpls = VppIpRoute(self, "5.4.3.1", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  mpls_tun.sw_if_index,
                                                  labels=[VppMplsLabel(33)])])
        label_via_mpls.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "5.4.3.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_4o4(self.pg0, rx, tx,
                                 self.pg0.local_ip4, "1.1.1.2")

        mpls_tun_l2 = VppMPLSTunnelInterface(
            self,
            [VppRoutePath("0.0.0.0",
                          gre_if.sw_if_index,
                          labels=[VppMplsLabel(44),
                                  VppMplsLabel(46)])],
            is_l2=1)
        mpls_tun_l2.add_vpp_config()
        mpls_tun_l2.admin_up()

        #
        # test case cleanup
        #
        route_tun_dst.remove_vpp_config()
        route_via_tun.remove_vpp_config()
        route6_via_tun.remove_vpp_config()
        label_via_mpls.remove_vpp_config()
        label_via_tun.remove_vpp_config()
        mpls_tun.remove_vpp_config()
        mpls_tun_l2.remove_vpp_config()
        gre_if.remove_vpp_config()

        self.pg0.unconfig_ip6()

    def test_gre6(self):
        """ GRE IPv6 tunnel Tests """

        self.pg1.config_ip6()
        self.pg1.resolve_ndp()

        #
        # Create an L3 GRE tunnel.
        #  - set it admin up
        #  - assign an IP Address
        #  - Add a route via the tunnel
        #
        gre_if = VppGreInterface(self,
                                 self.pg2.local_ip6,
                                 "1002::1")
        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip6()

        route_via_tun = VppIpRoute(self, "4004::1", 128,
                                   [VppRoutePath("0::0",
                                                 gre_if.sw_if_index)])

        route_via_tun.add_vpp_config()

        #
        # Send a packet stream that is routed into the tunnel
        #  - they are all dropped since the tunnel's destintation IP
        #    is unresolved - or resolves via the default route - which
        #    which is a drop.
        #
        tx = self.create_stream_ip6(self.pg2, "5005::1", "4004::1")
        self.send_and_assert_no_replies(
            self.pg2, tx,
            "GRE packets forwarded without DIP resolved")

        #
        # Add a route that resolves the tunnel's destination
        #
        route_tun_dst = VppIpRoute(self, "1002::1", 128,
                                   [VppRoutePath(self.pg2.remote_ip6,
                                                 self.pg2.sw_if_index)])
        route_tun_dst.add_vpp_config()

        #
        # Send a packet stream that is routed into the tunnel
        #  - packets are GRE encapped
        #
        tx = self.create_stream_ip6(self.pg2, "5005::1", "4004::1")
        rx = self.send_and_expect(self.pg2, tx, self.pg2)
        self.verify_tunneled_6o6(self.pg2, rx, tx,
                                 self.pg2.local_ip6, "1002::1")

        #
        # Test decap. decapped packets go out pg1
        #
        tx = self.create_tunnel_stream_6o6(self.pg2,
                                           "1002::1",
                                           self.pg2.local_ip6,
                                           "2001::1",
                                           self.pg1.remote_ip6)
        rx = self.send_and_expect(self.pg2, tx, self.pg1)

        #
        # RX'd packet is UDP over IPv6, test the GRE header is gone.
        #
        self.assertFalse(rx[0].haslayer(GRE))
        self.assertEqual(rx[0][IPv6].dst, self.pg1.remote_ip6)

        #
        # Send v4 over v6
        #
        route4_via_tun = VppIpRoute(self, "1.1.1.1", 32,
                                    [VppRoutePath("0.0.0.0",
                                                  gre_if.sw_if_index)])
        route4_via_tun.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "1.1.1.2", "1.1.1.1")
        rx = self.send_and_expect(self.pg0, tx, self.pg2)

        self.verify_tunneled_4o6(self.pg0, rx, tx,
                                 self.pg2.local_ip6, "1002::1")

        #
        # test case cleanup
        #
        route_tun_dst.remove_vpp_config()
        route_via_tun.remove_vpp_config()
        route4_via_tun.remove_vpp_config()
        gre_if.remove_vpp_config()

        self.pg2.unconfig_ip6()
        self.pg1.unconfig_ip6()

    def test_gre_vrf(self):
        """ GRE tunnel VRF Tests """

        e = VppEnum.vl_api_tunnel_encap_decap_flags_t

        #
        # Create an L3 GRE tunnel whose destination is in the non-default
        # table. The underlay is thus non-default - the overlay is still
        # the default.
        #  - set it admin up
        #  - assign an IP Addres
        #
        gre_if = VppGreInterface(
            self, self.pg1.local_ip4,
            "2.2.2.2",
            outer_table_id=1,
            flags=(e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP |
                   e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN))

        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip4()

        #
        # Add a route via the tunnel - in the overlay
        #
        route_via_tun = VppIpRoute(self, "9.9.9.9", 32,
                                   [VppRoutePath("0.0.0.0",
                                                 gre_if.sw_if_index)])
        route_via_tun.add_vpp_config()

        #
        # Add a route that resolves the tunnel's destination - in the
        # underlay table
        #
        route_tun_dst = VppIpRoute(self, "2.2.2.2", 32, table_id=1,
                                   paths=[VppRoutePath(self.pg1.remote_ip4,
                                                       self.pg1.sw_if_index)])
        route_tun_dst.add_vpp_config()

        #
        # Send a packet stream that is routed into the tunnel
        # packets are sent in on pg0 which is in the default table
        #  - packets are GRE encapped
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "5.5.5.5", "9.9.9.9",
                                    dscp=5, ecn=3)
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_tunneled_4o4(self.pg1, rx, tx,
                                 self.pg1.local_ip4, "2.2.2.2",
                                 dscp=5, ecn=3)

        #
        # Send tunneled packets that match the created tunnel and
        # are decapped and forwarded. This tests the decap lookup
        # does not happen in the encap table
        #
        self.vapi.cli("clear trace")
        tx = self.create_tunnel_stream_4o4(self.pg1,
                                           "2.2.2.2",
                                           self.pg1.local_ip4,
                                           self.pg0.local_ip4,
                                           self.pg0.remote_ip4)
        rx = self.send_and_expect(self.pg1, tx, self.pg0)
        self.verify_decapped_4o4(self.pg0, rx, tx)

        #
        # Send tunneled packets that match the created tunnel
        # but arrive on an interface that is not in the tunnel's
        # encap VRF, these are dropped.
        # IP enable the interface so they aren't dropped due to
        # IP not being enabled.
        #
        self.pg2.config_ip4()
        self.vapi.cli("clear trace")
        tx = self.create_tunnel_stream_4o4(self.pg2,
                                           "2.2.2.2",
                                           self.pg1.local_ip4,
                                           self.pg0.local_ip4,
                                           self.pg0.remote_ip4)
        rx = self.send_and_assert_no_replies(
            self.pg2, tx,
            "GRE decap packets in wrong VRF")

        self.pg2.unconfig_ip4()

        #
        # test case cleanup
        #
        route_tun_dst.remove_vpp_config()
        route_via_tun.remove_vpp_config()
        gre_if.remove_vpp_config()

    def test_gre_l2(self):
        """ GRE tunnel L2 Tests """

        #
        # Add routes to resolve the tunnel destinations
        #
        route_tun1_dst = VppIpRoute(self, "2.2.2.2", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index)])
        route_tun2_dst = VppIpRoute(self, "2.2.2.3", 32,
                                    [VppRoutePath(self.pg0.remote_ip4,
                                                  self.pg0.sw_if_index)])

        route_tun1_dst.add_vpp_config()
        route_tun2_dst.add_vpp_config()

        #
        # Create 2 L2 GRE tunnels and x-connect them
        #
        gre_if1 = VppGreInterface(self, self.pg0.local_ip4,
                                  "2.2.2.2",
                                  type=(VppEnum.vl_api_gre_tunnel_type_t.
                                        GRE_API_TUNNEL_TYPE_TEB))
        gre_if2 = VppGreInterface(self, self.pg0.local_ip4,
                                  "2.2.2.3",
                                  type=(VppEnum.vl_api_gre_tunnel_type_t.
                                        GRE_API_TUNNEL_TYPE_TEB))
        gre_if1.add_vpp_config()
        gre_if2.add_vpp_config()

        gre_if1.admin_up()
        gre_if2.admin_up()

        self.vapi.sw_interface_set_l2_xconnect(gre_if1.sw_if_index,
                                               gre_if2.sw_if_index,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(gre_if2.sw_if_index,
                                               gre_if1.sw_if_index,
                                               enable=1)

        #
        # Send in tunnel encapped L2. expect out tunnel encapped L2
        # in both directions
        #
        tx = self.create_tunnel_stream_l2o4(self.pg0,
                                            "2.2.2.2",
                                            self.pg0.local_ip4)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_l2o4(self.pg0, rx, tx,
                                  self.pg0.local_ip4,
                                  "2.2.2.3")

        tx = self.create_tunnel_stream_l2o4(self.pg0,
                                            "2.2.2.3",
                                            self.pg0.local_ip4)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_l2o4(self.pg0, rx, tx,
                                  self.pg0.local_ip4,
                                  "2.2.2.2")

        self.vapi.sw_interface_set_l2_xconnect(gre_if1.sw_if_index,
                                               gre_if2.sw_if_index,
                                               enable=0)
        self.vapi.sw_interface_set_l2_xconnect(gre_if2.sw_if_index,
                                               gre_if1.sw_if_index,
                                               enable=0)

        #
        # Create a VLAN sub-interfaces on the GRE TEB interfaces
        # then x-connect them
        #
        gre_if_11 = VppDot1QSubint(self, gre_if1, 11)
        gre_if_12 = VppDot1QSubint(self, gre_if2, 12)

        # gre_if_11.add_vpp_config()
        # gre_if_12.add_vpp_config()

        gre_if_11.admin_up()
        gre_if_12.admin_up()

        self.vapi.sw_interface_set_l2_xconnect(gre_if_11.sw_if_index,
                                               gre_if_12.sw_if_index,
                                               enable=1)
        self.vapi.sw_interface_set_l2_xconnect(gre_if_12.sw_if_index,
                                               gre_if_11.sw_if_index,
                                               enable=1)

        #
        # Configure both to pop thier respective VLAN tags,
        # so that during the x-coonect they will subsequently push
        #
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=gre_if_12.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=12)
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=gre_if_11.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=11)

        #
        # Send traffic in both directiond - expect the VLAN tags to
        # be swapped.
        #
        tx = self.create_tunnel_stream_vlano4(self.pg0,
                                              "2.2.2.2",
                                              self.pg0.local_ip4,
                                              11)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_vlano4(self.pg0, rx, tx,
                                    self.pg0.local_ip4,
                                    "2.2.2.3",
                                    12)

        tx = self.create_tunnel_stream_vlano4(self.pg0,
                                              "2.2.2.3",
                                              self.pg0.local_ip4,
                                              12)
        rx = self.send_and_expect(self.pg0, tx, self.pg0)
        self.verify_tunneled_vlano4(self.pg0, rx, tx,
                                    self.pg0.local_ip4,
                                    "2.2.2.2",
                                    11)

        #
        # Cleanup Test resources
        #
        gre_if_11.remove_vpp_config()
        gre_if_12.remove_vpp_config()
        gre_if1.remove_vpp_config()
        gre_if2.remove_vpp_config()
        route_tun1_dst.add_vpp_config()
        route_tun2_dst.add_vpp_config()

    def test_gre_loop(self):
        """ GRE tunnel loop Tests """

        #
        # Create an L3 GRE tunnel.
        #  - set it admin up
        #  - assign an IP Addres
        #
        gre_if = VppGreInterface(self,
                                 self.pg0.local_ip4,
                                 "1.1.1.2")
        gre_if.add_vpp_config()
        gre_if.admin_up()
        gre_if.config_ip4()

        #
        # add a route to the tunnel's destination that points
        # through the tunnel, hence forming a loop in the forwarding
        # graph
        #
        route_dst = VppIpRoute(self, "1.1.1.2", 32,
                               [VppRoutePath("0.0.0.0",
                                             gre_if.sw_if_index)])
        route_dst.add_vpp_config()

        #
        # packets to the tunnels destination should be dropped
        #
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "1.1.1.2")
        self.send_and_assert_no_replies(self.pg2, tx)

        self.logger.info(self.vapi.ppcli("sh adj 7"))

        #
        # break the loop
        #
        route_dst.modify([VppRoutePath(self.pg1.remote_ip4,
                                       self.pg1.sw_if_index)])
        route_dst.add_vpp_config()

        rx = self.send_and_expect(self.pg0, tx, self.pg1)

        #
        # a good route throught the tunnel to check it restacked
        #
        route_via_tun_2 = VppIpRoute(self, "2.2.2.2", 32,
                                     [VppRoutePath("0.0.0.0",
                                                   gre_if.sw_if_index)])
        route_via_tun_2.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "2.2.2.3", "2.2.2.2")
        rx = self.send_and_expect(self.pg0, tx, self.pg1)
        self.verify_tunneled_4o4(self.pg1, rx, tx,
                                 self.pg0.local_ip4, "1.1.1.2")

        #
        # cleanup
        #
        route_via_tun_2.remove_vpp_config()
        gre_if.remove_vpp_config()

    def test_mgre(self):
        """ mGRE IPv4 tunnel Tests """

        for itf in self.pg_interfaces[3:]:
            #
            # one underlay nh for each overlay/tunnel peer
            #
            itf.generate_remote_hosts(4)
            itf.configure_ipv4_neighbors()

            #
            # Create an L3 GRE tunnel.
            #  - set it admin up
            #  - assign an IP Addres
            #  - Add a route via the tunnel
            #
            gre_if = VppGreInterface(self,
                                     itf.local_ip4,
                                     "0.0.0.0",
                                     mode=(VppEnum.vl_api_tunnel_mode_t.
                                           TUNNEL_API_MODE_MP))
            gre_if.add_vpp_config()
            gre_if.admin_up()
            gre_if.config_ip4()
            gre_if.generate_remote_hosts(4)

            self.logger.info(self.vapi.cli("sh adj"))
            self.logger.info(self.vapi.cli("sh ip fib"))

            #
            # ensure we don't match to the tunnel if the source address
            # is all zeros
            #
            tx = self.create_tunnel_stream_4o4(self.pg0,
                                               "0.0.0.0",
                                               itf.local_ip4,
                                               self.pg0.local_ip4,
                                               self.pg0.remote_ip4)
            self.send_and_assert_no_replies(self.pg0, tx)

            #
            # for-each peer
            #
            for ii in range(1, 4):
                route_addr = "4.4.4.%d" % ii
                tx_e = self.create_stream_ip4(self.pg0, "5.5.5.5", route_addr)

                #
                # route traffic via the peer
                #
                route_via_tun = VppIpRoute(
                    self, route_addr, 32,
                    [VppRoutePath(gre_if._remote_hosts[ii].ip4,
                                  gre_if.sw_if_index)])
                route_via_tun.add_vpp_config()

                # all packets dropped at this point
                self.logger.error(self.vapi.cli("sh adj 19"))
                rx = self.send_and_assert_no_replies(self.pg0, tx_e)

                gre_if.admin_down()
                gre_if.admin_up()
                self.logger.error(self.vapi.cli("sh adj 19"))
                rx = self.send_and_assert_no_replies(self.pg0, tx_e)

                #
                # Add a TEIB entry resolves the peer
                #
                teib = VppTeib(self, gre_if,
                               gre_if._remote_hosts[ii].ip4,
                               itf._remote_hosts[ii].ip4)
                teib.add_vpp_config()

                #
                # Send a packet stream that is routed into the tunnel
                #  - packets are GRE encapped
                #
                try:
                    rx = self.send_and_expect(self.pg0, tx_e, itf)
                finally:
                    self.logger.error(self.vapi.cli("sh adj 19"))
                self.verify_tunneled_4o4(self.pg0, rx, tx_e,
                                         itf.local_ip4,
                                         itf._remote_hosts[ii].ip4)

                tx_i = self.create_tunnel_stream_4o4(self.pg0,
                                                     itf._remote_hosts[ii].ip4,
                                                     itf.local_ip4,
                                                     self.pg0.local_ip4,
                                                     self.pg0.remote_ip4)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)
                self.verify_decapped_4o4(self.pg0, rx, tx_i)

                #
                # delete and re-add the TEIB
                #
                teib.remove_vpp_config()
                self.send_and_assert_no_replies(self.pg0, tx_e)
                self.send_and_assert_no_replies(self.pg0, tx_i)

                teib.add_vpp_config()
                rx = self.send_and_expect(self.pg0, tx_e, itf)
                self.verify_tunneled_4o4(self.pg0, rx, tx_e,
                                         itf.local_ip4,
                                         itf._remote_hosts[ii].ip4)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)
                self.verify_decapped_4o4(self.pg0, rx, tx_i)

                #
                # bounce the interface state and try packets again
                #
                gre_if.admin_down()
                gre_if.admin_up()
                rx = self.send_and_expect(self.pg0, tx_e, itf)
                self.verify_tunneled_4o4(self.pg0, rx, tx_e,
                                         itf.local_ip4,
                                         itf._remote_hosts[ii].ip4)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)
                self.verify_decapped_4o4(self.pg0, rx, tx_i)

            gre_if.admin_down()
            gre_if.unconfig_ip4()

    def test_mgre6(self):
        """ mGRE IPv6 tunnel Tests """

        self.pg0.config_ip6()
        self.pg0.resolve_ndp()

        e = VppEnum.vl_api_tunnel_encap_decap_flags_t

        for itf in self.pg_interfaces[3:]:
            #
            # one underlay nh for each overlay/tunnel peer
            #
            itf.config_ip6()
            itf.generate_remote_hosts(4)
            itf.configure_ipv6_neighbors()

            #
            # Create an L3 GRE tunnel.
            #  - set it admin up
            #  - assign an IP Addres
            #  - Add a route via the tunnel
            #
            gre_if = VppGreInterface(
                self,
                itf.local_ip6,
                "::",
                mode=(VppEnum.vl_api_tunnel_mode_t.
                      TUNNEL_API_MODE_MP),
                flags=e.TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)

            gre_if.add_vpp_config()
            gre_if.admin_up()
            gre_if.config_ip6()
            gre_if.generate_remote_hosts(4)

            #
            # for-each peer
            #
            for ii in range(1, 4):
                route_addr = "4::%d" % ii

                #
                # Add a TEIB entry resolves the peer
                #
                teib = VppTeib(self, gre_if,
                               gre_if._remote_hosts[ii].ip6,
                               itf._remote_hosts[ii].ip6)
                teib.add_vpp_config()

                #
                # route traffic via the peer
                #
                route_via_tun = VppIpRoute(
                    self, route_addr, 128,
                    [VppRoutePath(gre_if._remote_hosts[ii].ip6,
                                  gre_if.sw_if_index)])
                route_via_tun.add_vpp_config()

                #
                # Send a packet stream that is routed into the tunnel
                #  - packets are GRE encapped
                #
                tx_e = self.create_stream_ip6(self.pg0, "5::5", route_addr,
                                              dscp=2, ecn=1)
                rx = self.send_and_expect(self.pg0, tx_e, itf)
                self.verify_tunneled_6o6(self.pg0, rx, tx_e,
                                         itf.local_ip6,
                                         itf._remote_hosts[ii].ip6,
                                         dscp=2)
                tx_i = self.create_tunnel_stream_6o6(self.pg0,
                                                     itf._remote_hosts[ii].ip6,
                                                     itf.local_ip6,
                                                     self.pg0.local_ip6,
                                                     self.pg0.remote_ip6)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)
                self.verify_decapped_6o6(self.pg0, rx, tx_i)

                #
                # delete and re-add the TEIB
                #
                teib.remove_vpp_config()
                self.send_and_assert_no_replies(self.pg0, tx_e)

                teib.add_vpp_config()
                rx = self.send_and_expect(self.pg0, tx_e, itf)
                self.verify_tunneled_6o6(self.pg0, rx, tx_e,
                                         itf.local_ip6,
                                         itf._remote_hosts[ii].ip6,
                                         dscp=2)
                rx = self.send_and_expect(self.pg0, tx_i, self.pg0)
                self.verify_decapped_6o6(self.pg0, rx, tx_i)

            gre_if.admin_down()
            gre_if.unconfig_ip4()
            itf.unconfig_ip6()
        self.pg0.unconfig_ip6()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
