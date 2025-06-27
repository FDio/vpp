#!/usr/bin/env python3
"""GSO functional tests"""

#
# Add tests for:
# - GSO
# - Verify that sending Jumbo frame without GSO enabled correctly
# - Verify that sending Jumbo frame with GSO enabled correctly
# - Verify that sending Jumbo frame with GSO enabled only on ingress interface
#
import unittest

from scapy.packet import Raw
from scapy.layers.l2 import GRE
from scapy.layers.inet6 import IPv6, Ether, IP, ICMPv6PacketTooBig
from scapy.layers.inet6 import ipv6nh, IPerror6
from scapy.layers.inet import TCP, ICMP, UDP, defragment
from scapy.layers.vxlan import VXLAN
from scapy.layers.ipsec import ESP

from vpp_papi import VppEnum
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_vxlan_tunnel import VppVxlanTunnel
from vpp_gre_interface import VppGreInterface
from config import config

from vpp_ipsec import VppIpsecSA, VppIpsecTunProtect
from template_ipsec import (
    IPsecIPv4Params,
    IPsecIPv6Params,
    config_tun_params,
)

""" Test_gso is a subclass of VPPTestCase classes.
    GSO tests.
"""


class TestGSO(VppTestCase):
    """GSO Test Case"""

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(self):
        super(TestGSO, self).setUpClass()
        res = self.create_pg_interfaces(range(2))
        res_gso1 = self.create_pg_interfaces(range(2, 3), 1, 1460)
        res_gso2 = self.create_pg_interfaces(range(3, 4), 1, 1440)
        self.pg_interfaces = self.create_pg_interfaces(range(4, 5), 1, 8940)
        self.pg_interfaces.append(res[0])
        self.pg_interfaces.append(res[1])
        self.pg_interfaces.append(res_gso1[0])
        self.pg_interfaces.append(res_gso2[0])
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1500, 0, 0, 0])
        self.vapi.sw_interface_set_mtu(self.pg2.sw_if_index, [1500, 0, 0, 0])
        self.vapi.sw_interface_set_mtu(self.pg3.sw_if_index, [1500, 0, 0, 0])

    @classmethod
    def tearDownClass(self):
        super(TestGSO, self).tearDownClass()

    def setUp(self):
        super(TestGSO, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        self.single_tunnel_bd = 10
        self.vxlan = VppVxlanTunnel(
            self,
            src=self.pg0.local_ip4,
            dst=self.pg0.remote_ip4,
            vni=self.single_tunnel_bd,
        )

        self.vxlan2 = VppVxlanTunnel(
            self,
            src=self.pg0.local_ip6,
            dst=self.pg0.remote_ip6,
            vni=self.single_tunnel_bd,
        )

        self.single_tunnel_bd2 = 20
        self.vxlan3 = VppVxlanTunnel(
            self,
            src=self.pg1.local_ip4,
            dst=self.pg1.remote_ip4,
            vni=self.single_tunnel_bd2,
        )
        self.vxlan4 = VppVxlanTunnel(
            self,
            src=self.pg1.local_ip6,
            dst=self.pg1.remote_ip6,
            vni=self.single_tunnel_bd2,
        )

        self.ipip4_0 = VppIpIpTunInterface(
            self, self.pg0, self.pg0.local_ip4, self.pg0.remote_ip4
        )
        self.ipip6_0 = VppIpIpTunInterface(
            self, self.pg0, self.pg0.local_ip6, self.pg0.remote_ip6
        )

        self.ipip4_1 = VppIpIpTunInterface(
            self, self.pg1, self.pg1.local_ip4, self.pg1.remote_ip4
        )
        self.ipip6_1 = VppIpIpTunInterface(
            self, self.pg1, self.pg1.local_ip6, self.pg1.remote_ip6
        )

        self.gre4 = VppGreInterface(self, self.pg0.local_ip4, self.pg0.remote_ip4)
        self.gre6 = VppGreInterface(self, self.pg0.local_ip6, self.pg0.remote_ip6)

    def tearDown(self):
        super(TestGSO, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def get_mtu(self, sw_if_index):
        rv = self.vapi.sw_interface_dump(sw_if_index=sw_if_index)
        for i in rv:
            if i.sw_if_index == sw_if_index:
                return i.mtu[0]
        return 0

    def test_gso(self):
        """GSO test"""
        #
        # Send jumbo frame with gso disabled and DF bit is set
        #
        p4 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg0, [p4], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[ICMP].type, 3)  # "dest-unreach"
            self.assertEqual(rx[ICMP].code, 4)  # "fragmentation-needed"

        #
        # Send checksum offload frames
        #
        p40 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4, flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 1460)
        )

        rxs = self.send_and_expect(self.pg2, 100 * [p40], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            payload_len = rx[IP].len - 20 - 20
            self.assert_ip_checksum_valid(rx)
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(payload_len, len(rx[Raw]))

        p60 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 1440)
        )

        rxs = self.send_and_expect(self.pg2, 100 * [p60], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            payload_len = rx[IPv6].plen - 20
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(payload_len, len(rx[Raw]))

        #
        # Send jumbo frame with gso enabled and DF bit is set
        # input and output interfaces support GSO
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg3.sw_if_index, enable_disable=1
        )
        p41 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4, flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 100 * [p41], self.pg3, 100)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(rx[IP].len, 65240)  # 65200 + 20 (IP) + 20 (TCP)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        #
        # ipv6
        #
        p61 = (
            Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac)
            / IPv6(src=self.pg3.remote_ip6, dst=self.pg2.remote_ip6)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg3, 100 * [p61], self.pg2, 100)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg3.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].plen, 65220)  # 65200 + 20 (TCP)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is set. GSO packet will be chunked into gso_size
        # data payload
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=1
        )
        p42 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4, flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p42], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            payload_len = rx[IP].len - 20 - 20  # len - 20 (IP4) - 20 (TCP)
            self.assert_ip_checksum_valid(rx)
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)
            self.assertEqual(payload_len, len(rx[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # ipv6
        #
        p62 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p62], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            payload_len = rx[IPv6].plen - 20
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)
            self.assertEqual(payload_len, len(rx[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is unset. GSO packet will be fragmented.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [576, 0, 0, 0])
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=1
        )

        p43 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst=self.pg1.remote_ip4)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p43], self.pg1, 5 * 119)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertTrue((rx[IP].flags == "MF") or (rx[IP].frag != 0))
            self.assert_ip_checksum_valid(rx)
            size += rx[IP].len - 20
        size -= 20 * 5  # TCP header
        self.assertEqual(size, 65200 * 5)

        #
        # IPv6
        # Send jumbo frame with gso enabled only on input interface.
        # ICMPv6 Packet Too Big will be sent back to sender.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        p63 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst=self.pg1.remote_ip6)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect_some(self.pg2, 5 * [p63], self.pg2, 5)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg2.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].plen, 1240)  # MTU - IPv6 header
            self.assertEqual(ipv6nh[rx[IPv6].nh], "ICMPv6")
            self.assertEqual(rx[ICMPv6PacketTooBig].mtu, 1280)
            self.assertEqual(rx[IPerror6].src, self.pg2.remote_ip6)
            self.assertEqual(rx[IPerror6].dst, self.pg1.remote_ip6)
            self.assertEqual(rx[IPerror6].plen - 20, 65200)

        #
        # Send jumbo frame with gso enabled only on input interface with 9K MTU.
        # GSO packet will be chunked. MSS is 8960. GSO
        # size will be min(MSS, 2048 - 14 - 20) vlib_buffer_t size
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [9000, 0, 0, 0])
        p44 = (
            Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac)
            / IP(src=self.pg4.remote_ip4, dst=self.pg1.remote_ip4)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg4, 5 * [p44], self.pg1, 165)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg4.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            payload_len = rx[IP].len - 20 - 20  # len - 20 (IP4) - 20 (TCP)
            self.assert_ip_checksum_valid(rx)
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(payload_len, len(rx[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # IPv6
        #
        p64 = (
            Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac)
            / IPv6(src=self.pg4.remote_ip6, dst=self.pg1.remote_ip6)
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg4, 5 * [p64], self.pg1, 170)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg4.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg1.remote_ip6)
            payload_len = rx[IPv6].plen - 20
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(payload_len, len(rx[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # Send jumbo frame with gso enabled only on input interface with 9K MTU.
        # DF bit is unset. GSO packet will be fragmented.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [8000, 0, 0, 0])

        rxs = self.send_and_expect(self.pg4, 5 * [p44], self.pg1, 165)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg4.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertTrue((rx[IP].flags == "MF") or (rx[IP].frag != 0))
            size += rx[IP].len - 20  # len - 20 (IP4)
        size -= 20 * 5  # TCP header
        self.assertEqual(size, 65200 * 5)

        rxs = self.send_and_expect_some(self.pg4, 5 * [p64], self.pg4, 5)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg4.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg4.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg4.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg4.remote_ip6)
            self.assertEqual(rx[IPv6].plen, 1240)  # MTU - IPv6 header
            self.assertEqual(ipv6nh[rx[IPv6].nh], "ICMPv6")
            self.assertEqual(rx[ICMPv6PacketTooBig].mtu, 8000)
            self.assertEqual(rx[IPerror6].src, self.pg4.remote_ip6)
            self.assertEqual(rx[IPerror6].dst, self.pg1.remote_ip6)
            self.assertEqual(rx[IPerror6].plen - 20, 65200)

        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1500, 0, 0, 0])
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=0
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=0
        )

    @unittest.skipIf(
        "vxlan" in config.excluded_plugins, "Exclude tests requiring VXLAN plugin"
    )
    def test_gso_vxlan(self):
        """GSO VXLAN test"""
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg2
        # into BD.
        #

        #
        # enable ipv4/vxlan
        #
        self.vxlan.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan.sw_if_index, bd_id=self.single_tunnel_bd
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.single_tunnel_bd
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=1
        )

        #
        # IPv4/IPv4 - VXLAN
        #
        p45 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p45], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=True)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IP].len - 20 - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, self.pg2.local_mac)
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # IPv4/IPv6 - VXLAN
        #
        p65 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p65], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=True)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IP].len - 20 - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, self.pg2.local_mac)
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # disable ipv4/vxlan
        #
        self.vxlan.remove_vpp_config()

        #
        # enable ipv6/vxlan
        #
        self.vxlan2.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan2.sw_if_index, bd_id=self.single_tunnel_bd
        )

        #
        # IPv6/IPv4 - VXLAN
        #
        p46 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p46], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IPv6].plen - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, self.pg2.local_mac)
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # IPv6/IPv6 - VXLAN
        #
        p66 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p66], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IPv6].plen - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, self.pg2.local_mac)
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # disable ipv4/vxlan
        #
        self.vxlan2.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=0
        )

        #
        # IPv4/IPv4 - VXLAN - Fragmented test
        # Send jumbo frame with gso enabled only on input interface and
        # create VXLAN VTEP on VPP pg1, and put vxlan_tunnel and pg2
        # into BD.
        # Packets will be fragmented as
        # gso_size (1460) + headers size (50 vxlan encap + 20 inner IPv4 + 20 TCP)
        # is larger than MTU of the output interface (1500).
        #

        self.vxlan3.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan3.sw_if_index, bd_id=self.single_tunnel_bd2
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.single_tunnel_bd2
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=1
        )

        p67 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.3.3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p67], self.pg1, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg1.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertTrue((rx[IP].flags == "MF") or (rx[IP].frag != 0))
            size += rx[IP].len - 20  # outer IP len
        size -= (
            8 + 8 + 14 + 20 + 20
        ) * 5  # UDP header + VXLAN header + Ethernet header + inner IP header + TCP header
        self.assertEqual(size, 65200 * 5)

        assembled_pkt = defragment(rxs)
        for rx in assembled_pkt:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg1.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(
                rx[IP].len, 65290
            )  # 65200 + 50 (VXLAN encap) + 20 (IP) + 20 (TCP)
            self.assertEqual(
                rx[UDP].len, 65270
            )  # 65200 + 50 (VXLAN encap) - 20 (outer IP) + 20 (IP) + 20 (TCP)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=True)
            self.assertEqual(rx[VXLAN].vni, 20)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, self.pg2.local_mac)
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            self.assertEqual(inner[IP].len - 20 - 20, 65200)

        self.vxlan3.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=0
        )

    def test_gso_ipip(self):
        """GSO IPIP test"""
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0.
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=1
        )

        #
        # enable ipip4
        #
        self.ipip4_0.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip4_0.admin_up()
        self.ipip4_0.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip4_tunnel = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.ipip4_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_ip4_tunnel.add_vpp_config()

        #
        # IPv4/IPv4 - IPIP
        #
        p47 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p47], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 4)  # ipencap
            inner = rx[IP].payload
            self.assertEqual(rx[IP].len - 20, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        self.ip6_via_ip4_tunnel = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.ipip4_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_ip4_tunnel.add_vpp_config()
        #
        # IPv4/IPv6 - IPIP
        #
        p67 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p67], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 41)  # ipv6
            inner = rx[IP].payload
            self.assertEqual(rx[IP].len - 20, len(inner))
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0. Enable gso feature node on ipip
        # tunnel - IPSec use case
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=0
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ipip4_0.sw_if_index, enable_disable=1
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p47], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 4)  # ipencap
            inner = rx[IP].payload
            self.assertEqual(rx[IP].len - 20, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # disable ipip4
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ipip4_0.sw_if_index, enable_disable=0
        )
        self.ip4_via_ip4_tunnel.remove_vpp_config()
        self.ip6_via_ip4_tunnel.remove_vpp_config()
        self.ipip4_0.remove_vpp_config()

        #
        # enable ipip6
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=1
        )
        self.ipip6_0.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip6_0.admin_up()
        self.ipip6_0.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip6_tunnel = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.ipip6_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_ip6_tunnel.add_vpp_config()

        #
        # IPv6/IPv4 - IPIP
        #
        p48 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p48], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "IP")
            inner = rx[IPv6].payload
            self.assertEqual(rx[IPv6].plen, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        self.ip6_via_ip6_tunnel = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.ipip6_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_ip6_tunnel.add_vpp_config()

        #
        # IPv6/IPv6 - IPIP
        #
        p68 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p68], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "IPv6")
            inner = rx[IPv6].payload
            self.assertEqual(rx[IPv6].plen, len(inner))
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        #
        # disable ipip6
        #
        self.ip4_via_ip6_tunnel.remove_vpp_config()
        self.ip6_via_ip6_tunnel.remove_vpp_config()
        self.ipip6_0.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=0
        )

        #
        # IPIP - Fragmented test
        # enable ipip4
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=1
        )
        self.ipip4_1.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip4_1.admin_up()
        self.ipip4_1.set_unnumbered(self.pg1.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip4_tunnel_1 = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.ipip4_1.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_ip4_tunnel_1.add_vpp_config()

        p47_1 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, 5 * [p47_1], self.pg1, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg1.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertTrue((rx[IP].flags == "MF") or (rx[IP].frag != 0))
            size += rx[IP].len - 20  # outer IP len
        size -= (20 + 20) * 5  # inner IP header + TCP header
        self.assertEqual(size, 65200 * 5)

        assembled_pkt = defragment(rxs)
        for rx in assembled_pkt:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg1.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(
                rx[IP].len, 65260
            )  # 65200 + 20 (outer IP) + 20 (inner IP) + 20 (TCP)
            self.assert_ip_checksum_valid(rx)
            inner = rx[IP].payload
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            self.assertEqual(inner[IP].len - 20 - 20, 65200)

        self.ip4_via_ip4_tunnel_1.remove_vpp_config()
        self.ipip4_1.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=0
        )

        #
        # enable ipip6
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=1
        )
        self.ipip6_1.add_vpp_config()
        # Set interface up and enable IP on it
        self.ipip6_1.admin_up()
        self.ipip6_1.set_unnumbered(self.pg1.sw_if_index)
        # Add IPv6 routes via tunnel interface
        self.ip6_via_ip6_tunnel_1 = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.ipip6_1.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_ip6_tunnel_1.add_vpp_config()

        p68_1 = (
            Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac)
            / IPv6(src=self.pg3.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg3, 5 * [p68_1], self.pg1, 230)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg1.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg1.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "Fragment Header")
            size += rx[IPv6].plen - 8  # remove fragment header size
        size -= (40 + 20) * 5  # inner IPv6 header + TCP header
        self.assertEqual(size, 65200 * 5)

        self.ip6_via_ip6_tunnel_1.remove_vpp_config()
        self.ipip6_1.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.pg1.sw_if_index, enable_disable=0
        )

    def test_gso_gre(self):
        """GSO GRE test"""
        #
        # Send jumbo frame with gso enabled only on gre tunnel interface.
        # create GRE tunnel on VPP pg0.
        #

        #
        # create gre 4 tunnel
        #
        self.gre4.add_vpp_config()
        self.gre4.admin_up()
        self.gre4.config_ip4()

        #
        # Add a route that resolves the tunnel's destination
        #
        # Add IPv4 routes via tunnel interface
        self.ip4_via_gre4_tunnel = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.gre4.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_gre4_tunnel.add_vpp_config()

        pgre4 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        # test when GSO segmentation is disabled, Packets are truncated
        rxs = self.send_and_expect(self.pg2, 5 * [pgre4], self.pg0, 5)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 0x2F)  # GRE encap
            self.assertEqual(rx[GRE].proto, 0x0800)  # IPv4
            inner = rx[GRE].payload
            self.assertNotEqual(rx[IP].len - 20 - 4, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, 65200)
            # truncated packet to MTU size
            self.assertNotEqual(payload_len, len(inner[Raw]))

        # enable the GSO segmentation on GRE tunnel
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.gre4.sw_if_index, enable_disable=1
        )

        # test again, this time payload will be chuncked to GSO size (i.e. 1448)
        rxs = self.send_and_expect(self.pg2, 5 * [pgre4], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 0x2F)  # GRE encap
            self.assertEqual(rx[GRE].proto, 0x0800)  # IPv4
            inner = rx[GRE].payload
            self.assertEqual(rx[IP].len - 20 - 4, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        # Disable the GSO segmentation on GRE tunnel
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.gre4.sw_if_index, enable_disable=0
        )

        # test again when GSO segmentation is disabled, Packets are truncated
        rxs = self.send_and_expect(self.pg2, 5 * [pgre4], self.pg0, 5)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assertEqual(rx[IP].proto, 0x2F)  # GRE encap
            self.assertEqual(rx[GRE].proto, 0x0800)  # IPv4
            inner = rx[GRE].payload
            self.assertNotEqual(rx[IP].len - 20 - 4, len(inner))
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            self.assert_ip_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, 65200)
            # truncated packet to MTU size
            self.assertNotEqual(payload_len, len(inner[Raw]))

        self.ip4_via_gre4_tunnel.remove_vpp_config()
        self.gre4.remove_vpp_config()

        self.gre6.add_vpp_config()
        self.gre6.admin_up()
        self.gre6.config_ip4()

        #
        # Add a route that resolves the tunnel's destination
        # Add IPv6 routes via tunnel interface
        #
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.gre6.sw_if_index, enable_disable=1
        )
        self.ip6_via_gre6_tunnel = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.gre6.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_gre6_tunnel.add_vpp_config()

        #
        # Create IPv6 packet
        #
        pgre6 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        # test when GSO segmentation is enabled, payload will be segmented
        # into GSO size (i.e. 1448)
        rxs = self.send_and_expect(self.pg2, 5 * [pgre6], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "GRE")
            self.assertEqual(rx[GRE].proto, 0x86DD)  # IPv6
            inner = rx[GRE].payload
            self.assertEqual(rx[IPv6].plen - 4, len(inner))
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200 * 5)

        # disable GSO segmentation
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.gre6.sw_if_index, enable_disable=0
        )

        # test again, this time packets will be truncated
        rxs = self.send_and_expect(self.pg2, 5 * [pgre6], self.pg0, 5)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "GRE")
            self.assertEqual(rx[GRE].proto, 0x86DD)  # IPv6
            inner = rx[GRE].payload
            self.assertNotEqual(rx[IPv6].plen - 4, len(inner))
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, 65200)
            # packets are truncated to MTU size
            self.assertNotEqual(payload_len, len(inner[Raw]))

        self.ip6_via_gre6_tunnel.remove_vpp_config()
        self.gre6.remove_vpp_config()

    def test_gso_ipsec(self):
        """GSO IPSEC test"""
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0.
        #

        #
        # enable ipip4
        #
        self.ipip4_0.add_vpp_config()
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ipip4_0.sw_if_index, enable_disable=1
        )

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip4_tunnel = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.ipip4_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_ip4_tunnel.add_vpp_config()

        # IPSec config
        self.ipv4_params = IPsecIPv4Params()
        self.encryption_type = ESP
        config_tun_params(self.ipv4_params, self.encryption_type, self.ipip4_0)

        self.tun_sa_in_v4 = VppIpsecSA(
            self,
            self.ipv4_params.scapy_tun_sa_id,
            self.ipv4_params.scapy_tun_spi,
            self.ipv4_params.auth_algo_vpp_id,
            self.ipv4_params.auth_key,
            self.ipv4_params.crypt_algo_vpp_id,
            self.ipv4_params.crypt_key,
            VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
        )
        self.tun_sa_in_v4.add_vpp_config()

        self.tun_sa_out_v4 = VppIpsecSA(
            self,
            self.ipv4_params.vpp_tun_sa_id,
            self.ipv4_params.vpp_tun_spi,
            self.ipv4_params.auth_algo_vpp_id,
            self.ipv4_params.auth_key,
            self.ipv4_params.crypt_algo_vpp_id,
            self.ipv4_params.crypt_key,
            VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
        )
        self.tun_sa_out_v4.add_vpp_config()

        self.tun_protect_v4 = VppIpsecTunProtect(
            self, self.ipip4_0, self.tun_sa_out_v4, [self.tun_sa_in_v4]
        )

        self.tun_protect_v4.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip4_0.admin_up()
        self.ipip4_0.set_unnumbered(self.pg0.sw_if_index)

        #
        # IPv4/IPv4 - IPSEC
        #
        ipsec44 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, [ipsec44], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].proto, 50)  # ESP
            self.assertEqual(rx[ESP].spi, self.ipv4_params.vpp_tun_spi)
            inner = self.ipv4_params.vpp_tun_sa.decrypt(rx[IP])
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        self.ip6_via_ip4_tunnel = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.ipip4_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_ip4_tunnel.add_vpp_config()
        #
        # IPv4/IPv6 - IPSEC
        #
        ipsec46 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, [ipsec46], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].proto, 50)  # ESP
            self.assertEqual(rx[ESP].spi, self.ipv4_params.vpp_tun_spi)
            inner = self.ipv4_params.vpp_tun_sa.decrypt(rx[IP])
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        # disable IPSec
        self.tun_protect_v4.remove_vpp_config()
        self.tun_sa_in_v4.remove_vpp_config()
        self.tun_sa_out_v4.remove_vpp_config()

        #
        # disable ipip4
        #
        self.vapi.feature_gso_enable_disable(self.ipip4_0.sw_if_index, enable_disable=0)
        self.ip4_via_ip4_tunnel.remove_vpp_config()
        self.ip6_via_ip4_tunnel.remove_vpp_config()
        self.ipip4_0.remove_vpp_config()

        #
        # enable ipip6
        #
        self.ipip6_0.add_vpp_config()
        self.vapi.feature_gso_enable_disable(self.ipip6_0.sw_if_index, enable_disable=1)

        # Set interface up and enable IP on it
        self.ipip6_0.admin_up()
        self.ipip6_0.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip6_tunnel = VppIpRoute(
            self,
            "172.16.10.0",
            24,
            [
                VppRoutePath(
                    "0.0.0.0",
                    self.ipip6_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                )
            ],
        )
        self.ip4_via_ip6_tunnel.add_vpp_config()

        # IPSec config
        self.ipv6_params = IPsecIPv6Params()
        self.encryption_type = ESP
        config_tun_params(self.ipv6_params, self.encryption_type, self.ipip6_0)
        self.tun_sa_in_v6 = VppIpsecSA(
            self,
            self.ipv6_params.scapy_tun_sa_id,
            self.ipv6_params.scapy_tun_spi,
            self.ipv6_params.auth_algo_vpp_id,
            self.ipv6_params.auth_key,
            self.ipv6_params.crypt_algo_vpp_id,
            self.ipv6_params.crypt_key,
            VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
        )
        self.tun_sa_in_v6.add_vpp_config()

        self.tun_sa_out_v6 = VppIpsecSA(
            self,
            self.ipv6_params.vpp_tun_sa_id,
            self.ipv6_params.vpp_tun_spi,
            self.ipv6_params.auth_algo_vpp_id,
            self.ipv6_params.auth_key,
            self.ipv6_params.crypt_algo_vpp_id,
            self.ipv6_params.crypt_key,
            VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
        )
        self.tun_sa_out_v6.add_vpp_config()

        self.tun_protect_v6 = VppIpsecTunProtect(
            self, self.ipip6_0, self.tun_sa_out_v6, [self.tun_sa_in_v6]
        )

        self.tun_protect_v6.add_vpp_config()

        #
        # IPv6/IPv4 - IPSEC
        #
        ipsec64 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, [ipsec64], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "ESP Header")
            self.assertEqual(rx[ESP].spi, self.ipv6_params.vpp_tun_spi)
            inner = self.ipv6_params.vpp_tun_sa.decrypt(rx[IPv6])
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        self.ip6_via_ip6_tunnel = VppIpRoute(
            self,
            "fd01:10::",
            64,
            [
                VppRoutePath(
                    "::",
                    self.ipip6_0.sw_if_index,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                )
            ],
        )
        self.ip6_via_ip6_tunnel.add_vpp_config()

        #
        # IPv6/IPv6 - IPSEC
        #
        ipsec66 = (
            Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
            / IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg2, [ipsec66], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "ESP Header")
            self.assertEqual(rx[ESP].spi, self.ipv6_params.vpp_tun_spi)
            inner = self.ipv6_params.vpp_tun_sa.decrypt(rx[IPv6])
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        # disable IPSec
        self.tun_protect_v6.remove_vpp_config()
        self.tun_sa_in_v6.remove_vpp_config()
        self.tun_sa_out_v6.remove_vpp_config()

        #
        # disable ipip6
        #
        self.ip4_via_ip6_tunnel.remove_vpp_config()
        self.ip6_via_ip6_tunnel.remove_vpp_config()
        self.ipip6_0.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index, enable_disable=0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
