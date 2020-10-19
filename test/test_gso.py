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
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet6 import ipv6nh, IPerror6
from scapy.layers.inet import TCP, ICMP
from scapy.layers.vxlan import VXLAN
from scapy.data import ETH_P_IP, ETH_P_IPV6, ETH_P_ARP

from framework import VppTestCase, VppTestRunner
from vpp_pom.vpp_object import VppObject
from vpp_pom.vpp_interface import VppInterface
from vpp_pom.vpp_ip import DpoProto
from vpp_pom.vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from vpp_pom.vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_pom.vpp_vxlan_tunnel import VppVxlanTunnel
from socket import AF_INET, AF_INET6, inet_pton
from vpp_pom.util import reassemble4


""" Test_gso is a subclass of VPPTestCase classes.
    GSO tests.
"""


class TestGSO(VppTestCase):
    """ GSO Test Case """

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(self):
        super(TestGSO, self).setUpClass()
        res = self.create_pg_interfaces(range(2))
        res_gso = self.create_pg_interfaces(range(2, 4), 1, 1460)
        self.create_pg_interfaces(range(4, 5), 1, 8940)
        self.pg_interfaces.append(res[0])
        self.pg_interfaces.append(res[1])
        self.pg_interfaces.append(res_gso[0])
        self.pg_interfaces.append(res_gso[1])

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
        self.vxlan = VppVxlanTunnel(self.vclient, src=self.pg0.local_ip4,
                                    dst=self.pg0.remote_ip4,
                                    vni=self.single_tunnel_bd)

        self.vxlan2 = VppVxlanTunnel(self.vclient, src=self.pg0.local_ip6,
                                     dst=self.pg0.remote_ip6,
                                     vni=self.single_tunnel_bd)

        self.ipip4 = VppIpIpTunInterface(self.vclient, self.pg0, self.pg0.local_ip4,
                                         self.pg0.remote_ip4)
        self.ipip6 = VppIpIpTunInterface(self.vclient, self.pg0, self.pg0.local_ip6,
                                         self.pg0.remote_ip6)

    def tearDown(self):
        super(TestGSO, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def test_gso(self):
        """ GSO test """
        #
        # Send jumbo frame with gso disabled and DF bit is set
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4,
                 flags='DF') /
              TCP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 65200))

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
        p40 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 1460))

        rxs = self.send_and_expect(self.pg2, 100*[p40], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            payload_len = rx[IP].len - 20 - 20
            self.assert_ip_checksum_valid(rx)
            self.assert_tcp_checksum_valid(rx)
            self.assertEqual(payload_len, len(rx[Raw]))

        p60 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 1440))

        rxs = self.send_and_expect(self.pg2, 100*[p60], self.pg0)

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
        self.vclient.feature_gso_enable_disable(self.pg3.sw_if_index)
        p41 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 100*[p41], self.pg3, 100)

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
        p61 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg3.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 100*[p61], self.pg3, 100)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg3.remote_ip6)
            self.assertEqual(rx[IPv6].plen, 65220)  # 65200 + 20 (TCP)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is set. GSO packet will be chunked into gso_size
        # data payload
        #
        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index)
        p42 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p42], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        #
        # ipv6
        #
        p62 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p62], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is unset. GSO packet will be fragmented.
        #
        self.vclient.sw_interface_set_mtu(self.pg1.sw_if_index, [576, 0, 0, 0])
        self.vclient.feature_gso_enable_disable(self.pg1.sw_if_index)

        p43 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p43], self.pg1, 5*119)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            size += rx[IP].len - 20
        size -= 20*5  # TCP header
        self.assertEqual(size, 65200*5)

        #
        # IPv6
        # Send jumbo frame with gso enabled only on input interface.
        # ICMPv6 Packet Too Big will be sent back to sender.
        #
        self.vclient.sw_interface_set_mtu(
            self.pg1.sw_if_index, [1280, 0, 0, 0])
        p63 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg1.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p63], self.pg2, 5)
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
        # Send jumbo frame with gso enabled only on input interface with 9K MTU
        # and DF bit is unset. GSO packet will be fragmented. MSS is 8960. GSO
        # size will be min(MSS, 2048 - 14 - 20) vlib_buffer_t size
        #
        self.vclient.sw_interface_set_mtu(
            self.pg1.sw_if_index, [9000, 0, 0, 0])
        self.vclient.sw_interface_set_mtu(
            self.pg4.sw_if_index, [9000, 0, 0, 0])
        p44 = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
               IP(src=self.pg4.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg4, 5*[p44], self.pg1, 165)
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
        self.assertEqual(size, 65200*5)

        #
        # IPv6
        #
        p64 = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
               IPv6(src=self.pg4.remote_ip6, dst=self.pg1.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg4, 5*[p64], self.pg1, 170)
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
        self.assertEqual(size, 65200*5)

        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index,
                                                enable_disable=0)
        self.vclient.feature_gso_enable_disable(self.pg1.sw_if_index,
                                                enable_disable=0)

    def test_gso_vxlan(self):
        """ GSO VXLAN test """
        self.logger.info(self.vclient.cli("sh int addr"))
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg2
        # into BD.
        #

        #
        # enable ipv4/vxlan
        #
        self.vxlan.add_vpp_config()
        self.vclient.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan.sw_if_index, bd_id=self.single_tunnel_bd)
        self.vclient.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.single_tunnel_bd)
        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index)

        #
        # IPv4/IPv4 - VXLAN
        #
        p45 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p45], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IP].len - 20 - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200*5)

        #
        # IPv4/IPv6 - VXLAN
        #
        p65 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p65], self.pg0, 225)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(rx[IP].len - 20 - 8 - 8, len(inner))
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200*5)

        #
        # disable ipv4/vxlan
        #
        self.vxlan.remove_vpp_config()

        #
        # enable ipv6/vxlan
        #
        self.vxlan2.add_vpp_config()
        self.vclient.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan2.sw_if_index,
            bd_id=self.single_tunnel_bd)

        #
        # IPv6/IPv4 - VXLAN
        #
        p46 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p46], self.pg0, 225)
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
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            self.assert_ip_checksum_valid(inner)
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IP].len - 20 - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200*5)

        #
        # IPv6/IPv6 - VXLAN
        #
        p66 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p66], self.pg0, 225)
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
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            self.assert_tcp_checksum_valid(inner)
            payload_len = inner[IPv6].plen - 20
            self.assertEqual(payload_len, len(inner[Raw]))
            size += payload_len
        self.assertEqual(size, 65200*5)

        #
        # disable ipv4/vxlan
        #
        self.vxlan2.remove_vpp_config()

        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index,
                                                enable_disable=0)

    def test_gso_ipip(self):
        """ GSO IPIP test """
        self.logger.info(self.vclient.cli("sh int addr"))
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0.
        #
        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index)

        #
        # enable ipip4
        #
        self.ipip4.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip4.admin_up()
        self.ipip4.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip4_tunnel = VppIpRoute(
            self.vclient, "172.16.10.0", 24,
            [VppRoutePath("0.0.0.0",
                          self.ipip4.sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
        self.ip4_via_ip4_tunnel.add_vpp_config()

        #
        # IPv4/IPv4 - IPIP
        #
        p47 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p47], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        self.ip6_via_ip4_tunnel = VppIpRoute(
            self.vclient, "fd01:10::", 64,
            [VppRoutePath("::",
                          self.ipip4.sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP6)])
        self.ip6_via_ip4_tunnel.add_vpp_config()
        #
        # IPv4/IPv6 - IPIP
        #
        p67 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p67], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0. Enable gso feature node on ipip
        # tunnel - IPSec use case
        #
        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index,
                                                enable_disable=0)
        self.vclient.feature_gso_enable_disable(self.ipip4.sw_if_index)

        rxs = self.send_and_expect(self.pg2, 5*[p47], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        #
        # disable ipip4
        #
        self.vclient.feature_gso_enable_disable(self.ipip4.sw_if_index,
                                                enable_disable=0)
        self.ip4_via_ip4_tunnel.remove_vpp_config()
        self.ip6_via_ip4_tunnel.remove_vpp_config()
        self.ipip4.remove_vpp_config()

        #
        # enable ipip6
        #
        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index)
        self.ipip6.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip6.admin_up()
        self.ipip6.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip6_tunnel = VppIpRoute(
            self.vclient, "172.16.10.0", 24,
            [VppRoutePath("0.0.0.0",
                          self.ipip6.sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
        self.ip4_via_ip6_tunnel.add_vpp_config()

        #
        # IPv6/IPv4 - IPIP
        #
        p48 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.10.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p48], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        self.ip6_via_ip6_tunnel = VppIpRoute(
            self.vclient, "fd01:10::", 64,
            [VppRoutePath("::",
                          self.ipip6.sw_if_index,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP6)])
        self.ip6_via_ip6_tunnel.add_vpp_config()

        #
        # IPv6/IPv6 - IPIP
        #
        p68 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:10::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, 5*[p68], self.pg0, 225)
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
        self.assertEqual(size, 65200*5)

        #
        # disable ipip6
        #
        self.ip4_via_ip6_tunnel.remove_vpp_config()
        self.ip6_via_ip6_tunnel.remove_vpp_config()
        self.ipip6.remove_vpp_config()

        self.vclient.feature_gso_enable_disable(self.pg0.sw_if_index,
                                                enable_disable=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
