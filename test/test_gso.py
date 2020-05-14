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
import copy

from scapy.packet import Raw
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet6 import ipv6nh, IPerror6
from scapy.layers.inet import TCP, ICMP
from scapy.layers.vxlan import VXLAN
from scapy.data import ETH_P_IP, ETH_P_IPV6, ETH_P_ARP
from scapy.layers.ipsec import SecurityAssociation, ESP

from vpp_papi import VppEnum
from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_interface import VppInterface
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_vxlan_tunnel import VppVxlanTunnel
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry,\
        VppIpsecSpdItfBinding
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTun6Tests, \
    IpsecTun4, IpsecTun6, IpsecTcpTests, mk_scapy_crypt_key, \
    IpsecTun6HandoffTests, IpsecTun4HandoffTests, config_tun_params
from test_ipsec_tun_if_esp import TemplateIpsec4TunProtect, TestIpsec4TunProtect

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
        self.vxlan = VppVxlanTunnel(self, src=self.pg0.local_ip4,
                                    dst=self.pg0.remote_ip4,
                                    vni=self.single_tunnel_bd)

        self.vxlan2 = VppVxlanTunnel(self, src=self.pg0.local_ip6,
                                     dst=self.pg0.remote_ip6,
                                     vni=self.single_tunnel_bd)

        self.ipip4 = VppIpIpTunInterface(self, self.pg0, self.pg0.local_ip4,
                                         self.pg0.remote_ip4)
        self.ipip6 = VppIpIpTunInterface(self, self.pg0, self.pg0.local_ip6,
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
        # Send jumbo frame with gso enabled and DF bit is set
        # input and output interfaces support GSO
        #
        p41 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p41], self.pg3)

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

        rxs = self.send_and_expect(self.pg2, [p61], self.pg3)

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
        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index)
        p42 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p42], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        size = rxs[44][TCP].seq + rxs[44][IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # ipv6
        #
        p62 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p62], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        size = rxs[44][TCP].seq + rxs[44][IPv6].plen - 20
        self.assertEqual(size, 65200)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is unset. GSO packet will be fragmented.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [576, 0, 0, 0])
        self.vapi.feature_gso_enable_disable(self.pg1.sw_if_index)

        p43 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p43], self.pg1, 119)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            size += rx[IP].len - 20
        size -= 20  # TCP header
        self.assertEqual(size, 65200)

        #
        # IPv6
        # Send jumbo frame with gso enabled only on input interface.
        # ICMPv6 Packet Too Big will be sent back to sender.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        p63 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IPv6(src=self.pg2.remote_ip6, dst=self.pg1.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p63], self.pg2, 1)
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
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [9000, 0, 0, 0])
        self.vapi.sw_interface_set_mtu(self.pg4.sw_if_index, [9000, 0, 0, 0])
        p44 = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
               IP(src=self.pg4.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        self.pg1.enable_capture()
        rxs = self.send_and_expect(self.pg4, [p44], self.pg1, 33)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg4.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
        size = rxs[32][TCP].seq + rxs[32][IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # IPv6
        #
        p64 = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
               IPv6(src=self.pg4.remote_ip6, dst=self.pg1.remote_ip6) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        self.pg1.enable_capture()
        rxs = self.send_and_expect(self.pg4, [p64], self.pg1, 34)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg4.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg1.remote_ip6)
        size = rxs[33][TCP].seq + rxs[33][IPv6].plen - 20
        self.assertEqual(size, 65200)

        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index,
                                             enable_disable=0)
        self.vapi.feature_gso_enable_disable(self.pg1.sw_if_index,
                                             enable_disable=0)

    def test_gso_vxlan(self):
        """ GSO VXLAN test """
        self.logger.info(self.vapi.cli("sh int addr"))
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
            rx_sw_if_index=self.vxlan.sw_if_index, bd_id=self.single_tunnel_bd)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.single_tunnel_bd)
        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index)

        #
        # IPv4/IPv4 - VXLAN
        #
        p45 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p45], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # IPv4/IPv6 - VXLAN
        #
        p65 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p65], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        #
        # disable ipv4/vxlan
        #
        self.vxlan.remove_vpp_config()

        #
        # enable ipv6/vxlan
        #
        self.vxlan2.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan2.sw_if_index,
            bd_id=self.single_tunnel_bd)

        #
        # IPv6/IPv4 - VXLAN
        #
        p46 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IP(src=self.pg2.remote_ip4, dst="172.16.3.3", flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p46], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.3.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # IPv6/IPv6 - VXLAN
        #
        p66 = (Ether(src=self.pg2.remote_mac, dst="02:fe:60:1e:a2:79") /
               IPv6(src=self.pg2.remote_ip6, dst="fd01:3::3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p66], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[VXLAN].vni, 10)
            inner = rx[VXLAN].payload
            self.assertEqual(inner[Ether].src, self.pg2.remote_mac)
            self.assertEqual(inner[Ether].dst, "02:fe:60:1e:a2:79")
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:3::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        #
        # disable ipv4/vxlan
        #
        self.vxlan2.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index,
                                             enable_disable=0)

    def test_gso_ipip(self):
        """ GSO IPIP test """
        self.logger.info(self.vapi.cli("sh int addr"))
        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0.
        #
        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index)

        #
        # enable ipip4
        #
        self.ipip4.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip4.admin_up()
        self.ipip4.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip4_tunnel = VppIpRoute(
                self, "172.16.10.0", 24,
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

        rxs = self.send_and_expect(self.pg2, [p47], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].proto, 4)  # ipencap
            inner = rx[IP].payload
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        self.ip6_via_ip4_tunnel = VppIpRoute(
                self, "fd01:10::", 64,
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

        rxs = self.send_and_expect(self.pg2, [p67], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].proto, 41)  # ipv6
            inner = rx[IP].payload
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        #
        # Send jumbo frame with gso enabled only on input interface and
        # create IPIP tunnel on VPP pg0. Enable gso feature node on ipip
        # tunnel - IPSec use case
        #
        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index,
                                             enable_disable=0)
        self.vapi.feature_gso_enable_disable(self.ipip4.sw_if_index)

        rxs = self.send_and_expect(self.pg2, [p47], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].proto, 4)  # ipencap
            inner = rx[IP].payload
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # disable ipip4
        #
        self.vapi.feature_gso_enable_disable(self.ipip4.sw_if_index,
                                             enable_disable=0)
        self.ip4_via_ip4_tunnel.remove_vpp_config()
        self.ip6_via_ip4_tunnel.remove_vpp_config()
        self.ipip4.remove_vpp_config()

        #
        # enable ipip6
        #
        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index)
        self.ipip6.add_vpp_config()

        # Set interface up and enable IP on it
        self.ipip6.admin_up()
        self.ipip6.set_unnumbered(self.pg0.sw_if_index)

        # Add IPv4 routes via tunnel interface
        self.ip4_via_ip6_tunnel = VppIpRoute(
                self, "172.16.10.0", 24,
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

        rxs = self.send_and_expect(self.pg2, [p48], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "IP")
            inner = rx[IPv6].payload
            self.assertEqual(inner[IP].src, self.pg2.remote_ip4)
            self.assertEqual(inner[IP].dst, "172.16.10.3")
            size += inner[IP].len - 20 - 20
        self.assertEqual(size, 65200)

        self.ip6_via_ip6_tunnel = VppIpRoute(
                self, "fd01:10::", 64,
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

        rxs = self.send_and_expect(self.pg2, [p68], self.pg0, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.local_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(ipv6nh[rx[IPv6].nh], "IPv6")
            inner = rx[IPv6].payload
            self.assertEqual(inner[IPv6].src, self.pg2.remote_ip6)
            self.assertEqual(inner[IPv6].dst, "fd01:10::3")
            size += inner[IPv6].plen - 20
        self.assertEqual(size, 65200)

        #
        # disable ipip6
        #
        self.ip4_via_ip6_tunnel.remove_vpp_config()
        self.ip6_via_ip6_tunnel.remove_vpp_config()
        self.ipip6.remove_vpp_config()

        self.vapi.feature_gso_enable_disable(self.pg0.sw_if_index,
                                             enable_disable=0)

class TestIpsecTransportModeGSO(TemplateIpsec,
                           TemplateIpsec4TunProtect,
                           IpsecTun4):
    """ IPsec IPv4 Tunnel protect - transport mode"""
    def setUp(self):
        super(TestIpsecTransportModeGSO, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsecTransportModeGSO, self).tearDown()

    def test_tun_44_gso(self):
        """IPSEC tunnel protect"""

        p = self.ipv4_params

        self.config_network(p)

        self.vapi.feature_gso_enable_disable(self.pg1.sw_if_index)
        self.vapi.cli("set int feature gso ipip enable")

        self.config_sa_tra(p)
        self.config_protect(p)

        self.verify_tun_44(p, count=1, payload_size=9000)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 1)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 1)

        # teardown
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)

class TestIpsecTunnelModeGSO(TemplateIpsec,
                              TemplateIpsec4TunProtect,
                              IpsecTun4):
    """ IPsec IPv4 Tunnel protect - tunnel mode"""

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def setUp(self):
        super(TestIpsecTunnelModeGSO, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsecTunnelModeGSO, self).tearDown()

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=sw_intf.remote_ip4,
                              dst=sw_intf.local_ip4) /
                           IP(src=src, dst=dst) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_equal(rx[IP].src, p.remote_tun_if_host)
            self.assert_packet_checksums_valid(rx)

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assert_equal(pkt[IP].dst, self.pg0.remote_ip4)
                self.assert_equal(pkt[IP].src, self.pg0.local_ip4)
                inner = pkt[IP].payload
                self.assertEqual(inner[IP][IP].dst, p.remote_tun_if_host)

            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def test_tun_44(self):
        """IPSEC tunnel protect """

        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p)
        self.config_protect(p)

        self.vapi.cli("set int feature gso ipip enable")
        self.vapi.feature_gso_enable_disable(self.pg1.sw_if_index)

        self.verify_tun_44(p, count=1, payload_size=9000)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 1)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 1)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
