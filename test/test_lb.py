# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import socket

import scapy.compat
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw
from scapy.data import IP_PROTOS

from framework import VppTestCase
from util import ppp
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX

""" TestLB is a subclass of  VPPTestCase classes.

 TestLB class defines Load Balancer test cases for:
  - IP4 to GRE4 encap on per-port vip case
  - IP4 to GRE6 encap on per-port vip case
  - IP6 to GRE4 encap on per-port vip case
  - IP6 to GRE6 encap on per-port vip case
  - IP4 to L3DSR encap on vip case
  - IP4 to L3DSR encap on per-port vip case
  - IP4 to NAT4 encap on per-port vip case
  - IP6 to NAT6 encap on per-port vip case

 As stated in comments below, GRE has issues with IPv6.
 All test cases involving IPv6 are executed, but
 received packets are not parsed and checked.

"""


class TestLB(VppTestCase):
    """ Load Balancer Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestLB, cls).setUpClass()

        cls.ass = range(5)
        cls.packets = range(1)

        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()

            dst4 = VppIpRoute(cls, "10.0.0.0", 24,
                              [VppRoutePath(cls.pg1.remote_ip4,
                                            INVALID_INDEX)],
                              register=False)
            dst4.add_vpp_config()
            dst6 = VppIpRoute(cls, "2002::", 16,
                              [VppRoutePath(cls.pg1.remote_ip6,
                                            INVALID_INDEX)],
                              register=False)
            dst6.add_vpp_config()
            cls.vapi.lb_conf(ip4_src_address="39.40.41.42",
                             ip6_src_address="2004::1")
        except Exception:
            super(TestLB, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestLB, cls).tearDownClass()

    def tearDown(self):
        super(TestLB, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show lb vip verbose"))

    def getIPv4Flow(self, id):
        return (IP(dst="90.0.%u.%u" % (id / 255, id % 255),
                   src="40.0.%u.%u" % (id / 255, id % 255)) /
                UDP(sport=10000 + id, dport=20000))

    def getIPv6Flow(self, id):
        return (IPv6(dst="2001::%u" % (id), src="fd00:f00d:ffff::%u" % (id)) /
                UDP(sport=10000 + id, dport=20000))

    def generatePackets(self, src_if, isv4):
        self.reset_packet_infos()
        pkts = []
        for pktid in self.packets:
            info = self.create_packet_info(src_if, self.pg1)
            payload = self.info_to_payload(info)
            ip = self.getIPv4Flow(pktid) if isv4 else self.getIPv6Flow(pktid)
            packet = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                      ip /
                      Raw(payload))
            self.extend_packet(packet, 128)
            info.data = packet.copy()
            pkts.append(packet)
        return pkts

    def checkInner(self, gre, isv4):
        IPver = IP if isv4 else IPv6
        self.assertEqual(gre.proto, 0x0800 if isv4 else 0x86DD)
        self.assertEqual(gre.flags, 0)
        self.assertEqual(gre.version, 0)
        inner = IPver(scapy.compat.raw(gre.payload))
        payload_info = self.payload_to_info(inner[Raw])
        self.info = self.packet_infos[payload_info.index]
        self.assertEqual(payload_info.src, self.pg0.sw_if_index)
        self.assertEqual(scapy.compat.raw(inner),
                         scapy.compat.raw(self.info.data[IPver]))

    def checkCapture(self, encap, isv4):
        self.pg0.assert_nothing_captured()
        out = self.pg1.get_capture(len(self.packets))

        load = [0] * len(self.ass)
        self.info = None
        for p in out:
            try:
                asid = 0
                gre = None
                if (encap == 'gre4'):
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.src, "39.40.41.42")
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 47)
                    self.assertEqual(len(ip.options), 0)
                    gre = p[GRE]
                    self.checkInner(gre, isv4)
                elif (encap == 'gre6'):
                    ip = p[IPv6]
                    asid = ip.dst.split(":")
                    asid = asid[len(asid) - 1]
                    asid = 0 if asid == "" else int(asid)
                    self.assertEqual(ip.version, 6)
                    self.assertEqual(ip.tc, 0)
                    self.assertEqual(ip.fl, 0)
                    self.assertEqual(ip.src, "2004::1")
                    self.assertEqual(
                        socket.inet_pton(socket.AF_INET6, ip.dst),
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % asid)
                    )
                    self.assertEqual(ip.nh, 47)
                    # self.assertEqual(len(ip.options), 0)
                    gre = GRE(scapy.compat.raw(p[IPv6].payload))
                    self.checkInner(gre, isv4)
                elif (encap == 'l3dsr'):
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.tos, 0x1c)
                    self.assertEqual(len(ip.options), 0)
                    self.assert_ip_checksum_valid(p)
                    if ip.proto == IP_PROTOS.tcp:
                        self.assert_tcp_checksum_valid(p)
                    elif ip.proto == IP_PROTOS.udp:
                        self.assert_udp_checksum_valid(p)
                elif (encap == 'nat4'):
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 17)
                    self.assertEqual(len(ip.options), 0)
                    udp = p[UDP]
                    self.assertEqual(udp.dport, 3307)
                elif (encap == 'nat6'):
                    ip = p[IPv6]
                    asid = ip.dst.split(":")
                    asid = asid[len(asid) - 1]
                    asid = 0 if asid == "" else int(asid)
                    self.assertEqual(ip.version, 6)
                    self.assertEqual(ip.tc, 0)
                    self.assertEqual(ip.fl, 0)
                    self.assertEqual(
                        socket.inet_pton(socket.AF_INET6, ip.dst),
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % asid)
                    )
                    self.assertEqual(ip.nh, 17)
                    self.assertGreaterEqual(ip.hlim, 63)
                    udp = UDP(scapy.compat.raw(p[IPv6].payload))
                    self.assertEqual(udp.dport, 3307)
                load[asid] += 1
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", p))
                raise

        # This is just to roughly check that the balancing algorithm
        # is not completely biased.
        for asid in self.ass:
            if load[asid] < int(len(self.packets) / (len(self.ass) * 2)):
                self.logger.error(
                    "ASS is not balanced: load[%d] = %d" % (asid, load[asid]))
                raise Exception("Load Balancer algorithm is biased")

    def test_lb_ip4_gre4(self):
        """ Load Balancer IP4 GRE4 on vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='gre4', isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre4(self):
        """ Load Balancer IP6 GRE4 on vip case """

        try:
            self.vapi.cli(
                "lb vip 2001::/16 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre4', isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 2001::/16 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre6(self):
        """ Load Balancer IP4 GRE6 on vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 2002::%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre6', isv4=True)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 2002::%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre6(self):
        """ Load Balancer IP6 GRE6 on vip case """
        try:
            self.vapi.cli(
                "lb vip 2001::/16 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 2002::%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre6', isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 2002::%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 2001::/16 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre4_port(self):
        """ Load Balancer IP4 GRE4 on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='gre4', isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre4_port(self):
        """ Load Balancer IP6 GRE4 on per-port-vip case """

        try:
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre4', isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre6_port(self):
        """ Load Balancer IP4 GRE6 on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 2002::%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre6', isv4=True)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 2002::%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre6_port(self):
        """ Load Balancer IP6 GRE6 on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap='gre6', isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr(self):
        """ Load Balancer IP4 L3DSR on vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap l3dsr dscp 7")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='l3dsr', isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 encap l3dsr"
                " dscp 7 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr_port(self):
        """ Load Balancer IP4 L3DSR on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr dscp 7")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='l3dsr', isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr"
                " dscp 7 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_nat4_port(self):
        """ Load Balancer IP4 NAT4 on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap nat4"
                " type clusterip target_port 3307")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='nat4', isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap nat4"
                " type clusterip target_port 3307 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_nat6_port(self):
        """ Load Balancer IP6 NAT6 on per-port-vip case """
        try:
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap nat6"
                " type clusterip target_port 3307")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u"
                    % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap='nat6', isv4=False)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u del"
                    % (asid))
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap nat6"
                " type clusterip target_port 3307 del")
            self.vapi.cli("test lb flowtable flush")
