#!/usr/bin/env python3
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

from framework import VppTestCase
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from scapy.contrib.gtp import *
from scapy.all import *


class TestSRv6EndMGTP4E(VppTestCase):
    """ SRv6 End.M.GTP4.E (SRv6 -> GTP-U) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP4E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip4()

            cls.ip4_dst = cls.pg_if_o.remote_ip4
            # cls.ip4_src = cls.pg_if_o.local_ip4
            cls.ip4_src = "192.168.192.10"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()

        except Exception:
            super(TestSRv6EndMGTP4E, cls).tearDownClass()
            raise

    def create_packets(self, inner):

        ip4_dst = IPv4Address(str(self.ip4_dst))
        # 32bit prefix + 32bit IPv4 DA + 8bit + 32bit TEID + 24bit
        dst = b'\xaa' * 4 + ip4_dst.packed + \
            b'\x11' + b'\xbb' * 4 + b'\x11' * 3
        ip6_dst = IPv6Address(dst)

        ip4_src = IPv4Address(str(self.ip4_src))
        # 64bit prefix + 32bit IPv4 SA + 16 bit port + 16bit
        src = b'\xcc' * 8 + ip4_src.packed + \
            b'\xdd' * 2 + b'\x11' * 2
        ip6_src = IPv6Address(src)

        self.logger.info("ip4 dst: {}".format(ip4_dst))
        self.logger.info("ip4 src: {}".format(ip4_src))
        self.logger.info("ip6 dst (remote srgw): {}".format(ip6_dst))
        self.logger.info("ip6 src (local  srgw): {}".format(ip6_src))

        pkts = list()
        for d, s in inner:
            pkt = (Ether() /
                   IPv6(dst=str(ip6_dst), src=str(ip6_src)) /
                   IPv6ExtHdrSegmentRouting() /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_mobile(self):
        """ test_srv6_mobile """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli(
            "sr localsid address {} behavior end.m.gtp4.e "
            .format(pkts[0]['IPv6'].dst) +
            "v4src_position 64 fib-table 0")
        self.logger.info(self.vapi.cli("show sr localsid"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(pkt[IP].dst, self.ip4_dst)
            self.assertEqual(pkt[IP].src, self.ip4_src)
            self.assertEqual(pkt[GTP_U_Header].teid, 0xbbbbbbbb)


class TestSRv6TMGTP4D(VppTestCase):
    """ SRv6 T.M.GTP4.D (GTP-U -> SRv6) """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6TMGTP4D, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip4()
            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip4()
            cls.pg_if_o.config_ip6()

            cls.ip4_dst = "1.1.1.1"
            cls.ip4_src = "2.2.2.2"

            cls.ip6_dst = cls.pg_if_o.remote_ip6

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_arp()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6TMGTP4D, cls).tearDownClass()
            raise

    def create_packets(self, inner):

        ip4_dst = IPv4Address(str(self.ip4_dst))

        ip4_src = IPv4Address(str(self.ip4_src))

        self.logger.info("ip4 dst: {}".format(ip4_dst))
        self.logger.info("ip4 src: {}".format(ip4_src))

        pkts = list()
        for d, s in inner:
            pkt = (Ether() /
                   IP(dst=str(ip4_dst), src=str(ip4_src)) /
                   UDP(sport=2152, dport=2152) /
                   GTP_U_Header(gtp_type="g_pdu", teid=200) /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_mobile(self):
        """ test_srv6_mobile """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli("sr policy add bsid D4:: next D2:: next D3::")
        self.vapi.cli(
            "sr policy add bsid D5:: behavior t.m.gtp4.d D4::/32 " +
            "v6src_prefix C1::/64 nhtype ipv6 fib-table 0 drop-in")
        self.vapi.cli("sr steer l3 {}/32 via bsid D5::".format(self.ip4_dst))
        self.vapi.cli("ip route add D2::/32 via {}".format(self.ip6_dst))

        self.logger.info(self.vapi.cli("show sr steer"))
        self.logger.info(self.vapi.cli("show sr policies"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.logger.info("GTP4.D Address={}".format(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[0])))
            self.assertEqual(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[0]),
                "d4:0:101:101::c800:0")


class TestSRv6EndMGTP6E(VppTestCase):
    """ SRv6 End.M.GTP6.E """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6E, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6EndMGTP6E, cls).tearDownClass()
            raise

    def create_packets(self, inner):
        # 64bit prefix + 8bit QFI + 32bit TEID + 24bit
        dst = b'\xaa' * 8 + b'\x00' + \
            b'\xbb' * 4 + b'\x00' * 3
        ip6_dst = IPv6Address(dst)

        self.ip6_dst = ip6_dst

        src = b'\xcc' * 8 + \
            b'\xdd' * 4 + b'\x11' * 4
        ip6_src = IPv6Address(src)

        self.ip6_src = ip6_src

        pkts = list()
        for d, s in inner:
            pkt = (Ether() /
                   IPv6(dst=str(ip6_dst),
                        src=str(ip6_src)) /
                   IPv6ExtHdrSegmentRouting(segleft=1,
                                            lastentry=0,
                                            tag=0,
                                            addresses=["a1::1"]) /
                   IPv6(dst=d, src=s) / UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_mobile(self):
        """ test_srv6_mobile """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli(
            "sr localsid prefix {}/64 behavior end.m.gtp6.e fib-table 0"
            .format(pkts[0]['IPv6'].dst))
        self.vapi.cli(
            "ip route add a1::/64 via {}".format(self.ip6_nhop))
        self.logger.info(self.vapi.cli("show sr localsid"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(pkt[IPv6].dst, "a1::1")
            self.assertEqual(pkt[IPv6].src, str(self.ip6_src))
            self.assertEqual(pkt[GTP_U_Header].teid, 0xbbbbbbbb)


class TestSRv6EndMGTP6D(VppTestCase):
    """ SRv6 End.M.GTP6.D """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6EndMGTP6D, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            cls.ip6_dst = "2001::1"
            cls.ip6_src = "2002::1"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6EndMGTP6D, cls).tearDownClass()
            raise

    def create_packets(self, inner):

        ip6_dst = IPv6Address(str(self.ip6_dst))

        ip6_src = IPv6Address(str(self.ip6_src))

        self.logger.info("ip6 dst: {}".format(ip6_dst))
        self.logger.info("ip6 src: {}".format(ip6_src))

        pkts = list()
        for d, s in inner:
            pkt = (Ether() /
                   IPv6(dst=str(ip6_dst), src=str(ip6_src)) /
                   UDP(sport=2152, dport=2152) /
                   GTP_U_Header(gtp_type="g_pdu", teid=200) /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_mobile(self):
        """ test_srv6_mobile """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli("sr policy add bsid D4:: next D2:: next D3::")
        self.vapi.cli(
            "sr localsid prefix 2001::/64 behavior end.m.gtp6.d " +
            "D4::/64 fib-table 0 drop-in")
        self.vapi.cli("ip route add D2::/64 via {}".format(self.ip6_nhop))

        self.logger.info(self.vapi.cli("show sr policies"))
        self.logger.info(self.vapi.cli("show sr localsid"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.logger.info("GTP6.D SID0={}".format(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[0])))
            self.logger.info("GTP6.D SID1={}".format(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[1])))
            self.assertEqual(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[0]), "2001::1")
            self.assertEqual(
                str(pkt[IPv6ExtHdrSegmentRouting].addresses[1]), "d4::c800:0")
