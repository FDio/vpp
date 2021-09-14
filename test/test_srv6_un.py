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


class TestSRv6uSIDSRH(VppTestCase):
    """ SRv6 End.uSID w/ SRH """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6uSIDSRH, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            cls.ip6_dst = "1111:2222:aaaa:bbbb:cccc:dddd:eeee:ffff"
            cls.ip6_src = "1111:2222::1"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6uSIDSRH, cls).tearDownClass()
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
                   IPv6ExtHdrSegmentRouting(segleft=1,
                                            lastentry=0,
                                            tag=0,
                                            addresses=[
                                                "a1::1",
                                                "1111:2222:aaaa:bbbb::"]) /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_usid_srh(self):
        """ test_srv6_usid_srh """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli(
            "sr localsid prefix 1111:2222:aaaa::/48 behavior un 16")
        self.vapi.cli(
            "ip route add 1111:2222:bbbb::/48 via {}".format(self.ip6_nhop))

        self.logger.info(self.vapi.cli("show sr localsids"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(
                    pkt[IPv6].dst, "1111:2222:bbbb:cccc:dddd:eeee:ffff:0")


class TestSRv6uSID(VppTestCase):
    """ SRv6 End.uSID w/o SRH """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6uSID, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            cls.ip6_dst = "1111:2222:aaaa:bbbb:cccc:dddd:eeee:ffff"
            cls.ip6_src = "1111:2222::1"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6uSID, cls).tearDownClass()
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
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_usid(self):
        """ test_srv6_usid """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli(
            "sr localsid prefix 1111:2222:aaaa::/48 behavior un 16")
        self.vapi.cli(
            "ip route add 1111:2222:bbbb::/48 via {}".format(self.ip6_nhop))

        self.logger.info(self.vapi.cli("show sr localsids"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(
                    pkt[IPv6].dst, "1111:2222:bbbb:cccc:dddd:eeee:ffff:0")


class TestSRv6uSIDFlexSRH(VppTestCase):
    """ SRv6 End.uSID.Flex w/ SRH """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6uSIDFlexSRH, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            cls.ip6_dst = "1111:2222:aaaa:bbbb:cccc:dddd:eeee:ffff"
            cls.ip6_src = "1111:2222::1"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6uSIDFlexSRH, cls).tearDownClass()
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
                   IPv6ExtHdrSegmentRouting(segleft=1,
                                            lastentry=0,
                                            tag=0,
                                            addresses=[
                                                "a1::1",
                                                "1111:2222:aaaa:bbbb::"]) /
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_usid_flex_srh(self):
        """ test_srv6_usid_flex_srh """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli(
            "sr localsid prefix 1111:2222:aaaa::/48 behavior un.flex 16")
        self.vapi.cli(
            "ip route add 1111:2222:bbbb::/48 via {}".format(self.ip6_nhop))

        self.logger.info(self.vapi.cli("show sr localsids"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(
                    pkt[IPv6].dst, "1111:2222:bbbb:cccc:dddd:eeee:ffff:0")


class TestSRv6uSIDFlex(VppTestCase):
    """ SRv6 End.uSID.Flex w/o SRH """

    @classmethod
    def setUpClass(cls):
        super(TestSRv6uSIDFlex, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.pg_if_i = cls.pg_interfaces[0]
            cls.pg_if_o = cls.pg_interfaces[1]

            cls.pg_if_i.config_ip6()
            cls.pg_if_o.config_ip6()

            cls.ip6_nhop = cls.pg_if_o.remote_ip6

            cls.ip6_dst = "1111:2222:aaaa:bbbb:cccc:dddd:eeee:ffff"
            cls.ip6_src = "1111:2222::1"

            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.resolve_ndp(timeout=5)

        except Exception:
            super(TestSRv6uSIDFlex, cls).tearDownClass()
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
                   IPv6(dst=d, src=s) /
                   UDP(sport=1000, dport=23))
            self.logger.info(pkt.show2(dump=True))
            pkts.append(pkt)

        return pkts

    def test_srv6_usid_flex(self):
        """ test_srv6_usid_flex """
        pkts = self.create_packets([("A::1", "B::1"), ("C::1", "D::1")])

        self.vapi.cli("set sr encaps source addr A1::1")
        self.vapi.cli(
            "sr localsid prefix 1111:2222:aaaa::/48 behavior un.flex 16")
        self.vapi.cli(
            "ip route add 1111:2222:bbbb::/48 via {}".format(self.ip6_nhop))

        self.logger.info(self.vapi.cli("show sr localsids"))

        self.vapi.cli("clear errors")

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show int address"))

        capture = self.pg1.get_capture(len(pkts))

        for pkt in capture:
            self.logger.info(pkt.show2(dump=True))
            self.assertEqual(
                    pkt[IPv6].dst, "1111:2222:bbbb:cccc:dddd:eeee:ffff:0")
