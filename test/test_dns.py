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

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from ipaddress import *

import scapy.compat
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, TCP, ICMP, icmptypes, icmpcodes
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.dns import DNSRR, DNS, DNSQR


class TestDns(VppTestCase):
    """ Dns Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDns, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDns, cls).tearDownClass()

    def setUp(self):
        super(TestDns, self).setUp()

        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestDns, self).tearDown()

    def create_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                        IP(src=src_if.remote_ip4) /
                        UDP(sport=1234, dport=53) /
                        DNS(rd=1, qd=DNSQR(qname="bozo.clown.org")))

        bad_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                       IP(src=src_if.remote_ip4) /
                       UDP(sport=1234, dport=53) /
                       DNS(rd=1, qd=DNSQR(qname="no.clown.org")))
        pkts = [good_request, bad_request]
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        for packet in capture:
            dns = packet[DNS]
            self.assertEqual(dns.an[0].rdata, '1.2.3.4')

    def test_dns_unittest(self):
        """ DNS Name Resolver Basic Functional Test """

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address(u'8.8.8.8').packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli("dns cache add bozo.clown.org 1.2.3.4"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b'bozo.clown.org')
        self.assertEqual(rv.ip4_address, IPv4Address(u'1.2.3.4').packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="127.0.0.1/8")

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('1.2.3.4', str)
        self.assertIn('[P] no.clown.org:', str)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
