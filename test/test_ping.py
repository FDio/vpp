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

from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase
from util import ppp
from vpp_ip_route import VppIpInterfaceAddress, VppIpRoute, VppRoutePath
from vpp_neighbor import VppNeighbor

""" TestPing is a subclass of  VPPTestCase classes.

Basic test for sanity check of the ping.

"""


class TestPing(VppTestCase):
    """ Ping Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPing, cls).setUpClass()
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
        except Exception:
            super(TestPing, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestPing, cls).tearDownClass()

    def tearDown(self):
        super(TestPing, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show hardware"))

    def verify_ping_request(self, p, src, dst, seq):
        ip = p[IP]
        self.assertEqual(ip.version, 4)
        self.assertEqual(ip.flags, 0)
        self.assertEqual(ip.src, src)
        self.assertEqual(ip.dst, dst)
        self.assertEqual(ip.proto, 1)
        self.assertEqual(len(ip.options), 0)
        self.assertGreaterEqual(ip.ttl, 254)
        icmp = p[ICMP]
        self.assertEqual(icmp.type, 8)
        self.assertEqual(icmp.code, 0)
        self.assertEqual(icmp.seq, seq)
        return icmp

    def test_ping_basic(self):
        """ basic ping test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.logger.info(self.vapi.cli("show ip4 neighbors"))
            self.logger.info(self.vapi.cli("show ip6 neighbors"))

            remote_ip4 = self.pg1.remote_ip4
            ping_cmd = "ping " + remote_ip4 + " interval 0.01 repeat 10"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(10)
            icmp_id = None
            icmp_seq = 1
            for p in out:
                icmp = self.verify_ping_request(p, self.pg1.local_ip4,
                                                self.pg1.remote_ip4, icmp_seq)
                icmp_seq = icmp_seq + 1
                if icmp_id is None:
                    icmp_id = icmp.id
                else:
                    self.assertEqual(icmp.id, icmp_id)
        finally:
            self.vapi.cli("show error")

    def test_ping_burst(self):
        """ burst ping test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.logger.info(self.vapi.cli("show ip neighbors"))

            remote_ip4 = self.pg1.remote_ip4
            ping_cmd = "ping " + remote_ip4 + " interval 0.01 burst 3"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(3*5)
            icmp_id = None
            icmp_seq = 1
            count = 0
            for p in out:
                icmp = self.verify_ping_request(p, self.pg1.local_ip4,
                                                self.pg1.remote_ip4, icmp_seq)
                count = count + 1
                if count >= 3:
                    icmp_seq = icmp_seq + 1
                    count = 0
                if icmp_id is None:
                    icmp_id = icmp.id
                else:
                    self.assertEqual(icmp.id, icmp_id)
        finally:
            self.vapi.cli("show error")

    def test_ping_src(self):
        """ ping with source address set """

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.logger.info(self.vapi.cli("show ip4 neighbors"))
        self.logger.info(self.vapi.cli("show ip6 neighbors"))

        nbr_addr = "10.0.0.2"
        VppIpInterfaceAddress(self, self.pg1, "10.0.0.1", 24).add_vpp_config()
        VppNeighbor(self, self.pg1.sw_if_index,
                    "00:11:22:33:44:55",
                    nbr_addr).add_vpp_config()

        ping_cmd = "ping %s interval 0.01 repeat 3" % self.pg1.remote_ip4
        ret = self.vapi.cli(ping_cmd)
        out = self.pg1.get_capture(3)
        icmp_seq = 1
        for p in out:
            icmp = self.verify_ping_request(p, self.pg1.local_ip4,
                                            self.pg1.remote_ip4, icmp_seq)
            icmp_seq = icmp_seq + 1

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        ping_cmd = "ping %s interval 0.01 repeat 3" % nbr_addr
        ret = self.vapi.cli(ping_cmd)
        out = self.pg1.get_capture(3)
        icmp_seq = 1
        for p in out:
            icmp = self.verify_ping_request(p, "10.0.0.1", nbr_addr, icmp_seq)
            icmp_seq = icmp_seq + 1

    def test_ping_fib_routed_dst(self):
        """ ping destination routed according to FIB table """

        try:
            self.pg1.generate_remote_hosts(1)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            routed_dst = "10.0.2.0"
            self.logger.info(self.vapi.cli("show ip4 neighbors"))
            VppIpRoute(self, routed_dst, 24,
                       [VppRoutePath(self.pg1.remote_hosts[0].ip4,
                                     self.pg1.sw_if_index)]).add_vpp_config()
            ping_cmd = "ping %s interval 0.01 repeat 3" % routed_dst
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(3)
            icmp_seq = 1
            for p in out:
                self.verify_ping_request(p, self.pg1.local_ip4, routed_dst,
                                         icmp_seq)
                icmp_seq = icmp_seq + 1
        finally:
            self.vapi.cli("show error")
