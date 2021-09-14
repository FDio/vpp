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
from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner

from vpp_udp_encap import find_udp_encap, VppUdpEncap
from vpp_udp_decap import VppUdpDecap
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, VppMplsLabel, \
    VppMplsTable, VppMplsRoute, FibPathType, FibPathProto
from vpp_neighbor import VppNeighbor
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS

NUM_PKTS = 67


@tag_fixme_vpp_workers
class TestUdpEncap(VppTestCase):
    """ UDP Encap Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestUdpEncap, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestUdpEncap, cls).tearDownClass()

    def setUp(self):
        super(TestUdpEncap, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        # setup interfaces
        # assign them different tables.
        table_id = 0
        self.tables = []

        for i in self.pg_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()
                self.tables.append(tbl)
                tbl = VppIpTable(self, table_id, is_ip6=1)
                tbl.add_vpp_config()
                self.tables.append(tbl)

            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            table_id += 1

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.set_table_ip4(0)
            i.set_table_ip6(0)
            i.admin_down()
        super(TestUdpEncap, self).tearDown()

    def validate_outer4(self, rx, encap_obj):
        self.assertEqual(rx[IP].src, encap_obj.src_ip_s)
        self.assertEqual(rx[IP].dst, encap_obj.dst_ip_s)
        self.assertEqual(rx[UDP].sport, encap_obj.src_port)
        self.assertEqual(rx[UDP].dport, encap_obj.dst_port)

    def validate_outer6(self, rx, encap_obj):
        self.assertEqual(rx[IPv6].src, encap_obj.src_ip_s)
        self.assertEqual(rx[IPv6].dst, encap_obj.dst_ip_s)
        self.assertEqual(rx[UDP].sport, encap_obj.src_port)
        self.assertEqual(rx[UDP].dport, encap_obj.dst_port)

    def validate_inner4(self, rx, tx, ttl=None):
        self.assertEqual(rx[IP].src, tx[IP].src)
        self.assertEqual(rx[IP].dst, tx[IP].dst)
        if ttl:
            self.assertEqual(rx[IP].ttl, ttl)
        else:
            self.assertEqual(rx[IP].ttl, tx[IP].ttl)

    def validate_inner6(self, rx, tx, hlim=None):
        self.assertEqual(rx.src, tx[IPv6].src)
        self.assertEqual(rx.dst, tx[IPv6].dst)
        if hlim:
            self.assertEqual(rx.hlim, hlim)
        else:
            self.assertEqual(rx.hlim, tx[IPv6].hlim)

    def test_udp_encap(self):
        """ UDP Encap test
        """

        #
        # construct a UDP encap object through each of the peers
        # v4 through the first two peers, v6 through the second.
        #
        udp_encap_0 = VppUdpEncap(self,
                                  self.pg0.local_ip4,
                                  self.pg0.remote_ip4,
                                  330, 440)
        udp_encap_1 = VppUdpEncap(self,
                                  self.pg1.local_ip4,
                                  self.pg1.remote_ip4,
                                  331, 441,
                                  table_id=1)
        udp_encap_2 = VppUdpEncap(self,
                                  self.pg2.local_ip6,
                                  self.pg2.remote_ip6,
                                  332, 442,
                                  table_id=2)
        udp_encap_3 = VppUdpEncap(self,
                                  self.pg3.local_ip6,
                                  self.pg3.remote_ip6,
                                  333, 443,
                                  table_id=3)
        udp_encap_0.add_vpp_config()
        udp_encap_1.add_vpp_config()
        udp_encap_2.add_vpp_config()
        udp_encap_3.add_vpp_config()

        self.logger.info(self.vapi.cli("sh udp encap"))

        self.assertTrue(find_udp_encap(self, udp_encap_2))
        self.assertTrue(find_udp_encap(self, udp_encap_3))
        self.assertTrue(find_udp_encap(self, udp_encap_0))
        self.assertTrue(find_udp_encap(self, udp_encap_1))

        #
        # Routes via each UDP encap object - all combinations of v4 and v6.
        #
        route_4o4 = VppIpRoute(
            self, "1.1.0.1", 24,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          type=FibPathType.FIB_PATH_TYPE_UDP_ENCAP,
                          next_hop_id=udp_encap_0.id)], table_id=1)
        route_4o6 = VppIpRoute(
            self, "1.1.2.1", 32,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          type=FibPathType.FIB_PATH_TYPE_UDP_ENCAP,
                          next_hop_id=udp_encap_2.id)])
        route_6o4 = VppIpRoute(
            self, "2001::1", 128,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          type=FibPathType.FIB_PATH_TYPE_UDP_ENCAP,
                          next_hop_id=udp_encap_1.id)])
        route_6o6 = VppIpRoute(
            self, "2001::3", 128,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          type=FibPathType.FIB_PATH_TYPE_UDP_ENCAP,
                          next_hop_id=udp_encap_3.id)])
        route_4o6.add_vpp_config()
        route_6o6.add_vpp_config()
        route_6o4.add_vpp_config()
        route_4o4.add_vpp_config()

        #
        # 4o4 encap
        #
        p_4o4 = (Ether(src=self.pg1.remote_mac,
                       dst=self.pg1.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.0.1") /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        rx = self.send_and_expect(self.pg1, p_4o4*NUM_PKTS, self.pg0)
        for p in rx:
            self.validate_outer4(p, udp_encap_0)
            p = IP(p["UDP"].payload.load)
            self.validate_inner4(p, p_4o4)
        self.assertEqual(udp_encap_0.get_stats()['packets'], NUM_PKTS)

        #
        # 4o6 encap
        #
        p_4o6 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.2.1") /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_4o6*NUM_PKTS, self.pg2)
        for p in rx:
            self.validate_outer6(p, udp_encap_2)
            p = IP(p["UDP"].payload.load)
            self.validate_inner4(p, p_4o6)
        self.assertEqual(udp_encap_2.get_stats()['packets'], NUM_PKTS)

        #
        # 6o4 encap
        #
        p_6o4 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="2001::100", dst="2001::1") /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_6o4*NUM_PKTS, self.pg1)
        for p in rx:
            self.validate_outer4(p, udp_encap_1)
            p = IPv6(p["UDP"].payload.load)
            self.validate_inner6(p, p_6o4)
        self.assertEqual(udp_encap_1.get_stats()['packets'], NUM_PKTS)

        #
        # 6o6 encap
        #
        p_6o6 = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IPv6(src="2001::100", dst="2001::3") /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_6o6*NUM_PKTS, self.pg3)
        for p in rx:
            self.validate_outer6(p, udp_encap_3)
            p = IPv6(p["UDP"].payload.load)
            self.validate_inner6(p, p_6o6)
        self.assertEqual(udp_encap_3.get_stats()['packets'], NUM_PKTS)

        #
        # A route with an output label
        # the TTL of the inner packet is decremented on LSP ingress
        #
        route_4oMPLSo4 = VppIpRoute(
            self, "1.1.2.22", 32,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          type=FibPathType.FIB_PATH_TYPE_UDP_ENCAP,
                          next_hop_id=1,
                          labels=[VppMplsLabel(66)])])
        route_4oMPLSo4.add_vpp_config()

        p_4omo4 = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IP(src="2.2.2.2", dst="1.1.2.22") /
                   UDP(sport=1234, dport=1234) /
                   Raw(b'\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p_4omo4*NUM_PKTS, self.pg1)
        for p in rx:
            self.validate_outer4(p, udp_encap_1)
            p = MPLS(p["UDP"].payload.load)
            self.validate_inner4(p, p_4omo4, ttl=63)
        self.assertEqual(udp_encap_1.get_stats()['packets'], 2*NUM_PKTS)

    def test_udp_decap(self):
        """ UDP Decap test
        """
        #
        # construct a UDP decap object for each type of protocol
        #

        # IPv4
        udp_api_proto = VppEnum.vl_api_udp_decap_next_proto_t
        next_proto = udp_api_proto.UDP_API_DECAP_PROTO_IP4
        udp_decap_0 = VppUdpDecap(self, 1, 220, next_proto)

        # IPv6
        next_proto = udp_api_proto.UDP_API_DECAP_PROTO_IP6
        udp_decap_1 = VppUdpDecap(self, 0, 221, next_proto)

        # MPLS
        next_proto = udp_api_proto.UDP_API_DECAP_PROTO_MPLS
        udp_decap_2 = VppUdpDecap(self, 1, 222, next_proto)

        udp_decap_0.add_vpp_config()
        udp_decap_1.add_vpp_config()
        udp_decap_2.add_vpp_config()

        #
        # Routes via the corresponding pg after the UDP decap
        #
        route_4 = VppIpRoute(
            self, "1.1.1.1", 32,
            [VppRoutePath("0.0.0.0", self.pg0.sw_if_index)],
            table_id=0)

        route_6 = VppIpRoute(
            self, "2001::1", 128,
            [VppRoutePath("::", self.pg1.sw_if_index)],
            table_id=1)

        route_mo4 = VppIpRoute(
            self, "3.3.3.3", 32,
            [VppRoutePath("0.0.0.0", self.pg2.sw_if_index)],
            table_id=2)

        route_4.add_vpp_config()
        route_6.add_vpp_config()
        route_mo4.add_vpp_config()

        #
        # Adding neighbors to route the packets
        #
        n_4 = VppNeighbor(self,
                          self.pg0.sw_if_index,
                          "00:11:22:33:44:55",
                          "1.1.1.1")
        n_6 = VppNeighbor(self,
                          self.pg1.sw_if_index,
                          "11:22:33:44:55:66",
                          "2001::1")
        n_mo4 = VppNeighbor(self,
                            self.pg2.sw_if_index,
                            "22:33:44:55:66:77",
                            "3.3.3.3")

        n_4.add_vpp_config()
        n_6.add_vpp_config()
        n_mo4.add_vpp_config()

        #
        # MPLS decapsulation config
        #
        mpls_table = VppMplsTable(self, 0)
        mpls_table.add_vpp_config()
        mpls_route = VppMplsRoute(
            self, 77, 1,
            [VppRoutePath("0.0.0.0",
                          0xFFFFFFFF,
                          nh_table_id=2,
                          proto=FibPathProto.FIB_PATH_NH_PROTO_IP4)])
        mpls_route.add_vpp_config()

        #
        # UDP over ipv4 decap
        #
        p_4 = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               UDP(sport=1111, dport=220) /
               IP(src="2.2.2.2", dst="1.1.1.1") /
               UDP(sport=1234, dport=4321) /
               Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_4*NUM_PKTS, self.pg0)
        p_4 = IP(p_4["UDP"].payload)
        for p in rx:
            p = IP(p["Ether"].payload)
            self.validate_inner4(p, p_4, ttl=63)

        #
        # UDP over ipv6 decap
        #
        p_6 = (Ether(src=self.pg1.remote_mac,
                     dst=self.pg1.local_mac) /
               IPv6(src=self.pg1.remote_ip6, dst=self.pg1.local_ip6) /
               UDP(sport=2222, dport=221) /
               IPv6(src="2001::100", dst="2001::1") /
               UDP(sport=1234, dport=4321) /
               Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg1, p_6*NUM_PKTS, self.pg1)
        p_6 = IPv6(p_6["UDP"].payload)
        p = IPv6(rx[0]["Ether"].payload)
        for p in rx:
            p = IPv6(p["Ether"].payload)
            self.validate_inner6(p, p_6, hlim=63)

        #
        # UDP over mpls decap
        #
        p_mo4 = (Ether(src=self.pg2.remote_mac,
                       dst=self.pg2.local_mac) /
                 IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4) /
                 UDP(sport=3333, dport=222) /
                 MPLS(label=77, ttl=1) /
                 IP(src="4.4.4.4", dst="3.3.3.3") /
                 UDP(sport=1234, dport=4321) /
                 Raw(b'\xa5' * 100))

        self.pg2.enable_mpls()
        rx = self.send_and_expect(self.pg2, p_mo4*NUM_PKTS, self.pg2)
        self.pg2.disable_mpls()
        p_mo4 = IP(MPLS(p_mo4["UDP"].payload).payload)
        for p in rx:
            p = IP(p["Ether"].payload)
            self.validate_inner4(p, p_mo4, ttl=63)


@tag_fixme_vpp_workers
class TestUDP(VppTestCase):
    """ UDP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestUDP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestUDP, cls).tearDownClass()

    def setUp(self):
        super(TestUDP, self).setUp()
        self.vapi.session_enable_disable(is_enable=1)
        self.create_loopback_interfaces(2)

        table_id = 0

        for i in self.lo_interfaces:
            i.admin_up()

            if table_id != 0:
                tbl = VppIpTable(self, table_id)
                tbl.add_vpp_config()

            i.set_table_ip4(table_id)
            i.config_ip4()
            table_id += 1

        # Configure namespaces
        self.vapi.app_namespace_add_del(namespace_id="0",
                                        sw_if_index=self.loop0.sw_if_index)
        self.vapi.app_namespace_add_del(namespace_id="1",
                                        sw_if_index=self.loop1.sw_if_index)

    def tearDown(self):
        for i in self.lo_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        self.vapi.session_enable_disable(is_enable=0)
        super(TestUDP, self).tearDown()

    def test_udp_transfer(self):
        """ UDP echo client/server transfer """

        # Add inter-table routes
        ip_t01 = VppIpRoute(self, self.loop1.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=1)])
        ip_t10 = VppIpRoute(self, self.loop0.local_ip4, 32,
                            [VppRoutePath("0.0.0.0",
                                          0xffffffff,
                                          nh_table_id=0)], table_id=1)
        ip_t01.add_vpp_config()
        ip_t10.add_vpp_config()

        # Start builtin server and client
        uri = "udp://" + self.loop0.local_ip4 + "/1234"
        error = self.vapi.cli("test echo server appns 0 fifo-size 4 no-echo" +
                              "uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        error = self.vapi.cli("test echo client mbytes 10 appns 1 " +
                              "fifo-size 4 no-output test-bytes " +
                              "syn-timeout 2 no-return uri " + uri)
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)

        self.logger.debug(self.vapi.cli("show session verbose 2"))

        # Delete inter-table routes
        ip_t01.remove_vpp_config()
        ip_t10.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
