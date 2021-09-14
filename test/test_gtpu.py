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

import socket
from util import ip4_range
import unittest
from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.gtp import GTP_U_Header
from scapy.utils import atol

import util
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX


@tag_fixme_vpp_workers
class TestGtpuUDP(VppTestCase):
    """ GTPU UDP ports Test Case """

    def setUp(self):
        super(TestGtpuUDP, self).setUp()

        self.dport = 2152

        self.ip4_err = 0
        self.ip6_err = 0

        self.create_pg_interfaces(range(1))
        for pg in self.pg_interfaces:
            pg.admin_up()
        self.pg0.config_ip4()
        self.pg0.config_ip6()

    def _check_udp_port_ip4(self, enabled=True):

        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               UDP(sport=self.dport, dport=self.dport, chksum=0))

        self.pg0.add_stream(pkt)
        self.pg_start()

        err = self.statistics.get_counter(
            '/err/ip4-udp-lookup/no_listener')[0]

        if enabled:
            self.assertEqual(err, self.ip4_err)
        else:
            self.assertEqual(err, self.ip4_err + 1)

        self.ip4_err = err

    def _check_udp_port_ip6(self, enabled=True):

        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               UDP(sport=self.dport, dport=self.dport, chksum=0))

        self.pg0.add_stream(pkt)
        self.pg_start()

        err = self.statistics.get_counter(
            '/err/ip6-udp-lookup/no_listener')[0]

        if enabled:
            self.assertEqual(err, self.ip6_err)
        else:
            self.assertEqual(err, self.ip6_err + 1)

        self.ip6_err = err

    def test_udp_port(self):
        """ test UDP ports
        Check if there are no udp listeners before gtpu is enabled
        """
        # UDP ports should be disabled unless a tunnel is configured
        self._check_udp_port_ip4(False)
        self._check_udp_port_ip6(False)

        r = self.vapi.gtpu_add_del_tunnel(is_add=True,
                                          mcast_sw_if_index=0xFFFFFFFF,
                                          decap_next_index=0xFFFFFFFF,
                                          src_address=self.pg0.local_ip4,
                                          dst_address=self.pg0.remote_ip4)

        # UDP port 2152 enabled for ip4
        self._check_udp_port_ip4()

        r = self.vapi.gtpu_add_del_tunnel(is_add=True,
                                          mcast_sw_if_index=0xFFFFFFFF,
                                          decap_next_index=0xFFFFFFFF,
                                          src_address=self.pg0.local_ip6,
                                          dst_address=self.pg0.remote_ip6)

        # UDP port 2152 enabled for ip6
        self._check_udp_port_ip6()

        r = self.vapi.gtpu_add_del_tunnel(is_add=False,
                                          mcast_sw_if_index=0xFFFFFFFF,
                                          decap_next_index=0xFFFFFFFF,
                                          src_address=self.pg0.local_ip4,
                                          dst_address=self.pg0.remote_ip4)

        r = self.vapi.gtpu_add_del_tunnel(is_add=False,
                                          mcast_sw_if_index=0xFFFFFFFF,
                                          decap_next_index=0xFFFFFFFF,
                                          src_address=self.pg0.local_ip6,
                                          dst_address=self.pg0.remote_ip6)


class TestGtpu(BridgeDomain, VppTestCase):
    """ GTPU Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding GTPU header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GTP_U_Header(teid=vni, gtp_type=self.gtp_type, length=150) /
                pkt)

    def ip_range(self, start, end):
        """ range of remote ip's """
        return ip4_range(self.pg0.remote_ip4, start, end)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding GTPU header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac) /
                IP(src=src_ip, dst=self.mcast_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GTP_U_Header(teid=vni, gtp_type=self.gtp_type, length=150) /
                pkt)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing GTPU header
        """
        return pkt[GTP_U_Header].payload

    # Method for checking GTPU encapsulation.
    #
    def check_encapsulation(self, pkt, vni, local_only=False, mcast_pkt=False):
        # Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.local_mac)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[Ether].dst, self.pg0.remote_mac)
            else:
                self.assertEqual(pkt[Ether].dst, type(self).mcast_mac)
        # Verify GTPU tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is GTPU 2152, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # Verify teid
        self.assertEqual(pkt[GTP_U_Header].teid, vni)

    def test_encap(self):
        """ Encapsulation test
        Send frames from pg1
        Verify receipt of encapsulated frames on pg0
        """
        self.pg1.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt, self.single_tunnel_vni)

        # payload = self.decapsulate(pkt)
        # self.assert_eq_pkts(payload, self.frame_reply)

    def test_ucast_flood(self):
        """ Unicast flood test
        Send frames from pg3
        Verify receipt of encapsulated frames on pg0
        """
        self.pg3.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Get packet from each tunnel and assert it's correctly encapsulated.
        out = self.pg0.get_capture(self.n_ucast_tunnels)
        for pkt in out:
            self.check_encapsulation(pkt, self.ucast_flood_bd, True)
            # payload = self.decapsulate(pkt)
            # self.assert_eq_pkts(payload, self.frame_reply)

    def test_mcast_flood(self):
        """ Multicast flood test
        Send frames from pg2
        Verify receipt of encapsulated frames on pg0
        """
        self.pg2.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt, self.mcast_flood_bd,
                                 local_only=False, mcast_pkt=True)

        # payload = self.decapsulate(pkt)
        # self.assert_eq_pkts(payload, self.frame_reply)

    @classmethod
    def create_gtpu_flood_test_bd(cls, teid, n_ucast_tunnels):
        # Create 10 ucast gtpu tunnels under bd
        ip_range_start = 10
        ip_range_end = ip_range_start + n_ucast_tunnels
        next_hop_address = cls.pg0.remote_ip4
        for dest_ip4 in ip4_range(next_hop_address, ip_range_start,
                                  ip_range_end):
            # add host route so dest_ip4 will not be resolved
            rip = VppIpRoute(cls, dest_ip4, 32,
                             [VppRoutePath(next_hop_address,
                                           INVALID_INDEX)],
                             register=False)
            rip.add_vpp_config()
            r = cls.vapi.gtpu_add_del_tunnel(
                is_add=True,
                mcast_sw_if_index=0xFFFFFFFF,
                decap_next_index=0xFFFFFFFF,
                src_address=cls.pg0.local_ip4,
                dst_address=dest_ip4,
                teid=teid)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=teid)

    @classmethod
    def add_del_shared_mcast_dst_load(cls, is_add):
        """
        add or del tunnels sharing the same mcast dst
        to test gtpu ref_count mechanism
        """
        n_shared_dst_tunnels = 20
        teid_start = 1000
        teid_end = teid_start + n_shared_dst_tunnels
        for teid in range(teid_start, teid_end):
            r = cls.vapi.gtpu_add_del_tunnel(
                decap_next_index=0xFFFFFFFF,
                src_address=cls.pg0.local_ip4,
                dst_address=cls.mcast_ip4,
                mcast_sw_if_index=1,
                teid=teid,
                is_add=is_add)
            if r.sw_if_index == 0xffffffff:
                raise ValueError("bad sw_if_index: ~0")

    @classmethod
    def add_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=1)

    @classmethod
    def del_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=0)

    @classmethod
    def add_del_mcast_tunnels_load(cls, is_add):
        """
        add or del tunnels to test gtpu stability
        """
        n_distinct_dst_tunnels = 20
        ip_range_start = 10
        ip_range_end = ip_range_start + n_distinct_dst_tunnels
        for dest_ip4 in ip4_range(cls.mcast_ip4, ip_range_start,
                                  ip_range_end):
            teid = int(dest_ip4.split('.')[3])
            cls.vapi.gtpu_add_del_tunnel(
                decap_next_index=0xFFFFFFFF,
                src_address=cls.pg0.local_ip4,
                dst_address=dest_ip4,
                mcast_sw_if_index=1,
                teid=teid,
                is_add=is_add)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the GTPU test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestGtpu, cls).setUpClass()

        try:
            cls.dport = 2152
            cls.gtp_type = 0xff

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv4 addresses on VPP pg0.
            cls.pg0.config_ip4()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_arp()

            # Our Multicast address
            cls.mcast_ip4 = '239.1.1.1'
            cls.mcast_mac = util.mcast_ip_to_mac(cls.mcast_ip4)

            # Create GTPU VTEP on VPP pg0, and put gtpu_tunnel0 and pg1
            #  into BD.
            cls.single_tunnel_bd = 11
            cls.single_tunnel_vni = 11
            r = cls.vapi.gtpu_add_del_tunnel(
                is_add=True,
                mcast_sw_if_index=0xFFFFFFFF,
                decap_next_index=0xFFFFFFFF,
                src_address=cls.pg0.local_ip4,
                dst_address=cls.pg0.remote_ip4,
                teid=cls.single_tunnel_vni)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg1.sw_if_index, bd_id=cls.single_tunnel_bd)

            # Setup teid 2 to test multicast flooding
            cls.n_ucast_tunnels = 10
            cls.mcast_flood_bd = 12
            cls.create_gtpu_flood_test_bd(cls.mcast_flood_bd,
                                          cls.n_ucast_tunnels)
            r = cls.vapi.gtpu_add_del_tunnel(
                is_add=True,
                src_address=cls.pg0.local_ip4,
                dst_address=cls.mcast_ip4,
                mcast_sw_if_index=1,
                decap_next_index=0xFFFFFFFF,
                teid=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg2.sw_if_index, bd_id=cls.mcast_flood_bd)

            # Add and delete mcast tunnels to check stability
            cls.add_shared_mcast_dst_load()
            cls.add_mcast_tunnels_load()
            cls.del_shared_mcast_dst_load()
            cls.del_mcast_tunnels_load()

            # Setup teid 3 to test unicast flooding
            cls.ucast_flood_bd = 13
            cls.create_gtpu_flood_test_bd(cls.ucast_flood_bd,
                                          cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg3.sw_if_index, bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestGtpu, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestGtpu, cls).tearDownClass()

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestGtpu, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show bridge-domain 11 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 12 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 13 detail"))
        self.logger.info(self.vapi.cli("show int"))
        self.logger.info(self.vapi.cli("show gtpu tunnel"))
        self.logger.info(self.vapi.cli("show trace"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
