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
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, ICMP
from scapy.contrib.geneve import GENEVE

import util
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX


class TestGeneve(BridgeDomain, VppTestCase):
    """ GENEVE Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):

        """
        Encapsulate the original payload frame by adding GENEVE header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GENEVE(vni=vni) /
                pkt)

    def ip_range(self, start, end):
        """ range of remote ip's """
        return ip4_range(self.pg0.remote_ip4, start, end)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding GENEVE header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac) /
                IP(src=src_ip, dst=self.mcast_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GENEVE(vni=vni) /
                pkt)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing GENEVE header
        """
        # check if is set I flag
        # self.assertEqual(pkt[GENEVE].flags, int('0x8', 16))
        return pkt[GENEVE].payload

    # Method for checking GENEVE encapsulation.
    #
    def check_encapsulation(self, pkt, vni, local_only=False, mcast_pkt=False):
        # TODO: add error messages
        # Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.local_mac)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[Ether].dst, self.pg0.remote_mac)
            else:
                self.assertEqual(pkt[Ether].dst, type(self).mcast_mac)
        # Verify GENEVE tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is GENEVE 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # TODO: checksum check
        # Verify VNI
        self.assertEqual(pkt[GENEVE].vni, vni)

    @classmethod
    def create_geneve_flood_test_bd(cls, vni, n_ucast_tunnels):
        # Create 10 ucast geneve tunnels under bd
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
            r = cls.vapi.geneve_add_del_tunnel(
                local_address=cls.pg0.local_ip4, remote_address=dest_ip4,
                vni=vni)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=vni)

    @classmethod
    def add_del_shared_mcast_dst_load(cls, is_add):
        """
        add or del tunnels sharing the same mcast dst
        to test geneve ref_count mechanism
        """
        n_shared_dst_tunnels = 10
        vni_start = 10000
        vni_end = vni_start + n_shared_dst_tunnels
        for vni in range(vni_start, vni_end):
            r = cls.vapi.geneve_add_del_tunnel(
                local_address=cls.pg0.local_ip4,
                remote_address=cls.mcast_ip4, mcast_sw_if_index=1,
                is_add=is_add, vni=vni)
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
        add or del tunnels to test geneve stability
        """
        n_distinct_dst_tunnels = 10
        ip_range_start = 10
        ip_range_end = ip_range_start + n_distinct_dst_tunnels
        for dest_ip4 in ip4_range(cls.mcast_ip4, ip_range_start,
                                  ip_range_end):
            vni = int(dest_ip4.split('.')[3])
            cls.vapi.geneve_add_del_tunnel(local_address=cls.pg0.local_ip4,
                                           remote_address=dest_ip4,
                                           mcast_sw_if_index=1, is_add=is_add,
                                           vni=vni)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the GENEVE test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestGeneve, cls).setUpClass()

        try:
            cls.dport = 6081

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

            # Create GENEVE VTEP on VPP pg0, and put geneve_tunnel0 and pg1
            #  into BD.
            cls.single_tunnel_vni = 0xabcde
            cls.single_tunnel_bd = 1
            r = cls.vapi.geneve_add_del_tunnel(
                local_address=cls.pg0.local_ip4,
                remote_address=cls.pg0.remote_ip4, vni=cls.single_tunnel_vni)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg1.sw_if_index, bd_id=cls.single_tunnel_bd)

            # Setup vni 2 to test multicast flooding
            cls.n_ucast_tunnels = 10
            cls.mcast_flood_bd = 2
            cls.create_geneve_flood_test_bd(cls.mcast_flood_bd,
                                            cls.n_ucast_tunnels)
            r = cls.vapi.geneve_add_del_tunnel(
                local_address=cls.pg0.local_ip4,
                remote_address=cls.mcast_ip4, mcast_sw_if_index=1,
                vni=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg2.sw_if_index, bd_id=cls.mcast_flood_bd)

            # Add and delete mcast tunnels to check stability
            cls.add_shared_mcast_dst_load()
            cls.add_mcast_tunnels_load()
            cls.del_shared_mcast_dst_load()
            cls.del_mcast_tunnels_load()

            # Setup vni 3 to test unicast flooding
            cls.ucast_flood_bd = 3
            cls.create_geneve_flood_test_bd(cls.ucast_flood_bd,
                                            cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg3.sw_if_index, bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestGeneve, cls).tearDownClass()
            raise

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestGeneve, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 2 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
        self.logger.info(self.vapi.cli("show geneve tunnel"))


class TestGeneveL3(VppTestCase):
    """ GENEVE L3 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestGeneveL3, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()
        except Exception:
            super(TestGeneveL3, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestGeneveL3, cls).tearDownClass()

    def tearDown(self):
        super(TestGeneveL3, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show geneve tunnel"))
        self.logger.info(self.vapi.cli("show ip neighbor"))

    def test_l3_packet(self):
        vni = 1234
        r = self.vapi.add_node_next(node_name="geneve4-input",
                                    next_name="ethernet-input")
        r = self.vapi.geneve_add_del_tunnel2(
            is_add=1,
            local_address=self.pg0.local_ip4,
            remote_address=self.pg0.remote_ip4,
            vni=vni,
            l3_mode=1,
            decap_next_index=r.next_index)

        self.vapi.sw_interface_add_del_address(
            sw_if_index=r.sw_if_index, prefix="10.0.0.1/24")

        pkt = (Ether(src=self.pg0.remote_mac, dst="d0:0b:ee:d0:00:00") /
               IP(src='10.0.0.2', dst='10.0.0.1') /
               ICMP())

        encap = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                 UDP(sport=6081, dport=6081, chksum=0) /
                 GENEVE(vni=vni))

        arp = (Ether(src=self.pg0.remote_mac, dst="d0:0b:ee:d0:00:00") /
               ARP(op="is-at", hwsrc=self.pg0.remote_mac,
                   hwdst="d0:0b:ee:d0:00:00", psrc="10.0.0.2",
                   pdst="10.0.0.1"))

        rx = self.send_and_expect(self.pg0, encap/pkt*1, self.pg0)
        rx = self.send_and_assert_no_replies(self.pg0, encap/arp*1, self.pg0)
        rx = self.send_and_expect(self.pg0, encap/pkt*1, self.pg0)
        self.assertEqual(rx[0][ICMP].type, 0)  # echo reply

        r = self.vapi.geneve_add_del_tunnel2(
            is_add=0,
            local_address=self.pg0.local_ip4,
            remote_address=self.pg0.remote_ip4,
            vni=vni)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
