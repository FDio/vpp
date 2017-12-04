#!/usr/bin/env python

import socket
from util import ip4n_range
import unittest
from framework import VppTestCase, VppTestRunner, running_extended_tests
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN
from scapy.utils import atol


@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class TestVxlanGpe(BridgeDomain, VppTestCase):
    """ VXLAN-GPE Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding VXLAN-GPE header
        with its UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags) /
                pkt)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding VXLAN-GPE header
        with its UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac) /
                IP(src=src_ip, dst=self.mcast_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags) /
                pkt)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN-GPE header
        """
        # check if is set I and P flag
        self.assertEqual(pkt[VXLAN].flags, 0x0c)
        return pkt[VXLAN].payload

    # Method for checking VXLAN-GPE encapsulation.
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
        # Verify VXLAN-GPE tunnel src IP is VPP_IP and dst IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is VXLAN-GPE 4790, source UDP port
        #  could be arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # Verify VNI
        self.assertEqual(pkt[VXLAN].vni, vni)

    @classmethod
    def create_vxlan_gpe_flood_test_bd(cls, vni, n_ucast_tunnels):
        # Create 10 ucast vxlan_gpe tunnels under bd
        ip_range_start = 10
        ip_range_end = ip_range_start + n_ucast_tunnels
        next_hop_address = cls.pg0.remote_ip4n
        for dest_ip4n in ip4n_range(next_hop_address, ip_range_start,
                                    ip_range_end):
            # add host route so dest_ip4n will not be resolved
            cls.vapi.ip_add_del_route(dest_ip4n, 32, next_hop_address)
            r = cls.vapi.vxlan_gpe_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_ip4n,
                vni=vni)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

    @classmethod
    def add_del_shared_mcast_dst_load(cls, is_add):
        """
        add or del tunnels sharing the same mcast dst
        to test vxlan_gpe ref_count mechanism
        """
        n_shared_dst_tunnels = 20
        vni_start = 1000
        vni_end = vni_start + n_shared_dst_tunnels
        for vni in range(vni_start, vni_end):
            r = cls.vapi.vxlan_gpe_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.mcast_ip4n,
                mcast_sw_if_index=1,
                vni=vni,
                is_add=is_add)
            if r.sw_if_index == 0xffffffff:
                raise "bad sw_if_index"

    @classmethod
    def add_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=1)

    @classmethod
    def del_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=0)

    @classmethod
    def add_del_mcast_tunnels_load(cls, is_add):
        """
        add or del tunnels to test vxlan_gpe stability
        """
        n_distinct_dst_tunnels = 20
        ip_range_start = 10
        ip_range_end = ip_range_start + n_distinct_dst_tunnels
        for dest_ip4n in ip4n_range(cls.mcast_ip4n, ip_range_start,
                                    ip_range_end):
            vni = bytearray(dest_ip4n)[3]
            cls.vapi.vxlan_gpe_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_ip4n,
                mcast_sw_if_index=1,
                vni=vni,
                is_add=is_add)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the VXLAN-GPE test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlanGpe, cls).setUpClass()

        try:
            cls.dport = 4790
            cls.flags = 0x0c

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
            cls.mcast_ip4n = socket.inet_pton(socket.AF_INET, cls.mcast_ip4)
            iplong = atol(cls.mcast_ip4)
            cls.mcast_mac = "01:00:5e:%02x:%02x:%02x" % (
                (iplong >> 16) & 0x7F, (iplong >> 8) & 0xFF, iplong & 0xFF)

            # Create VXLAN-GPE VTEP on VPP pg0, and put vxlan_gpe_tunnel0
            # and pg1 into BD.
            cls.single_tunnel_bd = 11
            r = cls.vapi.vxlan_gpe_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.pg0.remote_ip4n,
                vni=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)

            # Setup vni 2 to test multicast flooding
            cls.n_ucast_tunnels = 10
            cls.mcast_flood_bd = 12
            cls.create_vxlan_gpe_flood_test_bd(cls.mcast_flood_bd,
                                               cls.n_ucast_tunnels)
            r = cls.vapi.vxlan_gpe_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.mcast_ip4n,
                mcast_sw_if_index=1,
                vni=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)

            # Add and delete mcast tunnels to check stability
            cls.add_shared_mcast_dst_load()
            cls.add_mcast_tunnels_load()
            cls.del_shared_mcast_dst_load()
            cls.del_mcast_tunnels_load()

            # Setup vni 3 to test unicast flooding
            cls.ucast_flood_bd = 13
            cls.create_vxlan_gpe_flood_test_bd(cls.ucast_flood_bd,
                                               cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg3.sw_if_index,
                                                bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestVxlanGpe, cls).tearDownClass()
            raise

    @unittest.skip("test disabled for vxlan-gpe")
    def test_mcast_flood(self):
        """ inherited from BridgeDomain """
        pass

    @unittest.skip("test disabled for vxlan-gpe")
    def test_mcast_rcv(self):
        """ inherited from BridgeDomain """
        pass

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlanGpe, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show bridge-domain 11 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 12 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 13 detail"))
            self.logger.info(self.vapi.cli("show int"))
            self.logger.info(self.vapi.cli("show vxlan-gpe"))
            self.logger.info(self.vapi.cli("show trace"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
