#!/usr/bin/env python

import socket
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN
from scapy.utils import atol


class TestVxlan(BridgeDomain, VppTestCase):
    """ VXLAN Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags) /
                pkt)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac4) /
                IP(src=src_ip, dst=self.mcast_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags) /
                pkt)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN header
        """
        # check if is set I flag
        self.assertEqual(pkt[VXLAN].flags, int('0x8', 16))
        return pkt[VXLAN].payload

    # Method for checking VXLAN encapsulation.
    #
    def check_encapsulation(self, pkt, vni, local_only=False):
        # TODO: add error messages
        # Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.local_mac)
        if not local_only:
            self.assertEqual(pkt[Ether].dst, self.pg0.remote_mac)
        # Verify VXLAN tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
        # Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # TODO: checksum check
        # Verify VNI
        self.assertEqual(pkt[VXLAN].vni, vni)

    @staticmethod
    def ip4_range(ip4n, s=10, e=20):
        base = str(bytearray(ip4n)[:3])
        return ((base + ip) for ip in str(bytearray(range(s, e))))

    @classmethod
    def create_vxlan_flood_test_bd(cls, vni):
        # Create 10 ucast vxlan tunnels under bd
        ip_range_start = 10
        ip_range_end = 20
        next_hop_address = cls.pg0.remote_ip4n
        for dest_addr in cls.ip4_range(next_hop_address, ip_range_start,
                                       ip_range_end):
            # add host route so dest_addr will not be resolved
            cls.vapi.ip_add_del_route(dest_addr, 32, next_hop_address)
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_addr,
                vni=vni)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

    @classmethod
    def add_del_mcast_load(cls, is_add):
        ip_range_start = 10
        ip_range_end = 210
        for dest_addr in cls.ip4_range(cls.mcast_ip4n, ip_range_start,
                                       ip_range_end):
            vni = bytearray(dest_addr)[3]
            cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_addr,
                mcast_sw_if_index=1,
                vni=vni,
                is_add=is_add)

    @classmethod
    def add_mcast_load(cls):
        cls.add_del_mcast_load(is_add=1)

    @classmethod
    def del_mcast_load(cls):
        cls.add_del_mcast_load(is_add=0)

    # Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()

        try:
            cls.dport = 4789
            cls.flags = 0x8

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
            cls.mcast_mac4 = "01:00:5e:%02x:%02x:%02x" % (
                (iplong >> 16) & 0x7F, (iplong >> 8) & 0xFF, iplong & 0xFF)

            # Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
            #  into BD.
            cls.single_tunnel_bd = 1
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.pg0.remote_ip4n,
                vni=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)

            # Setup vni 2 to test multicast flooding
            cls.mcast_flood_bd = 2
            cls.create_vxlan_flood_test_bd(cls.mcast_flood_bd)
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.mcast_ip4n,
                mcast_sw_if_index=1,
                vni=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)

            # Add and delete mcast tunnels to check stability
            cls.add_mcast_load()
            cls.del_mcast_load()

            # Setup vni 3 to test unicast flooding
            cls.ucast_flood_bd = 3
            cls.create_vxlan_flood_test_bd(cls.ucast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg3.sw_if_index,
                                                bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestVxlan, cls).tearDownClass()
            raise

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlan, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 2 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
            self.logger.info(self.vapi.cli("show vxlan tunnel"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
