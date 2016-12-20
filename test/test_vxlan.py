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

    def encap_mcast(self, pkt, src_ipn, src_mac, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        src_ip = '.'.join(str(i) for i in bytearray(src_ipn))
        mcast_ip4 = '239.1.1.1'
        iplong = atol(mcast_ip4)
        mcast_mac = "01:00:5e:%02x:%02x:%02x" % ( (iplong>>16)&0x7F, (iplong>>8)&0xFF, (iplong)&0xFF )
        return (Ether(src=src_mac, dst=mcast_mac) /
                IP(src=src_ip, dst=mcast_ip4) /
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
    def check_encapsulation(self, pkt):
        # TODO: add error messages
        # Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.local_mac)
        self.assertEqual(pkt[Ether].dst, self.pg0.remote_mac)
        # Verify VXLAN tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
        # Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # TODO: checksum check
        # Verify VNI, based on configuration it must be 1.
        self.assertEqual(pkt[VXLAN].vni, type(self).vni)

    @classmethod
    def ip4_range(cls, ip4n, s=10, e=20):
        base = str(bytearray(ip4n)[:3])
        return ((base + ip) for ip in str(bytearray(range(s, e))))

    @classmethod
    def create_vxlan_flood_test_bd(cls, vni):
        # Create 10 ucast vxlan tunnels under bd
        next_hop_address = cls.pg0.remote_ip4n
        for dest_addr in cls.ip4_range(next_hop_address, 10, 20):
            # add host route so dest_addr will not be resolved
            cls.vapi.ip_add_del_route(dest_addr, 32, next_hop_address)
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_addr,
                vni=vni)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

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
            cls.vni = 1

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv4 addresses on VPP pg0.
            cls.pg0.config_ip4()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_arp()

            # Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
            #  into BD.
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.pg0.remote_ip4n,
                vni=cls.vni)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=1)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index, bd_id=1)

            # Setup vni 2 to test multicast flooding
            cls.create_vxlan_flood_test_bd(2)
            r = cls.vapi.vxlan_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=socket.inet_pton(socket.AF_INET, '239.1.1.1'),
                mcast_sw_if_index=1,
                vni=2)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=2)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2.sw_if_index, bd_id=2)

            # Setup vni 3 to test unicast flooding
            cls.create_vxlan_flood_test_bd(3)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg3.sw_if_index, bd_id=3)
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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
