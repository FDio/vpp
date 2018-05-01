#!/usr/bin/env python

import socket
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.vxlan import VXLAN
from scapy.utils import atol
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import *


class TestVxlan6(BridgeDomain, VppTestCase):
    """ VXLAN over IPv6 Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags) /
                pkt)

    @classmethod
    def ip_range(cls, s, e):
        """ range of remote ip's """
        tmp = cls.pg0.remote_ip6.rsplit(':', 1)[0]
        return ("%s:%x" % (tmp, i) for i in range(s, e))

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac) /
                IPv6(src=src_ip, dst=self.mcast_ip6) /
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
        # Verify VXLAN tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IPv6].src, self.pg0.local_ip6)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IPv6].dst, self.pg0.remote_ip6)
            else:
                self.assertEqual(pkt[IPv6].dst, type(self).mcast_ip6)
        # Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # TODO: checksum check
        # Verify VNI
        self.assertEqual(pkt[VXLAN].vni, vni)

    @classmethod
    def create_vxlan_flood_test_bd(cls, vni, n_ucast_tunnels):
        # Create 10 ucast vxlan tunnels under bd
        start = 10
        end = start + n_ucast_tunnels
        for dest_ip6 in cls.ip_range(start, end):
            dest_ip6n = socket.inet_pton(socket.AF_INET6, dest_ip6)
            # add host route so dest ip will not be resolved
            rip = VppIpRoute(cls, dest_ip6, 128,
                             [VppRoutePath(cls.pg0.remote_ip6, INVALID_INDEX)],
                             register=False)
            rip.add_vpp_config()
            r = cls.vapi.vxlan_add_del_tunnel(
                is_ipv6=1,
                src_addr=cls.pg0.local_ip6n,
                dst_addr=dest_ip6n,
                vni=vni)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan6, cls).setUpClass()

        try:
            cls.dport = 4789
            cls.flags = 0x8

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv4 addresses on VPP pg0.
            cls.pg0.config_ip6()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_ndp()

            cls.mcast_ip6 = 'ff0e::1'
            cls.mcast_ip6n = socket.inet_pton(socket.AF_INET6, cls.mcast_ip6)
            cls.mcast_mac = "33:33:00:00:00:%02x" % (1)

            # Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
            #  into BD.
            cls.single_tunnel_bd = 1
            r = cls.vapi.vxlan_add_del_tunnel(
                is_ipv6=1,
                src_addr=cls.pg0.local_ip6n,
                dst_addr=cls.pg0.remote_ip6n,
                vni=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)

            # Setup vni 2 to test multicast flooding
            cls.n_ucast_tunnels = 10
            cls.mcast_flood_bd = 2
            cls.create_vxlan_flood_test_bd(cls.mcast_flood_bd,
                                           cls.n_ucast_tunnels)
            r = cls.vapi.vxlan_add_del_tunnel(
                mcast_sw_if_index=1,
                src_addr=cls.pg0.local_ip6n,
                dst_addr=cls.mcast_ip6n,
                vni=cls.mcast_flood_bd, is_ipv6=1)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)

            # Setup vni 3 to test unicast flooding
            cls.ucast_flood_bd = 3
            cls.create_vxlan_flood_test_bd(cls.ucast_flood_bd,
                                           cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg3.sw_if_index,
                                                bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestVxlan6, cls).tearDownClass()
            raise

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlan6, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 2 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
            self.logger.info(self.vapi.cli("show vxlan tunnel"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
