#!/usr/bin/env python3

import socket
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet6 import IP, IPv6, UDP
from scapy.layers.vxlan import VXLAN

import util
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_vxlan_tunnel import VppVxlanTunnel
from vpp_ip import INVALID_INDEX


class TestVxlan6(BridgeDomain, VppTestCase):
    """ VXLAN over IPv6 Test Case """

    dport = 4789
    I_flag = 0x8
    flags = I_flag

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
        self.assertEqual(pkt[VXLAN].flags, self.flags)
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
        # Verify UDP checksum
        self.assert_udp_checksum_valid(pkt, ignore_zero_checksum=False)
        # Verify VNI
        self.assertEqual(pkt[VXLAN].vni, vni)

    @classmethod
    def create_vxlan_flood_test_bd(cls, vni, n_ucast_tunnels):
        # Create 10 ucast vxlan tunnels under bd
        start = 10
        end = start + n_ucast_tunnels
        for dest_ip6 in cls.ip_range(start, end):
            # add host route so dest ip will not be resolved
            rip = VppIpRoute(cls, dest_ip6, 128,
                             [VppRoutePath(cls.pg0.remote_ip6, INVALID_INDEX)],
                             register=False)
            rip.add_vpp_config()
            r = VppVxlanTunnel(cls, src=cls.pg0.local_ip6,
                               dst=dest_ip6, vni=vni)
            r.add_vpp_config()
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls._add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls._add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan6, cls).setUpClass()

        try:

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv6 addresses on VPP pg0.
            cls.pg0.config_ip6()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_ndp()

            # Our Multicast address
            cls.mcast_ip6 = 'ff0e::1'
            cls.mcast_mac = util.mcast_ip_to_mac(cls.mcast_ip6)
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestVxlan6, cls).tearDownClass()

    def setUp(self):
        super(TestVxlan6, self).setUp()
        # Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
        #  into BD.

        # needed for BridgeDomain tests
        self.single_tunnel_vni = 0x12345

        self.single_tunnel_bd = 1
        self.vni1 = VppVxlanTunnel(self, src=self.pg0.local_ip6,
                                   dst=self.pg0.remote_ip6,
                                   vni=self.single_tunnel_vni)
        self.vni1.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vni1.sw_if_index,
            bd_id=self.single_tunnel_bd)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index,
            bd_id=self.single_tunnel_bd)

        # Setup vni 2 to test multicast flooding
        self.n_ucast_tunnels = 10
        self.mcast_flood_bd = 2
        self.create_vxlan_flood_test_bd(self.mcast_flood_bd,
                                        self.n_ucast_tunnels)
        self.vni2 = VppVxlanTunnel(self, src=self.pg0.local_ip6,
                                   dst=self.mcast_ip6,
                                   vni=self.mcast_flood_bd,
                                   mcast_sw_if_index=1)
        self.vni2.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vni2.sw_if_index, bd_id=self.mcast_flood_bd)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.mcast_flood_bd)

        # Setup vni 3 to test unicast flooding
        self.ucast_flood_bd = 3
        self.create_vxlan_flood_test_bd(self.ucast_flood_bd,
                                        self.n_ucast_tunnels)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg3.sw_if_index, bd_id=self.ucast_flood_bd)

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlan6, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 2 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
        self.logger.info(self.vapi.cli("show vxlan tunnel"))

    def test_encap_fragmented_packet(self):
        """ Encapsulation test send fragments from pg1
        Verify receipt of encapsulated frames on pg0
        """

        frame = (Ether(src='00:00:00:00:00:02', dst='00:00:00:00:00:01') /
                 IP(src='4.3.2.1', dst='1.2.3.4') /
                 UDP(sport=20000, dport=10000) /
                 Raw(b'\xa5' * 1000))

        frags = util.fragment_rfc791(frame, 400)

        self.pg1.add_stream(frags)

        self.pg0.enable_capture()

        self.pg_start()

        out = self.pg0.get_capture(3)

        payload = []
        for pkt in out:
            payload.append(self.decapsulate(pkt))
            self.check_encapsulation(pkt, self.single_tunnel_vni)

        reassembled = util.reassemble4(payload)

        self.assertEqual(Ether(raw(frame))[IP], reassembled[IP])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
