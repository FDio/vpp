#!/usr/bin/env python3

import socket
from util import ip4_range, reassemble4_ether
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN

from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX


class TestVxlanGbp(VppTestCase):
    """ VXLAN GBP Test Case """

    dport = 48879
    I_flag = 0x8
    G_flag = 0x80
    flags = I_flag | G_flag
    gpflags = 0x0
    sclass = 0

    @property
    def frame_request(self):
        """ Ethernet frame modeling a generic request """
        return (Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
                IP(src='1.2.3.4', dst='4.3.2.1') /
                UDP(sport=10000, dport=20000) /
                Raw(b'\xa5' * 100))

    @property
    def frame_reply(self):
        """ Ethernet frame modeling a generic reply """
        return (Ether(src='00:00:00:00:00:02', dst='00:00:00:00:00:01') /
                IP(src='4.3.2.1', dst='1.2.3.4') /
                UDP(sport=20000, dport=10000) /
                Raw(b'\xa5' * 100))

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding VXLAN GBP header with
        its UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=vni, flags=self.flags, gpflags=self.gpflags,
                gpid=self.sclass) / pkt)

    def ip_range(self, start, end):
        """ range of remote ip's """
        return ip4_range(self.pg0.remote_ip4, start, end)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN header
        """
        # check if is set G and I flag
        self.assertEqual(pkt[VXLAN].flags, self.flags)
        return pkt[VXLAN].payload

    # Method for checking VXLAN GBP encapsulation.
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
        # Verify VXLAN GBP tunnel source IP is VPP_IP and destination IP is
        # MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is VXLAN GBP 48879, source UDP port could
        # be arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # Verify UDP checksum
        self.assert_udp_checksum_valid(pkt)
        # Verify VNI
        # pkt.show()
        self.assertEqual(pkt[VXLAN].vni, vni)
        # Verify Source Class
        self.assertEqual(pkt[VXLAN].gpid, 0)

    @classmethod
    def create_vxlan_gbp_flood_test_bd(cls, vni, n_ucast_tunnels, *,
                                       ip_range_start=10):
        # Create 2 ucast vxlan tunnels under bd

        ip_range_end = ip_range_start + n_ucast_tunnels
        next_hop_address = cls.pg0.remote_ip4
        for dest_ip4 in ip4_range(cls.pg0.remote_ip4,
                                  ip_range_start,
                                  ip_range_end):
            # add host route so dest_ip4 will not be resolved
            rip = VppIpRoute(cls, dest_ip4, 32,
                             [VppRoutePath(next_hop_address,
                                           INVALID_INDEX)],
                             register=False)
            rip.add_vpp_config()
            r = cls.vapi.vxlan_gbp_tunnel_add_del(
                tunnel={
                    'src': cls.pg0.local_ip4,
                    'dst': dest_ip4,
                    'vni': vni,
                    'instance': INVALID_INDEX,
                    'mcast_sw_if_index': INVALID_INDEX,
                    'mode': 1,
                },
                is_add=1
            )
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=vni)

    # Class method to start the VXLAN GBP test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlanGbp, cls).setUpClass()

        try:

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv4 addresses on VPP pg0.
            cls.pg0.config_ip4()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_arp()

            # Create VXLAN GBP VTEP on VPP pg0, and put vxlan_gbp_tunnel0 and
            # pg1 into BD.
            cls.single_tunnel_bd = 1
            cls.single_tunnel_vni = 0xabcde
            r = cls.vapi.vxlan_gbp_tunnel_add_del(
                tunnel={
                    'src': cls.pg0.local_ip4,
                    'dst': cls.pg0.remote_ip4,
                    'vni': cls.single_tunnel_vni,
                    'instance': INVALID_INDEX,
                    'mcast_sw_if_index': INVALID_INDEX,
                    'mode': 1,
                },
                is_add=1
            )
            cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg1.sw_if_index,
                bd_id=cls.single_tunnel_bd)

            # Setup vni 2 to test multicast flooding
            cls.n_ucast_tunnels = 2
            # Setup vni 3 to test unicast flooding
            cls.ucast_flood_bd = 3
            cls.create_vxlan_gbp_flood_test_bd(cls.ucast_flood_bd,
                                               cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg3.sw_if_index,
                bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestVxlanGbp, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestVxlanGbp, cls).tearDownClass()

    def assert_eq_pkts(self, pkt1, pkt2):
        """ Verify the Ether, IP, UDP, payload are equal in both
        packets
        """
        self.assertEqual(pkt1[Ether].src, pkt2[Ether].src)
        self.assertEqual(pkt1[Ether].dst, pkt2[Ether].dst)
        self.assertEqual(pkt1[IP].src, pkt2[IP].src)
        self.assertEqual(pkt1[IP].dst, pkt2[IP].dst)
        self.assertEqual(pkt1[UDP].sport, pkt2[UDP].sport)
        self.assertEqual(pkt1[UDP].dport, pkt2[UDP].dport)
        self.assertEqual(pkt1[Raw], pkt2[Raw])

    def test_decap(self):
        """ Decapsulation test
        Send encapsulated frames from pg0
        Verify receipt of decapsulated frames on pg1
        """
        encapsulated_pkt = self.encapsulate(self.frame_request,
                                            self.single_tunnel_vni)

        self.pg0.add_stream([encapsulated_pkt, ])

        self.pg1.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's the non-encapsulated
        # frame
        out = self.pg1.get_capture(1)
        pkt = out[0]
        print(out)
        self.assert_eq_pkts(pkt, self.frame_request)

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

        payload = self.decapsulate(pkt)
        self.assert_eq_pkts(payload, self.frame_reply)

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
            payload = self.decapsulate(pkt)
            self.assert_eq_pkts(payload, self.frame_reply)

    def test_encap_big_packet(self):
        """ Encapsulation test send MTU 1500 frame from pg1
        Verify receipt of encapsulated frames on pg0
        """

        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [1500, 0, 0, 0])

        frame = (Ether(src='00:00:00:00:00:02', dst='00:00:00:00:00:01') /
                 IP(src='4.3.2.1', dst='1.2.3.4') /
                 UDP(sport=20000, dport=10000) /
                 Raw(b'\xa5' * 1450))

        self.pg1.add_stream([frame])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(2)
        pkt = reassemble4_ether(out)
        self.check_encapsulation(pkt, self.single_tunnel_vni)

        payload = self.decapsulate(pkt)
        self.assert_eq_pkts(payload, frame)

# Method to define VPP actions before tear down of the test case.
#  Overrides tearDown method in VppTestCase class.
#  @param self The object pointer.
    def tearDown(self):
        super(TestVxlanGbp, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
        self.logger.info(self.vapi.cli("show vxlan-gbp tunnel"))
        self.logger.info(self.vapi.cli("show error"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
