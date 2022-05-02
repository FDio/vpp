#!/usr/bin/env python3

import socket
from util import ip4_range, reassemble4
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
from scapy.packet import Raw, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN

import util
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_vxlan_tunnel import VppVxlanTunnel
from vpp_ip import INVALID_INDEX
from vpp_neighbor import VppNeighbor


class TestVxlan(BridgeDomain, VppTestCase):
    """VXLAN Test Case"""

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / UDP(sport=self.dport, dport=self.dport, chksum=0)
            / VXLAN(vni=vni, flags=self.flags)
            / pkt
        )

    def ip_range(self, start, end):
        """range of remote ip's"""
        return ip4_range(self.pg0.remote_ip4, start, end)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding VXLAN header with its
        UDP, IP and Ethernet fields
        """
        return (
            Ether(src=src_mac, dst=self.mcast_mac)
            / IP(src=src_ip, dst=self.mcast_ip4)
            / UDP(sport=self.dport, dport=self.dport, chksum=0)
            / VXLAN(vni=vni, flags=self.flags)
            / pkt
        )

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN header
        """
        # check if is set I flag
        self.assertEqual(pkt[VXLAN].flags, int("0x8", 16))
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
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, self.dport)
        # Verify UDP checksum
        self.assert_udp_checksum_valid(pkt)
        # Verify VNI
        self.assertEqual(pkt[VXLAN].vni, vni)

    @classmethod
    def create_vxlan_flood_test_bd(cls, vni, n_ucast_tunnels, port):
        # Create 10 ucast vxlan tunnels under bd
        ip_range_start = 10
        ip_range_end = ip_range_start + n_ucast_tunnels
        next_hop_address = cls.pg0.remote_ip4
        for dest_ip4 in ip4_range(next_hop_address, ip_range_start, ip_range_end):
            # add host route so dest_ip4 will not be resolved
            rip = VppIpRoute(
                cls,
                dest_ip4,
                32,
                [VppRoutePath(next_hop_address, INVALID_INDEX)],
                register=False,
            )
            rip.add_vpp_config()

            r = VppVxlanTunnel(
                cls,
                src=cls.pg0.local_ip4,
                src_port=port,
                dst_port=port,
                dst=dest_ip4,
                vni=vni,
            )
            r.add_vpp_config()
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=vni)

    @classmethod
    def add_del_shared_mcast_dst_load(cls, port, is_add):
        """
        add or del tunnels sharing the same mcast dst
        to test vxlan ref_count mechanism
        """
        n_shared_dst_tunnels = 20
        vni_start = 10000
        vni_end = vni_start + n_shared_dst_tunnels
        for vni in range(vni_start, vni_end):
            r = VppVxlanTunnel(
                cls,
                src=cls.pg0.local_ip4,
                src_port=port,
                dst_port=port,
                dst=cls.mcast_ip4,
                mcast_sw_if_index=1,
                vni=vni,
            )
            if is_add:
                r.add_vpp_config()
                if r.sw_if_index == 0xFFFFFFFF:
                    raise ValueError("bad sw_if_index: ~0")
            else:
                r.remove_vpp_config()

    @classmethod
    def add_shared_mcast_dst_load(cls, port):
        cls.add_del_shared_mcast_dst_load(port=port, is_add=1)

    @classmethod
    def del_shared_mcast_dst_load(cls, port):
        cls.add_del_shared_mcast_dst_load(port=port, is_add=0)

    @classmethod
    def add_del_mcast_tunnels_load(cls, port, is_add):
        """
        add or del tunnels to test vxlan stability
        """
        n_distinct_dst_tunnels = 200
        ip_range_start = 10
        ip_range_end = ip_range_start + n_distinct_dst_tunnels
        for dest_ip4 in ip4_range(cls.mcast_ip4, ip_range_start, ip_range_end):
            vni = bytearray(socket.inet_pton(socket.AF_INET, dest_ip4))[3]
            r = VppVxlanTunnel(
                cls,
                src=cls.pg0.local_ip4,
                src_port=port,
                dst_port=port,
                dst=dest_ip4,
                mcast_sw_if_index=1,
                vni=vni,
            )
            if is_add:
                r.add_vpp_config()
            else:
                r.remove_vpp_config()

    @classmethod
    def add_mcast_tunnels_load(cls, port):
        cls.add_del_mcast_tunnels_load(port=port, is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls, port):
        cls.add_del_mcast_tunnels_load(port=port, is_add=0)

    # Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()

        try:
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
            cls.mcast_ip4 = "239.1.1.1"
            cls.mcast_mac = util.mcast_ip_to_mac(cls.mcast_ip4)
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestVxlan, cls).tearDownClass()

    def setUp(self):
        super(TestVxlan, self).setUp()

    def createVxLANInterfaces(self, port=4789):
        # Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
        #  into BD.
        self.dport = port

        self.single_tunnel_vni = 0x12345
        self.single_tunnel_bd = 1
        r = VppVxlanTunnel(
            self,
            src=self.pg0.local_ip4,
            dst=self.pg0.remote_ip4,
            src_port=self.dport,
            dst_port=self.dport,
            vni=self.single_tunnel_vni,
        )
        r.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=r.sw_if_index, bd_id=self.single_tunnel_bd
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=self.single_tunnel_bd
        )

        # Setup vni 2 to test multicast flooding
        self.n_ucast_tunnels = 10
        self.mcast_flood_bd = 2
        self.create_vxlan_flood_test_bd(
            self.mcast_flood_bd, self.n_ucast_tunnels, self.dport
        )
        r = VppVxlanTunnel(
            self,
            src=self.pg0.local_ip4,
            dst=self.mcast_ip4,
            src_port=self.dport,
            dst_port=self.dport,
            mcast_sw_if_index=1,
            vni=self.mcast_flood_bd,
        )
        r.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=r.sw_if_index, bd_id=self.mcast_flood_bd
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg2.sw_if_index, bd_id=self.mcast_flood_bd
        )

        # Add and delete mcast tunnels to check stability
        self.add_shared_mcast_dst_load(self.dport)
        self.add_mcast_tunnels_load(self.dport)
        self.del_shared_mcast_dst_load(self.dport)
        self.del_mcast_tunnels_load(self.dport)

        # Setup vni 3 to test unicast flooding
        self.ucast_flood_bd = 3
        self.create_vxlan_flood_test_bd(
            self.ucast_flood_bd, self.n_ucast_tunnels, self.dport
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg3.sw_if_index, bd_id=self.ucast_flood_bd
        )

        # Set scapy listen custom port for VxLAN
        bind_layers(UDP, VXLAN, dport=self.dport)

    def encap_big_packet(self):
        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [1500, 0, 0, 0])

        frame = (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / IP(src="4.3.2.1", dst="1.2.3.4")
            / UDP(sport=20000, dport=10000)
            / Raw(b"\xa5" * 1450)
        )

        self.pg1.add_stream([frame])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(2)
        ether = out[0]
        pkt = reassemble4(out)
        pkt = ether / pkt
        self.check_encapsulation(pkt, self.single_tunnel_vni)

        payload = self.decapsulate(pkt)
        # TODO: Scapy bug?
        # self.assert_eq_pkts(payload, frame)

    """
    Tests with default port (4789)
    """

    def test_decap(self):
        """Decapsulation test
        from BridgeDoman
        """
        self.createVxLANInterfaces()
        super(TestVxlan, self).test_decap()

    def test_encap(self):
        """Encapsulation test
        from BridgeDoman
        """
        self.createVxLANInterfaces()
        super(TestVxlan, self).test_encap()

    def test_encap_big_packet(self):
        """Encapsulation test send big frame from pg1
        Verify receipt of encapsulated frames on pg0
        """
        self.createVxLANInterfaces()
        self.encap_big_packet()

    def test_ucast_flood(self):
        """Unicast flood test
        from BridgeDoman
        """
        self.createVxLANInterfaces()
        super(TestVxlan, self).test_ucast_flood()

    def test_mcast_flood(self):
        """Multicast flood test
        from BridgeDoman
        """
        self.createVxLANInterfaces()
        super(TestVxlan, self).test_mcast_flood()

    def test_mcast_rcv(self):
        """Multicast receive test
        from BridgeDoman
        """
        self.createVxLANInterfaces()
        super(TestVxlan, self).test_mcast_rcv()

    """
    Tests with custom port
    """

    def test_decap_custom_port(self):
        """Decapsulation test custom port
        from BridgeDoman
        """
        self.createVxLANInterfaces(1111)
        super(TestVxlan, self).test_decap()

    def test_encap_custom_port(self):
        """Encapsulation test custom port
        from BridgeDoman
        """
        self.createVxLANInterfaces(1111)
        super(TestVxlan, self).test_encap()

    def test_ucast_flood_custom_port(self):
        """Unicast flood test custom port
        from BridgeDoman
        """
        self.createVxLANInterfaces(1111)
        super(TestVxlan, self).test_ucast_flood()

    def test_mcast_flood_custom_port(self):
        """Multicast flood test custom port
        from BridgeDoman
        """
        self.createVxLANInterfaces(1111)
        super(TestVxlan, self).test_mcast_flood()

    def test_mcast_rcv_custom_port(self):
        """Multicast receive test custom port
        from BridgeDoman
        """
        self.createVxLANInterfaces(1111)
        super(TestVxlan, self).test_mcast_rcv()

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.

    def tearDown(self):
        super(TestVxlan, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show bridge-domain 1 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 2 detail"))
        self.logger.info(self.vapi.cli("show bridge-domain 3 detail"))
        self.logger.info(self.vapi.cli("show vxlan tunnel"))


class TestVxlan2(VppTestCase):
    """VXLAN Test Case"""

    def setUp(self):
        super(TestVxlan2, self).setUp()

        # Create 2 pg interfaces.
        self.create_pg_interfaces(range(4))
        for pg in self.pg_interfaces:
            pg.admin_up()

        # Configure IPv4 addresses on VPP pg0.
        self.pg0.config_ip4()
        self.pg0.resolve_arp()

    def tearDown(self):
        super(TestVxlan2, self).tearDown()

    def test_xconnect(self):
        """VXLAN source address not local"""

        #
        # test the broken configuration of a VXLAN tunnel whose
        # source address is not local ot the box. packets sent
        # through the tunnel should be dropped
        #
        t = VppVxlanTunnel(self, src="10.0.0.5", dst=self.pg0.local_ip4, vni=1000)
        t.add_vpp_config()
        t.admin_up()

        self.vapi.sw_interface_set_l2_xconnect(
            t.sw_if_index, self.pg1.sw_if_index, enable=1
        )
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg1.sw_if_index, t.sw_if_index, enable=1
        )

        p = (
            Ether(src="00:11:22:33:44:55", dst="00:00:00:11:22:33")
            / IP(src="4.3.2.1", dst="1.2.3.4")
            / UDP(sport=20000, dport=10000)
            / Raw(b"\xa5" * 1450)
        )

        rx = self.send_and_assert_no_replies(self.pg1, [p])


class TestVxlanL2Mode(VppTestCase):
    """VXLAN Test Case"""

    def setUp(self):
        super(TestVxlanL2Mode, self).setUp()

        # Create 2 pg interfaces.
        self.create_pg_interfaces(range(2))
        for pg in self.pg_interfaces:
            pg.admin_up()

        # Configure IPv4 addresses on VPP pg0.
        self.pg0.config_ip4()
        self.pg0.resolve_arp()

        # Configure IPv4 addresses on VPP pg1.
        self.pg1.config_ip4()

    def tearDown(self):
        super(TestVxlanL2Mode, self).tearDown()

    def test_l2_mode(self):
        """VXLAN L2 mode"""
        t = VppVxlanTunnel(
            self, src=self.pg0.local_ip4, dst=self.pg0.remote_ip4, vni=1000, is_l3=False
        )
        t.add_vpp_config()
        t.config_ip4()
        t.admin_up()

        dstIP = t.local_ip4[:-1] + "2"

        # Create a packet to send
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IP(src=self.pg1.local_ip4, dst=dstIP)
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )

        # Expect ARP request
        rx = self.send_and_expect(self.pg1, [p], self.pg0)
        for p in rx:
            self.assertEqual(p[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(p[Ether].src, self.pg0.local_mac)
            self.assertEqual(p[ARP].op, 1)
            self.assertEqual(p[ARP].pdst, dstIP)

        # Resolve ARP
        VppNeighbor(self, t.sw_if_index, self.pg1.remote_mac, dstIP).add_vpp_config()

        # Send packets
        NUM_PKTS = 128
        rx = self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)
        self.assertEqual(NUM_PKTS, len(rx))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
