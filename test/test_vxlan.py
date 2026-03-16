#!/usr/bin/env python3

import socket
from util import ip4_range, reassemble4
import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
from scapy.packet import Raw, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN
from scapy.contrib.mpls import MPLS

import util
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpTable, FibPathType, find_route
from vpp_vxlan_tunnel import VppVxlanTunnel, find_vxlan_tunnel_endpoints
from vpp_ip import INVALID_INDEX
from vpp_neighbor import VppNeighbor
from config import config


@unittest.skipIf("vxlan" in config.excluded_plugins, "Exclude VXLAN plugin tests")
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

    def encap_packets(self):
        def encap_frames(frame, n=10):
            frames = []

            # Provide IP flow hash difference.
            for i in range(n):
                p = frame.copy()
                p[UDP].dport += i
                frames.append(p)

            self.pg1.add_stream(frames)

            self.pg0.enable_capture()
            self.pg_start()

            # Pick received frames and check if they're correctly encapsulated.
            out = self.pg0.get_capture(n)
            sports = set()
            for i in range(n):
                pkt = out[i]
                self.check_encapsulation(pkt, self.single_tunnel_vni)

                payload = self.decapsulate(pkt)
                self.assert_eq_pkts(payload, frames[i])

                sports.add(pkt[UDP].sport)

            # Check src port randomization presence, not concerned with the
            # src ports split ratio, just as long as there are more then one.
            self.assertGreaterEqual(len(sports), min(n, 2))

        frame_ip4 = (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / IP(src="4.3.2.1", dst="1.2.3.4")
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100)
        )
        encap_frames(frame_ip4)

        frame_ip6 = (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / IPv6(src="2001:db8::4321", dst="2001:db8::1234")
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100)
        )
        encap_frames(frame_ip6)

        frame_mpls4 = (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / MPLS(label=44, ttl=64)
            / IP(src="4.3.2.1", dst="1.2.3.4")
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100)
        )
        encap_frames(frame_mpls4)

        frame_mpls6 = (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / MPLS(label=44, ttl=64)
            / IPv6(src="2001:db8::4321", dst="2001:db8::1234")
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100)
        )
        encap_frames(frame_mpls6)

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
        self.encap_packets()

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


@unittest.skipIf("vxlan" in config.excluded_plugins, "Exclude VXLAN plugin tests")
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


@unittest.skipIf("vxlan" in config.excluded_plugins, "Exclude VXLAN plugin tests")
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
        p.dst = self.pg1.local_mac
        rx = self.send_and_expect(self.pg1, p * NUM_PKTS, self.pg0)
        self.assertEqual(NUM_PKTS, len(rx))


class TestVxlanRouting(VppTestCase):
    """VXLAN Routing Test Case"""

    def setUp(self):
        super(TestVxlanRouting, self).setUp()

        # Create pg interface.
        self.create_pg_interfaces(range(1))
        for pg in self.pg_interfaces:
            pg.admin_up()

        # Configure IPv4 addresses on VPP pg0.
        self.pg0.config_ip4()
        self.pg0.resolve_arp()

    def tearDown(self):
        super(TestVxlanRouting, self).tearDown()

    def route_lookup(self, prefix, exact, table_id=0):
        return self.vapi.api(
            self.vapi.papi.ip_route_lookup,
            {
                "table_id": table_id,
                "exact": exact,
                "prefix": prefix,
            },
        )

    def test_dst_tracking(self):
        """VXLAN destination tracking"""

        # Create non-default table
        table = VppIpTable(self, 1, False)
        table.add_vpp_config()

        # Create drop prefix in non-default table
        drop_route = VppIpRoute(
            self,
            "1.1.2.0",
            24,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, type=FibPathType.FIB_PATH_TYPE_DROP)],
            table_id=table.table_id,
        )
        drop_route.add_vpp_config()

        # Create tunnel dst host route via nh in default table
        dst_route = VppIpRoute(
            self,
            "1.1.2.1",
            32,
            [VppRoutePath(self.pg0.remote_ip4, 0xFFFFFFFF, 0)],
            table_id=table.table_id,
        )
        dst_route.add_vpp_config()

        # Create tunnels, using tunnel using dst route tracking
        tunnels = []
        for i in range(3):
            t = VppVxlanTunnel(
                self,
                src=self.pg0.local_ip4,
                dst="1.1.2.1",
                vni=1000 + i,
                encap_vrf_id=table.table_id,
            )
            t.add_vpp_config()
            t.config_ip4()
            t.admin_up()
            tunnels.append(t)

        # Remove first dst host route
        dst_route.remove_vpp_config()
        self.assertFalse(dst_route.query_vpp_config())
        self.assertTrue(self.route_lookup("1.1.2.1/32", True, table.table_id))

        # Remove less specific drop route
        drop_route.remove_vpp_config()
        self.assertFalse(drop_route.query_vpp_config())
        self.assertTrue(self.route_lookup("1.1.2.1/32", True, table.table_id))

        # Remove first tunnel
        tunnels[0].admin_down()
        tunnels[0].remove_vpp_config()
        self.assertTrue(self.route_lookup("1.1.2.1/32", True, table.table_id))

        # Remove table, should be still locked
        table.remove_vpp_config()
        self.assertTrue(table.query_vpp_config())

        # Remove next tunnel, table should be still locked
        tunnels[1].admin_down()
        tunnels[1].remove_vpp_config()
        self.assertTrue(self.route_lookup("1.1.2.1/32", True, table.table_id))

        # Remove last tunnel, table should be gone
        tunnels[2].admin_down()
        tunnels[2].remove_vpp_config()
        self.assertFalse(table.query_vpp_config())


@unittest.skipIf("vxlan" in config.excluded_plugins, "Exclude VXLAN plugin tests")
class TestVxlanP2MP(VppTestCase):
    """VXLAN P2MP Test Case"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(3))
        for pg in cls.pg_interfaces:
            pg.admin_up()
        cls.pg0.config_ip4()
        cls.pg0.resolve_arp()
        cls.pg2.config_ip4()
        cls.pg2.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        cls.pg0.unconfig_ip4()
        cls.pg2.unconfig_ip4()
        for pg in cls.pg_interfaces:
            pg.admin_down()
        super().tearDownClass()

    def test_p2mp_decap(self):
        """P2MP: two remote VTEPs decap to the same tunnel"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.1.100"

        # Route remote2 via pg0 nexthop so the tunnel dst is resolvable
        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        # Create tunnel with the first remote VTEP
        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, dst=remote1, vni=100)
        t.add_vpp_config()
        t.admin_up()

        # Add second remote VTEP to the same tunnel
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        # Bridge the tunnel and pg1 together
        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=1
        )

        inner = (
            Ether(src="00:11:22:33:44:55", dst="00:00:00:11:22:33")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=1000, dport=2000)
            / Raw(b"\xab" * 64)
        )

        def send_vxlan(src_vtep):
            return (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=src_vtep, dst=self.pg0.local_ip4)
                / UDP(sport=4789, dport=4789, chksum=0)
                / VXLAN(vni=100, flags=0x8)
                / inner
            )

        # Frames from remote1 must arrive on pg1
        rx = self.send_and_expect(self.pg0, [send_vxlan(remote1)], self.pg1)
        self.assertEqual(rx[0][Ether].src, inner[Ether].src)
        self.assertEqual(rx[0][Ether].dst, inner[Ether].dst)

        # Frames from remote2 must also arrive on pg1 via the same tunnel
        rx = self.send_and_expect(self.pg0, [send_vxlan(remote2)], self.pg1)
        self.assertEqual(rx[0][Ether].src, inner[Ether].src)
        self.assertEqual(rx[0][Ether].dst, inner[Ether].dst)

        # Remove second endpoint; frames from remote2 must now be dropped
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=False, dst=remote2
        )
        self.send_and_assert_no_replies(self.pg0, [send_vxlan(remote2)])

    def test_p2mp_dump(self):
        """P2MP: endpoint dump returns all endpoints"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.3.1"

        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, dst=remote1, vni=500)
        t.add_vpp_config()

        # Initially one endpoint (the original dst)
        eps = find_vxlan_tunnel_endpoints(self, t.sw_if_index)
        self.assertEqual(len(eps), 1)
        self.assertEqual(str(eps[0].dst), remote1)

        # Add second endpoint
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        eps = find_vxlan_tunnel_endpoints(self, t.sw_if_index)
        self.assertEqual(len(eps), 2)
        dsts = {str(e.dst) for e in eps}
        self.assertIn(remote1, dsts)
        self.assertIn(remote2, dsts)

        # Verify all details fields are populated
        for e in eps:
            self.assertEqual(str(e.src), self.pg0.local_ip4)
            self.assertEqual(e.vni, 500)
            self.assertEqual(e.sw_if_index, t.sw_if_index)

        # v2 dump still returns exactly one entry (first endpoint)
        v2 = list(self.vapi.vxlan_tunnel_v2_dump(sw_if_index=t.sw_if_index))
        self.assertEqual(len(v2), 1)

        # Remove second endpoint; dump returns one again
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=False, dst=remote2
        )
        eps = find_vxlan_tunnel_endpoints(self, t.sw_if_index)
        self.assertEqual(len(eps), 1)
        self.assertEqual(str(eps[0].dst), remote1)

    def test_p2mp_create_no_dst(self):
        """P2MP: create tunnel without dst, add endpoint later"""
        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, vni=600, is_p2mp=True)
        t.add_vpp_config()
        t.admin_up()

        # Bridge tunnel and pg1 into BD 6
        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=6)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=6
        )

        frame = (
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="10.0.0.1", dst="10.0.0.255")
            / Raw(b"\xab" * 64)
        )

        # No endpoints: frame sent into the BD should not leave on pg0
        self.send_and_assert_no_replies(self.pg1, [frame])

        # Add one endpoint
        remote = self.pg0.remote_ip4
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote
        )

        # Endpoint dump returns the new endpoint
        eps = find_vxlan_tunnel_endpoints(self, t.sw_if_index)
        self.assertEqual(len(eps), 1)
        self.assertEqual(str(eps[0].dst), remote)
        self.assertEqual(eps[0].vni, 600)

    def test_p2mp_route_change(self):
        """P2MP: per-endpoint DPO restacking on route change"""
        remote1 = "172.16.7.1"
        remote2 = "172.16.7.2"

        r1_route = VppIpRoute(
            self,
            remote1,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        )
        r2_route = VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        )
        r1_route.add_vpp_config()
        r2_route.add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, dst=remote1, vni=700)
        t.add_vpp_config()
        t.admin_up()
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=7)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=7
        )

        frame = (
            Ether(src="00:11:22:33:44:55", dst="00:00:00:11:22:33")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / Raw(b"\xab" * 64)
        )

        # Both routes up: encap uses ep[0]=remote1, packet goes to remote1
        rx = self.send_and_expect(self.pg1, [frame], self.pg0)
        self.assertEqual(rx[0][IP].dst, remote1)

        # Withdraw remote2's route: ep[1] DPO restacks, ep[0] is unaffected
        r2_route.remove_vpp_config()
        rx = self.send_and_expect(self.pg1, [frame], self.pg0)
        self.assertEqual(rx[0][IP].dst, remote1)

        # Withdraw remote1's route: ep[0] DPO restacks to drop
        r1_route.remove_vpp_config()
        self.send_and_assert_no_replies(self.pg1, [frame])

        # Restore remote1's route: ep[0] DPO restacks, forwarding resumes
        r1_route.add_vpp_config()
        rx = self.send_and_expect(self.pg1, [frame], self.pg0)
        self.assertEqual(rx[0][IP].dst, remote1)

    def test_p2mp_route_change_nexthop(self):
        """P2MP: DPO restacks when route moves from one interface to another"""
        remote1 = "172.16.8.1"

        r1_via_pg0 = VppIpRoute(
            self,
            remote1,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        )
        r1_via_pg2 = VppIpRoute(
            self,
            remote1,
            32,
            [VppRoutePath(self.pg2.remote_ip4, self.pg2.sw_if_index)],
            register=False,
        )
        r1_via_pg0.add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, dst=remote1, vni=800)
        t.add_vpp_config()
        t.admin_up()
        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=8)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=8
        )

        frame = (
            Ether(src="00:11:22:33:44:55", dst="00:00:00:11:22:33")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / Raw(b"\xab" * 64)
        )

        # Route via pg0: encapped packet exits on pg0
        rx = self.send_and_expect(self.pg1, [frame], self.pg0)
        self.assertEqual(rx[0][IP].dst, remote1)

        # Move route to pg2: DPO restacks, encapped packet now exits on pg2
        r1_via_pg0.remove_vpp_config()
        r1_via_pg2.add_vpp_config()
        rx = self.send_and_expect(self.pg1, [frame], self.pg2)
        self.assertEqual(rx[0][IP].dst, remote1)

    def test_p2mp_mac_endpoint_dump(self):
        """P2MP: MAC→endpoint dump returns all programmed mappings"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.11.1"

        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, vni=1100, is_p2mp=True)
        t.add_vpp_config()
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote1
        )
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        mac_a = bytes.fromhex("aabbccddee11")
        mac_b = bytes.fromhex("aabbccddee22")

        # No mappings yet: dump returns empty
        entries = list(
            self.vapi.vxlan_p2mp_mac_endpoint_dump(sw_if_index=t.sw_if_index)
        )
        self.assertEqual(len(entries), 0)

        # Add two mappings
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, mac=mac_a, ep_dst=remote1
        )
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, mac=mac_b, ep_dst=remote2
        )

        entries = list(
            self.vapi.vxlan_p2mp_mac_endpoint_dump(sw_if_index=t.sw_if_index)
        )
        self.assertEqual(len(entries), 2)
        by_mac = {bytes(e.mac).hex(): str(e.ep_dst) for e in entries}
        self.assertEqual(by_mac[mac_a.hex()], remote1)
        self.assertEqual(by_mac[mac_b.hex()], remote2)

        # Remove one mapping: dump returns one
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index, is_add=False, mac=mac_a, ep_dst=remote1
        )
        entries = list(
            self.vapi.vxlan_p2mp_mac_endpoint_dump(sw_if_index=t.sw_if_index)
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(bytes(entries[0].mac), mac_b)
        self.assertEqual(str(entries[0].ep_dst), remote2)

        # Dump all tunnels (~0): at least our tunnel's entry is included
        all_entries = list(self.vapi.vxlan_p2mp_mac_endpoint_dump())
        self.assertGreaterEqual(len(all_entries), 1)
        all_macs = {bytes(e.mac).hex() for e in all_entries}
        self.assertIn(mac_b.hex(), all_macs)

    def test_p2mp_encap_bum(self):
        """P2MP: BUM traffic is replicated to all endpoints"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.9.1"

        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, vni=900, is_p2mp=True)
        t.add_vpp_config()
        t.admin_up()
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote1
        )
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=9)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=9
        )

        # Broadcast frame — no MAC→endpoint mapping, so BUM flood to both VTEPs
        frame = (
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="10.0.0.1", dst="10.0.0.255")
            / Raw(b"\xab" * 64)
        )

        rx = self.send_and_expect(self.pg1, [frame], self.pg0, n_rx=2)
        self.assertEqual(len(rx), 2)
        dsts = {pkt[IP].dst for pkt in rx}
        self.assertIn(remote1, dsts)
        self.assertIn(remote2, dsts)
        for pkt in rx:
            self.assertIn(VXLAN, pkt)
            self.assertEqual(pkt[VXLAN].vni, 900)

    def test_p2mp_encap_unicast(self):
        """P2MP: MAC→endpoint lookup steers known-unicast to a single endpoint"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.10.1"

        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, vni=1000, is_p2mp=True)
        t.add_vpp_config()
        t.admin_up()
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote1
        )
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=t.sw_if_index, bd_id=10)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=10
        )

        mac_a = "aa:bb:cc:dd:ee:01"
        mac_b = "aa:bb:cc:dd:ee:02"
        mac_a_bytes = bytes.fromhex("aabbccddee01")
        mac_b_bytes = bytes.fromhex("aabbccddee02")

        # Program MAC-A → remote1, MAC-B → remote2
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index,
            is_add=True,
            mac=mac_a_bytes,
            ep_dst=remote1,
        )
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index,
            is_add=True,
            mac=mac_b_bytes,
            ep_dst=remote2,
        )

        inner = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(b"\xab" * 64)

        # Unicast to MAC-A: expect exactly one copy, encapped toward remote1
        frame_a = Ether(src="00:11:22:33:44:55", dst=mac_a) / inner
        rx = self.send_and_expect(self.pg1, [frame_a], self.pg0)
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0][IP].dst, remote1)
        self.assertEqual(rx[0][VXLAN].vni, 1000)

        # Unicast to MAC-B: expect exactly one copy, encapped toward remote2
        frame_b = Ether(src="00:11:22:33:44:55", dst=mac_b) / inner
        rx = self.send_and_expect(self.pg1, [frame_b], self.pg0)
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0][IP].dst, remote2)
        self.assertEqual(rx[0][VXLAN].vni, 1000)

    def test_p2mp_endpoint_del_cleans_macs(self):
        """P2MP: removing an endpoint purges its MAC→endpoint mappings"""
        remote1 = self.pg0.remote_ip4
        remote2 = "172.16.20.1"

        VppIpRoute(
            self,
            remote2,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
            register=False,
        ).add_vpp_config()

        t = VppVxlanTunnel(self, src=self.pg0.local_ip4, vni=1100, is_p2mp=True)
        t.add_vpp_config()
        t.admin_up()
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote1
        )
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, dst=remote2
        )

        mac_a_bytes = bytes.fromhex("aabbccddee01")
        mac_b_bytes = bytes.fromhex("aabbccddee02")

        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, mac=mac_a_bytes, ep_dst=remote1
        )
        self.vapi.vxlan_p2mp_add_del_mac_endpoint(
            sw_if_index=t.sw_if_index, is_add=True, mac=mac_b_bytes, ep_dst=remote2
        )

        # Both mappings should be present
        entries = self.vapi.vxlan_p2mp_mac_endpoint_dump(sw_if_index=t.sw_if_index)
        self.assertEqual(len(entries), 2)

        # Remove the second endpoint — its MAC mapping should be automatically purged
        self.vapi.vxlan_add_del_tunnel_endpoint(
            sw_if_index=t.sw_if_index, is_add=False, dst=remote2
        )

        entries = self.vapi.vxlan_p2mp_mac_endpoint_dump(sw_if_index=t.sw_if_index)
        self.assertEqual(len(entries), 1)
        self.assertEqual(bytes(entries[0].mac), mac_a_bytes)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
