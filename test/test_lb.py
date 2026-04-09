import socket
from ipaddress import ip_network

import scapy.compat
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw
from scapy.data import IP_PROTOS

from framework import VppTestCase
from util import ppp
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX
from config import config
import unittest

""" TestLB is a subclass of  VPPTestCase classes.

 TestLB class defines Load Balancer test cases for:
  - IP4 to GRE4 encap on per-port vip case
  - IP4 to GRE6 encap on per-port vip case
  - IP6 to GRE4 encap on per-port vip case
  - IP6 to GRE6 encap on per-port vip case
  - IP4 to L3DSR encap on vip case
  - IP4 to L3DSR encap on per-port vip case
  - IP4 to L3DSR encap on per-port vip with src_ip_sticky case
  - IP4 to NAT4 encap on per-port vip case
  - IP6 to NAT6 encap on per-port vip case

 As stated in comments below, GRE has issues with IPv6.
 All test cases involving IPv6 are executed, but
 received packets are not parsed and checked.

"""


@unittest.skipIf("lb" in config.excluded_plugins, "Exclude LB plugin tests")
class TestLB(VppTestCase):
    """Load Balancer Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestLB, cls).setUpClass()

        cls.ass = range(5)
        cls.packets = range(100)

        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()

            dst4 = VppIpRoute(
                cls,
                "10.0.0.0",
                24,
                [VppRoutePath(cls.pg1.remote_ip4, INVALID_INDEX)],
                register=False,
            )
            dst4.add_vpp_config()
            dst6 = VppIpRoute(
                cls,
                "2002::",
                16,
                [VppRoutePath(cls.pg1.remote_ip6, INVALID_INDEX)],
                register=False,
            )
            dst6.add_vpp_config()
            cls.vapi.lb_conf(ip4_src_address="39.40.41.42", ip6_src_address="2004::1")
        except Exception:
            super(TestLB, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestLB, cls).tearDownClass()

    def tearDown(self):
        super(TestLB, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show lb vip verbose"))

    def getIPv4Flow(self, id):
        return IP(
            dst="90.0.%u.%u" % (id / 255, id % 255),
            src="40.0.%u.%u" % (id / 255, id % 255),
        ) / UDP(sport=10000 + id, dport=20000)

    def getIPv6Flow(self, id):
        return IPv6(dst="2001::%u" % (id), src="fd00:f00d:ffff::%u" % (id)) / UDP(
            sport=10000 + id, dport=20000
        )

    def generatePackets(self, src_if, isv4):
        self.reset_packet_infos()
        pkts = []
        for pktid in self.packets:
            info = self.create_packet_info(src_if, self.pg1)
            payload = self.info_to_payload(info)
            ip = self.getIPv4Flow(pktid) if isv4 else self.getIPv6Flow(pktid)
            packet = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac) / ip / Raw(payload)
            )
            self.extend_packet(packet, 128)
            info.data = packet.copy()
            pkts.append(packet)
        return pkts

    def checkInner(self, gre, isv4):
        IPver = IP if isv4 else IPv6
        self.assertEqual(gre.proto, 0x0800 if isv4 else 0x86DD)
        self.assertEqual(gre.flags, 0)
        self.assertEqual(gre.version, 0)
        inner = IPver(scapy.compat.raw(gre.payload))
        payload_info = self.payload_to_info(inner[Raw])
        self.info = self.packet_infos[payload_info.index]
        self.assertEqual(payload_info.src, self.pg0.sw_if_index)
        self.assertEqual(
            scapy.compat.raw(inner), scapy.compat.raw(self.info.data[IPver])
        )

    def checkCapture(self, encap, isv4, src_ip_sticky=False):
        self.pg0.assert_nothing_captured()
        out = self.pg1.get_capture(len(self.packets))

        load = [0] * len(self.ass)
        sticky_as = {}
        self.info = None
        for p in out:
            try:
                asid = 0
                gre = None
                if encap == "gre4":
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.src, "39.40.41.42")
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 47)
                    self.assertEqual(len(ip.options), 0)
                    gre = p[GRE]
                    self.checkInner(gre, isv4)
                elif encap == "gre6":
                    ip = p[IPv6]
                    asid = ip.dst.split(":")
                    asid = asid[len(asid) - 1]
                    asid = 0 if asid == "" else int(asid)
                    self.assertEqual(ip.version, 6)
                    self.assertEqual(ip.tc, 0)
                    self.assertEqual(ip.fl, 0)
                    self.assertEqual(ip.src, "2004::1")
                    self.assertEqual(
                        socket.inet_pton(socket.AF_INET6, ip.dst),
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % asid),
                    )
                    self.assertEqual(ip.nh, 47)
                    # self.assertEqual(len(ip.options), 0)
                    gre = GRE(scapy.compat.raw(p[IPv6].payload))
                    self.checkInner(gre, isv4)
                elif encap == "l3dsr":
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.tos, 0x1C)
                    self.assertEqual(len(ip.options), 0)
                    self.assert_ip_checksum_valid(p)
                    if ip.proto == IP_PROTOS.tcp:
                        self.assert_tcp_checksum_valid(p)
                    elif ip.proto == IP_PROTOS.udp:
                        self.assert_udp_checksum_valid(p)
                elif encap == "nat4":
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 17)
                    self.assertEqual(len(ip.options), 0)
                    udp = p[UDP]
                    self.assertEqual(udp.dport, 3307)
                elif encap == "nat6":
                    ip = p[IPv6]
                    asid = ip.dst.split(":")
                    asid = asid[len(asid) - 1]
                    asid = 0 if asid == "" else int(asid)
                    self.assertEqual(ip.version, 6)
                    self.assertEqual(ip.tc, 0)
                    self.assertEqual(ip.fl, 0)
                    self.assertEqual(
                        socket.inet_pton(socket.AF_INET6, ip.dst),
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % asid),
                    )
                    self.assertEqual(ip.nh, 17)
                    self.assertGreaterEqual(ip.hlim, 63)
                    udp = UDP(scapy.compat.raw(p[IPv6].payload))
                    self.assertEqual(udp.dport, 3307)
                load[asid] += 1

                # In case of source ip sticky, check that packets with same
                # src_ip are routed to same as.
                if src_ip_sticky:
                    # For GRE encap with IPv6 inner, stickiness is on the
                    # inner IPv6 source (outer src is always the LB address).
                    if gre is not None and not isv4:
                        inner_pkt = IPv6(scapy.compat.raw(gre.payload))
                        sticky_src = str(inner_pkt.src)
                    else:
                        sticky_src = ip.src
                    if sticky_as.get(sticky_src, asid) != asid:
                        raise Exception(
                            "Packets with same src_ip are routed to another as"
                        )
                    sticky_as[sticky_src] = asid

            except:
                self.logger.error(ppp("Unexpected or invalid packet:", p))
                raise

        # This is just to roughly check that the balancing algorithm
        # is not completely biased.
        for asid in self.ass:
            if load[asid] < int(len(self.packets) / (len(self.ass) * 2)):
                self.logger.error(
                    "ASS is not balanced: load[%d] = %d" % (asid, load[asid])
                )
                raise Exception("Load Balancer algorithm is biased")

    def test_lb_ip4_gre4(self):
        """Load Balancer IP4 GRE4 on vip case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre4")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="gre4", isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre4(self):
        """Load Balancer IP6 GRE4 on vip case"""

        try:
            self.vapi.cli("lb vip 2001::/16 encap gre4")
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 10.0.0.%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre4", isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 2001::/16 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre6(self):
        """Load Balancer IP4 GRE6 on vip case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre6")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 2002::%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre6", isv4=True)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 2002::%u del" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre6(self):
        """Load Balancer IP6 GRE6 on vip case"""
        try:
            self.vapi.cli("lb vip 2001::/16 encap gre6")
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 2002::%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre6", isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 2002::%u del" % (asid))
            self.vapi.cli("lb vip 2001::/16 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre4_port(self):
        """Load Balancer IP4 GRE4 on per-port-vip case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 protocol udp port 20000 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="gre4", isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del" % (asid)
                )
            self.vapi.cli("lb vip 90.0.0.0/8 protocol udp port 20000 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre4_port(self):
        """Load Balancer IP6 GRE4 on per-port-vip case"""

        try:
            self.vapi.cli("lb vip 2001::/16 protocol udp port 20000 encap gre4")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre4", isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u del" % (asid)
                )
            self.vapi.cli("lb vip 2001::/16 protocol udp port 20000 encap gre4 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_gre6_port(self):
        """Load Balancer IP4 GRE6 on per-port-vip case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 protocol udp port 20000 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 2002::%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre6", isv4=True)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 2002::%u del" % (asid)
                )
            self.vapi.cli("lb vip 90.0.0.0/8 protocol udp port 20000 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre6_port(self):
        """Load Balancer IP6 GRE6 on per-port-vip case"""
        try:
            self.vapi.cli("lb vip 2001::/16 protocol udp port 20000 encap gre6")
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(encap="gre6", isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u del" % (asid)
                )
            self.vapi.cli("lb vip 2001::/16 protocol udp port 20000 encap gre6 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr(self):
        """Load Balancer IP4 L3DSR on vip case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap l3dsr dscp 7")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="l3dsr", isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap l3dsr dscp 7 del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr_src_ip_sticky(self):
        """Load Balancer IP4 L3DSR on vip with src_ip_sticky case"""
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap l3dsr dscp 7 src_ip_sticky")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u" % (asid))

            # Generate duplicated packets
            pkts = self.generatePackets(self.pg0, isv4=True)
            pkts = pkts[: len(pkts) // 2]
            pkts = pkts + pkts

            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="l3dsr", isv4=True, src_ip_sticky=True)

        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap l3dsr dscp 7 src_ip_sticky del")
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr_port(self):
        """Load Balancer IP4 L3DSR on per-port-vip case"""
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr dscp 7"
            )
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="l3dsr", isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del" % (asid)
                )
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr dscp 7 del"
            )
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_l3dsr_port_src_ip_sticky(self):
        """Load Balancer IP4 L3DSR on per-port-vip with src_ip_sticky case"""
        try:
            # This VIP at port 1000 does not receive packets, but is defined
            # as a dummy to verify that the src_ip_sticky flag can be set
            # independently for each port.
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 10000 encap l3dsr dscp 7"
            )
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr dscp 7 src_ip_sticky"
            )
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u" % (asid)
                )

            # Generate duplicated packets
            pkts = self.generatePackets(self.pg0, isv4=True)
            pkts = pkts[: len(pkts) // 2]
            pkts = pkts + pkts

            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="l3dsr", isv4=True, src_ip_sticky=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del" % (asid)
                )
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap l3dsr dscp 7 src_ip_sticky del"
            )
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 10000 encap l3dsr dscp 7 del"
            )
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip4_nat4_port(self):
        """Load Balancer IP4 NAT4 on per-port-vip case"""
        try:
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap nat4"
                " type clusterip target_port 3307"
            )
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="nat4", isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 90.0.0.0/8 protocol udp port 20000 10.0.0.%u del" % (asid)
                )
            self.vapi.cli(
                "lb vip 90.0.0.0/8 protocol udp port 20000 encap nat4"
                " type clusterip target_port 3307 del"
            )
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_nat6_port(self):
        """Load Balancer IP6 NAT6 on per-port-vip case"""
        try:
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap nat6"
                " type clusterip target_port 3307"
            )
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u" % (asid)
                )

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="nat6", isv4=False)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 2002::%u del" % (asid)
                )
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap nat6"
                " type clusterip target_port 3307 del"
            )
            self.vapi.cli("test lb flowtable flush")

    def test_lb_ip6_gre4_port_src_ip_sticky(self):
        """Load Balancer IP6 GRE4 on per-port-vip with src_ip_sticky case"""
        try:
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre4 src_ip_sticky"
            )
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u" % asid
                )

            # Send each flow twice: stickiness requires same src → same AS
            pkts = self.generatePackets(self.pg0, isv4=False)
            pkts = pkts[: len(pkts) // 2]
            pkts = pkts + pkts

            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(encap="gre4", isv4=False, src_ip_sticky=True)

        finally:
            for asid in self.ass:
                self.vapi.cli(
                    "lb as 2001::/16 protocol udp port 20000 10.0.0.%u del" % asid
                )
            self.vapi.cli(
                "lb vip 2001::/16 protocol udp port 20000 encap gre4 src_ip_sticky del"
            )
            self.vapi.cli("test lb flowtable flush")

    def test_lb_conf_get(self):
        """lb_conf_get binary API returns current global configuration"""
        reply = self.vapi.lb_conf_get()
        self.assertEqual(str(reply.ip4_src_address), "39.40.41.42")
        self.assertEqual(str(reply.ip6_src_address), "2004::1")

    def test_lb_show_vips(self):
        """show lb vips (without verbose) must display VIP output"""
        self.vapi.cli("lb vip 90.0.0.0/8 encap gre4")
        try:
            out = self.vapi.cli("show lb vips")
            self.assertIn("90.0.0.0", out)
        finally:
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre4 del")

    def test_lb_vip_dump_api(self):
        """lb_add_del_vip + lb_vip_dump: IPv4 prefix intact and encap type correct"""
        # LB_API_ENCAP_TYPE_GRE4=0, GRE6=1, L3DSR=2
        cases = [
            ("90.0.0.0/8", 0),   # IPv4 VIP, GRE4 — regression for IPv4 prefix bug (#1)
            ("91.0.0.0/8", 1),   # IPv4 VIP, GRE6 — byte order fix for encap enum (#2)
            ("2001::/16",  0),   # IPv6 VIP, GRE4 — encap type 0 (#2)
            ("2002::/16",  1),   # IPv6 VIP, GRE6 — encap type 1 (#2)
        ]
        try:
            for pfx_str, encap in cases:
                self.vapi.lb_add_del_vip(pfx=pfx_str, encap=encap)

            vips = self.vapi.lb_vip_dump()
            dumped = {str(v.vip.pfx): int(v.encap) for v in vips}

            for pfx_str, expected_encap in cases:
                net = str(ip_network(pfx_str))
                self.assertIn(net, dumped, "VIP %s not found in dump" % pfx_str)
                self.assertEqual(
                    dumped[net],
                    expected_encap,
                    "VIP %s: expected encap %d, got %d" % (pfx_str, expected_encap, dumped[net]),
                )
        finally:
            for pfx_str, encap in cases:
                self.vapi.lb_add_del_vip(pfx=pfx_str, encap=encap, is_del=True)

    def test_lb_as_dump_api(self):
        """lb_add_del_as + lb_as_dump: AS list is correct via binary API"""
        try:
            self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0)
            for asid in self.ass:
                self.vapi.lb_add_del_as(
                    pfx="90.0.0.0/8", as_address="10.0.0.%u" % asid
                )

            # protocol=255 (~0) and port=0 match the all-port VIP
            ass = self.vapi.lb_as_dump(pfx="90.0.0.0/8", protocol=255, port=0)
            self.assertEqual(len(ass), len(self.ass))
            as_addrs = {str(a.app_srv) for a in ass}
            for asid in self.ass:
                self.assertIn("10.0.0.%u" % asid, as_addrs)
        finally:
            for asid in self.ass:
                self.vapi.lb_add_del_as(
                    pfx="90.0.0.0/8",
                    as_address="10.0.0.%u" % asid,
                    is_del=True,
                )
            self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0, is_del=True)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_vip_dump_encap_types(self):
        """lb_add_del_vip: L3DSR, NAT4, NAT6 encap types accepted via binary API"""
        # LB_API_ENCAP_TYPE_L3DSR=2, NAT4=3, NAT6=4
        cases = [
            # (prefix, encap, extra kwargs)
            ("90.0.0.0/8", 2, {"dscp": 7}),                          # IPv4 L3DSR
            ("91.0.0.0/8", 3, {"type": 0, "target_port": 8080}),     # IPv4 NAT4
            ("2001::/16",  4, {"type": 0, "target_port": 8080}),     # IPv6 NAT6
        ]
        try:
            for pfx_str, encap, kwargs in cases:
                self.vapi.lb_add_del_vip(pfx=pfx_str, encap=encap, **kwargs)

            vips = self.vapi.lb_vip_dump()
            dumped = {str(v.vip.pfx): int(v.encap) for v in vips}

            for pfx_str, expected_encap, _ in cases:
                net = str(ip_network(pfx_str))
                self.assertIn(net, dumped, "VIP %s not found in dump" % pfx_str)
                self.assertEqual(
                    dumped[net],
                    expected_encap,
                    "VIP %s: expected encap %d, got %d"
                    % (pfx_str, expected_encap, dumped[net]),
                )
        finally:
            for pfx_str, encap, kwargs in cases:
                self.vapi.lb_add_del_vip(pfx=pfx_str, encap=encap, is_del=True, **kwargs)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_vip_dump_deleted_vip_hidden(self):
        """lb_vip_dump: soft-deleted VIPs do not appear (LB_VIP_FLAGS_USED check)"""
        self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0)
        self.vapi.lb_add_del_vip(pfx="91.0.0.0/8", encap=0)
        try:
            self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0, is_del=True)
            vips = self.vapi.lb_vip_dump()
            dumped = {str(v.vip.pfx) for v in vips}
            self.assertNotIn(
                str(ip_network("90.0.0.0/8")),
                dumped,
                "deleted VIP 90.0.0.0/8 should not appear in dump",
            )
            self.assertIn(
                str(ip_network("91.0.0.0/8")),
                dumped,
                "active VIP 91.0.0.0/8 should appear in dump",
            )
        finally:
            self.vapi.lb_add_del_vip(pfx="91.0.0.0/8", encap=0, is_del=True)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_vip_dump_flow_table_length(self):
        """lb_vip_dump: flow_table_length is correctly byte-swapped (htons fix)"""
        self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0, new_flows_table_length=4096)
        try:
            vips = self.vapi.lb_vip_dump()
            net = str(ip_network("90.0.0.0/8"))
            match = [v for v in vips if str(v.vip.pfx) == net]
            self.assertEqual(len(match), 1)
            self.assertEqual(
                match[0].flow_table_length,
                4096,
                "flow_table_length: expected 4096, got %d" % match[0].flow_table_length,
            )
        finally:
            self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0, is_del=True)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_as_dump_all(self):
        """lb_as_dump: dump_all (prefix len=0) returns AS from all VIPs"""
        try:
            self.vapi.lb_add_del_vip(pfx="92.0.0.0/8", encap=0)
            self.vapi.lb_add_del_vip(pfx="93.0.0.0/8", encap=0)
            self.vapi.lb_add_del_as(pfx="92.0.0.0/8", as_address="10.0.0.1")
            self.vapi.lb_add_del_as(pfx="93.0.0.0/8", as_address="10.0.0.2")

            # all-zeros /0 prefix means dump all
            ass = self.vapi.lb_as_dump(pfx="0.0.0.0/0", protocol=0, port=0)
            as_addrs = {str(a.app_srv) for a in ass}
            self.assertIn("10.0.0.1", as_addrs)
            self.assertIn("10.0.0.2", as_addrs)
        finally:
            self.vapi.lb_add_del_as(pfx="92.0.0.0/8", as_address="10.0.0.1", is_del=True)
            self.vapi.lb_add_del_as(pfx="93.0.0.0/8", as_address="10.0.0.2", is_del=True)
            self.vapi.lb_add_del_vip(pfx="92.0.0.0/8", encap=0, is_del=True)
            self.vapi.lb_add_del_vip(pfx="93.0.0.0/8", encap=0, is_del=True)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_flush_vip_api(self):
        """lb_flush_vip: IPv4 prefix correctly decoded via binary API"""
        self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0)
        self.vapi.lb_add_del_as(pfx="90.0.0.0/8", as_address="10.0.0.1")
        try:
            # flush_vip should find the VIP by IPv4 prefix and succeed
            self.vapi.lb_flush_vip(pfx="90.0.0.0/8", protocol=255, port=0)
        finally:
            self.vapi.lb_add_del_as(
                pfx="90.0.0.0/8", as_address="10.0.0.1", is_del=True
            )
            self.vapi.lb_add_del_vip(pfx="90.0.0.0/8", encap=0, is_del=True)
            self.vapi.cli("test lb flowtable flush")

    def test_lb_add_del_vip_v2_src_ip_sticky(self):
        """lb_add_del_vip_v2: src_ip_sticky flag accepted via binary API"""
        try:
            self.vapi.lb_add_del_vip_v2(pfx="90.0.0.0/8", encap=0, src_ip_sticky=True)
            vips = self.vapi.lb_vip_dump()
            net = str(ip_network("90.0.0.0/8"))
            match = [v for v in vips if str(v.vip.pfx) == net]
            self.assertEqual(len(match), 1, "VIP 90.0.0.0/8 not found in dump")
        finally:
            self.vapi.lb_add_del_vip_v2(
                pfx="90.0.0.0/8", encap=0, src_ip_sticky=True, is_del=True
            )
            self.vapi.cli("test lb flowtable flush")
