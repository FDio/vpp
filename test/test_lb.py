import socket
import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase, VppMultiWorkerScenario
from util import ppp

""" TestLB is a subclass of  VPPTestCase classes.

 TestLB class defines Load Balancer test cases for:
  - IP4 to GRE4 encap
  - IP4 to GRE6 encap
  - IP6 to GRE4 encap
  - IP6 to GRE6 encap

 As stated in comments below, GRE has issues with IPv6.
 All test cases involving IPv6 are executed, but
 received packets are not parsed and checked.

"""


@VppMultiWorkerScenario.skip("test doesn't pass with multiple workers")
class TestLB(VppTestCase):
    """ Load Balancer Test Case """

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
            dst4 = socket.inet_pton(socket.AF_INET, "10.0.0.0")
            dst6 = socket.inet_pton(socket.AF_INET6, "2002::")
            cls.vapi.ip_add_del_route(dst4, 24, cls.pg1.remote_ip4n)
            cls.vapi.ip_add_del_route(dst6, 16, cls.pg1.remote_ip6n, is_ipv6=1)
            cls.vapi.cli("lb conf ip4-src-address 39.40.41.42")
            cls.vapi.cli("lb conf ip6-src-address 2004::1")
        except Exception:
            super(TestLB, cls).tearDownClass()
            raise

    def tearDown(self):
        super(TestLB, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show lb vip verbose"))

    def getIPv4Flow(self, id):
        return (IP(dst="90.0.%u.%u" % (id / 255, id % 255),
                   src="40.0.%u.%u" % (id / 255, id % 255)) /
                UDP(sport=10000 + id, dport=20000 + id))

    def getIPv6Flow(self, id):
        return (IPv6(dst="2001::%u" % (id), src="fd00:f00d:ffff::%u" % (id)) /
                UDP(sport=10000 + id, dport=20000 + id))

    def generatePackets(self, src_if, isv4):
        self.reset_packet_infos()
        pkts = []
        for pktid in self.packets:
            info = self.create_packet_info(src_if, self.pg1)
            payload = self.info_to_payload(info)
            ip = self.getIPv4Flow(pktid) if isv4 else self.getIPv6Flow(pktid)
            packet = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                      ip /
                      Raw(payload))
            self.extend_packet(packet, 128)
            info.data = packet.copy()
            pkts.append(packet)
        return pkts

    def checkInner(self, gre, isv4):
        IPver = IP if isv4 else IPv6
        self.assertEqual(gre.proto, 0x0800 if isv4 else 0x86DD)
        self.assertEqual(gre.flags, 0)
        self.assertEqual(gre.version, 0)
        inner = IPver(str(gre.payload))
        payload_info = self.payload_to_info(str(inner[Raw]))
        self.info = self.packet_infos[payload_info.index]
        self.assertEqual(payload_info.src, self.pg0.sw_if_index)
        self.assertEqual(str(inner), str(self.info.data[IPver]))

    def checkCapture(self, gre4, isv4):
        self.pg0.assert_nothing_captured()
        out = self.pg1.get_capture(len(self.packets))

        load = [0] * len(self.ass)
        self.info = None
        for p in out:
            try:
                asid = 0
                gre = None
                if gre4:
                    ip = p[IP]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.src, "39.40.41.42")
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 47)
                    self.assertEqual(len(ip.options), 0)
                    self.assertGreaterEqual(ip.ttl, 64)
                    gre = p[GRE]
                else:
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
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % asid)
                    )
                    self.assertEqual(ip.nh, 47)
                    self.assertGreaterEqual(ip.hlim, 64)
                    # self.assertEqual(len(ip.options), 0)
                    gre = GRE(str(p[IPv6].payload))
                self.checkInner(gre, isv4)
                load[asid] += 1
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", p))
                raise

        # This is just to roughly check that the balancing algorithm
        # is not completly biased.
        for asid in self.ass:
            if load[asid] < len(self.packets) / (len(self.ass) * 2):
                self.log(
                    "ASS is not balanced: load[%d] = %d" % (asid, load[asid]))
                raise Exception("Load Balancer algorithm is biased")

    def test_lb_ip4_gre4(self):
        """ Load Balancer IP4 GRE4 """
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre4")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(gre4=True, isv4=True)

        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre4 del")

    def test_lb_ip6_gre4(self):
        """ Load Balancer IP6 GRE4 """

        try:
            self.vapi.cli("lb vip 2001::/16 encap gre4")
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 10.0.0.%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(gre4=True, isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 10.0.0.%u del" % (asid))
            self.vapi.cli("lb vip 2001::/16 encap gre4 del")

    def test_lb_ip4_gre6(self):
        """ Load Balancer IP4 GRE6 """
        try:
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre6")
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 2002::%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(gre4=False, isv4=True)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 90.0.0.0/8 2002::%u" % (asid))
            self.vapi.cli("lb vip 90.0.0.0/8 encap gre6 del")

    def test_lb_ip6_gre6(self):
        """ Load Balancer IP6 GRE6 """
        try:
            self.vapi.cli("lb vip 2001::/16 encap gre6")
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 2002::%u" % (asid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(gre4=False, isv4=False)
        finally:
            for asid in self.ass:
                self.vapi.cli("lb as 2001::/16 2002::%u del" % (asid))
            self.vapi.cli("lb vip 2001::/16 encap gre6 del")
