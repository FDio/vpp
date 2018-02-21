import socket
import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework import VppTestCase, running_extended_tests
from util import ppp

""" TestKP is a subclass of VPPTestCase classes.

 TestKP class defines Four NAT test case for:
  - IP4 to IP4 NAT
  - IP4 to IP6 NAT
  - IP6 to IP4 NAT
  - IP6 to IP6 NAT

"""


class TestKP(VppTestCase):
    """ Kube-proxy Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestKP, cls).setUpClass()
        cls.pods = range(5)
        cls.packets = range(5)

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
        except Exception:
            super(TestKP, cls).tearDownClass()
            raise

    def tearDown(self):
        super(TestKP, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show ku vip verbose"))

    def getIPv4Flow(self, id):
        return (IP(dst="90.0.%u.%u" % (id / 255, id % 255),
                   src="40.0.%u.%u" % (id / 255, id % 255)) /
                UDP(sport=10000 + id, dport=3306))

    def getIPv6Flow(self, id):
        return (IPv6(dst="2001::%u" % (id), src="fd00:f00d:ffff::%u" % (id)) /
                UDP(sport=10000 + id, dport=3306))

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

    def checkInner(self, udp):
        self.assertEqual(udp.dport, 3307)

    def checkCapture(self, nat4, isv4):
        self.pg0.assert_nothing_captured()
        out = self.pg1.get_capture(len(self.packets))

        load = [0] * len(self.pods)
        self.info = None
        for p in out:
            try:
                podid = 0
                udp = None
                if nat4:
                    ip = p[IP]
                    podid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.dst, "10.0.0.%u" % podid)
                    self.assertEqual(ip.proto, 17)
                    self.assertEqual(len(ip.options), 0)
                    self.assertGreaterEqual(ip.ttl, 63)
                    udp = p[UDP]
                else:
                    ip = p[IPv6]
                    podid = ip.dst.split(":")
                    podid = podid[len(podid) - 1]
                    podid = 0 if podid == "" else int(podid)
                    self.assertEqual(ip.version, 6)
                    self.assertEqual(ip.tc, 0)
                    self.assertEqual(ip.fl, 0)
                    self.assertEqual(
                        socket.inet_pton(socket.AF_INET6, ip.dst),
                        socket.inet_pton(socket.AF_INET6, "2002::%u" % podid)
                    )
                    self.assertEqual(ip.nh, 17)
                    self.assertGreaterEqual(ip.hlim, 63)
                    udp = UDP(str(p[IPv6].payload))
                    # self.assertEqual(len(ip.options), 0)
                self.checkInner(udp)
                load[podid] += 1
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", p))
                raise

        # This is just to roughly check that the balancing algorithm
        # is not completly biased.
        for podid in self.pods:
            if load[podid] < len(self.packets) / (len(self.pods) * 2):
                self.log(
                    "Pod isn't balanced: load[%d] = %d" % (podid, load[podid]))
                raise Exception("Kube-proxy algorithm is biased")

    def test_kp_ip4_nat4(self):
        """ Kube-proxy NAT44 """
        try:
            self.vapi.cli("ku vip 90.0.0.0/8 port 3306 target_port 3307 nat4")
            for podid in self.pods:
                self.vapi.cli("ku pod 90.0.0.0/8 10.0.0.%u" % (podid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.checkCapture(nat4=True, isv4=True)

        finally:
            for podid in self.pods:
                self.vapi.cli("ku pod 90.0.0.0/8 10.0.0.%u del" % (podid))
            self.vapi.cli("ku vip 90.0.0.0/8 nat4 del")
            self.vapi.cli("test kube-proxy flowtable flush")

    @unittest.skip("this test is broken")
    def test_kp_ip6_nat4(self):
        """ Kube-proxy NAT64 """

        try:
            self.vapi.cli("ku vip 90.0.0.0/8 port 3306 target_port 3307 nat4")
            for podid in self.pods:
                self.vapi.cli("ku pod 2001::/16 10.0.0.%u" % (podid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(nat4=True, isv4=False)
        finally:
            for podid in self.pods:
                self.vapi.cli("ku pod 2001::/16 10.0.0.%u del" % (podid))
            self.vapi.cli("ku vip 2001::/16 nat4 del")
            self.vapi.cli("test kube-proxy flowtable flush")

    @unittest.skip("this test is broken")
    def test_kp_ip4_nat6(self):
        """ Kube-proxy NAT46 """
        try:
            self.vapi.cli("ku vip 90.0.0.0/8 port 3306 target_port 3307 nat6")
            for podid in self.pods:
                self.vapi.cli("ku pod 90.0.0.0/8 2002::%u" % (podid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=True))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(nat4=False, isv4=True)
        finally:
            for podid in self.pods:
                self.vapi.cli("ku pod 90.0.0.0/8 2002::%u del" % (podid))
            self.vapi.cli("ku vip 90.0.0.0/8 nat6 del")
            self.vapi.cli("test kube-proxy flowtable flush")

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_kp_ip6_nat6(self):
        """ Kube-proxy NAT66 """
        try:
            self.vapi.cli("ku vip 2001::/16 port 3306 target_port 3307 nat6")
            for podid in self.pods:
                self.vapi.cli("ku pod 2001::/16 2002::%u" % (podid))

            self.pg0.add_stream(self.generatePackets(self.pg0, isv4=False))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

            self.checkCapture(nat4=False, isv4=False)
        finally:
            for podid in self.pods:
                self.vapi.cli("ku pod 2001::/16 2002::%u del" % (podid))
            self.vapi.cli("ku vip 2001::/16 nat6 del")
            self.vapi.cli("test kube-proxy flowtable flush")
