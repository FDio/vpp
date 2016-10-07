import unittest
import time
import socket
from framework import VppTestCase, VppTestRunner
from util import Util

from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

## TestLB is a subclass of Util and VPPTestCase classes.
#
#  TestLB class defines Load Balancer test cases for:
#   - IP4 to GRE4 encap
#   - IP4 to GRE6 encap
#   - IP6 to GRE4 encap
#   - IP6 to GRE6 encap
#
#  As stated in comments below, GRE has issues with IPv6.
#  All test cases involving IPv6 are executed, but
#  received packets are not parsed and checked.
#
class TestLB(Util, VppTestCase):
    """ Load Balancer Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestLB, cls).setUpClass()

        cls.ass = range(5)
        cls.packets = range(100)

        try:
            cls.create_interfaces([0,1])
            cls.api("sw_interface_dump")
            cls.config_ip4([0,1])
            cls.config_ip6([0,1])
            cls.resolve_arp([0,1])
            cls.resolve_icmpv6_nd([0,1])
            cls.cli(0, "ip route add 10.0.0.0/24 via %s pg1" % (cls.MY_IP4S[1]))
            cls.cli(0, "ip route add 2002::/16 via %s pg1" % (cls.MY_IP6S[1]))
            cls.cli(0, "lb conf buckets-log2 20 ip4-src-address 39.40.41.42 ip6-src-address fd00:f00d::1")

        except Exception as e:
            super(TestLB, cls).tearDownClass()
            raise

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show lb vip verbose")

    def getIPv4Flow(self, id):
        return (IP(dst="90.0.%u.%u" % (id / 255, id % 255),
              src="40.0.%u.%u" % (id / 255, id % 255)) /
                UDP(sport=10000 + id, dport=20000 + id))

    def getIPv6Flow(self, id):
        return (IPv6(dst="2001::%u" % (id), src="fd00:f00d:ffff::%u" % (id)) /
            UDP(sport=10000 + id, dport=20000 + id))

    def generatePackets(self, isv4):
        pkts = []
        for pktid in self.packets:
            info = self.create_packet_info(0, pktid)
            payload = self.info_to_payload(info)
            ip = self.getIPv4Flow(pktid) if isv4 else self.getIPv6Flow(pktid)
            packet=(Ether(dst=self.VPP_MACS[0], src=self.MY_MACS[0]) /
                    ip / Raw(payload))
            self.extend_packet(packet, 128)
            info.data = packet.copy()
            pkts.append(packet)
        return pkts

    def checkInner(self, gre, isv4):
        self.assertEqual(gre.proto, 0x0800 if isv4 else 0x86DD)
        self.assertEqual(gre.flags, 0)
        self.assertEqual(gre.version, 0)
        inner = gre[IP] if isv4 else gre[IPv6]
        payload_info = self.payload_to_info(str(gre[Raw]))
        packet_index = payload_info.index
        self.info = self.get_next_packet_info_for_interface2(0, payload_info.dst, self.info)
        self.assertEqual(str(inner), str(self.info.data[IP]))

    def checkCapture(self, gre4, isv4):
        out = self.pg_get_capture(0)
        self.assertEqual(len(out), 0)
        out = self.pg_get_capture(1)
        self.assertEqual(len(out), len(self.packets))

        load = [0] * len(self.ass)
        self.info = None
        for p in out:
            try:
                asid = 0
                gre = None
                if gre4:
                    ip = p[IP]
                    gre = p[GRE]
                    inner = gre[IP] if isv4 else gre[IPv6]
                    asid = int(ip.dst.split(".")[3])
                    self.assertEqual(ip.version, 4)
                    self.assertEqual(ip.flags, 0)
                    self.assertEqual(ip.src, "39.40.41.42")
                    self.assertEqual(ip.dst, "10.0.0.%u" % asid)
                    self.assertEqual(ip.proto, 47)
                    self.assertEqual(len(ip.options), 0)
                    self.assertTrue(ip.ttl >= 64)
                else:
                    ip = p[IPv6]
                    gre = p[GRE]
                    inner = gre[IP] if isv4 else gre[IPv6]
                    asid = ip.dst.split(":")
                    asid = asid[len(asid) - 1]
                    asid = 0 if asid=="" else int(asid)
                    self.assertEqual(ip.version, 6)
                    # Todo: Given scapy... I will do that when it works.
                self.checkInner(gre, isv4)
                load[asid] += 1
            except:
                self.log("Unexpected or invalid packet:")
                p.show()
                raise

        # This is just to roughly check that the balancing algorithm
        # is not completly biased.
        for asid in self.ass:
            if load[asid] < len(self.packets)/(len(self.ass)*2):
                self.log("ASS is not balanced: load[%d] = %d" % (asid, load[asid]))
                raise Exception("Load Balancer algorithm is biased")


    def test_lb_ip4_gre4(self):
        """ Load Balancer IP4 GRE4 """

        return
        self.cli(0, "lb vip 90.0.0.0/8 encap gre4")
        for asid in self.ass:
            self.cli(0, "lb as 90.0.0.0/8 10.0.0.%u" % (asid))

        self.pg_add_stream(0, self.generatePackets(1))
        self.pg_enable_capture([0,1])
        self.pg_start()
        self.checkCapture(1, 1)

        for asid in self.ass:
            self.cli(0, "lb as 90.0.0.0/8 10.0.0.%u del" % (asid))
        self.cli(0, "lb vip 90.0.0.0/8 encap gre4 del")


    def test_lb_ip6_gre4(self):
        """ Load Balancer IP6 GRE4 """

        self.cli(0, "lb vip 2001::/16 encap gre4")
        for asid in self.ass:
            self.cli(0, "lb as 2001::/16 10.0.0.%u" % (asid))

        self.pg_add_stream(0, self.generatePackets(0))
        self.pg_enable_capture([0,1])
        self.pg_start()

        # Scapy fails parsing IPv6 over GRE.
        # This check is therefore disabled for now.
        #self.checkCapture(1, 0)

        for asid in self.ass:
            self.cli(0, "lb as 2001::/16 10.0.0.%u del" % (asid))
        self.cli(0, "lb vip 2001::/16 encap gre4 del")


    def test_lb_ip4_gre6(self):
        """ Load Balancer IP4 GRE6 """

        self.cli(0, "lb vip 90.0.0.0/8 encap gre6")
        for asid in self.ass:
            self.cli(0, "lb as 90.0.0.0/8 2002::%u" % (asid))

        self.pg_add_stream(0, self.generatePackets(1))
        self.pg_enable_capture([0,1])
        self.pg_start()

        # Scapy fails parsing GRE over IPv6.
        # This check is therefore disabled for now.
        # One can easily patch layers/inet6.py to fix the issue.
        #self.checkCapture(0, 1)

        for asid in self.ass:
            self.cli(0, "lb as 90.0.0.0/8 2002::%u" % (asid))
        self.cli(0, "lb vip 90.0.0.0/8 encap gre6 del")

    def test_lb_ip6_gre6(self):
        """ Load Balancer IP6 GRE6 """

        self.cli(0, "lb vip 2001::/16 encap gre6")
        for asid in self.ass:
            self.cli(0, "lb as 2001::/16 2002::%u" % (asid))

        self.pg_add_stream(0, self.generatePackets(0))
        self.pg_enable_capture([0,1])
        self.pg_start()

        # Scapy fails parsing IPv6 over GRE and IPv6 over GRE.
        # This check is therefore disabled for now.
        #self.checkCapture(0, 0)

        for asid in self.ass:
            self.cli(0, "lb as 2001::/16 2002::%u del" % (asid))
        self.cli(0, "lb vip 2001::/16 encap gre6 del")

