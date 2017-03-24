import socket

from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase
from util import ppp

""" TestPing is a subclass of  VPPTestCase classes.

Basic test for sanity check of the ping.

"""


class TestPing(VppTestCase):
    """ Ping Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPing, cls).setUpClass()
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
        except Exception:
            super(TestPing, cls).tearDownClass()
            raise

    def tearDown(self):
        super(TestPing, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def test_ping_basic(self):
        """ basic ping test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.logger.info(self.vapi.cli("show ip arp"))
            self.logger.info(self.vapi.cli("show ip6 neighbors"))

            remote_ip4 = self.pg1.remote_ip4
            ping_cmd = "ping " + remote_ip4 + " interval 0.01 repeat 10"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(10)
            icmp_id = None
            icmp_seq = 1
            for p in out:
                ip = p[IP]
                self.assertEqual(ip.version, 4)
                self.assertEqual(ip.flags, 0)
                self.assertEqual(ip.src, self.pg1.local_ip4)
                self.assertEqual(ip.dst, self.pg1.remote_ip4)
                self.assertEqual(ip.proto, 1)
                self.assertEqual(len(ip.options), 0)
                self.assertGreaterEqual(ip.ttl, 254)
                icmp = p[ICMP]
                self.assertEqual(icmp.type, 8)
                self.assertEqual(icmp.code, 0)
                self.assertEqual(icmp.seq, icmp_seq)
                icmp_seq = icmp_seq + 1
                if icmp_id is None:
                    icmp_id = icmp.id
                else:
                    self.assertEqual(icmp.id, icmp_id)
        finally:
            self.vapi.cli("show error")

    def test_ping_burst(self):
        """ burst ping test """
        try:
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.logger.info(self.vapi.cli("show ip arp"))
            self.logger.info(self.vapi.cli("show ip6 neighbors"))

            remote_ip4 = self.pg1.remote_ip4
            ping_cmd = "ping " + remote_ip4 + " interval 0.01 burst 3"
            ret = self.vapi.cli(ping_cmd)
            self.logger.info(ret)
            out = self.pg1.get_capture(3*5)
            icmp_id = None
            icmp_seq = 1
            count = 0
            for p in out:
                ip = p[IP]
                self.assertEqual(ip.version, 4)
                self.assertEqual(ip.flags, 0)
                self.assertEqual(ip.src, self.pg1.local_ip4)
                self.assertEqual(ip.dst, self.pg1.remote_ip4)
                self.assertEqual(ip.proto, 1)
                self.assertEqual(len(ip.options), 0)
                self.assertGreaterEqual(ip.ttl, 254)
                icmp = p[ICMP]
                self.assertEqual(icmp.type, 8)
                self.assertEqual(icmp.code, 0)
                self.assertEqual(icmp.seq, icmp_seq)
                count = count + 1
                if count >= 3:
                    icmp_seq = icmp_seq + 1
                    count = 0
                if icmp_id is None:
                    icmp_id = icmp.id
                else:
                    self.assertEqual(icmp.id, icmp_id)
        finally:
            self.vapi.cli("show error")
