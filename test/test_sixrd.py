#
# Test plan
# - configure sixrd
# - configure ip4 interface and ip6 interface
# - encap 6to4:
#   - send ip6 packet verify on ip4 interface
# - decap 6to4:
#   - send ip4 packet verify on ip6 interface
# - encap recursive
#   - send ip6 packet verify on ip4 interface
# - decap recursive
#   - send ip4 packet verify on ip6 interface
#
#
# TODO:
#  Add API
#  Recursive route handling
#

from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase
from util import ppp
from ipaddress import *

""" Test6rd is a subclass of  VPPTestCase classes.

Basic test for sanity check.

"""


class Test6RD(VppTestCase):
    """ 6RD Test Case """

    @classmethod
    def setUpClass(cls):
        super(Test6RD, cls).setUpClass()
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
            super(Test6RD, cls).tearDownClass()
            raise

    def tearDown(self):
        super(Test6RD, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def test_6rd_basic(self):
        """ basic 6rd test """
        args = { 'ip6_prefix': str(ip_address('2002::').packed),
                 'ip6_prefix_len': 16,
                 'ip4_prefix': str(ip_address('0.0.0.0').packed),
                 'ip4_prefix_len': 0,
                 'ip4_src': str(ip_address('1.1.1.1').packed)
                 }

        rv = self.vapi.vpp.sixrd_add_domain(**args)
        self.assertEqual(rv.retval, 0)
        print('RV', rv)

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src="1::1", dst="2002::0101:0101") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, p, self.pg1)
        for p in rx:
            print('P', p)

        #self.pg0.add_stream(p)
        #self.pg_enable_capture(self.pg_interfaces)
        #self.pg_start()
        #capture = self.pg0.get_capture(1)


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

