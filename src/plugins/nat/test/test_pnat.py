#!/usr/bin/env python3
"""Policy 1:1 NAT functional tests"""

import unittest
from scapy.layers.inet import Ether, IP, UDP
from framework import VppTestCase, VppTestRunner


class TestPNAT(VppTestCase):
    """ PNAT Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestPNAT, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestPNAT, cls).tearDownClass()

    def setUp(self):
        super(TestPNAT, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestPNAT, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def test_pnat(self):
        """ PNAT test """

        # RX rewrite
        match = {'mask': 0xa, 'dst': '10.10.10.10', 'proto': 17, 'dport': 6871}
        rewrite = {'mask': 0x2, 'dst': self.pg1.remote_ip4}
        self.vapi.pnat_binding_add(match=match, rewrite=rewrite,
                                   sw_if_index=self.pg0.sw_if_index,
                                   is_input=True)

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='10.10.10.10')
        p4 = p_ether / p_ip4 / UDP(dport=6871)
        p4_reply = (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                    UDP(dport=6871))
        p4_reply.ttl -= 1

        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            p.show2()
            self.validate(p[1], p4_reply)
        # self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)

        # TX rewrite
        match = {'mask': 0x9, 'src': self.pg0.remote_ip4, 'proto': 17,
                 'dport': 6871}
        rewrite = {'mask': 0x1, 'src': '11.11.11.11'}
        self.vapi.pnat_binding_add(match=match, rewrite=rewrite,
                                   sw_if_index=self.pg1.sw_if_index,
                                   is_input=False)

        print(self.vapi.cli("show pnat translations"))

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='10.10.10.10')
        p4 = p_ether / p_ip4 / UDP(dport=6871)
        p4_reply = (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                    UDP(dport=6871))
        p4_reply.ttl -= 1

        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            p.show2()
            self.validate(p[1], p4_reply)
        # self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
