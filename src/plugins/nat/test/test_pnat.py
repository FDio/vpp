#!/usr/bin/env python3
"""Policy 1:1 NAT functional tests"""

import unittest
from scapy.layers.inet import Ether, IP, UDP, ICMP
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

    def test_pnat(self):
        """ PNAT test """

        tests = [
            {
                'input': True,
                'sw_if_index': self.pg0.sw_if_index,
                'match': {'mask': 0xa, 'dst': '10.10.10.10', 'proto': 17,
                          'dport': 6871},
                'rewrite': {'mask': 0x2, 'dst': self.pg1.remote_ip4},
                'send': (IP(src=self.pg0.remote_ip4, dst='10.10.10.10') /
                         UDP(dport=6871)),
                'reply': (IP(src=self.pg0.remote_ip4,
                             dst=self.pg1.remote_ip4) /
                          UDP(dport=6871))
            },
            {
                'input': False,
                'sw_if_index': self.pg1.sw_if_index,
                'match': {'mask': 0x9, 'src': self.pg0.remote_ip4, 'proto': 17,
                          'dport': 6871},
                'rewrite': {'mask': 0x1, 'src': '11.11.11.11'},
                'send': (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                         UDP(dport=6871)),
                'reply': (IP(src='11.11.11.11', dst=self.pg1.remote_ip4) /
                          UDP(dport=6871))
            },
            {
                'input': True,
                'sw_if_index': self.pg0.sw_if_index,
                'match': {'mask': 0xa, 'dst': '10.10.10.10', 'proto': 17,
                          'dport': 6871},
                'rewrite': {'mask': 0xa, 'dst': self.pg1.remote_ip4,
                            'dport': 5555},
                'send': (IP(src=self.pg0.remote_ip4, dst='10.10.10.10') /
                         UDP(dport=6871)),
                'reply': (IP(src=self.pg0.remote_ip4,
                             dst=self.pg1.remote_ip4) /
                          UDP(dport=5555))
            },
            {
                'input': True,
                'sw_if_index': self.pg0.sw_if_index,
                'match': {'mask': 0xa, 'dst': self.pg1.remote_ip4, 'proto': 17,
                          'dport': 6871},
                'rewrite': {'mask': 0x8, 'dport': 5555},
                'send': (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                         UDP(dport=6871)),
                'reply': (IP(src=self.pg0.remote_ip4,
                             dst=self.pg1.remote_ip4) /
                          UDP(dport=5555))
            },
            {
                'input': True,
                'sw_if_index': self.pg0.sw_if_index,
                'match': {'mask': 0x2, 'dst': self.pg1.remote_ip4, 'proto': 1},
                'rewrite': {'mask': 0x1, 'src': '8.8.8.8'},
                'send': (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                         ICMP()),
                'reply': IP(src='8.8.8.8', dst=self.pg1.remote_ip4)/ICMP(),
            },
        ]

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        for t in tests:
            rv = self.vapi.pnat_binding_add(match=t['match'],
                                            rewrite=t['rewrite'],
                                            sw_if_index=t['sw_if_index'],
                                            is_input=t['input'])
            reply = t['reply']
            reply[IP].ttl -= 1
            rx = self.send_and_expect(self.pg0, p_ether/t['send']*1, self.pg1)
            for p in rx:
                p.show2()
                self.validate(p[1], reply)
            self.vapi.pnat_binding_del(index=rv.index)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
