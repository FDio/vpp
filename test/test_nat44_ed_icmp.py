#!/usr/bin/env python3
"""NAT44 ED ICMP errors"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet import ICMP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4, ppp
from vpp_papi import VppEnum


"""
Test NAT44 ICMP errors.
"""


class TestNATICMPError(VppTestCase):
    """ NAT ICMP error Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.nat44_ed_plugin_enable_disable(sessions=10, enable=1)

    def tearDown(self):
        super().tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()
        self.vapi.nat44_ed_plugin_enable_disable(enable=0)

    def validate(self, rx, expected):
        self.assertEqual(ppp("", rx), ppp("", expected.__class__(scapy.compat.raw(expected))))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def nat_output_feature(self, sw_if_index):
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=sw_if_index, is_add=1,)

    def nat_inside_interface(self, sw_if_index):
        flags = VppEnum.vl_api_nat_config_flags_t
        self.vapi.nat44_interface_add_del_feature(flags=flags.NAT_IS_INSIDE,
                                                  sw_if_index=sw_if_index,
                                                  is_add=1)

    def nat_outside_interface(self, sw_if_index):
        flags = VppEnum.vl_api_nat_config_flags_t
        self.vapi.nat44_interface_add_del_feature(flags=flags.NAT_IS_OUTSIDE,
                                                  sw_if_index=sw_if_index,
                                                  is_add=1)

    def nat_add_address(self, nat_address):
        self.vapi.nat44_add_del_address_range(first_ip_address=nat_address,
                                              last_ip_address=nat_address,
                                              vrf_id=0, is_add=1, flags=0)

    def test_nat_output_feature_ttl_2(self):
        ''' in2out: output feature with ttl 2'''
        nat_address = '10.11.12.13'
        self.nat_add_address(nat_address)
        self.nat_output_feature(self.pg1.sw_if_index)

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=2)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = p_ip4 / p_payload
        p4_reply.ttl -= 1
        p4_reply[IP].src = nat_address
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)

        # Recived packet
        print('RECEIVED PACKET:')
        rx[0].show2()
        self.validate(rx[0][IP], p4_reply)

    def test_nat_local_icmp_time_exceeded(self):
        ''' in2out: locally generated time exceeded'''
        nat_address = '10.11.12.13'
        self.nat_add_address(nat_address)
        self.nat_output_feature(self.pg1.sw_if_index)

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=1)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1)

        p4 = p_ether / p_ip4 / p_payload
        p_ip4_reply = p_ip4
        p_ip4_reply.ttl = 0
        p4_reply = (IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4,
                       ttl=254, id=0) /
                    ICMP(type='time-exceeded',
                         code='ttl-zero-during-transit') /
                    p_ip4_reply / p_payload)
        rx = self.send_and_expect(self.pg0, p4*1, self.pg0)

        # Recived packet
        print('RECEIVED PACKET:')
        rx[0].show2()
        print('EXPECTED PACKET:')
        p4_reply.show2()
        self.validate(rx[0][IP], p4_reply)

    def test_nat_out2in_icmp_error(self):
        """ out2in: verify received icmp error translated correctly """

        nat_address = '10.11.12.13'
        self.nat_add_address(nat_address)
        self.nat_inside_interface(self.pg0.sw_if_index)
        self.nat_outside_interface(self.pg1.sw_if_index)

        # Packet to trigger session creation
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1)

        p4 = p_ether / p_ip4 / p_payload
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)

        # Recived packet
        print('RECEIVED PACKET:')
        rx[0].show2()

        # Reply with ICMP error.
        p_o2i_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        p_icmp4 = ICMP(type='time-exceeded', code='ttl-zero-during-transit')
        icmp4_reply = (IP(src='88.88.88.88',
                          dst=rx[0][IP].src,
                          ttl=254, id=0) /
                       p_icmp4 / rx[0][IP])
        p_o2i = p_o2i_ether / icmp4_reply
        print('ICMP REPLY TO SEND:')
        icmp4_reply.show2()

        # Do we get a correctly translated ICMP error back???
        rx = self.send_and_expect(self.pg1, p_o2i*1, self.pg0)

        p_ip4_reply = icmp4_reply
        p_ip4_reply.ttl -= 1
        p_ip4_reply.dst = self.pg0.remote_ip4
        p_ip4_reply[ICMP][IP].src = self.pg0.remote_ip4
        print('TRANSLATED ICMP ERROR:')
        rx[0].show2()
        print('EXPECTED ICMP ERROR:')
        del p_ip4_reply[IP].chksum
        del p_ip4_reply[ICMP].chksum
        del p_ip4_reply[ICMP][IP].chksum
        del p_ip4_reply[ICMP][UDP].chksum
        p_ip4_reply.show2()

        self.validate(rx[0][IP], p_ip4_reply)

        print('SESSIONS', self.vapi.cli('show nat44 sessions'))

    def test_nat_out2in_icmp_error_checksum(self):
        """ out2in: verify received icmp error translated correctly """

        nat_address = '10.11.12.13'
        self.nat_add_address(nat_address)
        self.nat_inside_interface(self.pg0.sw_if_index)
        self.nat_outside_interface(self.pg1.sw_if_index)

        # Packet to trigger session creation
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1)

        p4 = p_ether / p_ip4 / p_payload
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)

        # Recived packet
        print('RECEIVED PACKET:')
        rx[0].show2()

        # Reply with ICMP error.
        p_o2i_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        p_icmp4 = ICMP(type='time-exceeded',
                       code='ttl-zero-during-transit', chksum=0x1234)
        icmp4_reply = (IP(src='88.88.88.88',
                          dst=rx[0][IP].src,
                          ttl=254, id=0) /
                       p_icmp4 / rx[0][IP])
        p_o2i = p_o2i_ether / icmp4_reply
        print('ICMP REPLY TO SEND:')
        icmp4_reply.show2()

        # Do we get a correctly translated ICMP error back???
        rx = self.send_and_expect(self.pg1, p_o2i*1, self.pg0)

        # TODO check drop counter
        self.assertEqual(len(rx), 0)

    def test_nat_out2in_icmp_error_short(self):
        """ out2in: verify received icmp error translated correctly """

        nat_address = '10.11.12.13'
        self.nat_add_address(nat_address)
        self.nat_inside_interface(self.pg0.sw_if_index)
        self.nat_outside_interface(self.pg1.sw_if_index)

        # Packet to trigger session creation
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
        p_payload = UDP(sport=1234, dport=1234) / self.payload(1)

        p4 = p_ether / p_ip4 / p_payload
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)

        # Recived packet
        print('RECEIVED PACKET:')
        rx[0].show2()

        # Reply with ICMP error.
        p_o2i_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        p_icmp4 = ICMP(type='time-exceeded', code='ttl-zero-during-transit')
        icmp4_reply = (IP(src='88.88.88.88',
                          dst=rx[0][IP].src,
                          ttl=254, id=0) /
                       p_icmp4 / rx[0][IP])

        # Bit of a hack, just setting the outer IP length and shipping
        # packet with a bit of padding
        icmp4_reply.len = 28
        p_o2i = p_o2i_ether / icmp4_reply
        print('ICMP REPLY TO SEND:')
        icmp4_reply.show2()

        # Verify that we do not receive an ICMP back. Should be silently
        # dropped
        rx = self.send_and_expect(self.pg1, p_o2i*1, self.pg0)
        self.assertEqual(len(rx), 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
