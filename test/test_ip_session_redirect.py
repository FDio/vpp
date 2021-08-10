#!/usr/bin/env python3

import unittest

import socket

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from vpp_papi import VppEnum
from vpp_ip_route import VppRoutePath

from framework import VppTestCase


class TestIpSessionRedirect(VppTestCase):
    """ IP session redirect Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIpSessionRedirect, cls).setUpClass()
        itfs = cls.create_pg_interfaces(range(3))
        for itf in itfs:
            itf.admin_up()
            itf.config_ip4()
            itf.resolve_arp()
            itf.config_ip6()
            itf.resolve_ndp()

    def __build_mask(self, ip, src_port, match_n_vectors):
        # UDP: udp src port (2 bytes)
        udp = src_port.to_bytes(2, byteorder='big')
        match = ip + udp
        # skip the remainer
        match += b'\x00' * (match_n_vectors * 16 - len(match))
        return match

    def build_mask4(self, proto, src_ip, src_port):
        proto = proto.to_bytes(1, byteorder='big')
        # IP: skip 9 bytes | proto (1 byte) | skip checksum (2 bytes) | src IP
        # (4 bytes) | skip dst IP (4 bytes)
        ip = b'\x00' * 9 + proto + b'\x00' * 2 + src_ip + b'\x00' * 4
        return self.__build_mask(ip, src_port, 2)

    def build_mask6(self, proto, src_ip, src_port):
        nh = proto.to_bytes(1, byteorder='big')
        # IPv6: skip 6 bytes | nh (1 byte) | skip hl (1 byte) | src IP (16
        # bytes) | skip dst IP (16 bytes)
        ip = b'\x00' * 6 + nh + b'\x00' + src_ip + b'\x00' * 16
        return self.__build_mask(ip, src_port, 4)

    def build_match(self, src_ip, src_port, is_ip6):
        if is_ip6:
            return self.build_mask6(
                0x11, socket.inet_pton(
                    socket.AF_INET6, src_ip), src_port)
        else:
            return self.build_mask4(
                0x11, socket.inet_pton(
                    socket.AF_INET, src_ip), src_port)

    def create_table(self, is_ip6):
        if is_ip6:
            mask = self.build_mask6(0xff, b'\xff' * 16, 0xffff)
            match_n_vectors = 4
        else:
            mask = self.build_mask4(0xff, b'\xff' * 4, 0xffff)
            match_n_vectors = 2
        r = self.vapi.classify_add_del_table(
            is_add=True,
            match_n_vectors=match_n_vectors,
            miss_next_index=0,    # drop
            current_data_flag=1,  # match on current header (ip)
            mask_len=len(mask),
            mask=mask)
        return r.new_table_index

    def punt_redirect(self, sport, dport, is_ip6):
        if is_ip6:
            af = VppEnum.vl_api_address_family_t.ADDRESS_IP6
            nh1 = self.pg1.remote_ip6
            nh2 = self.pg2.remote_ip6
            src = self.pg0.remote_ip6
            dst = self.pg0.local_ip6
            IP46 = IPv6
        else:
            af = VppEnum.vl_api_address_family_t.ADDRESS_IP4
            nh1 = self.pg1.remote_ip4
            nh2 = self.pg2.remote_ip4
            src = self.pg0.remote_ip4
            dst = self.pg0.local_ip4
            IP46 = IP

        # punt udp packets to dport
        self.vapi.set_punt(
            is_add=1,
            punt={
                'type': VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4,
                'punt': {
                    'l4': {
                        'af': af,
                        'protocol': VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                        'port': dport,
                    }}})

        pkts = [(Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP46(src=src, dst=dst) /
                 UDP(sport=sport, dport=dport) /
                 Raw('\x17' * 100))] * 2

        # create table and configure punt ACL
        table_index = self.create_table(is_ip6)
        ip4_tid, ip6_tid = (
            0xffffffff, table_index) if is_ip6 else (
            table_index, 0xffffffff)
        self.vapi.punt_acl_add_del(is_add=1, ip4_table_index=ip4_tid,
                                   ip6_table_index=ip6_tid)

        # add a session redirect rule but not matching the stream: expect to
        # drop
        paths = [VppRoutePath(nh1, 0xffffffff).encode()]
        match1 = self.build_match(src, sport + 10, is_ip6)
        self.vapi.ip_session_redirect_add(table_index, len(match1), match1,
                                          is_punt=True, n_paths=1, paths=paths)
        self.send_and_assert_no_replies(self.pg0, pkts)

        # redirect a session matching the stream: expect to pass
        match2 = self.build_match(src, sport, is_ip6)
        self.vapi.ip_session_redirect_add(table_index, len(match2), match2,
                                          is_punt=True, n_paths=1, paths=paths)
        self.send_and_expect_only(self.pg0, pkts, self.pg1)

        # update the matching entry so it redirects to pg2
        paths = [VppRoutePath(nh2, 0xffffffff).encode()]
        self.vapi.ip_session_redirect_add(table_index, len(match2), match2,
                                          is_punt=True, n_paths=1, paths=paths)
        self.send_and_expect_only(self.pg0, pkts, self.pg2)

        # we still have only 2 sessions, not 3
        t = self.vapi.classify_table_info(table_id=table_index)
        self.assertEqual(t.active_sessions, 2)

        # cleanup
        self.vapi.ip_session_redirect_del(table_index, len(match2), match2)
        self.vapi.ip_session_redirect_del(table_index, len(match1), match1)
        self.vapi.punt_acl_add_del(is_add=0, ip4_table_index=ip4_tid,
                                   ip6_table_index=ip6_tid)

    def test_punt_redirect_ipv4(self):
        """ IPv4 punt session redirect test """
        return self.punt_redirect(sport=6754, dport=17923, is_ip6=False)

    def test_punt_redirect_ipv6(self):
        """ IPv6 punt session redirect test """
        return self.punt_redirect(sport=28447, dport=4035, is_ip6=True)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
