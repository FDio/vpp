#!/usr/bin/env python
"""CRUD tests of APIs (Create, Read, Update, Delete) HLD:

- interface up/down/add/delete - interface type:
    - pg (TBD)
    - loopback
    - vhostuser (TBD)
    - af_packet (TBD)
    - netmap (TBD)
    - tuntap (root privileges needed)
    - vxlan (TBD)
"""

import socket
import unittest
from random import choice

from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppDot1QSubint


class TestLoopbackInterfaceCRUD(VppTestCase):
    """CRUD Loopback

    """

    @classmethod
    def setUpClass(cls):
        super(TestLoopbackInterfaceCRUD, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
        except:
            cls.tearDownClass()
            raise

    @staticmethod
    def create_icmp_stream(src_if, dst_ifs):
        """

        :param src_if:
        :param dst_ifs:
        :return:
        """
        pkts = []
        for i in dst_ifs:
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=i.local_ip4) /
                 ICMP(id=i.sw_if_index, type='echo-request'))
            pkts.append(p)
        return pkts

    def verify_icmp(self, capture, request_src_if, dst_ifs):
        """

        :param capture:
        :param src_if:
        :param dst_ifs:
        """
        rcvd_icmp_pkts = []
        for pkt in capture:
            try:
                ip = pkt[IP]
                icmp = pkt[ICMP]
            except IndexError:
                pass
            else:
                info = (ip.src, ip.dst, icmp.type, icmp.id)
                rcvd_icmp_pkts.append(info)

        for i in dst_ifs:
            # 0 - icmp echo response
            info = (i.local_ip4, request_src_if.remote_ip4, 0, i.sw_if_index)
            self.assertIn(info, rcvd_icmp_pkts)

        pass

    def verify_ip_in_fib_dump(self, dump, ips, mask=32, vrf=0):
        """ Verify if each IP network is in FIB dump.

        :param dump: IPv4 FIB dump.
        :param list ips: IPv4 addresses.
        :param int mask: Address prefix.
        :param int vrf: VRF.
        :return:
        """
        # dumped_fib = [(i.address, i) for i in dump]
        dumped_fib = [(socket.inet_ntop(socket.AF_INET, i.address),
                       i.address_length, i.table_id) for i in dump]
        for i in ips:
            ip = (i, mask, vrf)
            self.assertIn(ip, dumped_fib)

    def verify_ip_not_in_fib_dump(self, dump, ips, mask=32, vrf=0):
        """ Verify if none IP network is in FIB dump.

        :param dump: IPv4 FIB dump.
        :param list ips: IPv4 addresses.
        :param int mask: Address prefix.
        :param int vrf: VRF.
        :return:
        """
        dumped_fib = [(socket.inet_ntop(socket.AF_INET, i.address),
                       i.address_length, i.table_id) for i in dump]

        for i in ips:
            ip = (socket.inet_pton(socket.AF_INET, i), mask, vrf)
            self.assertNotIn(ip, dumped_fib)

    def verify_interface_in_dump(self, dump, interfaces):
        """ Verify if each interface is in interface dump.

        :param dump: PAPI interface dump.
        :param list interfaces: interfaces which must be in dump,
        """
        dumped_interfaces = [
            (i.interface_name.rstrip(' \t\r\n\0'), i.sw_if_index) for i in dump]
        for i in interfaces:
            self.assertIn((i.name, i.sw_if_index), dumped_interfaces)

    def verify_interface_not_in_dump(self, dump, interfaces):
        """ Verify if none of interfaces is in interface dump.

        :param dump: PAPI interface dump.
        :param list interfaces: interfaces which must be in dump.
        """
        dumped_interfaces = [
            (i.interface_name.rstrip(' \t\r\n\0'), i.sw_if_index) for i in dump]
        for i in interfaces:
            self.assertNotIn((i.name, i.sw_if_index), dumped_interfaces)

    def test_crud(self):
        # create
        self.create_loopback_interfaces(range(20))
        for i in self.lo_interfaces:
            i.config_ip4(addr_len=32)

        # read (check sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        self.verify_interface_in_dump(if_dump, self.lo_interfaces)

        fib4_dump = self.vapi.ip_fib_dump()
        self.verify_ip_in_fib_dump(
            fib4_dump,
            (i.local_ip4 for i in self.lo_interfaces))

        # check ping
        stream = self.create_icmp_stream(self.pg0, self.lo_interfaces)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture()

        self.verify_icmp(capture, self.pg0, self.lo_interfaces)

        # delete
        for i in self.lo_interfaces:
            self.vapi.delete_loopback(i.sw_if_index)

        # read (check not in sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        self.verify_interface_not_in_dump(if_dump, self.lo_interfaces)

        fib4_dump = self.vapi.ip_fib_dump()
        self.verify_ip_not_in_fib_dump(
            fib4_dump,
            [i.local_ip4 for i in self.lo_interfaces])

        #  check not ping
        stream = self.create_icmp_stream(self.pg0, self.lo_interfaces)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
