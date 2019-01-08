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

import unittest

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

from framework import extended_test, reported_bug, VppTestCase, VppTestRunner


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

        :param VppInterface src_if: Packets are send to this interface,
            using this interfaces remote host.
        :param list dst_ifs: IPv4 ICMP requests are send to interfaces
            addresses.
        :return: List of generated packets.
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

        :param capture: Capture to verify.
        :param VppInterface request_src_if: Interface where was send packets.
        :param list dst_ifs: Interfaces where was generated IPv4 ICMP requests.
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

    def test_crud(self):
        # create
        loopbacks = self.create_loopback_interfaces(20)
        for i in loopbacks:
            i.local_ip4_prefix_len = 32
            i.config_ip4()
            i.admin_up()

        # read (check sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        fib4_dump = self.vapi.ip_fib_dump()
        for i in loopbacks:
            self.assertTrue(i.is_interface_config_in_dump(if_dump))
            self.assertTrue(i.is_ip4_entry_in_fib_dump(fib4_dump))

        # check ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(expected_count=len(stream))

        self.verify_icmp(capture, self.pg0, loopbacks)

        # delete
        for i in loopbacks:
            i.remove_vpp_config()

        # read (check not in sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        fib4_dump = self.vapi.ip_fib_dump()
        for i in loopbacks:
            self.assertFalse(i.is_interface_config_in_dump(if_dump))
            self.assertFalse(i.is_ip4_entry_in_fib_dump(fib4_dump))

        #  check not ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

    def test_down(self):
        # create
        loopbacks = self.create_loopback_interfaces(20)
        for i in loopbacks:
            i.local_ip4_prefix_len = 32
            i.config_ip4()
            i.admin_up()

        # disable
        for i in loopbacks:
            i.admin_down()
            i.unconfig_ip4()

        # read (check not in sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        fib4_dump = self.vapi.ip_fib_dump()
        for i in loopbacks:
            self.assertTrue(i.is_interface_config_in_dump(if_dump))
            self.assertFalse(i.is_ip4_entry_in_fib_dump(fib4_dump))

        #  check not ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()


class TestLoopbackSimpleTests(VppTestCase):
    """Simple Loopback Tests (No PG's, etc...)"""

    @reported_bug
    def test_idempotent_add_address(self):
        """Test re-adding the same address passes silently."""
        _loopback, = self.create_loopback_interfaces(1)
        _addr = '\x01\x02\x03\x04'
        _addr_len = 24
        _args = {'sw_if_index': _loopback.sw_if_index,
                 'address': _addr,
                 'address_length': _addr_len,
                 'is_add': 1}
        for _ in range(2):
            _rv = self.vapi.api(self.vapi.papi.sw_interface_add_del_address,
                                _args)
            self.assertEqual(_rv.retval, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
