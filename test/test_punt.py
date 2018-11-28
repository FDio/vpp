#!/usr/bin/env python
import binascii
import random
import socket
import unittest
from re import compile

from framework import VppTestCase, VppTestRunner
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
import scapy.layers.inet6 as inet6
from scapy.layers.inet6 import IPv6


class TestPuntSocket(VppTestCase):
    """ Punt Socket """

    tempdir = ""
    err_ptr = compile(r"^([\d]+)\s+([-\w]+)\s+([ -\.\w)(]+)$")

    @classmethod
    def setUpConstants(cls):
        tempdir = cls.tempdir
        cls.extra_vpp_punt_config = [
            "punt", "{", "socket", cls.tempdir+"/socket_punt", "}"]
        super(TestPuntSocket, cls).setUpConstants()

    def process_cli(self, exp, ptr):
        for line in self.vapi.cli(exp).split('\n')[1:]:
            m = ptr.match(line.strip())
            if m:
                yield m.groups()

    def show_errors(self):
        for pack in self.process_cli("show errors", self.err_ptr):
            try:
                count, node, reason = pack
            except ValueError:
                pass
            else:
                yield count, node, reason

    def get_punt_count(self, counter):
        errors = list(self.show_errors())
        for count, node, reason in errors:
            if (node == counter and
                    reason == u'Socket TX'):
                return int(count)
        return 0


class TestIP4PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv4 """

    def setUp(self):
        super(TestIP4PuntSocket, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIP4PuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_punt_socket_dump(self):
        """ Punt socket registration"""

        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt_1234")
        self.vapi.punt_socket_register(5678, self.tempdir+"/socket_punt_5678")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1234)
        # self.assertEqual(punts[0].pathname, "/tmp/punt_socket_udp_1234")
        self.assertEqual(punts[1].punt.l4_port, 5678)
        # self.assertEqual(punts[1].pathname, "/tmp/punt_socket_udp_5678")

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1234)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 2)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1234)
        self.vapi.punt_socket_deregister(5678)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic(self):
        """ Punt socket traffic"""

        nr_packets = 16
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=9876, dport=1234) /
             Raw('\xa5' * 100))

        pkts = p * nr_packets

        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

        #
        # expect full drop
        #
#        self.send_and_expect(self.pg0, pkts, self.pg0)
#        self.send_and_assert_no_replies(self.pg0, pkts, "IP no punt config")

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 1)

        #
        # expect punt socket
        #
        self.vapi.cli("clear errors")
        self.send_and_expect(self.pg0, pkts, self.pg0)
        self.assertEqual(self.get_punt_count(u'ip4-udp-punt-socket'),
                         nr_packets, "Not all packet have been punted")

        #
        # remove punt socket. expect full drop
        #
        self.vapi.punt_socket_deregister(1234)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)
        self.send_and_assert_no_replies(self.pg0, pkts, "IP no punt config")
        self.assertEqual(self.get_punt_count(u'ip4-udp-punt-socket'),
                         nr_packets, "Unexpected punt")


class TestIP6PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv6"""

    def setUp(self):
        super(TestIP6PuntSocket, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIP6PuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_punt_socket_dump(self):
        """ Punt socket registration """

        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt_1234",
                                       is_ip4=0)
        self.vapi.punt_socket_register(5678, self.tempdir+"/socket_punt_5678",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1234)
        # self.assertEqual(punts[0].pathname, "/tmp/punt_socket_udp_1234")
        self.assertEqual(punts[1].punt.l4_port, 5678)
        # self.assertEqual(punts[1].pathname, "/tmp/punt_socket_udp_5678")

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1234, is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 2)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1234, is_ip4=0)
        self.vapi.punt_socket_deregister(5678, is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic(self):
        """ Punt socket traffic"""

        nr_packets = 2
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
             inet6.UDP(sport=9876, dport=1234) /
             Raw('\xa5' * 100))

        pkts = p * nr_packets

        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 1)

        #
        # expect punt socket
        #
        self.vapi.cli("clear errors")
        self.send_and_expect(self.pg0, pkts, self.pg0)
        self.assertEqual(self.get_punt_count(u'ip6-udp-punt-socket'),
                         nr_packets, "Not all packet have been punted")

        #
        # remove punt socket. expect full drop
        #
        self.vapi.punt_socket_deregister(1234, is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 0)
        self.send_and_assert_no_replies(self.pg0, pkts, "IP no punt config")
        self.assertEqual(self.get_punt_count(u'ip6-udp-punt-socket'),
                         nr_packets, "Unexpected punt")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
