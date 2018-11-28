#!/usr/bin/env python
import binascii
import random
import socket
import unittest
import os
import scapy.layers.inet6 as inet6

from util import ppp, ppc
from re import compile
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from framework import VppTestCase, VppTestRunner


class TestPuntSocket(VppTestCase):
    """ Punt Socket """

    tempdir = ""
    sock = None
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

    def socket_client_create(self, sock_name):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            os.unlink(sock_name)
        except:
            self.logger.debug("Unlink socket faild")
        self.sock.bind(sock_name)

    def socket_client_close(self):
        self.sock.close()


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
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111")
        self.vapi.punt_socket_register(2222, self.tempdir+"/socket_punt_2222")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1111)
        # self.assertEqual(punts[0].pathname, "/tmp/punt_socket_udp_1234")
        self.assertEqual(punts[1].punt.l4_port, 2222)
        # self.assertEqual(punts[1].pathname, "/tmp/punt_socket_udp_5678")

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1111)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111")
        self.vapi.punt_socket_register(3333, self.tempdir+"/socket_punt_3333")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 3)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1111)
        self.vapi.punt_socket_deregister(2222)
        self.vapi.punt_socket_deregister(3333)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic(self):
        """ Punt socket traffic"""

        nr_packets = 8
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=9876, dport=1234) /
             Raw('\xa5' * 100))

        pkts = p * nr_packets

        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)

        #
        # expect ICMP - port unreachable for all packets
        #
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(nr_packets)
        for p in rx:
            self.assertEqual(int(p[IP].proto), 1)   # ICMP
            self.assertEqual(int(p[ICMP].code), 3)  # unreachable

        #
        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_punt_1234")
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt_1234")
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 1)

        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.socket_client_close()

        #
        # remove punt socket. expect ICMP - port unreachable for all packets
        #
        self.vapi.punt_socket_deregister(1234)
        punts = self.vapi.punt_socket_dump(0)
        self.assertEqual(len(punts), 0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
        # self.pg0.get_capture(nr_packets)


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
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111",
                                       is_ip4=0)
        self.vapi.punt_socket_register(2222, self.tempdir+"/socket_punt_2222",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1111)
        # self.assertEqual(punts[0].pathname, "/tmp/punt_socket_udp_1234")
        self.assertEqual(punts[1].punt.l4_port, 2222)
        # self.assertEqual(punts[1].pathname, "/tmp/punt_socket_udp_5678")

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1111, is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 2)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1111, is_ip4=0)
        self.vapi.punt_socket_deregister(2222, is_ip4=0)
        self.vapi.punt_socket_deregister(3333, is_ip4=0)
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
        # expect ICMPv6 - destination unreachable for all packets
        #
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(nr_packets)
        for p in rx:
            self.assertEqual(int(p[IPv6].nh), 58)                # ICMPv6
            self.assertEqual(int(p[ICMPv6DestUnreach].code), 4)  # unreachable

        #
        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_punt_1234")
        self.vapi.punt_socket_register(1234, self.tempdir+"/socket_punt_1234",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 1)

        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.socket_client_close()

        #
        # remove punt socket. expect ICMP - dest. unreachable for all packets
        #
        self.vapi.punt_socket_deregister(1234, is_ip4=0)
        punts = self.vapi.punt_socket_dump(1)
        self.assertEqual(len(punts), 0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
#        self.pg0.get_capture(nr_packets)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
