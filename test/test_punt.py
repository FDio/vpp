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
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from socket import AF_INET, AF_INET6, inet_pton


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


class TestPunt(VppTestCase):
    """ Punt Test Case """

    def setUp(self):
        super(TestPunt, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.ip6_disable()
            i.admin_down()
        super(TestPunt, self).tearDown()

    def test_punt(self):
        """ Excpetion Path testing """

        #
        # Using the test CLI we will hook in a exception path to
        # send ACL deny packets out of pg0 and pg1.
        # the ACL is src,dst = 1.1.1.1,1.1.1.2
        #
        ip_1_1_1_2 = VppIpRoute(self, "1.1.1.2", 32,
                                [VppRoutePath(self.pg3.remote_ip4,
                                              self.pg3.sw_if_index)])
        ip_1_1_1_2.add_vpp_config()
        ip_1_2 = VppIpRoute(self, "1::2", 128,
                            [VppRoutePath(self.pg3.remote_ip6,
                                          self.pg3.sw_if_index,
                                          proto=DpoProto.DPO_PROTO_IP6)],
                            is_ip6=1)
        ip_1_2.add_vpp_config()

        rule_4 = ({'is_permit': 0,
                   'is_ipv6': 0,
                   'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1234,
                   'src_ip_prefix_len': 32,
                   'src_ip_addr': inet_pton(AF_INET, "1.1.1.1"),
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_prefix_len': 32,
                   'dst_ip_addr': inet_pton(AF_INET, "1.1.1.2")})
        acl_4 = self.vapi.acl_add_replace(acl_index=4294967295, r=[rule_4])
        rule_6 = ({'is_permit': 0,
                   'is_ipv6': 1,
                   'proto': 17,
                   'srcport_or_icmptype_first': 1234,
                   'srcport_or_icmptype_last': 1234,
                   'src_ip_prefix_len': 128,
                   'src_ip_addr': inet_pton(AF_INET6, "1::1"),
                   'dstport_or_icmpcode_first': 1234,
                   'dstport_or_icmpcode_last': 1234,
                   'dst_ip_prefix_len': 128,
                   'dst_ip_addr': inet_pton(AF_INET6, "1::2")})
        acl_6 = self.vapi.acl_add_replace(acl_index=4294967295, r=[rule_6])

        p4 = (Ether(src=self.pg2.remote_mac,
                    dst=self.pg2.local_mac) /
              IP(src="1.1.1.1", dst="1.1.1.2") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        p6 = (Ether(src=self.pg2.remote_mac,
                    dst=self.pg2.local_mac) /
              IPv6(src="1::1", dst="1::2") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        self.send_and_expect(self.pg2, p4*1, self.pg3)
        self.send_and_expect(self.pg2, p6*1, self.pg3)

        #
        # apply the ACLs on pg2
        #
        self.vapi.acl_interface_set_acl_list(sw_if_index=self.pg2.sw_if_index,
                                             n_input=2,
                                             acls=[acl_4.acl_index,
                                                   acl_6.acl_index])

        #
        # pkts now dropped
        #
        self.send_and_assert_no_replies(self.pg2, p4*65)
        self.send_and_assert_no_replies(self.pg2, p6*65)

        #
        # Check state:
        #  1 - node error counters
        #  2 - per-reason counters
        #
        stats = self.statistics.get_counter(
            "/err/punt-dispatch/No registrations")
        self.assertEqual(stats, 130)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][0]['packets'], 65)
        self.assertEqual(stats[0][1]['packets'], 65)

        #
        # use the test CLI to test a client that punts ACL exception
        # packets out of pg0
        #
        self.vapi.cli("test punt pg0 %s" % self.pg0.remote_ip4)
        self.vapi.cli("test punt pg0 %s" % self.pg0.remote_ip6)

        rx4s = self.send_and_expect(self.pg2, p4*65, self.pg0)
        rx6s = self.send_and_expect(self.pg2, p6*65, self.pg0)

        #
        # check the packets come out IP modified but destined to pg0 host
        #
        for rx in rx4s:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)
        for rx in rx6s:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][0]['packets'], 2*65)
        self.assertEqual(stats[0][1]['packets'], 2*65)

        #
        # add another registration for the same reason to send packets
        # out of pg1
        #
        self.vapi.cli("test punt pg1 %s" % self.pg1.remote_ip4)
        self.vapi.cli("test punt pg1 %s" % self.pg1.remote_ip6)

        self.vapi.cli("clear trace")
        self.pg2.add_stream(p4 * 65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = self.pg0.get_capture(65)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)
        rxd = self.pg1.get_capture(65)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)

        self.vapi.cli("clear trace")
        self.pg2.add_stream(p6 * 65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = self.pg0.get_capture(65)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)
        rxd = self.pg1.get_capture(65)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][0]['packets'], 3*65)
        self.assertEqual(stats[0][1]['packets'], 3*65)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
