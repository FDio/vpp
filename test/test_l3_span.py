#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_udp_encap import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def find_l3_span(test, ip_addr, len, table_id=0, inet=AF_INET):
    if inet == AF_INET:
        s = 4
        routes = test.vapi.l3_span_dump()
    else:
        s = 16
        routes = test.vapi.l3_span_dump()

    for e in routes:
        if ip_addr == e.span.dst_address[:s] \
           and len == e.span.dst_address_length \
           and table_id == e.span.table_id:
            return True
    return False


class VppL3Span(VppObject):
    """
    L3 Span Entry
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, is_ip6=0):
        self._test = test
        self.paths = paths
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.dest_addr_p = dest_addr
        if is_ip6:
            self.dest_addr = inet_pton(AF_INET6, dest_addr)
        else:
            self.dest_addr = inet_pton(AF_INET, dest_addr)

    def add_vpp_config(self):
        paths = []
        for p in self.paths:
            paths.append(p.encode())

        self._test.vapi.l3_span_add_del(
            self.table_id,
            self.dest_addr,
            self.dest_addr_len,
            self.is_ip6,
            paths,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        paths = []
        for p in self.paths:
            paths.append(p.encode())

        self._test.vapi.l3_span_add_del(
            self.table_id,
            self.dest_addr,
            self.dest_addr_len,
            self.is_ip6,
            paths,
            is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("l3-span[%d:%s/%d]" % (self.table_id,
                                       self.dest_addr_p,
                                       self.dest_addr_len))

    def query_vpp_config(self):
        return find_l3_span(self._test,
                            self.dest_addr,
                            self.dest_addr_len,
                            self.table_id,
                            inet=AF_INET6 if self.is_ip6 == 1 else AF_INET)


class TestL3Span(VppTestCase):
    """ L3-span Test Case """
    def setUp(self):
        super(TestL3Span, self).setUp()

        # create 4 pg interfaces
        self.create_pg_interfaces(range(4))

        # setup all interfaces
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.set_table_ip4(0)
            i.admin_down()
        super(TestL3Span, self).tearDown()

    def test_l3_span(self):
        """L3 Span"""

        #
        # Use a UDP encap object as the span 'collectors'
        #
        udp_encap_1 = VppUdpEncap(self, 1,
                                  self.pg1.local_ip4,
                                  self.pg1.remote_ip4,
                                  310, 311)
        udp_encap_2 = VppUdpEncap(self, 2,
                                  self.pg2.local_ip4,
                                  self.pg2.remote_ip4,
                                  320, 321)
        udp_encap_1.add_vpp_config()
        udp_encap_2.add_vpp_config()

        route_10_s_24 = VppIpRoute(self, "10.0.0.0", 24,
                                   [VppRoutePath(self.pg3.remote_ip4,
                                                 self.pg3.sw_if_index)])
        route_10_s_24.add_vpp_config()

        l3s_10_0_0_0 = VppL3Span(self, "10.0.0.0", 24,
                                 [VppRoutePath("0.0.0.0",
                                               0xFFFFFFFF,
                                               is_udp_encap=1,
                                               next_hop_id=1),
                                  VppRoutePath("0.0.0.0",
                                               0xFFFFFFFF,
                                               is_udp_encap=1,
                                               next_hop_id=2)])
        l3s_10_0_0_0.add_vpp_config()

        self.logger.error(self.vapi.cli("sh l3-span"))

        #
        # A packet matching the Spanned route
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.0.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        self.pg0.add_stream(p * 65)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(65)
        rx = self.pg2.get_capture(65)
        rx = self.pg1.get_capture(65)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
