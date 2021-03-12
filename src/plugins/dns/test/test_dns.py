#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
from ipaddress import *

import scapy.compat
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, TCP, ICMP, icmptypes, icmpcodes
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.dns import DNSRR, DNS, DNSQR


class TestDns(VppTestCase):
    """ Dns Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDns, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDns, cls).tearDownClass()

    def setUp(self):
        super(TestDns, self).setUp()

        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestDns, self).tearDown()

    def create_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                        IP(src=src_if.remote_ip4) /
                        UDP(sport=1234, dport=53) /
                        DNS(rd=1, qd=DNSQR(qname="bozo.clown.org")))

        bad_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                       IP(src=src_if.remote_ip4) /
                       UDP(sport=1234, dport=53) /
                       DNS(rd=1, qd=DNSQR(qname="no.clown.org")))
        pkts = [good_request, bad_request]
        return pkts

    def create_stream6(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                        IP(src=src_if.remote_ip4) /
                        UDP(sport=1234, dport=53) /
                        DNS(rd=1,
                            qd=DNSQR(qname="bozo.clown.org", qtype='AAAA')))

        bad_request = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                       IP(src=src_if.remote_ip4) /
                       UDP(sport=1234, dport=53) /
                       DNS(rd=1,
                           qd=DNSQR(qname="no.clown.org", qtype='AAAA')))
        pkts = [good_request, bad_request]
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        for packet in capture:
            dns = packet[DNS]
            self.assertEqual(dns.an[0].rdata, '1.2.3.4')

    def verify_capture6(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        for packet in capture:
            dns = packet[DNS]
            self.assertEqual(dns.an[0].rdata, 'deaf::beef')

    def test_dns_unittest(self):
        """ DNS Name Resolver Basic Functional Test """

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address(u'8.8.8.8').packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli(
            "dns cache add bozo.clown.org 1.2.3.4"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b'bozo.clown.org')
        self.assertEqual(rv.ip4_address, IPv4Address(u'1.2.3.4').packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="127.0.0.1/8")

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('1.2.3.4', str)
        self.assertIn('[P] no.clown.org:', str)

    def test_dns_unittest4(self):
        """ DNS Name Resolver Basic Functional Test """

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address(u'8.8.8.8').packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli(
            "dns cache add bozo.clown.org a 1.2.3.4"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b'bozo.clown.org')
        self.assertEqual(rv.ip4_address, IPv4Address(u'1.2.3.4').packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="127.0.0.1/8")

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('1.2.3.4', str)
        self.assertIn('[P] no.clown.org:', str)

    def test_dns_unittest6(self):
        """ DNS Name Resolver Basic Functional Test """

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address(u'8.8.8.8').packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli(
            "dns cache add bozo.clown.org aaaa deaf::beef"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name6(name=b'bozo.clown.org')
        self.assertEqual(rv.ip6_address, IPv6Address(u'deaf::beef').packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="127.0.0.1/8")

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve

        pkts = self.create_stream6(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_capture6(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('deaf::beef', str)
        self.assertIn('[P] no.clown.org:', str)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
