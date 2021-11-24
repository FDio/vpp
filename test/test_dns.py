#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from ipaddress import *

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNSRR, DNS, DNSQR


class TestDnsAPI(VppTestCase):
    """ Dns Test API Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDnsAPI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDnsAPI, cls).tearDownClass()

    def setUp(self):
        super(TestDnsAPI, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestDnsAPI, self).tearDown()

    def create_stream_res(self, src_if):
        """Response from fake DNS server to VPP. """
        answer_A = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
            IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
            UDP(sport=53, dport=53053) /
            DNS(id=1, qr=1, ra=1, rd=1,
                qd=DNSQR(qname="no.clown.org.", qtype="A"),
                an=DNSRR(rrname=b'\xC0\x0C', ttl=600, rdata="4.3.2.1")))
        answer_AAAA = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
            IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
            UDP(sport=53, dport=53053) /
            DNS(id=1, qr=1, ra=1, rd=1,
                qd=DNSQR(qname="no.clown.org.", qtype="AAAA"),
                an=DNSRR(rrname=b'\xC0\x0C',
                         type=28,
                         ttl=600,
                         rdata="2001:db8:1::3")))
        pkts = [answer_A, answer_AAAA]
        return pkts

    def test_dns_unittest(self):
        """ DNS Name Resolver API Test """

        # Set up an upstream name resolver
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1,
            server_address=IPv4Address(self.pg1.remote_ip4).packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli(
            "dns cache add bozo.clown.org 1.2.3.4 2001:db8:1::2"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b'bozo.clown.org')
        self.assertEqual(rv.ip4_address, IPv4Address(u'1.2.3.4').packed)

        # Applied type of api will block thread
        # The first api call will return record from cache
        # or empty message what signalling pending then thread is unblocked
        rv = self.vapi.dns_resolve_name(name=b'no.clown.org')

        res_pkts = self.create_stream_res(self.pg1)
        self.pg1.add_stream(res_pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        # The second api call will return record or retval -139
        # if record has no addresses
        rv = self.vapi.dns_resolve_name(name=b'no.clown.org')

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('1.2.3.4', str)
        self.assertIn('2001:db8:1::2', str)
        self.assertIn('4.3.2.1', str)
        self.assertIn('2001:db8:1::3', str)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)


class TestDnsPeer(VppTestCase):
    """ Dns Test Peer Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDnsPeer, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDnsPeer, cls).tearDownClass()

    def setUp(self):
        super(TestDnsPeer, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestDnsPeer, self).tearDown()

    def create_stream_req(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request_A_static = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
                    UDP(sport=1234, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname="bozo.clown.org")))

        good_request_AAAA_static = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
                    UDP(sport=1234, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname="bozo.clown.org", qtype="AAAA")))

        good_request_A_dynamic = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
                    UDP(sport=1234, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname="no.clown.org")))
        good_request_AAAA_dynamic = (
                    Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
                    UDP(sport=1234, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname="no.clown.org", qtype="AAAA")))
        pkts = [good_request_A_static,
                good_request_AAAA_static,
                good_request_A_dynamic,
                good_request_AAAA_dynamic]
        return pkts

    def create_stream_res(self, src_if):
        """Response from fake DNS server to VPP. """
        answer_A = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
            IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
            UDP(sport=53, dport=53053) /
            DNS(id=1, qr=1, ra=1, rd=1,
                qd=DNSQR(qname="no.clown.org.", qtype="A"),
                an=DNSRR(rrname=b'\xC0\x0C', ttl=600, rdata="4.3.2.1")))
        answer_AAAA = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
            IP(src=src_if.remote_ip4, dst=src_if.local_ip4) /
            UDP(sport=53, dport=53053) /
            DNS(id=1, qr=1, ra=1, rd=1,
                qd=DNSQR(qname="no.clown.org.", qtype="AAAA"),
                an=DNSRR(rrname=b'\xC0\x0C',
                         type=28,
                         ttl=600,
                         rdata="2001:db8:1::3")))
        pkts = [answer_A, answer_AAAA]
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        dns = capture[0][DNS]
        self.assertEqual(dns.an[0].rdata, '1.2.3.4')
        dns = capture[1][DNS]
        self.assertEqual(dns.an[0].rdata, '2001:db8:1::2')
        dns = capture[2][DNS]
        self.assertEqual(dns.an[0].rdata, '4.3.2.1')

    def test_dns_unittest(self):
        """ DNS Name Resolver Peer Test """

        # Set up an upstream name resolver
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1,
            server_address=IPv4Address(self.pg1.remote_ip4).packed)

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli(
            "dns cache add bozo.clown.org 1.2.3.4 2001:db8:1::2"))

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which will ask DNS server

        pkts = self.create_stream_req(self.pg0)
        self.pg0.add_stream(pkts)

        res_pkts = self.create_stream_res(self.pg1)
        self.pg1.add_stream(res_pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(3)
        res_pkts = self.pg1.get_capture(2)
        self.verify_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn('1.2.3.4', str)
        self.assertIn('2001:db8:1::2', str)
        self.assertIn('4.3.2.1', str)
        self.assertIn('2001:db8:1::3', str)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
