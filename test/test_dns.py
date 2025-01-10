#!/usr/bin/env python3

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from ipaddress import *
from config import config

from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR


@unittest.skipIf("dns" in config.excluded_plugins, "Exclude DNS plugin tests")
class TestDns(VppTestCase):
    """Dns Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestDns, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
        except Exception:
            super(TestDns, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestDns, cls).tearDownClass()

    def setUp(self):
        super(TestDns, self).setUp()

    def tearDown(self):
        super(TestDns, self).tearDown()

    def create_a_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="bozo.clown.org"))
        )

        bad_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="no.clown.org"))
        )
        pkts = [good_request, bad_request]
        return pkts

    def verify_a_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        for packet in capture:
            dns = packet[DNS]
            self.assertEqual(dns.an[0].rdata, "1.2.3.4")

    def create_4a_stream(self, src_if):
        good_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IPv6(src=src_if.remote_ip6)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="bozo.clown.org"))
        )

        bad_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IPv6(src=src_if.remote_ip6)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="no.clown.org"))
        )
        pkts = [good_request, bad_request]
        return pkts

    def verify_4a_capture(self, dst_if, capture):
        self.logger.info("Verifying capture on interface %s" % dst_if.name)

        for packet in capture:
            if DNS in packet:
                dns = packet[DNS]
                self.assertEqual(dns.an[0].rdata, "2001:4860:4860::1111")

    def test_dns_unittest(self):
        """DNS Name Resolver Basic Functional Test"""

        self.pg0.config_ip4()
        self.pg0.resolve_arp()

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address("8.8.8.8").packed
        )

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli("dns cache add bozo.clown.org 1.2.3.4"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b"bozo.clown.org")
        self.assertEqual(rv.ip4_address, IPv4Address("1.2.3.4").packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index, prefix="127.0.0.1/8"
        )

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve
        pkts = self.create_a_stream(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_a_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn("1.2.3.4", str)
        self.assertIn("[P] no.clown.org:", str)

        # clear dns config
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=0, server_address=IPv4Address("8.8.8.8").packed
        )
        self.logger.info(self.vapi.cli("dns cache del bozo.clown.org"))

    def test_dns6_unittest(self):
        """DNS Name Resolver Basic Functional Test for IPv6"""

        self.pg1.config_ip6()
        self.pg1.resolve_ndp()

        # Set up an upstream name resolver (IPv6)
        self.vapi.dns_name_server_add_del(
            is_ip6=1,
            is_add=1,
            server_address=IPv6Address("2001:4860:4860::8888").packed,
        )

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(
            self.vapi.cli("dns cache add bozo.clown.org 2001:4860:4860::1111")
        )

        # Test the binary API for IPv6
        rv = self.vapi.dns_resolve_name(name=b"bozo.clown.org")
        self.assertEqual(rv.ip6_address, IPv6Address("2001:4860:4860::1111").packed)

        # Configure IPv6 loopback on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg1.sw_if_index, prefix="::1/128", is_add=1
        )

        # Send DNS request packets for IPv6
        self.logger.info(self.vapi.cli("show ip6 neighbors"))
        pkts = self.create_4a_stream(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg1.get_capture(1)
        self.verify_4a_capture(self.pg1, pkts)

        # Verify DNS cache contents for IPv6
        dns_cache_contents = self.vapi.cli("show dns cache verbose")
        self.assertIn("2001:4860:4860::1111", dns_cache_contents)
        self.assertIn("[P] no.clown.org:", dns_cache_contents)

        # clear dns config
        self.vapi.dns_name_server_add_del(
            is_ip6=1,
            is_add=0,
            server_address=IPv6Address("2001:4860:4860::8888").packed,
        )
        self.logger.info(self.vapi.cli("dns cache del bozo.clown.org"))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
