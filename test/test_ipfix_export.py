#!/usr/bin/env python3
from __future__ import print_function
import binascii
import random
import socket
import unittest
import time
import re

from framework import VppTestCase
from vpp_object import VppObject
from vpp_pg_interface import CaptureTimeoutError
from vpp_ip_route import VppIpRoute, VppRoutePath
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import AF_INET, AF_INET6


class TestIpfixExporter(VppTestCase):
    """ Ipfix Exporter Tests """

    def setUp(self):
        super(TestIpfixExporter, self).setUp()
        self.create_pg_interfaces(range(4))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.disable_ipv6_ra()

    def tearDown(self):
        super(TestIpfixExporter, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def find_exp_by_collector_addr(self, exporters, addr):
        """ Find the exporter in the list of exportes with the given  addr """

        for exp in exporters:
            if exp.collector_address == IPv4Address(addr):
                return exp
        return None

    def verify_exporter_detail(self, exp, collector_addr, src_addr,
                               collector_port=4739, mtu=1400, interval=20):
        self.assertTrue(exp is not None)
        self.assert_equal(exp.collector_address, collector_addr)
        self.assert_equal(exp.src_address, src_addr)
        self.assert_equal(exp.collector_port, collector_port)
        self.assert_equal(exp.path_mtu, mtu)
        self.assert_equal(exp.template_interval, interval)

    def test_create_multipe_exporters(self):
        """ test that we can create and dump multiple exporters """

        mtu = 1400
        interval = 20
        port = 4739

        # Old API - always gives us pool index 0.
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg1.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval)

        exporters = self.vapi.ipfix_exporter_dump()
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        # create a 2nd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True)

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 2)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg2.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        # Create a 3rd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True)

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 3)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg2.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg3.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        # Modify the 2nd exporter.
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu+1,
            template_interval=interval+1,
            is_create=True)

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 3)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
        exp = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg2.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4),
                                    mtu=mtu+1, interval=interval+1)
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg3.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        # Delete 2nd exporter
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False)

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 2)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
        exp = self.find_exp_by_collector_addr(exporters, self.pg3.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg3.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))

        # Delete final exporter (exporter in slot 0 can not be deleted)
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=4739,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False)

        exporters = list(self.vapi.vpp.details_iter(
            self.vapi.ipfix_all_exporter_get))
        self.assertTrue(len(exporters) == 1)
        exp = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(exp,
                                    IPv4Address(self.pg1.remote_ip4),
                                    IPv4Address(self.pg0.local_ip4))
