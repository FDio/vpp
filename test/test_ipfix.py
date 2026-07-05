#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import unittest
from config import config
from framework import VppTestCase
from ipaddress import IPv4Address
from ipfix import IPFIX, Set, Template
from scapy.layers.inet import IP, UDP
from vpp_papi import VppEnum


@unittest.skipIf(
    "ipfix" in config.excluded_plugins,
    "Exclude IPFIX plugin tests",
)
class TestIpfixExporter(VppTestCase):
    """IPFIX exporter tests"""

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(4))
        for interface in self.pg_interfaces:
            interface.admin_up()
            interface.config_ip4()
            interface.resolve_arp()
            interface.config_ip6()
            interface.resolve_ndp()
            interface.disable_ipv6_ra()

    def tearDown(self):
        super().tearDown()
        for interface in self.pg_interfaces:
            interface.unconfig_ip4()
            interface.unconfig_ip6()
            interface.admin_down()

    def find_exp_by_collector_addr(self, exporters, addr):
        """Find the exporter with the given collector address."""

        for exporter in exporters:
            if exporter.collector_address == IPv4Address(addr):
                return exporter
        return None

    def verify_exporter_detail(
        self,
        exporter,
        collector_addr,
        src_addr,
        collector_port=4739,
        mtu=1400,
        interval=20,
    ):
        self.assertIsNotNone(exporter)
        self.assert_equal(exporter.collector_address, collector_addr)
        self.assert_equal(exporter.src_address, src_addr)
        self.assert_equal(exporter.collector_port, collector_port)
        self.assert_equal(exporter.path_mtu, mtu)
        self.assert_equal(exporter.template_interval, interval)

    def test_create_multiple_exporters(self):
        """Create, modify, dump, and remove multiple exporters."""

        mtu = 1400
        interval = 20
        port = 4739

        # The legacy API always uses pool index zero.
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg1.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu,
            template_interval=interval,
        )

        exporters = self.vapi.ipfix_exporter_dump()
        exporter = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exporter,
            IPv4Address(self.pg1.remote_ip4),
            IPv4Address(self.pg0.local_ip4),
        )
        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        exporter = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exporter,
            IPv4Address(self.pg1.remote_ip4),
            IPv4Address(self.pg0.local_ip4),
        )

        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertEqual(len(exporters), 2)
        for collector in (self.pg1.remote_ip4, self.pg2.remote_ip4):
            exporter = self.find_exp_by_collector_addr(exporters, collector)
            self.verify_exporter_detail(
                exporter,
                IPv4Address(collector),
                IPv4Address(self.pg0.local_ip4),
            )

        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu,
            template_interval=interval,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertEqual(len(exporters), 3)
        for collector in (
            self.pg1.remote_ip4,
            self.pg2.remote_ip4,
            self.pg3.remote_ip4,
        ):
            exporter = self.find_exp_by_collector_addr(exporters, collector)
            self.verify_exporter_detail(
                exporter,
                IPv4Address(collector),
                IPv4Address(self.pg0.local_ip4),
            )

        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu + 1,
            template_interval=interval + 1,
            is_create=True,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertEqual(len(exporters), 3)
        exporter = self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        self.verify_exporter_detail(
            exporter,
            IPv4Address(self.pg2.remote_ip4),
            IPv4Address(self.pg0.local_ip4),
            mtu=mtu + 1,
            interval=interval + 1,
        )

        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg2.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertEqual(len(exporters), 2)
        self.assertIsNone(
            self.find_exp_by_collector_addr(exporters, self.pg2.remote_ip4)
        )

        # Delete the remaining non-legacy exporter.
        self.vapi.ipfix_exporter_create_delete(
            collector_address=self.pg3.remote_ip4,
            src_address=self.pg0.local_ip4,
            collector_port=port,
            path_mtu=mtu,
            template_interval=interval,
            is_create=False,
        )

        exporters = list(self.vapi.vpp.details_iter(self.vapi.ipfix_all_exporter_get))
        self.assertEqual(len(exporters), 1)
        exporter = self.find_exp_by_collector_addr(exporters, self.pg1.remote_ip4)
        self.verify_exporter_detail(
            exporter,
            IPv4Address(self.pg1.remote_ip4),
            IPv4Address(self.pg0.local_ip4),
        )

    def test_classify_api(self):
        """Classify replies use the IPFIX plugin message ID base."""

        domain_id = 123
        src_port = 4739
        address_family = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        protocol = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        classify_mask = b"\xff" * 48

        classify_reply = self.vapi.classify_add_del_table(
            is_add=True,
            mask=classify_mask,
            mask_len=len(classify_mask),
            match_n_vectors=3,
        )
        table_id = classify_reply.new_table_index

        stream_reply = self.vapi.set_ipfix_classify_stream(
            domain_id=domain_id,
            src_port=src_port,
        )
        self.assertEqual(type(stream_reply).__name__, "set_ipfix_classify_stream_reply")
        streams = self.vapi.ipfix_classify_stream_dump()
        self.assertEqual(len(streams), 1)
        self.assertEqual(type(streams[0]).__name__, "ipfix_classify_stream_details")
        self.assertEqual(streams[0].domain_id, domain_id)
        self.assertEqual(streams[0].src_port, src_port)

        add_reply = self.vapi.ipfix_classify_table_add_del(
            table_id=table_id,
            ip_version=address_family,
            transport_protocol=protocol,
            is_add=True,
        )
        self.assertEqual(type(add_reply).__name__, "ipfix_classify_table_add_del_reply")
        tables = self.vapi.ipfix_classify_table_dump()
        self.assertEqual(len(tables), 1)
        self.assertEqual(type(tables[0]).__name__, "ipfix_classify_table_details")
        self.assertEqual(tables[0].table_id, table_id)
        self.assertEqual(tables[0].ip_version, address_family)
        self.assertEqual(tables[0].transport_protocol, protocol)

        delete_reply = self.vapi.ipfix_classify_table_add_del(
            table_id=table_id,
            ip_version=address_family,
            transport_protocol=protocol,
            is_add=False,
        )
        self.assertEqual(
            type(delete_reply).__name__, "ipfix_classify_table_add_del_reply"
        )
        self.assertEqual(len(self.vapi.ipfix_classify_table_dump()), 0)

        self.vapi.classify_add_del_table(
            is_add=False,
            table_index=table_id,
            mask=classify_mask,
            mask_len=len(classify_mask),
            match_n_vectors=3,
        )


@unittest.skipIf(
    "ioam" in config.excluded_plugins or "ipfix" in config.excluded_plugins,
    "Exclude IOAM or IPFIX plugin tests",
)
class TestIOAMWithIpfix(VppTestCase):
    """IOAM resolves its optional IPFIX provider during initialization."""

    extra_vpp_plugin_config = [
        "plugin ioam_plugin.so { enable }",
        "plugin ipfix_plugin.so { enable }",
    ]

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(1))
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.vapi.set_ipfix_exporter(
            collector_address=self.pg0.remote_ip4,
            src_address=self.pg0.local_ip4,
            path_mtu=512,
            template_interval=300,
        )

    def tearDown(self):
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super().tearDown()

    def assert_template_exported(self):
        self.vapi.ipfix_flush()
        capture = self.pg0.get_capture(1, timeout=5)
        packet = capture[0]
        self.assertEqual(packet[IP].src, self.pg0.local_ip4)
        self.assertEqual(packet[IP].dst, self.pg0.remote_ip4)
        self.assertEqual(packet[UDP].dport, 4739)
        self.assertTrue(packet.haslayer(IPFIX))
        self.assertEqual(packet[IPFIX].version, 10)
        self.assertEqual(packet[IPFIX].observationDomainID, 0)
        self.assertTrue(packet.haslayer(Set))
        self.assertEqual(packet[Set].setID, 2)
        self.assertTrue(packet.haslayer(Template))
        self.assertEqual(packet[Template].templateID, 260)

    def test_analyse_export_with_ipfix(self):
        self.pg0.enable_capture()
        reply = self.vapi.cli_return_response("set ioam analyse export-ipfix-collector")
        self.assertEqual(reply.retval, 0)
        try:
            self.assert_template_exported()
        finally:
            reply = self.vapi.cli_return_response(
                "set ioam analyse export-ipfix-collector disable"
            )
        self.assertEqual(reply.retval, 0)

    def test_udp_ping_export_with_ipfix(self):
        self.pg0.enable_capture()
        reply = self.vapi.udp_ping_export(enable=True)
        self.assertEqual(reply.retval, 0)
        try:
            self.assert_template_exported()
        finally:
            reply = self.vapi.udp_ping_export(enable=False)
        self.assertEqual(reply.retval, 0)


@unittest.skipIf("ioam" in config.excluded_plugins, "Exclude IOAM plugin tests")
class TestIOAMWithoutIpfix(VppTestCase):
    """IOAM behavior without the IPFIX plugin."""

    extra_vpp_plugin_config = [
        "plugin ioam_plugin.so { enable }",
        "plugin ipfix_plugin.so { disable }",
    ]

    VNET_API_ERROR_FEATURE_DISABLED = -30

    def test_analyse_export_without_ipfix(self):
        for _ in range(2):
            reply = self.vapi.cli_return_response(
                "set ioam analyse export-ipfix-collector"
            )
            self.assertNotEqual(reply.retval, 0)
            self.assertIn("ipfix plugin not loaded", reply.reply)

        reply = self.vapi.cli_return_response(
            "set ioam analyse export-ipfix-collector disable"
        )
        self.assertEqual(reply.retval, 0)

    def test_udp_ping_export_without_ipfix(self):
        for _ in range(2):
            with self.vapi.assert_negative_api_retval():
                reply = self.vapi.udp_ping_export(enable=True)

            self.assertEqual(reply.retval, self.VNET_API_ERROR_FEATURE_DISABLED)

        reply = self.vapi.udp_ping_export(enable=False)
        self.assertEqual(reply.retval, 0)

    def test_disable_without_ipfix(self):
        """Disabling unbound IOAM exporters remains a no-op."""

        reply = self.vapi.cli_return_response(
            "set ioam analyse export-ipfix-collector disable"
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.udp_ping_export(enable=False)
        self.assertEqual(reply.retval, 0)
