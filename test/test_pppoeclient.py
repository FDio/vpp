#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Hi-Jiajun.

import unittest
import struct
import time

from config import config
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPPoED_Tags
from scapy.packet import Raw

from asfframework import VppTestRunner, tag_run_solo
from framework import VppTestCase
from vpp_papi_exceptions import UnexpectedApiReturnValueError
from vpp_papi_provider import CliFailedCommandError
from vpp_pg_interface import CaptureTimeoutError


@unittest.skipIf(
    "pppoeclient" in config.excluded_plugins, "Exclude pppoeclient plugin tests"
)
@tag_run_solo
class TestPPPoEClient(VppTestCase):
    """PPPoE client tests."""

    HOST_UNIQ = 0x12345678
    ALL_INTERFACES = 0xFFFFFFFF
    INVALID_INTERFACE_RETVAL = -71
    AUTH_USERNAME = b"pfsense"
    AUTH_PASSWORD = b"admin"
    AC_NAME = b"my-ac"
    SERVICE_NAME = b"internet"
    AUTH_USERNAME_MAX = b"u" * 64
    AUTH_PASSWORD_MAX = b"p" * 64

    @classmethod
    def setUpClass(cls):
        super(TestPPPoEClient, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.config_ip6()
            cls.pg0.resolve_arp()
            cls.pg0.resolve_ndp()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestPPPoEClient, cls).tearDownClass()

    def setUp(self):
        super(TestPPPoEClient, self).setUp()
        # pem->orphan_control_history is process-wide and survives the
        # per-test client teardown. Without a clear here, orphan PADOs
        # injected by earlier tests leak into any test that asserts on
        # orphan-history totals.
        self.vapi.cli("clear pppoe client history orphan")

    def tearDown(self):
        try:
            self.delete_all_clients()
        finally:
            super(TestPPPoEClient, self).tearDown()

    @staticmethod
    def normalize_interface_name(name):
        if isinstance(name, bytes):
            name = name.decode("ascii")
        return name.rstrip("\x00")

    @staticmethod
    def normalize_api_string(value):
        if isinstance(value, bytes):
            value = value.decode("ascii")
        return value.rstrip("\x00")

    @staticmethod
    def is_not_padi(pkt):
        pppoed = pkt.getlayer(PPPoED)
        return pppoed is None or pppoed.code != 0x09

    @staticmethod
    def is_not_padr(pkt):
        pppoed = pkt.getlayer(PPPoED)
        return pppoed is None or pppoed.code != 0x19

    @staticmethod
    def pppoe_tag(tag_type, tag_value=b""):
        return struct.pack("!HH", tag_type, len(tag_value)) + tag_value

    def make_pado_with_error(self, src_mac, tag_type, message, host_uniq=HOST_UNIQ):
        tags = [self.pppoe_tag(0x0101, b"")]
        if host_uniq is not None:
            tags.append(self.pppoe_tag(0x0103, host_uniq.to_bytes(4, "little")))
        tags.append(self.pppoe_tag(tag_type, message))
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x07, sessionid=0)
            / Raw(b"".join(tags))
        )

    def make_pads_with_error(
        self, src_mac, session_id, tag_type, message, host_uniq=HOST_UNIQ
    ):
        tags = [self.pppoe_tag(0x0101, b"")]
        if host_uniq is not None:
            tags.append(self.pppoe_tag(0x0103, host_uniq.to_bytes(4, "little")))
        tags.append(self.pppoe_tag(tag_type, message))
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x65, sessionid=session_id)
            / Raw(b"".join(tags))
        )

    def make_pado(
        self, src_mac, ac_name, cookie=None, host_uniq=HOST_UNIQ, service_name=b""
    ):
        tags = [self.pppoe_tag(0x0101, service_name)]
        if host_uniq is not None:
            tags.append(self.pppoe_tag(0x0103, host_uniq.to_bytes(4, "little")))
        tags.extend(
            [
                self.pppoe_tag(0x0102, ac_name),
                self.pppoe_tag(0x0104, cookie) if cookie is not None else b"",
            ]
        )
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x07, sessionid=0)
            / Raw(b"".join(tags))
        )

    def make_pads(
        self,
        src_mac,
        session_id,
        ac_name,
        cookie=None,
        host_uniq=HOST_UNIQ,
        service_name=b"",
    ):
        tags = [self.pppoe_tag(0x0101, service_name)]
        if host_uniq is not None:
            tags.append(self.pppoe_tag(0x0103, host_uniq.to_bytes(4, "little")))
        tags.extend(
            [
                self.pppoe_tag(0x0102, ac_name),
                self.pppoe_tag(0x0104, cookie) if cookie is not None else b"",
            ]
        )
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x65, sessionid=session_id)
            / Raw(b"".join(tags))
        )

    def make_malformed_pado(self, src_mac):
        malformed_tags = b"".join(
            [
                self.pppoe_tag(0x0101, b""),
                self.pppoe_tag(0x0103, self.HOST_UNIQ.to_bytes(4, "little")),
                struct.pack("!HH", 0x0104, 16) + b"x",
            ]
        )
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x07, sessionid=0)
            / Raw(malformed_tags)
        )

    def make_malformed_pads(self, src_mac, session_id):
        malformed_tags = b"".join(
            [
                self.pppoe_tag(0x0101, b""),
                self.pppoe_tag(0x0103, self.HOST_UNIQ.to_bytes(4, "little")),
                struct.pack("!HH", 0x0104, 16) + b"x",
            ]
        )
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x65, sessionid=session_id)
            / Raw(malformed_tags)
        )

    def make_padt(self, src_mac, session_id):
        return Ether(dst=self.pg0.local_mac, src=src_mac) / PPPoED(
            code=0xA7, sessionid=session_id
        )

    def wait_for_client_session(self, expected_session_id, timeout=3):
        deadline = time.time() + timeout
        while time.time() < deadline:
            clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
            if (
                len(clients) == 1
                and clients[0].session_id == expected_session_id
                and clients[0].client_state == 2
            ):
                return clients[0]
            self.sleep(0.1)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.fail(
            "PPPoE client did not reach session %u, current dump: %s"
            % (expected_session_id, clients)
        )

    def establish_session(
        self, ac_mac="02:00:00:00:00:22", ac_name=None, session_id=0x1234
    ):
        pppox_sw_if_index = self.add_client()
        ac_name = ac_name or self.AC_NAME

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        pado = self.make_pado(ac_mac, ac_name)
        self.pg0.enable_capture()
        self.pg0.add_stream([pado])
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), ac_mac)

        pads = self.make_pads(ac_mac, session_id, ac_name)
        self.pg0.add_stream([pads])
        self.pg_start()

        self.wait_for_client_session(session_id)
        return pppox_sw_if_index, session_id, ac_mac

    def delete_all_clients(self):
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        # VPP's pool_put pushes freed indices onto a LIFO free stack, so
        # deleting in pool-iteration order leaves the highest index on top
        # and the next add_client() reuses that instead of index 0. Many
        # tests hardcode `set pppoe client 0` / `pppoeclient_index=0`, so
        # we reverse here to keep index 0 at the top of the free stack.
        for client in reversed(clients):
            self.vapi.pppoeclient_add_del(
                is_add=False,
                sw_if_index=client.sw_if_index,
                host_uniq=client.host_uniq,
            )

    def add_client(
        self,
        service_name=None,
        configured_ac_name=None,
        host_uniq=HOST_UNIQ,
        set_source_mac=False,
        source_mac_mode=None,
        source_mac=None,
    ):
        kwargs = {
            "is_add": True,
            "sw_if_index": self.pg0.sw_if_index,
            "host_uniq": host_uniq,
        }
        if service_name is not None:
            if isinstance(service_name, bytes):
                service_name = service_name.decode("ascii")
            kwargs["service_name"] = service_name
        if configured_ac_name is not None:
            if isinstance(configured_ac_name, bytes):
                configured_ac_name = configured_ac_name.decode("ascii")
            kwargs["configured_ac_name"] = configured_ac_name
        if set_source_mac:
            kwargs["set_source_mac"] = True
            kwargs["source_mac_mode"] = source_mac_mode
            if source_mac is not None:
                kwargs["source_mac"] = source_mac

        response = self.vapi.pppoeclient_add_del(**kwargs)

        self.assertEqual(response.retval, 0)
        self.assertNotEqual(response.pppox_sw_if_index, self.ALL_INTERFACES)

        interface_dump = self.vapi.sw_interface_dump(
            sw_if_index=response.pppox_sw_if_index
        )
        self.assertEqual(len(interface_dump), 1)
        self.assertEqual(interface_dump[0].sw_if_index, response.pppox_sw_if_index)
        self.assertTrue(
            self.normalize_interface_name(interface_dump[0].interface_name).startswith(
                "pppox"
            )
        )

        return response.pppox_sw_if_index

    def wait_for_client_state(
        self, host_uniq, expected_state, expected_session_id, timeout=3
    ):
        deadline = time.time() + timeout
        while time.time() < deadline:
            clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
            for client in clients:
                if client.host_uniq != host_uniq:
                    continue
                if (
                    client.client_state == expected_state
                    and client.session_id == expected_session_id
                ):
                    return client
            self.sleep(0.1)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.fail(
            "PPPoE client %u did not reach state %u session %u, current dump: %s"
            % (host_uniq, expected_state, expected_session_id, clients)
        )

    def remove_client(self):
        response = self.vapi.pppoeclient_add_del(
            is_add=False,
            sw_if_index=self.pg0.sw_if_index,
            host_uniq=self.HOST_UNIQ,
        )
        self.assertEqual(response.retval, 0)

    def test_pppoe_interface_creation(self):
        """Create and delete a PPPoE client."""

        pppox_sw_if_index = self.add_client()

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(clients[0].host_uniq, self.HOST_UNIQ)
        self.assertEqual(clients[0].pppox_sw_if_index, pppox_sw_if_index)
        self.assertEqual(clients[0].session_id, 0)
        self.assertEqual(clients[0].client_state, 0)
        self.assertEqual(clients[0].use_peer_dns, 0)
        self.assertEqual(clients[0].add_default_route4, 0)
        self.assertEqual(clients[0].add_default_route6, 0)
        self.assertEqual(clients[0].dhcp6_ia_na_enabled, 0)
        self.assertEqual(clients[0].dhcp6_pd_enabled, 0)
        self.assertEqual(clients[0].peer_dns6_count, 0)
        self.assertEqual(clients[0].source_mac_mode, 0)
        self.assertEqual(clients[0].effective_source_mac_mode, 0)
        self.assertEqual(clients[0].source_mac_fallbacks, 0)
        self.assertEqual(clients[0].last_source_mac_fallback_reason, 0)

        other_clients = self.vapi.pppoeclient_dump(sw_if_index=0xFFFFFFFE)
        self.assertEqual(len(other_clients), 0)

        all_clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(all_clients), 1)
        self.assertEqual(all_clients[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(all_clients[0].host_uniq, self.HOST_UNIQ)
        self.assertEqual(all_clients[0].pppox_sw_if_index, pppox_sw_if_index)

        self.remove_client()

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 0)

    def test_pppoe_interface_creation_bad_sw_if_index(self):
        """Reject interface creation with an invalid sw_if_index."""

        with self.assertRaises(UnexpectedApiReturnValueError) as ctx:
            self.vapi.pppoeclient_add_del(
                is_add=True,
                sw_if_index=128,
                host_uniq=self.HOST_UNIQ,
            )

        self.assertEqual(ctx.exception.retval, self.INVALID_INTERFACE_RETVAL)

    def test_pppoe_interface_creation_not_ethernet(self):
        """Reject interface creation on a non-Ethernet interface."""

        with self.assertRaises(UnexpectedApiReturnValueError) as ctx:
            self.vapi.pppoeclient_add_del(
                is_add=True,
                sw_if_index=0,
                host_uniq=self.HOST_UNIQ,
            )

        self.assertEqual(ctx.exception.retval, self.INVALID_INTERFACE_RETVAL)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 0)

    def test_pppoe_custom_ifname_overrides_pppox_default(self):
        """custom_ifname=wan0 renames the PPPoX virtual interface."""

        response = self.vapi.pppoeclient_add_del(
            is_add=True,
            sw_if_index=self.pg0.sw_if_index,
            host_uniq=self.HOST_UNIQ,
            custom_ifname="wan0",
        )
        self.assertEqual(response.retval, 0)
        self.assertNotEqual(response.pppox_sw_if_index, self.ALL_INTERFACES)

        interface_dump = self.vapi.sw_interface_dump(
            sw_if_index=response.pppox_sw_if_index
        )
        self.assertEqual(len(interface_dump), 1)
        self.assertEqual(
            self.normalize_interface_name(interface_dump[0].interface_name),
            "wan0",
        )

        # Empty custom_ifname falls back to the default "pppoxN" formatting.
        response2 = self.vapi.pppoeclient_add_del(
            is_add=True,
            sw_if_index=self.pg0.sw_if_index,
            host_uniq=self.HOST_UNIQ + 1,
            custom_ifname="",
        )
        self.assertEqual(response2.retval, 0)
        interface_dump2 = self.vapi.sw_interface_dump(
            sw_if_index=response2.pppox_sw_if_index
        )
        self.assertTrue(
            self.normalize_interface_name(interface_dump2[0].interface_name).startswith(
                "pppox"
            )
        )

        self.delete_all_clients()

    def test_pppoe_custom_ifname_via_cli_name_option(self):
        """create pppoe client name ppp0 renames via CLI path."""

        output = self.vapi.cli(
            "create pppoe client %s host-uniq %u name ppp0"
            % (self.pg0.name, self.HOST_UNIQ)
        )
        # CLI success is silent; confirm by dumping state.
        del output

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)

        interface_dump = self.vapi.sw_interface_dump(
            sw_if_index=clients[0].pppox_sw_if_index
        )
        self.assertEqual(len(interface_dump), 1)
        self.assertEqual(
            self.normalize_interface_name(interface_dump[0].interface_name),
            "ppp0",
        )

        self.delete_all_clients()

    def test_pppoe_discover(self):
        """Setting auth starts PPPoE discovery and emits a PADI packet."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli(
            "set pppoe client 0 service-name %s" % self.SERVICE_NAME.decode("ascii")
        )

        self.pg0.enable_capture()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(
            self.normalize_api_string(clients[0].auth_user),
            self.AUTH_USERNAME.decode("ascii"),
        )
        self.assertEqual(
            self.normalize_api_string(clients[0].service_name),
            self.SERVICE_NAME.decode("ascii"),
        )

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        ethernet = packet.getlayer(Ether)
        self.assertIsNotNone(ethernet)
        self.assertEqual(ethernet.type, 0x8863)

        pppoed = packet.getlayer(PPPoED)
        self.assertIsNotNone(pppoed)
        self.assertEqual(pppoed.code, 0x09)
        self.assertEqual(pppoed.sessionid, 0)

        tags = packet.getlayer(PPPoED_Tags)
        self.assertIsNotNone(tags)

        found_host_uniq = False
        found_service_name = False
        for tag in tags.tag_list:
            if tag.tag_type == 0x0101:
                found_service_name = True
                self.assertEqual(tag.tag_value, self.SERVICE_NAME)
            if tag.tag_type == 0x0103:
                found_host_uniq = True
                self.assertEqual(
                    int.from_bytes(tag.tag_value, "little"), self.HOST_UNIQ
                )

        self.assertTrue(found_host_uniq)
        self.assertTrue(found_service_name)

    def test_pppox_set_auth_accepts_full_length_credentials(self):
        """Allow 64-byte username/password values via the API."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME_MAX,
            password=self.AUTH_PASSWORD_MAX,
        )
        self.assertEqual(response.retval, 0)

    def test_pppoe_service_name_any_clears_tag(self):
        """Allow service-name any to reset back to zero-length Service-Name tag."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli(
            "set pppoe client 0 service-name %s" % self.SERVICE_NAME.decode("ascii")
        )
        self.vapi.cli("set pppoe client 0 service-name any")

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(self.normalize_api_string(clients[0].service_name), "")

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        tags = packet.getlayer(PPPoED_Tags)
        self.assertIsNotNone(tags)

        found_service_name = False
        for tag in tags.tag_list:
            if tag.tag_type == 0x0101:
                found_service_name = True
                self.assertEqual(tag.tag_value, b"")

        self.assertTrue(found_service_name)

    def test_pppoe_add_del_api_accepts_service_name(self):
        """Allow service-name to be configured through the add/del API."""

        pppox_sw_if_index = self.add_client(service_name=self.SERVICE_NAME)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(
            self.normalize_api_string(clients[0].service_name),
            self.SERVICE_NAME.decode("ascii"),
        )

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        tags = packet.getlayer(PPPoED_Tags)
        self.assertIsNotNone(tags)

        found_service_name = False
        for tag in tags.tag_list:
            if tag.tag_type == 0x0101:
                found_service_name = True
                self.assertEqual(tag.tag_value, self.SERVICE_NAME)

        self.assertTrue(found_service_name)

    def test_pppoe_add_del_api_accepts_source_mac(self):
        """Allow source-MAC policy to be configured through the add/del API."""

        static_mac = "02:fe:ed:00:00:66"
        pppox_sw_if_index = self.add_client(
            set_source_mac=True, source_mac_mode=2, source_mac=static_mac
        )

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].pppox_sw_if_index, pppox_sw_if_index)
        self.assertEqual(clients[0].source_mac_mode, 2)
        self.assertEqual(str(clients[0].configured_source_mac).lower(), static_mac)
        self.assertEqual(str(clients[0].effective_source_mac).lower(), static_mac)

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        padi = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.assertEqual(padi[Ether].src.lower(), static_mac)

    def test_pppoe_create_cli_accepts_source_mac(self):
        """Allow source-MAC policy to be configured through the create CLI."""

        static_mac = "02:fe:ed:00:00:67"
        host_uniq = 0x31415926
        output = self.vapi.cli(
            "create pppoe client %s host-uniq %u source-mac %s"
            % (self.pg0.name, host_uniq, static_mac)
        )
        self.assertEqual(output, "")

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].host_uniq, host_uniq)
        self.assertEqual(clients[0].source_mac_mode, 2)
        self.assertEqual(clients[0].effective_source_mac_mode, 2)
        self.assertEqual(str(clients[0].configured_source_mac).lower(), static_mac)
        self.assertEqual(str(clients[0].effective_source_mac).lower(), static_mac)

        response = self.vapi.pppox_set_auth(
            sw_if_index=clients[0].pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        padi = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.assertEqual(padi[Ether].src.lower(), static_mac)

    def test_pppoe_discovery_rejects_mismatched_service_name_pado(self):
        """Configured service-name must reject a PADO for a different service."""

        pppox_sw_if_index = self.add_client(service_name=self.SERVICE_NAME)

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:28",
                    self.AC_NAME,
                    host_uniq=self.HOST_UNIQ,
                    service_name=b"other-service",
                )
            ]
        )
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        self.wait_for_client_state(self.HOST_UNIQ, 0, 0)

    def test_pppoe_ac_name_setting_round_trip(self):
        """Allow ac-name to be configured and cleared back to <any>."""

        self.add_client()

        self.vapi.cli("set pppoe client 0 ac-name %s" % self.AC_NAME.decode("ascii"))
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(
            self.normalize_api_string(clients[0].configured_ac_name),
            self.AC_NAME.decode("ascii"),
        )

        self.vapi.cli("set pppoe client 0 ac-name any")
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(self.normalize_api_string(clients[0].configured_ac_name), "")

    def test_pppoe_add_del_api_accepts_ac_name_filter(self):
        """Allow ac-name filtering to be configured through the add/del API."""

        pppox_sw_if_index = self.add_client(configured_ac_name=self.AC_NAME)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(
            self.normalize_api_string(clients[0].configured_ac_name),
            self.AC_NAME.decode("ascii"),
        )

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        bad_pado = self.make_pado("02:00:00:00:00:11", b"other-ac")
        good_pado = self.make_pado("02:00:00:00:00:22", self.AC_NAME)

        self.pg0.enable_capture()
        self.pg0.add_stream([bad_pado, good_pado])
        self.pg_start()

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(packet[Ether].dst.lower(), "02:00:00:00:00:22")

    def test_pppoe_set_cli_rejects_unknown_token_without_partial_apply(self):
        """Reject unknown set-CLI tokens instead of silently applying partial config."""

        self.add_client()

        with self.assertRaises(CliFailedCommandError):
            self.vapi.cli("set pppoe client 0 use-peer-dnss add-default-route")

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].use_peer_dns, 0)
        self.assertEqual(clients[0].add_default_route4, 0)
        self.assertEqual(clients[0].add_default_route6, 0)

    def test_pppoe_set_cli_auth_starts_discovery_without_corrupting_state(self):
        """CLI auth configuration must safely sync to PPPoX and start discovery."""

        self.add_client()
        self.pg0.enable_capture()

        self.vapi.cli(
            "set pppoe client 0 username %s password %s"
            % (
                self.AUTH_USERNAME.decode("ascii"),
                self.AUTH_PASSWORD.decode("ascii"),
            )
        )

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(
            self.normalize_api_string(clients[0].auth_user),
            self.AUTH_USERNAME.decode("ascii"),
        )

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        pppoed = packet.getlayer(PPPoED)
        self.assertIsNotNone(pppoed)
        self.assertEqual(pppoed.code, 0x09)

    def test_pppoe_ac_name_filter_does_not_reuse_rejected_cookie(self):
        """Carry only the accepted AC-Cookie into PADR."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli("set pppoe client 0 ac-name %s" % self.AC_NAME.decode("ascii"))

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        bad_pado = self.make_pado(
            "02:00:00:00:00:11", b"other-ac", cookie=b"stale-cookie"
        )
        good_cookie = b"good-cookie"
        good_pado = self.make_pado(
            "02:00:00:00:00:22", self.AC_NAME, cookie=good_cookie
        )

        self.pg0.enable_capture()
        self.pg0.add_stream([bad_pado, good_pado])
        self.pg_start()

        packet = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        tags = packet.getlayer(PPPoED_Tags)
        self.assertIsNotNone(tags)
        self.assertEqual(packet[Ether].dst.lower(), "02:00:00:00:00:22")

        seen_cookie = None
        found_host_uniq = False
        for tag in tags.tag_list:
            if tag.tag_type == 0x0104:
                seen_cookie = tag.tag_value
            if tag.tag_type == 0x0103:
                found_host_uniq = True

        self.assertTrue(found_host_uniq)
        self.assertEqual(seen_cookie, good_cookie)

    def test_pppoe_duplicate_pado_does_not_clear_selected_cookie(self):
        """Late duplicate PADO must not wipe the selected AC-Cookie."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli("set pppoe client 0 ac-name %s" % self.AC_NAME.decode("ascii"))

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        good_cookie = b"good-cookie"
        good_pado = self.make_pado(
            "02:00:00:00:00:22", self.AC_NAME, cookie=good_cookie
        )

        self.pg0.enable_capture()
        self.pg0.add_stream([good_pado])
        self.pg_start()
        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        first_tags = first_padr.getlayer(PPPoED_Tags)
        self.assertIsNotNone(first_tags)

        first_cookie = None
        for tag in first_tags.tag_list:
            if tag.tag_type == 0x0104:
                first_cookie = tag.tag_value
        self.assertEqual(first_cookie, good_cookie)

        duplicate_pado = self.make_pado("02:00:00:00:00:22", self.AC_NAME)
        self.pg0.enable_capture()
        self.pg0.add_stream([duplicate_pado])
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        retransmitted_padr = self.pg0.wait_for_packet(
            timeout=12, filter_out_fn=self.is_not_padr
        )
        retransmitted_tags = retransmitted_padr.getlayer(PPPoED_Tags)
        self.assertIsNotNone(retransmitted_tags)

        retransmit_cookie = None
        for tag in retransmitted_tags.tag_list:
            if tag.tag_type == 0x0104:
                retransmit_cookie = tag.tag_value
        self.assertEqual(retransmit_cookie, good_cookie)

    def test_pppoe_request_ignores_pado_from_unselected_ac(self):
        """Ignore stray PADO from a different AC after REQUEST has started."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli("set pppoe client 0 ac-name %s" % self.AC_NAME.decode("ascii"))

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        good_cookie = b"good-cookie"
        good_pado = self.make_pado(
            "02:00:00:00:00:22", self.AC_NAME, cookie=good_cookie
        )

        self.pg0.enable_capture()
        self.pg0.add_stream([good_pado])
        self.pg_start()
        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(first_padr[Ether].dst.lower(), "02:00:00:00:00:22")

        counter = (
            "/err/pppoeclient-discovery-input/"
            "PADO in REQUEST from an AC that was not selected"
        )
        before = self.statistics.get_err_counter(counter)

        stray_pado = self.make_pado("02:00:00:00:00:11", b"other-ac")
        self.pg0.enable_capture()
        self.pg0.add_stream([stray_pado])
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        after = self.statistics.get_err_counter(counter)
        self.assertEqual(after, before + 1)

    def test_pppoe_request_ignores_pads_from_unselected_ac(self):
        """Ignore stray PADS from a different AC after REQUEST has started."""

        pppox_sw_if_index = self.add_client()
        self.vapi.cli("set pppoe client 0 ac-name %s" % self.AC_NAME.decode("ascii"))

        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        good_pado = self.make_pado("02:00:00:00:00:22", self.AC_NAME)

        self.pg0.enable_capture()
        self.pg0.add_stream([good_pado])
        self.pg_start()
        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(first_padr[Ether].dst.lower(), "02:00:00:00:00:22")

        stray_pads = self.make_pads("02:00:00:00:00:11", 0x1234, self.AC_NAME)
        self.pg0.add_stream([stray_pads])
        self.pg_start()

        self.sleep(0.5)
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 1)
        self.assertEqual(clients[0].session_id, 0)

        retransmitted_padr = self.pg0.wait_for_packet(
            timeout=12, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(retransmitted_padr[Ether].dst.lower(), "02:00:00:00:00:22")

    def test_pppoe_request_matches_hostuniqless_pads_by_selected_ac(self):
        """Host-Uniq-less PADS should still match the selected AC in REQUEST."""

        host_uniq_one = 0x11111111
        host_uniq_two = 0x22222222
        pppox_sw_if_index_one = self.add_client(host_uniq=host_uniq_one)
        pppox_sw_if_index_two = self.add_client(host_uniq=host_uniq_two)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        pado_one = self.make_pado(
            "02:00:00:00:00:21", b"ac-one", host_uniq=host_uniq_one
        )
        pado_two = self.make_pado(
            "02:00:00:00:00:22", b"ac-two", host_uniq=host_uniq_two
        )
        self.pg0.enable_capture()
        self.pg0.add_stream([pado_one, pado_two])
        self.pg_start()

        padr_one = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        padr_two = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(
            {padr_one[Ether].dst.lower(), padr_two[Ether].dst.lower()},
            {"02:00:00:00:00:21", "02:00:00:00:00:22"},
        )

        self.pg0.add_stream(
            [self.make_pads("02:00:00:00:00:21", 0x1001, b"ac-one", host_uniq=None)]
        )
        self.pg_start()

        self.wait_for_client_state(host_uniq_one, 2, 0x1001)
        self.wait_for_client_state(host_uniq_two, 1, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match ac-mac", output)

    def test_pppoe_discovery_matches_hostuniqless_pado_by_ac_name_filter(self):
        """Host-Uniq-less PADO should still match the configured AC-Name filter."""

        host_uniq_one = 0x11111111
        host_uniq_two = 0x22222222
        pppox_sw_if_index_one = self.add_client(
            configured_ac_name=b"ac-one", host_uniq=host_uniq_one
        )
        pppox_sw_if_index_two = self.add_client(
            configured_ac_name=b"ac-two", host_uniq=host_uniq_two
        )

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:21", b"ac-one", host_uniq=None)]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:21")

        self.wait_for_client_state(host_uniq_one, 1, 0)
        self.wait_for_client_state(host_uniq_two, 0, 0)

    def test_pppoe_discovery_matches_hostuniqless_pado_by_service_name(self):
        """Host-Uniq-less PADO should still honor configured service-name."""

        host_uniq_one = 0x77777771
        host_uniq_two = 0x77777772
        pppox_sw_if_index_one = self.add_client(
            service_name=b"internet-a", host_uniq=host_uniq_one
        )
        pppox_sw_if_index_two = self.add_client(
            service_name=b"internet-b", host_uniq=host_uniq_two
        )

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:26",
                    self.AC_NAME,
                    host_uniq=None,
                    service_name=b"internet-b",
                )
            ]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:26")

        self.wait_for_client_state(host_uniq_one, 0, 0)
        self.wait_for_client_state(host_uniq_two, 1, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match service-name", output)
        self.assertIn("service-name internet-b", output)

    def test_pppoe_discovery_service_name_match_does_not_override_ac_filter(self):
        """Service-name fallback must still respect explicit AC-Name constraints."""

        host_uniq_filtered = 0x77777781
        host_uniq_any = 0x77777782
        pppox_sw_if_index_filtered = self.add_client(
            configured_ac_name=b"ac-one",
            service_name=b"internet-b",
            host_uniq=host_uniq_filtered,
        )
        pppox_sw_if_index_any = self.add_client(host_uniq=host_uniq_any)

        for sw_if_index in (pppox_sw_if_index_filtered, pppox_sw_if_index_any):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:29",
                    b"ac-two",
                    host_uniq=None,
                    service_name=b"internet-b",
                )
            ]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:29")

        self.wait_for_client_state(host_uniq_filtered, 0, 0)
        self.wait_for_client_state(host_uniq_any, 1, 0)

    def test_pppoe_discovery_prefers_combined_ac_and_service_match(self):
        """Combined AC-name and service-name match should outrank AC-only candidates."""

        host_uniq_ac_only = 0x88888881
        host_uniq_combined = 0x88888882
        pppox_sw_if_index_ac_only = self.add_client(
            configured_ac_name=b"ac-one", host_uniq=host_uniq_ac_only
        )
        pppox_sw_if_index_combined = self.add_client(
            configured_ac_name=b"ac-one",
            service_name=b"internet-b",
            host_uniq=host_uniq_combined,
        )

        for sw_if_index in (pppox_sw_if_index_ac_only, pppox_sw_if_index_combined):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:2c",
                    b"ac-one",
                    host_uniq=None,
                    service_name=b"internet-b",
                )
            ]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:2c")

        self.wait_for_client_state(host_uniq_ac_only, 0, 0)
        self.wait_for_client_state(host_uniq_combined, 1, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match ac+service", output)

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1, orphan=False, max_events=1
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].code, 0x07)
        self.assertEqual(events[0].match_reason, 8)
        self.assertEqual(events[0].match_score, 4)
        self.assertEqual(
            self.normalize_api_string(events[0].service_name), "internet-b"
        )
        self.assertTrue(events[0].raw_tags_len > 0)

        filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_min_match_score=True,
            min_match_score=4,
        )
        self.assertGreaterEqual(len(filtered), 1)
        self.assertTrue(all(e.match_score >= 4 for e in filtered))

        service_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_service_name=True,
            service_name="internet-b",
        )
        self.assertGreaterEqual(len(service_filtered), 1)
        self.assertTrue(
            all(
                self.normalize_api_string(e.service_name) == "internet-b"
                for e in service_filtered
            )
        )

        top_reason = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_top_match_reason=True,
            top_match_reason=8,
        )
        self.assertGreaterEqual(len(top_reason), 1)
        self.assertTrue(all(e.top_match_reason == 8 for e in top_reason))

        top_score = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_min_top_match_score=True,
            min_top_match_score=4,
        )
        self.assertGreaterEqual(len(top_score), 1)
        self.assertTrue(all(e.top_match_score >= 4 for e in top_score))

    def test_pppoe_discovery_hostuniqless_pado_scans_past_ambiguous_clients(self):
        """Host-Uniq-less PADO should still find a later AC-name-filter match."""

        host_uniq_one = 0x11111111
        host_uniq_two = 0x22222222
        host_uniq_three = 0x33333333
        pppox_sw_if_index_one = self.add_client(host_uniq=host_uniq_one)
        pppox_sw_if_index_two = self.add_client(host_uniq=host_uniq_two)
        pppox_sw_if_index_three = self.add_client(
            configured_ac_name=b"ac-three", host_uniq=host_uniq_three
        )

        for sw_if_index in (
            pppox_sw_if_index_one,
            pppox_sw_if_index_two,
            pppox_sw_if_index_three,
        ):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:23", b"ac-three", host_uniq=None)]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:23")

        self.wait_for_client_state(host_uniq_one, 0, 0)
        self.wait_for_client_state(host_uniq_two, 0, 0)
        self.wait_for_client_state(host_uniq_three, 1, 0)

    def test_pppoe_discovery_hostuniqless_pado_prefers_single_any_client(self):
        """Host-Uniq-less PADO should fall back to a single <any> AC candidate."""

        host_uniq_any = 0x44444444
        host_uniq_filtered_one = 0x55555555
        host_uniq_filtered_two = 0x66666666
        pppox_sw_if_index_any = self.add_client(host_uniq=host_uniq_any)
        pppox_sw_if_index_filtered_one = self.add_client(
            configured_ac_name=b"ac-one", host_uniq=host_uniq_filtered_one
        )
        pppox_sw_if_index_filtered_two = self.add_client(
            configured_ac_name=b"ac-two", host_uniq=host_uniq_filtered_two
        )

        for sw_if_index in (
            pppox_sw_if_index_any,
            pppox_sw_if_index_filtered_one,
            pppox_sw_if_index_filtered_two,
        ):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:24", b"unlisted-ac", host_uniq=None)]
        )
        self.pg_start()

        padr = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.assertEqual(padr[Ether].dst.lower(), "02:00:00:00:00:24")

        self.wait_for_client_state(host_uniq_any, 1, 0)
        self.wait_for_client_state(host_uniq_filtered_one, 0, 0)
        self.wait_for_client_state(host_uniq_filtered_two, 0, 0)

    def test_pppoe_discovery_hostuniqless_pado_ambiguous_match_stays_orphan(self):
        """Host-Uniq-less PADO must stay orphan when two <any> candidates tie."""

        host_uniq_one = 0x77777777
        host_uniq_two = 0x88888888
        pppox_sw_if_index_one = self.add_client(host_uniq=host_uniq_one)
        pppox_sw_if_index_two = self.add_client(host_uniq=host_uniq_two)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_pado("02:00:00:00:00:26", b"", host_uniq=None)])
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        self.wait_for_client_state(host_uniq_one, 0, 0)
        self.wait_for_client_state(host_uniq_two, 0, 0)

        output = self.vapi.cli("show pppoe client summary orphan")
        self.assertIn("orphan-control-summary total 1", output)

    def test_pppoe_discovery_ignores_malformed_pado(self):
        """Malformed PADO tags must not advance discovery into REQUEST."""

        pppox_sw_if_index = self.add_client()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_malformed_pado("02:00:00:00:00:22")])
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 0)
        self.assertEqual(clients[0].session_id, 0)

    def test_pppoe_discovery_ignores_generic_error_pado(self):
        """Generic-Error PADO must not advance discovery into REQUEST."""

        pppox_sw_if_index = self.add_client()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado_with_error(
                    "02:00:00:00:00:22", 0x0203, b"temporary-bas-error"
                )
            ]
        )
        self.pg_start()

        with self.assertRaises(CaptureTimeoutError):
            self.pg0.wait_for_packet(timeout=0.5, filter_out_fn=self.is_not_padr)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 0)
        self.assertEqual(clients[0].session_id, 0)

        error_events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_has_error_tag=True,
            has_error_tag=True,
            filter_error_tag_type=True,
            error_tag_type=0x0203,
        )
        self.assertGreaterEqual(len(error_events), 1)
        self.assertTrue(all(e.error_tag_type == 0x0203 for e in error_events))

    def test_pppoe_request_ignores_malformed_pads(self):
        """Malformed PADS tags must not complete the REQUEST state."""

        pppox_sw_if_index = self.add_client()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_pado("02:00:00:00:00:22", self.AC_NAME)])
        self.pg_start()

        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(first_padr[Ether].dst.lower(), "02:00:00:00:00:22")

        self.pg0.add_stream([self.make_malformed_pads("02:00:00:00:00:22", 0x1234)])
        self.pg_start()

        self.sleep(0.5)
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 1)
        self.assertEqual(clients[0].session_id, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("recent-control", output)
        self.assertIn("PADS", output)
        self.assertIn("parse-error 1", output)

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, parse_errors_only=True
        )
        self.assertGreaterEqual(len(events), 1)
        self.assertTrue(all(e.parse_error for e in events))
        self.assertTrue(any(e.code == 0x65 for e in events))

        orphan_events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True, parse_errors_only=True
        )
        self.assertEqual(len(orphan_events), 0)

    def test_pppoe_request_rejects_generic_error_pads(self):
        """Generic-Error PADS must return the client to DISCOVERY."""

        pppox_sw_if_index = self.add_client()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_pado("02:00:00:00:00:22", self.AC_NAME)])
        self.pg_start()

        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(first_padr[Ether].dst.lower(), "02:00:00:00:00:22")

        self.pg0.add_stream(
            [
                self.make_pads_with_error(
                    "02:00:00:00:00:22",
                    0x1234,
                    0x0203,
                    b"temporary-bas-error",
                )
            ]
        )
        self.pg_start()

        self.wait_for_client_state(self.HOST_UNIQ, 0, 0)

    def _bring_request_state(self, ac_mac="02:00:00:00:00:22"):
        pppox_sw_if_index = self.add_client()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_pado(ac_mac, self.AC_NAME)])
        self.pg_start()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

    def test_pppoe_pads_zero_session_id_bumps_invalid_session_counter(self):
        """PADS carrying session-id 0 must bump the invalid-session-id error counter."""

        counter = (
            "/err/pppoeclient-discovery-input/"
            "PADS session-id is zero or reserved 0xffff"
        )
        before = self.statistics.get_err_counter(counter)

        self._bring_request_state()
        self.pg0.add_stream([self.make_pads("02:00:00:00:00:22", 0, self.AC_NAME)])
        self.pg_start()

        after = self.statistics.get_err_counter(counter)
        self.assertEqual(after, before + 1)

    def test_pppoe_pads_duplicate_session_id_bumps_collision_counter(self):
        """A second client landing on an already-bound session id bumps the collision counter."""

        counter = (
            "/err/pppoeclient-discovery-input/"
            "PADS session-id already bound to another client"
        )
        before = self.statistics.get_err_counter(counter)

        # Client one lands on session 0x1234 with AC 02:00:00:00:00:22.
        self.establish_session()

        # Client two tries to reach the SAME (sw_if_index, ac_mac, session_id)
        # tuple — a pathological BAS handing out a duplicate session id.
        ac_mac = "02:00:00:00:00:22"
        second_pppox_sw_if_index = self.add_client(host_uniq=0x99999999)
        response = self.vapi.pppox_set_auth(
            sw_if_index=second_pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [self.make_pado(ac_mac, self.AC_NAME, host_uniq=0x99999999)]
        )
        self.pg_start()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        self.pg0.add_stream(
            [
                self.make_pads(
                    ac_mac,
                    0x1234,
                    self.AC_NAME,
                    host_uniq=0x99999999,
                )
            ]
        )
        self.pg_start()

        after = self.statistics.get_err_counter(counter)
        self.assertEqual(after, before + 1)

    def test_pppoe_request_matches_hostuniqless_pads_by_cookie(self):
        """Host-Uniq-less PADS should use the selected AC cookie to disambiguate clients."""

        host_uniq_one = 0x11111111
        host_uniq_two = 0x22222222
        ac_mac = "02:00:00:00:00:22"
        cookie_one = b"cookie-one"
        cookie_two = b"cookie-two"

        pppox_sw_if_index_one = self.add_client(host_uniq=host_uniq_one)
        pppox_sw_if_index_two = self.add_client(host_uniq=host_uniq_two)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream(
            [
                self.make_pado(
                    ac_mac, self.AC_NAME, cookie=cookie_one, host_uniq=host_uniq_one
                ),
                self.make_pado(
                    ac_mac, self.AC_NAME, cookie=cookie_two, host_uniq=host_uniq_two
                ),
            ]
        )
        self.pg_start()

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        self.pg0.add_stream(
            [
                self.make_pads(
                    ac_mac, 0x1002, self.AC_NAME, cookie=cookie_two, host_uniq=None
                )
            ]
        )
        self.pg_start()

        self.wait_for_client_state(host_uniq_one, 1, 0)
        self.wait_for_client_state(host_uniq_two, 2, 0x1002)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match cookie", output)

    def test_pppoe_request_matches_hostuniqless_pads_by_service_name(self):
        """Host-Uniq-less PADS should still honor configured service-name."""

        host_uniq_one = 0x33333331
        host_uniq_two = 0x33333332
        ac_mac = "02:00:00:00:00:2a"
        pppox_sw_if_index_one = self.add_client(
            service_name=b"internet-a", host_uniq=host_uniq_one
        )
        pppox_sw_if_index_two = self.add_client(
            service_name=b"internet-b", host_uniq=host_uniq_two
        )

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream(
            [
                self.make_pado(
                    ac_mac,
                    self.AC_NAME,
                    host_uniq=host_uniq_one,
                    service_name=b"internet-a",
                ),
                self.make_pado(
                    ac_mac,
                    self.AC_NAME,
                    host_uniq=host_uniq_two,
                    service_name=b"internet-b",
                ),
            ]
        )
        self.pg_start()

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        self.pg0.add_stream(
            [
                self.make_pads(
                    ac_mac,
                    0x2002,
                    self.AC_NAME,
                    host_uniq=None,
                    service_name=b"internet-b",
                )
            ]
        )
        self.pg_start()

        self.wait_for_client_state(host_uniq_one, 1, 0)
        self.wait_for_client_state(host_uniq_two, 2, 0x2002)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match ac-mac+service", output)

    def test_pppoe_request_rejects_mismatched_service_name_pads(self):
        """Configured service-name must reject a PADS for a different service."""

        pppox_sw_if_index = self.add_client(service_name=self.SERVICE_NAME)
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:2b",
                    self.AC_NAME,
                    host_uniq=self.HOST_UNIQ,
                    service_name=self.SERVICE_NAME,
                )
            ]
        )
        self.pg_start()

        first_padr = self.pg0.wait_for_packet(
            timeout=10, filter_out_fn=self.is_not_padr
        )
        self.assertEqual(first_padr[Ether].dst.lower(), "02:00:00:00:00:2b")

        self.pg0.add_stream(
            [
                self.make_pads(
                    "02:00:00:00:00:2b",
                    0x2345,
                    self.AC_NAME,
                    host_uniq=self.HOST_UNIQ,
                    service_name=b"other-service",
                )
            ]
        )
        self.pg_start()

        self.sleep(0.5)
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 1)
        self.assertEqual(clients[0].session_id, 0)

    def test_pppoe_request_prefers_cookie_and_service_match(self):
        """Cookie+service should outrank plain AC-MAC matches in REQUEST fallback."""

        host_uniq_one = 0x99999991
        host_uniq_two = 0x99999992
        ac_mac = "02:00:00:00:00:2d"
        cookie_one = b"cookie-one"
        cookie_two = b"cookie-two"
        pppox_sw_if_index_one = self.add_client(
            service_name=b"internet-a", host_uniq=host_uniq_one
        )
        pppox_sw_if_index_two = self.add_client(
            service_name=b"internet-b", host_uniq=host_uniq_two
        )

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream(
            [
                self.make_pado(
                    ac_mac,
                    self.AC_NAME,
                    cookie=cookie_one,
                    host_uniq=host_uniq_one,
                    service_name=b"internet-a",
                ),
                self.make_pado(
                    ac_mac,
                    self.AC_NAME,
                    cookie=cookie_two,
                    host_uniq=host_uniq_two,
                    service_name=b"internet-b",
                ),
            ]
        )
        self.pg_start()

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        self.pg0.add_stream(
            [
                self.make_pads(
                    ac_mac,
                    0x3456,
                    self.AC_NAME,
                    cookie=cookie_two,
                    host_uniq=None,
                    service_name=b"internet-b",
                )
            ]
        )
        self.pg_start()

        self.wait_for_client_state(host_uniq_one, 1, 0)
        self.wait_for_client_state(host_uniq_two, 2, 0x3456)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("match cookie+service", output)

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1, orphan=False, max_events=1
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].code, 0x65)
        self.assertEqual(events[0].match_reason, 11)
        self.assertEqual(events[0].match_score, 4)
        self.assertEqual(
            self.normalize_api_string(events[0].service_name), "internet-b"
        )
        self.assertTrue(events[0].raw_tags_len > 0)

        filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_min_match_score=True,
            min_match_score=4,
        )
        self.assertGreaterEqual(len(filtered), 1)
        self.assertTrue(all(e.match_score >= 4 for e in filtered))

        service_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_service_name=True,
            service_name="internet-b",
        )
        self.assertGreaterEqual(len(service_filtered), 1)
        self.assertTrue(
            all(
                self.normalize_api_string(e.service_name) == "internet-b"
                for e in service_filtered
            )
        )

        top_reason = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_top_match_reason=True,
            top_match_reason=11,
        )
        self.assertGreaterEqual(len(top_reason), 1)
        self.assertTrue(all(e.top_match_reason == 11 for e in top_reason))

        top_score = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=1,
            orphan=False,
            filter_min_top_match_score=True,
            min_top_match_score=4,
        )
        self.assertGreaterEqual(len(top_score), 1)
        self.assertTrue(all(e.top_match_score >= 4 for e in top_score))

    def test_pppoe_debug_cli_reports_ppp_state(self):
        """Expose PPP state and stored config through a debug-oriented CLI."""

        self.add_client()

        self.vapi.cli(
            "set pppoe client 0 service-name %s" % self.SERVICE_NAME.decode("ascii")
        )

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("ppp phase", output)
        self.assertIn("stored-config", output)
        self.assertIn("service-name", output)

    def test_pppoe_debug_cli_reflects_dns_and_route_requests(self):
        """Reflect stored DNS/default-route intent into PPP debug runtime."""

        self.add_client()
        self.vapi.cli("set pppoe client 0 use-peer-dns add-default-route")

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("req-dns1 1", output)
        self.assertIn("req-dns2 1", output)
        self.assertIn("default-route4 1", output)

    def test_pppoe_debug_cli_reports_restart_reason_and_retry_window(self):
        """Expose reconnect reason/counter and next discovery timing after restart."""

        self.establish_session()

        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=1)
        self.assertEqual(response.retval, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("last-disconnect admin", output)
        self.assertIn("reconnects 1", output)
        self.assertIn("next-discovery", output)

    def test_pppoe_restart_during_cooldown_is_idempotent(self):
        """Repeated restart during cooldown must not keep bumping reconnect count."""

        self.establish_session()

        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=1)
        self.assertEqual(response.retval, 0)
        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=1)
        self.assertEqual(response.retval, 0)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("reconnects 1", output)

    def test_pppoe_auth_fail_backoff_grows_exponentially(self):
        """Each consecutive auth failure must widen the rediscovery cooldown."""

        self.establish_session()

        self.vapi.cli("test pppoe client inject-auth-fail 0")
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].consecutive_auth_failures, 1)
        self.assertEqual(clients[0].last_disconnect_reason, 5)

        self.vapi.cli("test pppoe client inject-auth-fail 0")
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].consecutive_auth_failures, 2)

        debug = self.vapi.cli("show pppoe client debug")
        self.assertIn("auth-failures 2", debug)
        self.assertIn("last-disconnect auth-fail", debug)

    def test_pppoe_backoff_show_and_clear_cli(self):
        """show/clear pppoe client backoff expose and reset counters."""

        # Reset jitter so cross-test contamination from the jitter case
        # can't shift this assertion's expected output.
        self.vapi.cli("set pppoeclient backoff-jitter 0")

        self.establish_session()
        self.vapi.cli("test pppoe client inject-auth-fail 0")
        self.vapi.cli("test pppoe client inject-auth-fail 0")

        output = self.vapi.cli("show pppoe client backoff")
        self.assertIn("auth-backoff base 30s cap 300s jitter-permille 0", output)
        self.assertIn("client 0", output)
        self.assertIn("auth-failures 2", output)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].consecutive_auth_failures, 2)

        # Targeted clear brings the specific client back to 0.
        self.vapi.cli("clear pppoe client backoff 0")
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].consecutive_auth_failures, 0)

        # Accumulate again, then exercise the `all` form.
        self.vapi.cli("test pppoe client inject-auth-fail 0")
        self.vapi.cli("clear pppoe client backoff all")
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].consecutive_auth_failures, 0)

    def test_pppoe_backoff_jitter_fraction_is_configurable(self):
        """set pppoeclient backoff-jitter updates the plugin-global fraction."""

        output = self.vapi.cli("set pppoeclient backoff-jitter 0.1")
        self.assertIn("jitter-permille set to 100", output)

        backoff = self.vapi.cli("show pppoe client backoff")
        self.assertIn("jitter-permille 100", backoff)

        # Out-of-range rejected; previous value preserved.
        try:
            self.vapi.cli("set pppoeclient backoff-jitter 0.9")
            self.fail("CLI should have rejected out-of-range fraction")
        except Exception as e:
            self.assertIn("must be in [0, 0.5]", str(e))
        backoff = self.vapi.cli("show pppoe client backoff")
        self.assertIn("jitter-permille 100", backoff)

        # Restore default so this case doesn't perturb sibling cooldown tests.
        self.vapi.cli("set pppoeclient backoff-jitter 0")

    def test_pppoe_discovery_tag_length_overflow_is_rejected(self):
        """A PADO whose Service-Name tag length exceeds the PPPoE payload is dropped."""

        pppox_sw_if_index = self.add_client()
        self.pg0.enable_capture()
        self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        padi = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        # Handcraft a PADO whose first TLV claims a length larger than what
        # the PPPoE payload can fit. parse_pppoe_packet must refuse the frame
        # without advancing state past DISCOVERY.
        ac_mac = "02:00:00:00:00:42"
        eth = Ether(src=ac_mac, dst=padi[Ether].src, type=0x8863)
        # PPPoE header: ver/type=0x11, code=PADO (0x07), session-id=0, length=8.
        # Payload: tag-type=Service-Name (0x0101), tag-length=0xffff (bogus).
        pppoe_and_bogus_tag = (
            b"\x11\x07\x00\x00"
            + struct.pack("!H", 0x0008)
            + b"\x01\x01"
            + struct.pack("!H", 0xFFFF)
        )
        raw = bytes(eth) + pppoe_and_bogus_tag
        self.pg0.add_stream([Ether(raw)])
        self.pg_start()

        # The client must neither crash nor advance to SESSION; no valid PADO
        # arrived so session_id stays 0 (REQUEST never started).
        self.sleep(0.2)
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].session_id, 0)

    def test_pppoe_debug_cli_reports_padt_reason(self):
        """Expose PADT-triggered reconnect reason through the debug CLI."""

        _, session_id, ac_mac = self.establish_session()

        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("last-disconnect padt", output)
        self.assertIn("reconnects 1", output)

    def test_pppoe_debug_cli_reports_recent_control_packets(self):
        """Expose recent PADO/PADS/PADT history through the debug CLI."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        pado = self.make_pado("02:00:00:00:00:22", self.AC_NAME, cookie=b"good-cookie")
        self.pg0.enable_capture()
        self.pg0.add_stream([pado])
        self.pg_start()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        pads = self.make_pads(
            "02:00:00:00:00:22", 0x1234, self.AC_NAME, cookie=b"good-cookie"
        )
        self.pg0.add_stream([pads])
        self.pg_start()
        self.wait_for_client_session(0x1234)

        self.pg0.add_stream([self.make_padt("02:00:00:00:00:22", 0x1234)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("recent-control-summary total 3", output)
        self.assertIn("recent-control-summary codes pado 1 pads 1 padt 1", output)
        self.assertIn(
            "recent-control-summary max match-score 0 candidates 1 top-score 0 top-count 1",
            output,
        )
        self.assertIn("recent-control", output)
        self.assertIn("PADO", output)
        self.assertIn("PADS", output)
        self.assertIn("PADT", output)
        self.assertIn("disposition accepted", output)
        self.assertIn("cookie-len 11", output)
        self.assertIn("ac-name my-ac", output)
        self.assertIn("raw-tags", output)

    def test_pppoe_debug_cli_can_focus_single_client(self):
        """Allow the debug CLI to target one client without printing unrelated sections."""

        _, session_id, ac_mac = self.establish_session()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug 0")
        self.assertIn("source-mac policy", output)
        self.assertIn("recent-control-summary total 3", output)
        self.assertIn("recent-control", output)
        self.assertIn("PADO", output)
        self.assertIn("PADT", output)
        self.assertNotIn("orphan-control", output)

    def test_pppoe_debug_cli_can_filter_history_output(self):
        """Allow the debug CLI to filter embedded control-history output."""

        _, session_id, ac_mac = self.establish_session()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug 0 code pads")
        self.assertIn("recent-control-summary total 1", output)
        self.assertIn("PADS", output)
        self.assertNotIn("PADO", output)
        self.assertNotIn("PADT", output)
        self.assertIn("source-mac policy", output)

    def test_pppoe_summary_cli_reports_recent_control_summary(self):
        """Expose control-history summary without verbose event details."""

        _, session_id, ac_mac = self.establish_session()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client summary")
        self.assertIn("recent-control-summary total 3", output)
        self.assertIn("recent-control-summary codes pado 1 pads 1 padt 1", output)
        self.assertIn(
            "recent-control-summary max match-score 0 candidates 1 top-score 0 top-count 1",
            output,
        )
        # The verbose event body dumps raw tag hex prefixed by four spaces; the
        # summary keeps a `raw-tags <count>` field, so narrow the negative match
        # to the verbose marker rather than the bare field name.
        self.assertNotIn("    raw-tags ", output)
        self.assertNotIn("cookie-len 11", output)

        pads_only = self.vapi.cli("show pppoe client summary 0 code pads")
        self.assertIn("recent-control-summary total 1", pads_only)
        self.assertIn("recent-control-summary codes pado 0 pads 1 padt 0", pads_only)

    def test_pppoe_history_cli_reports_recent_control_history(self):
        """Expose control-history summary plus event detail without full debug output."""

        _, session_id, ac_mac = self.establish_session()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        output = self.vapi.cli("show pppoe client history 0")
        self.assertIn("recent-control-summary total 3", output)
        self.assertIn("recent-control", output)
        self.assertIn("PADO", output)
        self.assertIn("PADS", output)
        self.assertIn("PADT", output)
        self.assertIn("raw-tags", output)
        self.assertNotIn("source-mac policy", output)
        self.assertNotIn("ppp debug-runtime", output)

        latest_only = self.vapi.cli("show pppoe client history 0 max-events 1")
        self.assertIn("recent-control-summary total 1", latest_only)
        self.assertIn("PADT", latest_only)
        self.assertNotIn("PADO", latest_only)
        self.assertNotIn("PADS", latest_only)

    def test_pppoe_history_cli_can_filter_parse_errors(self):
        """Allow the history CLI to focus only on parse-error events."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream([self.make_malformed_pado("02:00:00:00:00:22")])
        self.pg_start()

        output = self.vapi.cli("show pppoe client history 0 parse-errors-only")
        self.assertIn("recent-control-summary total 1", output)
        self.assertIn("PADO", output)
        self.assertIn("parse-error 1", output)
        self.assertNotIn("PADS", output)

    def test_pppoe_history_cli_can_filter_by_disposition(self):
        """Allow the history CLI to focus on a specific event disposition."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream([self.make_malformed_pado("02:00:00:00:00:22")])
        self.pg_start()

        errors = self.vapi.cli("show pppoe client history 0 disposition error")
        self.assertIn("recent-control-summary total 1", errors)
        self.assertIn("disposition error", errors)
        self.assertNotIn("disposition accepted", errors)

        accepted = self.vapi.cli("show pppoe client history 0 disposition accepted")
        self.assertIn("recent-control-summary <empty>", accepted)
        self.assertNotIn("disposition error", accepted)

    def test_pppoe_summary_cli_can_filter_by_match_reason(self):
        """Allow the summary CLI to focus on a specific match reason."""

        _, session_id, ac_mac = self.establish_session()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        # PADO + PADS match via host-uniq; PADT matches via session id.
        host_uniq_only = self.vapi.cli(
            "show pppoe client summary 0 match-reason host-uniq"
        )
        self.assertIn("recent-control-summary total 2", host_uniq_only)

        session_only = self.vapi.cli("show pppoe client summary 0 match-reason session")
        self.assertIn("recent-control-summary total 1", session_only)

        none_only = self.vapi.cli("show pppoe client summary 0 match-reason none")
        self.assertIn("recent-control-summary <empty>", none_only)

    def test_pppoe_control_history_dump_api_reports_recent_packets(self):
        """Expose recent control history through the dump API."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        pado = self.make_pado(
            "02:00:00:00:00:22",
            self.AC_NAME,
            cookie=b"good-cookie",
            service_name=b"svc",
        )
        self.pg0.enable_capture()
        self.pg0.add_stream([pado])
        self.pg_start()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        pads = self.make_pads(
            "02:00:00:00:00:22", 0x1234, self.AC_NAME, cookie=b"good-cookie"
        )
        self.pg0.add_stream([pads])
        self.pg_start()
        self.wait_for_client_session(0x1234)

        self.pg0.add_stream([self.make_padt("02:00:00:00:00:22", 0x1234)])
        self.pg_start()

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False
        )
        self.assertGreaterEqual(len(events), 3)
        self.assertTrue(all(e.age_msec >= 0 for e in events))
        self.assertIn(0x07, [e.code for e in events])
        self.assertIn(0x65, [e.code for e in events])
        self.assertIn(0xA7, [e.code for e in events])
        self.assertTrue(
            any(
                e.code == 0x07
                and e.client_state == 1
                and e.disposition == 1
                and e.match_reason == 1
                and e.match_score == 0
                for e in events
            )
        )
        self.assertTrue(
            any(
                e.code == 0x65 and e.client_state == 2 and e.disposition == 1
                for e in events
            )
        )
        self.assertTrue(
            any(
                e.code == 0xA7
                and e.client_state == 3
                and e.disposition == 1
                and e.match_reason == 7
                and e.match_score == 0
                for e in events
            )
        )
        self.assertTrue(
            any(self.normalize_api_string(e.ac_name) == "my-ac" for e in events)
        )
        self.assertTrue(any(e.cookie_len == 11 for e in events))
        self.assertTrue(
            any(
                bytes(e.cookie_value[: e.cookie_value_len]) == b"good-cookie"
                and e.cookie_value_truncated is False
                for e in events
            )
        )
        with_cookie = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_has_cookie=True,
            has_cookie=True,
        )
        self.assertGreaterEqual(len(with_cookie), 1)
        self.assertTrue(all(e.cookie_len > 0 for e in with_cookie))

        cookie_len_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_cookie_len=True,
            cookie_len=11,
        )
        self.assertGreaterEqual(len(cookie_len_filtered), 1)
        self.assertTrue(all(e.cookie_len == 11 for e in cookie_len_filtered))

        wrong_cookie_len = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_cookie_len=True,
            cookie_len=12,
        )
        self.assertEqual(len(wrong_cookie_len), 0)

        cookie_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_cookie_value=True,
            cookie_value_len=len(b"good-cookie"),
            cookie_value=b"good-cookie",
        )
        self.assertGreaterEqual(len(cookie_filtered), 1)
        self.assertTrue(
            all(
                bytes(e.cookie_value[: e.cookie_value_len]) == b"good-cookie"
                for e in cookie_filtered
            )
        )

        wrong_cookie = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_cookie_value=True,
            cookie_value_len=len(b"bad-cookie"),
            cookie_value=b"bad-cookie",
        )
        self.assertEqual(len(wrong_cookie), 0)

        with_names_and_tags = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_has_service_name=True,
            has_service_name=True,
            filter_has_ac_name=True,
            has_ac_name=True,
            filter_has_raw_tags=True,
            has_raw_tags=True,
        )
        self.assertGreaterEqual(len(with_names_and_tags), 1)
        self.assertTrue(
            all(self.normalize_api_string(e.ac_name) for e in with_names_and_tags)
        )
        self.assertTrue(all(e.raw_tags_len > 0 for e in with_names_and_tags))

        pado_events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, filter_code=True, code=0x07
        )
        self.assertGreaterEqual(len(pado_events), 1)
        raw_tags_len = pado_events[0].raw_tags_len

        raw_tags_len_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_code=True,
            code=0x07,
            filter_raw_tags_len=True,
            raw_tags_len=raw_tags_len,
        )
        self.assertGreaterEqual(len(raw_tags_len_filtered), 1)
        self.assertTrue(
            all(e.raw_tags_len == raw_tags_len for e in raw_tags_len_filtered)
        )

        wrong_raw_tags_len = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_code=True,
            code=0x07,
            filter_raw_tags_len=True,
            raw_tags_len=raw_tags_len + 1,
        )
        self.assertEqual(len(wrong_raw_tags_len), 0)

        ac_name_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_ac_name=True,
            ac_name="my-ac",
        )
        self.assertGreaterEqual(len(ac_name_filtered), 1)
        self.assertTrue(
            all(
                self.normalize_api_string(e.ac_name) == "my-ac"
                for e in ac_name_filtered
            )
        )

        wrong_ac_name = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_ac_name=True,
            ac_name="wrong-ac",
        )
        self.assertEqual(len(wrong_ac_name), 0)
        self.assertTrue(all(e.service_name_truncated is False for e in events))
        self.assertTrue(all(e.ac_name_truncated is False for e in events))
        self.assertTrue(any(e.raw_tags_len > 0 for e in events))
        self.assertTrue(
            any(
                e.code == 0x07
                and e.candidate_count == 1
                and e.top_match_count == 1
                and e.top_match_reason == 1
                and e.top_match_score == 0
                for e in events
            )
        )
        self.assertTrue(
            any(
                e.code == 0xA7
                and e.candidate_count == 1
                and e.top_match_count == 1
                and e.top_match_reason == 7
                and e.top_match_score == 0
                for e in events
            )
        )

        latest = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, max_events=1
        )
        self.assertEqual(len(latest), 1)
        self.assertEqual(latest[0].code, 0xA7)

        latest_two = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, max_events=2
        )
        self.assertEqual(len(latest_two), 2)
        self.assertEqual([e.code for e in latest_two], [0x65, 0xA7])

        summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0, orphan=False
        )
        self.assertEqual(summary.retval, 0)
        self.assertEqual(summary.matched_events, 3)
        self.assertEqual(summary.pado_count, 1)
        self.assertEqual(summary.pads_count, 1)
        self.assertEqual(summary.padt_count, 1)
        self.assertEqual(summary.accepted_count, 3)
        self.assertEqual(summary.ignored_count, 0)
        self.assertEqual(summary.error_count, 0)
        self.assertEqual(summary.orphan_count, 0)
        self.assertEqual(summary.discovery_state_count, 1)
        self.assertEqual(summary.request_state_count, 1)
        self.assertEqual(summary.session_state_count, 1)
        self.assertEqual(summary.unknown_state_count, 0)
        self.assertEqual(summary.parse_error_count, 0)
        self.assertEqual(summary.host_uniq_present_count, 2)
        self.assertEqual(summary.cookie_present_count, 2)
        self.assertEqual(summary.service_name_count, 1)
        self.assertEqual(summary.ac_name_count, 2)
        self.assertEqual(summary.raw_tags_count, 2)
        self.assertEqual(summary.error_tag_count, 0)
        self.assertEqual(summary.service_name_truncated_count, 0)
        self.assertEqual(summary.ac_name_truncated_count, 0)
        self.assertEqual(summary.cookie_value_truncated_count, 0)
        self.assertEqual(summary.raw_tags_truncated_count, 0)
        self.assertEqual(summary.match_none_count, 0)
        self.assertEqual(summary.match_host_uniq_count, 2)
        self.assertEqual(summary.match_session_count, 1)
        self.assertEqual(summary.match_ac_name_count, 0)
        self.assertEqual(summary.match_service_name_count, 0)
        self.assertEqual(summary.match_any_count, 0)
        self.assertEqual(summary.match_cookie_count, 0)
        self.assertEqual(summary.match_unique_count, 0)
        self.assertEqual(summary.match_ac_and_service_count, 0)
        self.assertEqual(summary.match_ac_mac_count, 0)
        self.assertEqual(summary.match_ac_mac_and_service_count, 0)
        self.assertEqual(summary.match_cookie_and_service_count, 0)
        self.assertEqual(summary.top_match_none_count, 0)
        self.assertEqual(summary.top_match_host_uniq_count, 2)
        self.assertEqual(summary.top_match_session_count, 1)
        self.assertEqual(summary.top_match_ac_name_count, 0)
        self.assertEqual(summary.top_match_service_name_count, 0)
        self.assertEqual(summary.top_match_any_count, 0)
        self.assertEqual(summary.top_match_cookie_count, 0)
        self.assertEqual(summary.top_match_unique_count, 0)
        self.assertEqual(summary.top_match_ac_and_service_count, 0)
        self.assertEqual(summary.top_match_ac_mac_count, 0)
        self.assertEqual(summary.top_match_ac_mac_and_service_count, 0)
        self.assertEqual(summary.top_match_cookie_and_service_count, 0)
        self.assertEqual(summary.ambiguous_events_count, 0)
        self.assertEqual(summary.max_match_score, 0)
        self.assertEqual(summary.max_candidate_count, 1)
        self.assertEqual(summary.max_top_match_score, 0)
        self.assertEqual(summary.max_top_match_count, 1)
        self.assertGreaterEqual(summary.max_age_msec, summary.min_age_msec)

        latest_summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0, orphan=False, max_events=2
        )
        self.assertEqual(latest_summary.retval, 0)
        self.assertEqual(latest_summary.matched_events, 2)
        self.assertEqual(latest_summary.pado_count, 0)
        self.assertEqual(latest_summary.pads_count, 1)
        self.assertEqual(latest_summary.padt_count, 1)
        self.assertEqual(latest_summary.cookie_present_count, 1)
        self.assertEqual(latest_summary.ac_name_count, 1)
        self.assertEqual(latest_summary.raw_tags_count, 1)
        self.assertEqual(latest_summary.match_host_uniq_count, 1)
        self.assertEqual(latest_summary.match_session_count, 1)
        self.assertEqual(latest_summary.top_match_host_uniq_count, 1)
        self.assertEqual(latest_summary.top_match_session_count, 1)
        self.assertEqual(latest_summary.ambiguous_events_count, 0)
        self.assertEqual(latest_summary.max_match_score, 0)
        self.assertEqual(latest_summary.max_candidate_count, 1)
        self.assertEqual(latest_summary.max_top_match_score, 0)
        self.assertEqual(latest_summary.max_top_match_count, 1)

        recent = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_max_age_msec=True,
            max_age_msec=5000,
        )
        self.assertGreaterEqual(len(recent), 1)

        filtered_pads = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, filter_code=True, code=0x65
        )
        self.assertGreaterEqual(len(filtered_pads), 1)
        self.assertTrue(all(e.code == 0x65 for e in filtered_pads))

        peer_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_peer_mac=True,
            peer_mac="02:00:00:00:00:22",
        )
        self.assertEqual(len(peer_filtered), len(events))

        sw_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_sw_if_index=True,
            sw_if_index=self.pg0.sw_if_index,
        )
        self.assertEqual(len(sw_filtered), len(events))

        wrong_sw = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_sw_if_index=True,
            sw_if_index=self.pg0.sw_if_index + 100,
        )
        self.assertEqual(len(wrong_sw), 0)

        wrong_peer = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_peer_mac=True,
            peer_mac="02:00:00:00:00:99",
        )
        self.assertEqual(len(wrong_peer), 0)

        session_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_session_id=True,
            session_id=0x1234,
        )
        self.assertGreaterEqual(len(session_filtered), 2)
        self.assertTrue(all(e.session_id == 0x1234 for e in session_filtered))
        self.assertTrue(all(e.code in (0x65, 0xA7) for e in session_filtered))

        wrong_session = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_session_id=True,
            session_id=0x4321,
        )
        self.assertEqual(len(wrong_session), 0)

        request_events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_client_state=True,
            client_state=2,
        )
        self.assertGreaterEqual(len(request_events), 1)
        self.assertTrue(all(e.client_state == 2 for e in request_events))
        self.assertTrue(all(e.code == 0x65 for e in request_events))

        session_events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_client_state=True,
            client_state=3,
        )
        self.assertGreaterEqual(len(session_events), 1)
        self.assertTrue(all(e.client_state == 3 for e in session_events))
        self.assertTrue(all(e.code == 0xA7 for e in session_events))

        request_summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0,
            orphan=False,
            filter_client_state=True,
            client_state=2,
        )
        self.assertEqual(request_summary.retval, 0)
        self.assertEqual(request_summary.matched_events, len(request_events))
        self.assertEqual(request_summary.pado_count, 0)
        self.assertEqual(request_summary.pads_count, len(request_events))
        self.assertEqual(request_summary.padt_count, 0)
        self.assertEqual(request_summary.request_state_count, len(request_events))

        orphan_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_top_match_reason=True,
            top_match_reason=4,
        )
        orphan_summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0,
            orphan=True,
            filter_top_match_reason=True,
            top_match_reason=4,
        )
        self.assertEqual(orphan_summary.retval, 0)
        self.assertEqual(orphan_summary.matched_events, len(orphan_filtered))

        accepted = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_disposition=True,
            disposition=1,
        )
        self.assertGreaterEqual(len(accepted), 1)
        self.assertTrue(all(e.disposition == 1 for e in accepted))

        with_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_host_uniq_present=True,
            host_uniq_present=True,
        )
        self.assertGreaterEqual(len(with_hostuniq), 1)
        self.assertTrue(all(e.host_uniq_present is True for e in with_hostuniq))

        non_parse_errors = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_parse_error=True,
            parse_error=False,
        )
        self.assertGreaterEqual(len(non_parse_errors), 1)
        self.assertTrue(all(e.parse_error is False for e in non_parse_errors))

        exact_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_host_uniq=True,
            host_uniq=self.HOST_UNIQ,
        )
        self.assertGreaterEqual(len(exact_hostuniq), 1)
        self.assertTrue(all(e.host_uniq == self.HOST_UNIQ for e in exact_hostuniq))

        wrong_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_host_uniq=True,
            host_uniq=0xDEADBEEF,
        )
        self.assertEqual(len(wrong_hostuniq), 0)

        scored = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_min_match_score=True,
            min_match_score=1,
        )
        self.assertEqual(len(scored), 0)

        self.sleep(0.05)
        older = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, filter_min_age_msec=True, min_age_msec=1
        )
        self.assertGreaterEqual(len(older), 1)

        stale = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, filter_max_age_msec=True, max_age_msec=1
        )
        self.assertEqual(len(stale), 0)

        output = self.vapi.cli("clear pppoe client history 0")
        self.assertIn("Cleared PPPoE control history for client 0", output)
        cleared = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False
        )
        self.assertEqual(len(cleared), 0)

    def test_pppoe_control_history_dump_api_filters_truncated_fields(self):
        """Expose truncation flags through control-history filters."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        long_service = b"s" * 80
        long_ac_name = b"a" * 80
        long_cookie = b"c" * 96

        self.pg0.enable_capture()
        self.pg0.add_stream(
            [
                self.make_pado(
                    "02:00:00:00:00:2d",
                    long_ac_name,
                    cookie=long_cookie,
                    service_name=long_service,
                )
            ]
        )
        self.pg_start()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padr)

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, max_events=1
        )
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].service_name_truncated)
        self.assertTrue(events[0].ac_name_truncated)
        self.assertTrue(events[0].cookie_value_truncated)
        self.assertTrue(events[0].raw_tags_truncated)

        service_truncated = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_service_name_truncated=True,
            service_name_truncated=True,
        )
        self.assertGreaterEqual(len(service_truncated), 1)
        self.assertTrue(all(e.service_name_truncated for e in service_truncated))

        ac_truncated = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_ac_name_truncated=True,
            ac_name_truncated=True,
        )
        self.assertGreaterEqual(len(ac_truncated), 1)
        self.assertTrue(all(e.ac_name_truncated for e in ac_truncated))

        cookie_truncated = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_cookie_value_truncated=True,
            cookie_value_truncated=True,
        )
        self.assertGreaterEqual(len(cookie_truncated), 1)
        self.assertTrue(all(e.cookie_value_truncated for e in cookie_truncated))

        raw_tags_truncated = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_raw_tags_truncated=True,
            raw_tags_truncated=True,
        )
        self.assertGreaterEqual(len(raw_tags_truncated), 1)
        self.assertTrue(all(e.raw_tags_truncated for e in raw_tags_truncated))

        no_service_trunc = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_service_name_truncated=True,
            service_name_truncated=False,
        )
        self.assertEqual(len(no_service_trunc), 0)

    def test_pppoe_debug_cli_reports_parse_error_in_recent_control(self):
        """Expose malformed discovery packets through recent-control debug history."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream([self.make_malformed_pado("02:00:00:00:00:22")])
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("recent-control-summary total 1", output)
        self.assertIn("recent-control", output)
        self.assertIn("PADO", output)
        self.assertIn("client-state discovery", output)
        self.assertIn("host-uniq %u" % self.HOST_UNIQ, output)
        self.assertIn("disposition error", output)
        self.assertIn("parse-error 1", output)
        self.assertIn("raw-tags", output)

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=False, parse_errors_only=True
        )
        self.assertGreaterEqual(len(events), 1)
        self.assertTrue(all(e.parse_error for e in events))
        self.assertTrue(all(e.disposition == 3 for e in events))
        self.assertTrue(all(e.code == 0x07 for e in events))

        exact_errors = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_parse_error=True,
            parse_error=True,
        )
        self.assertGreaterEqual(len(exact_errors), 1)
        self.assertTrue(all(e.parse_error is True for e in exact_errors))

        errors = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=False,
            filter_disposition=True,
            disposition=3,
        )
        self.assertGreaterEqual(len(errors), 1)
        self.assertTrue(all(e.disposition == 3 for e in errors))

    def test_pppoe_debug_cli_reports_source_mac_policy(self):
        """Expose configured source-MAC policy and use it for discovery packets."""

        static_mac = "02:fe:ed:00:00:42"
        pppox_sw_if_index = self.add_client()
        self.vapi.cli("set pppoe client 0 source-mac %s" % static_mac)

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        padi = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.assertEqual(padi[Ether].src.lower(), static_mac)

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("source-mac policy static", output)
        self.assertIn("via static", output)
        self.assertIn(static_mac, output)
        self.assertIn("source-mac fallbacks 0 last-reason none", output)

    def test_pppoe_debug_cli_reports_orphan_control_packets(self):
        """Expose unmatched discovery/control packets through orphan-control history."""

        pppox_sw_if_index_one = self.add_client(host_uniq=0x11111111)
        pppox_sw_if_index_two = self.add_client(host_uniq=0x22222222)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:25", b"orphan-ac", host_uniq=None)]
        )
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug")
        self.assertIn("orphan-control-summary total 1", output)
        self.assertIn(
            "orphan-control-summary fields host-uniq 0 cookie 0 service-name 0 ac-name 1 raw-tags 1 error-tag 0",
            output,
        )
        self.assertIn(
            "orphan-control-summary max match-score 0 candidates 2 top-score 1 top-count 2",
            output,
        )
        self.assertIn("orphan-control", output)
        self.assertIn("PADO", output)
        self.assertIn("disposition orphan", output)
        self.assertIn("sw-if-index %u" % self.pg0.sw_if_index, output)
        self.assertIn("host-uniq <none>", output)
        self.assertIn("ac-name orphan-ac", output)
        self.assertIn("candidates 2", output)
        self.assertIn("top any x2 score 1", output)

    def test_pppoe_debug_cli_can_focus_orphan_history(self):
        """Allow the debug CLI to print only orphan control history."""

        pppox_sw_if_index_one = self.add_client(host_uniq=0x11111111)
        pppox_sw_if_index_two = self.add_client(host_uniq=0x22222222)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:25", b"orphan-ac", host_uniq=None)]
        )
        self.pg_start()

        output = self.vapi.cli("show pppoe client debug orphan")
        self.assertIn("orphan-control-summary total 1", output)
        self.assertIn("orphan-control", output)
        self.assertIn("PADO", output)
        self.assertNotIn("source-mac policy", output)

    def test_pppoe_summary_cli_reports_orphan_control_summary(self):
        """Expose orphan control-history summary without verbose orphan details."""

        pppox_sw_if_index_one = self.add_client(host_uniq=0x11111111)
        pppox_sw_if_index_two = self.add_client(host_uniq=0x22222222)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:25", b"orphan-ac", host_uniq=None)]
        )
        self.pg_start()

        output = self.vapi.cli("show pppoe client summary orphan")
        self.assertIn("orphan-control-summary total 1", output)
        self.assertIn(
            "orphan-control-summary fields host-uniq 0 cookie 0 service-name 0 ac-name 1 raw-tags 1 error-tag 0",
            output,
        )
        self.assertIn(
            "orphan-control-summary max match-score 0 candidates 2 top-score 1 top-count 2",
            output,
        )
        # Summary mode surfaces `raw-tags <count>` in the fields line; the
        # verbose body emits `    raw-tags <hex>` with a four-space prefix, so
        # assert only the verbose marker is absent.
        self.assertNotIn("    raw-tags ", output)

    def test_pppoe_history_cli_reports_orphan_control_history(self):
        """Expose orphan control-history summary plus event detail without full client debug."""

        pppox_sw_if_index_one = self.add_client(host_uniq=0x11111111)
        pppox_sw_if_index_two = self.add_client(host_uniq=0x22222222)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:25", b"orphan-ac", host_uniq=None)]
        )
        self.pg_start()

        output = self.vapi.cli("show pppoe client history orphan")
        self.assertIn("orphan-control-summary total 1", output)
        self.assertIn("orphan-control", output)
        self.assertIn("PADO", output)
        self.assertIn("raw-tags", output)
        self.assertNotIn("source-mac policy", output)

    def test_pppoe_control_history_dump_api_reports_orphan_packets(self):
        """Expose orphan control history through the dump API."""

        pppox_sw_if_index_one = self.add_client(host_uniq=0x11111111)
        pppox_sw_if_index_two = self.add_client(host_uniq=0x22222222)

        for sw_if_index in (pppox_sw_if_index_one, pppox_sw_if_index_two):
            response = self.vapi.pppox_set_auth(
                sw_if_index=sw_if_index,
                username=self.AUTH_USERNAME,
                password=self.AUTH_PASSWORD,
            )
            self.assertEqual(response.retval, 0)

        self.pg0.enable_capture()
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        self.pg0.add_stream(
            [self.make_pado("02:00:00:00:00:25", b"orphan-ac", host_uniq=None)]
        )
        self.pg_start()

        events = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True
        )
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[-1].orphan, True)
        self.assertGreaterEqual(events[-1].age_msec, 0)
        self.assertEqual(events[-1].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(events[-1].code, 0x07)
        self.assertEqual(events[-1].client_state, 0)
        self.assertEqual(events[-1].disposition, 4)
        self.assertEqual(events[-1].match_reason, 0)
        self.assertEqual(events[-1].match_score, 0)
        self.assertEqual(events[-1].candidate_count, 2)
        self.assertEqual(events[-1].top_match_count, 2)
        self.assertEqual(events[-1].top_match_reason, 4)
        self.assertEqual(events[-1].top_match_score, 1)
        self.assertEqual(self.normalize_api_string(events[-1].ac_name), "orphan-ac")
        self.assertTrue(events[-1].raw_tags_len > 0)

        latest = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True, max_events=1
        )
        self.assertEqual(len(latest), 1)
        self.assertEqual(latest[0].code, 0x07)

        summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0, orphan=True
        )
        self.assertEqual(summary.retval, 0)
        self.assertGreaterEqual(summary.matched_events, 1)
        self.assertEqual(summary.pado_count, summary.matched_events)
        self.assertEqual(summary.pads_count, 0)
        self.assertEqual(summary.padt_count, 0)
        self.assertEqual(summary.orphan_count, summary.matched_events)
        self.assertEqual(summary.unknown_state_count, summary.matched_events)
        self.assertEqual(summary.parse_error_count, 0)
        self.assertEqual(summary.host_uniq_present_count, 0)
        self.assertEqual(summary.cookie_present_count, 0)
        self.assertEqual(summary.service_name_count, 0)
        self.assertEqual(summary.ac_name_count, summary.matched_events)
        self.assertEqual(summary.raw_tags_count, summary.matched_events)
        self.assertEqual(summary.error_tag_count, 0)
        self.assertEqual(summary.service_name_truncated_count, 0)
        self.assertEqual(summary.ac_name_truncated_count, 0)
        self.assertEqual(summary.cookie_value_truncated_count, 0)
        self.assertEqual(summary.raw_tags_truncated_count, 0)
        self.assertEqual(summary.match_none_count, summary.matched_events)
        self.assertEqual(summary.match_host_uniq_count, 0)
        self.assertEqual(summary.match_session_count, 0)
        self.assertEqual(summary.match_ac_name_count, 0)
        self.assertEqual(summary.match_service_name_count, 0)
        self.assertEqual(summary.match_any_count, 0)
        self.assertEqual(summary.match_cookie_count, 0)
        self.assertEqual(summary.match_unique_count, 0)
        self.assertEqual(summary.match_ac_and_service_count, 0)
        self.assertEqual(summary.match_ac_mac_count, 0)
        self.assertEqual(summary.match_ac_mac_and_service_count, 0)
        self.assertEqual(summary.match_cookie_and_service_count, 0)
        self.assertEqual(summary.top_match_none_count, 0)
        self.assertEqual(summary.top_match_host_uniq_count, 0)
        self.assertEqual(summary.top_match_session_count, 0)
        self.assertEqual(summary.top_match_ac_name_count, 0)
        self.assertEqual(summary.top_match_service_name_count, 0)
        self.assertEqual(summary.top_match_any_count, summary.matched_events)
        self.assertEqual(summary.top_match_cookie_count, 0)
        self.assertEqual(summary.top_match_unique_count, 0)
        self.assertEqual(summary.top_match_ac_and_service_count, 0)
        self.assertEqual(summary.top_match_ac_mac_count, 0)
        self.assertEqual(summary.top_match_ac_mac_and_service_count, 0)
        self.assertEqual(summary.top_match_cookie_and_service_count, 0)
        self.assertEqual(summary.ambiguous_events_count, summary.matched_events)
        self.assertEqual(summary.max_match_score, 0)
        self.assertEqual(summary.max_candidate_count, 2)
        self.assertEqual(summary.max_top_match_score, 1)
        self.assertEqual(summary.max_top_match_count, 2)
        self.assertGreaterEqual(summary.max_age_msec, summary.min_age_msec)

        orphan_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_top_match_reason=True,
            top_match_reason=4,
        )
        orphan_summary = self.vapi.pppoeclient_control_history_summary(
            pppoeclient_index=0,
            orphan=True,
            filter_top_match_reason=True,
            top_match_reason=4,
        )
        self.assertEqual(orphan_summary.retval, 0)
        self.assertEqual(orphan_summary.matched_events, len(orphan_filtered))

        recent = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_max_age_msec=True,
            max_age_msec=5000,
        )
        self.assertGreaterEqual(len(recent), 1)

        filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True, filter_match_reason=True, match_reason=0
        )
        self.assertGreaterEqual(len(filtered), 1)
        self.assertTrue(all(e.match_reason == 0 for e in filtered))

        unknown_state = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_client_state=True,
            client_state=0,
        )
        self.assertGreaterEqual(len(unknown_state), 1)
        self.assertTrue(all(e.client_state == 0 for e in unknown_state))

        empty_cookie = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_cookie_value=True,
            cookie_value_len=0,
            cookie_value=b"",
        )
        self.assertGreaterEqual(len(empty_cookie), 1)
        self.assertTrue(all(e.cookie_value_len == 0 for e in empty_cookie))

        zero_cookie_len = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_cookie_len=True,
            cookie_len=0,
        )
        self.assertGreaterEqual(len(zero_cookie_len), 1)
        self.assertTrue(all(e.cookie_len == 0 for e in zero_cookie_len))

        peer_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_peer_mac=True,
            peer_mac="02:00:00:00:00:25",
        )
        self.assertGreaterEqual(len(peer_filtered), 1)
        self.assertTrue(all(e.code == 0x07 for e in peer_filtered))

        sw_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_sw_if_index=True,
            sw_if_index=self.pg0.sw_if_index,
        )
        self.assertGreaterEqual(len(sw_filtered), 1)
        self.assertTrue(all(e.sw_if_index == self.pg0.sw_if_index for e in sw_filtered))

        wrong_sw = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_sw_if_index=True,
            sw_if_index=self.pg0.sw_if_index + 100,
        )
        self.assertEqual(len(wrong_sw), 0)

        wrong_peer = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_peer_mac=True,
            peer_mac="02:00:00:00:00:26",
        )
        self.assertEqual(len(wrong_peer), 0)

        session_zero = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_session_id=True,
            session_id=0,
        )
        self.assertGreaterEqual(len(session_zero), 1)
        self.assertTrue(all(e.session_id == 0 for e in session_zero))

        orphan_only = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_disposition=True,
            disposition=4,
        )
        self.assertGreaterEqual(len(orphan_only), 1)
        self.assertTrue(all(e.disposition == 4 for e in orphan_only))

        without_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_host_uniq_present=True,
            host_uniq_present=False,
        )
        self.assertGreaterEqual(len(without_hostuniq), 1)
        self.assertTrue(all(e.host_uniq_present is False for e in without_hostuniq))

        zero_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_host_uniq=True,
            host_uniq=0,
        )
        self.assertGreaterEqual(len(zero_hostuniq), 1)
        self.assertTrue(all(e.host_uniq == 0 for e in zero_hostuniq))

        wrong_hostuniq = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_host_uniq=True,
            host_uniq=0xDEADBEEF,
        )
        self.assertEqual(len(wrong_hostuniq), 0)
        with_names_and_tags = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_has_service_name=True,
            has_service_name=False,
            filter_has_ac_name=True,
            has_ac_name=True,
            filter_has_raw_tags=True,
            has_raw_tags=True,
        )
        self.assertGreaterEqual(len(with_names_and_tags), 1)
        self.assertTrue(
            all(self.normalize_api_string(e.ac_name) for e in with_names_and_tags)
        )
        self.assertTrue(all(e.raw_tags_len > 0 for e in with_names_and_tags))

        raw_tags_len_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_raw_tags_len=True,
            raw_tags_len=events[-1].raw_tags_len,
        )
        self.assertGreaterEqual(len(raw_tags_len_filtered), 1)
        self.assertTrue(
            all(
                e.raw_tags_len == events[-1].raw_tags_len for e in raw_tags_len_filtered
            )
        )

        ac_name_filtered = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_ac_name=True,
            ac_name="orphan-ac",
        )
        self.assertGreaterEqual(len(ac_name_filtered), 1)
        self.assertTrue(
            all(
                self.normalize_api_string(e.ac_name) == "orphan-ac"
                for e in ac_name_filtered
            )
        )

        wrong_ac_name = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_ac_name=True,
            ac_name="wrong-ac",
        )
        self.assertEqual(len(wrong_ac_name), 0)

        ambiguous = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_min_candidate_count=True,
            min_candidate_count=2,
        )
        self.assertGreaterEqual(len(ambiguous), 1)
        self.assertTrue(all(e.candidate_count >= 2 for e in ambiguous))

        top_reason = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_top_match_reason=True,
            top_match_reason=4,
        )
        self.assertGreaterEqual(len(top_reason), 1)
        self.assertTrue(all(e.top_match_reason == 4 for e in top_reason))

        top_score = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_min_top_match_score=True,
            min_top_match_score=1,
        )
        self.assertGreaterEqual(len(top_score), 1)
        self.assertTrue(all(e.top_match_score >= 1 for e in top_score))

        top_count = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_min_top_match_count=True,
            min_top_match_count=2,
        )
        self.assertGreaterEqual(len(top_count), 1)
        self.assertTrue(all(e.top_match_count >= 2 for e in top_count))

        scored = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0,
            orphan=True,
            filter_min_match_score=True,
            min_match_score=1,
        )
        self.assertEqual(len(scored), 0)

        self.sleep(0.05)
        older = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True, filter_min_age_msec=True, min_age_msec=1
        )
        self.assertGreaterEqual(len(older), 1)

        stale = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True, filter_max_age_msec=True, max_age_msec=1
        )
        self.assertEqual(len(stale), 0)

        output = self.vapi.cli("clear pppoe client history orphan")
        self.assertIn("Cleared PPPoE orphan control history", output)
        cleared = self.vapi.pppoeclient_control_history_dump(
            pppoeclient_index=0, orphan=True
        )
        self.assertEqual(len(cleared), 0)

    def test_pppoe_set_options_api(self):
        """Set and verify client options via the set_options API."""

        self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            username="testuser",
            password="testpass",
            set_use_peer_dns=True,
            use_peer_dns=True,
            set_add_default_route4=True,
            add_default_route4=True,
            set_add_default_route6=True,
            add_default_route6=False,
            mtu=1492,
            mru=1492,
        )

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(self.normalize_api_string(clients[0].auth_user), "testuser")
        self.assertEqual(clients[0].use_peer_dns, True)
        self.assertEqual(clients[0].add_default_route4, True)
        self.assertEqual(clients[0].add_default_route6, False)
        self.assertEqual(clients[0].mtu, 1492)
        self.assertEqual(clients[0].mru, 1492)

    def test_pppoe_set_options_api_updates_source_mac_policy(self):
        """Set source-MAC policy through the API and use it for discovery packets."""

        static_mac = "02:fe:ed:00:00:24"
        pppox_sw_if_index = self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            set_source_mac=True,
            source_mac_mode=2,
            source_mac=static_mac,
        )

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].source_mac_mode, 2)
        self.assertEqual(clients[0].effective_source_mac_mode, 2)
        self.assertEqual(str(clients[0].configured_source_mac).lower(), static_mac)
        self.assertEqual(str(clients[0].effective_source_mac).lower(), static_mac)
        self.assertEqual(clients[0].source_mac_fallbacks, 0)
        self.assertEqual(clients[0].last_source_mac_fallback_reason, 0)

        # Flush pg0's capture so stale PADIs emitted by earlier tests (with
        # pg0's hw MAC as src) can't race ahead of the first PADI emitted
        # under the newly configured MANUAL source-MAC policy.
        self.pg0.enable_capture()
        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        padi = self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)
        self.assertEqual(padi[Ether].src.lower(), static_mac)

    def test_pppoe_linux_source_mac_tracks_fallback_on_missing_netdev(self):
        """LINUX source-MAC mode must record each PADI fallback when no netdev resolves."""

        pppox_sw_if_index = self.add_client(set_source_mac=True, source_mac_mode=1)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].source_mac_mode, 1)
        self.assertEqual(clients[0].source_mac_fallbacks, 0)
        self.assertEqual(clients[0].last_source_mac_fallback_reason, 0)

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertGreaterEqual(clients[0].source_mac_fallbacks, 1)
        self.assertIn(clients[0].last_source_mac_fallback_reason, (1, 2, 3))

    def test_pppoe_interface_source_mac_mode_has_no_fallback(self):
        """INTERFACE source-MAC mode must never flag a fallback."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

        self.pg0.wait_for_packet(timeout=10, filter_out_fn=self.is_not_padi)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].source_mac_mode, 0)
        self.assertEqual(clients[0].source_mac_fallbacks, 0)
        self.assertEqual(clients[0].last_source_mac_fallback_reason, 0)

    def test_pppoe_set_options_api_can_unset_flags(self):
        """Verify that set_options can clear previously set flags."""

        self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            username="u",
            password="p",
            set_use_peer_dns=True,
            use_peer_dns=True,
            set_add_default_route4=True,
            add_default_route4=True,
            set_add_default_route6=True,
            add_default_route6=True,
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].use_peer_dns, True)
        self.assertEqual(clients[0].add_default_route4, True)
        self.assertEqual(clients[0].add_default_route6, True)

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            set_use_peer_dns=True,
            use_peer_dns=False,
            set_add_default_route4=True,
            add_default_route4=False,
            set_add_default_route6=True,
            add_default_route6=False,
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].use_peer_dns, False)
        self.assertEqual(clients[0].add_default_route4, False)
        self.assertEqual(clients[0].add_default_route6, False)

    def test_pppoe_set_options_api_preserves_untouched_flags(self):
        """set_options without set_* sentinels must not clobber existing flags."""

        self.add_client()
        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            set_use_peer_dns=True,
            use_peer_dns=True,
            set_add_default_route4=True,
            add_default_route4=True,
            set_add_default_route6=True,
            add_default_route6=True,
        )

        # Patch only one field; the other two must survive untouched even
        # though the wire value of add_default_route6 is implicitly False.
        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            set_add_default_route4=True,
            add_default_route4=False,
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].use_peer_dns, True)
        self.assertEqual(clients[0].add_default_route4, False)
        self.assertEqual(clients[0].add_default_route6, True)

    def test_pppoe_set_options_api_sets_ac_name_and_service_filters(self):
        """Set and clear ac_name_filter / service_name via set_options."""

        self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            configured_ac_name=self.AC_NAME.decode("ascii"),
            service_name=self.SERVICE_NAME.decode("ascii"),
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(
            self.normalize_api_string(clients[0].configured_ac_name),
            self.AC_NAME.decode("ascii"),
        )
        self.assertEqual(
            self.normalize_api_string(clients[0].service_name),
            self.SERVICE_NAME.decode("ascii"),
        )

        # Empty strings without clear_* must preserve the filters.
        self.vapi.pppoeclient_set_options(pppoeclient_index=0)
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(
            self.normalize_api_string(clients[0].configured_ac_name),
            self.AC_NAME.decode("ascii"),
        )
        self.assertEqual(
            self.normalize_api_string(clients[0].service_name),
            self.SERVICE_NAME.decode("ascii"),
        )

        # clear_* wins even if a value is also supplied.
        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            clear_ac_name=True,
            configured_ac_name="ignored",
            clear_service_name=True,
            service_name="ignored",
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(self.normalize_api_string(clients[0].configured_ac_name), "")
        self.assertEqual(self.normalize_api_string(clients[0].service_name), "")

    def test_pppoe_set_options_api_rejects_invalid_index(self):
        """Reject set_options for a non-existent client."""

        self.add_client()
        with self.assertRaises(UnexpectedApiReturnValueError):
            self.vapi.pppoeclient_set_options(
                pppoeclient_index=99,
                username="u",
                password="p",
            )

    def test_pppoe_session_action_restart(self):
        """Restart a client session via the session_action API."""

        pppox_sw_if_index = self.add_client()
        self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )

        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=1)
        self.assertEqual(response.retval, 0)

    def test_pppoe_session_action_restart_waits_before_rediscovery(self):
        """Restart should not emit a new PADI immediately after tearing down."""

        self.establish_session()

        self.pg0.enable_capture()
        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=1)
        self.assertEqual(response.retval, 0)

        self.pg0.assert_nothing_captured(timeout=1, filter_out_fn=self.is_not_padi)
        packet = self.pg0.wait_for_packet(timeout=35, filter_out_fn=self.is_not_padi)
        self.assertEqual(packet[PPPoED].code, 0x09)

    def test_pppoe_session_action_stop(self):
        """Stop a client session via the session_action API."""

        pppox_sw_if_index = self.add_client()
        self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )

        response = self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=2)
        self.assertEqual(response.retval, 0)

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].client_state, 0)

    def test_pppoe_session_action_rejects_invalid_index(self):
        """Reject session_action for a non-existent client."""

        self.add_client()
        with self.assertRaises(UnexpectedApiReturnValueError):
            self.vapi.pppoeclient_session_action(pppoeclient_index=99, action=1)

    def test_pppoe_session_action_rejects_invalid_action(self):
        """Reject session_action with an invalid action value."""

        self.add_client()
        with self.assertRaises(UnexpectedApiReturnValueError):
            self.vapi.pppoeclient_session_action(pppoeclient_index=0, action=0)

    def test_pppoe_restart_cli(self):
        """Restart a client via CLI."""

        pppox_sw_if_index = self.add_client()
        self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )

        output = self.vapi.cli("pppoe client restart 0")
        self.assertIn("restarted", output)

    def test_pppoe_stop_cli(self):
        """Stop a client via CLI."""

        pppox_sw_if_index = self.add_client()
        self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )

        output = self.vapi.cli("pppoe client stop 0")
        self.assertIn("stopped", output)

    def test_pppoe_padt_waits_before_rediscovery(self):
        """PADT-triggered rediscovery should respect a cool-down window."""

        _, session_id, ac_mac = self.establish_session()

        self.pg0.enable_capture()
        self.pg0.add_stream([self.make_padt(ac_mac, session_id)])
        self.pg_start()

        self.pg0.assert_nothing_captured(timeout=1, filter_out_fn=self.is_not_padi)
        packet = self.pg0.wait_for_packet(timeout=35, filter_out_fn=self.is_not_padi)
        self.assertEqual(packet[PPPoED].code, 0x09)

    def test_pppoe_double_delete(self):
        """Second delete of the same client returns NO_SUCH_ENTRY."""

        self.add_client()
        self.remove_client()

        with self.assertRaises(UnexpectedApiReturnValueError):
            self.vapi.pppoeclient_add_del(
                is_add=False,
                sw_if_index=self.pg0.sw_if_index,
                host_uniq=self.HOST_UNIQ,
            )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
