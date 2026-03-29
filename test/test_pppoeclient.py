#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Hi-Jiajun.

import unittest
import struct

from config import config
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPPoED_Tags
from scapy.packet import Raw

from asfframework import VppTestRunner, tag_run_solo
from framework import VppTestCase
from vpp_papi_exceptions import UnexpectedApiReturnValueError
from vpp_papi_provider import CliFailedCommandError


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

    def make_pado(self, src_mac, ac_name, cookie=None):
        tags = b"".join(
            [
                self.pppoe_tag(0x0101, b""),
                self.pppoe_tag(0x0103, self.HOST_UNIQ.to_bytes(4, "little")),
                self.pppoe_tag(0x0102, ac_name),
                self.pppoe_tag(0x0104, cookie) if cookie is not None else b"",
            ]
        )
        return (
            Ether(dst=self.pg0.local_mac, src=src_mac)
            / PPPoED(code=0x07, sessionid=0)
            / Raw(tags)
        )

    def delete_all_clients(self):
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        for client in clients:
            self.vapi.pppoeclient_add_del(
                is_add=False,
                sw_if_index=client.sw_if_index,
                host_uniq=client.host_uniq,
            )

    def add_client(self, service_name=None, configured_ac_name=None):
        kwargs = {
            "is_add": True,
            "sw_if_index": self.pg0.sw_if_index,
            "host_uniq": self.HOST_UNIQ,
        }
        if service_name is not None:
            if isinstance(service_name, bytes):
                service_name = service_name.decode("ascii")
            kwargs["service_name"] = service_name
        if configured_ac_name is not None:
            if isinstance(configured_ac_name, bytes):
                configured_ac_name = configured_ac_name.decode("ascii")
            kwargs["configured_ac_name"] = configured_ac_name

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
        self.assertEqual(clients[0].use_peer_dns4, 0)
        self.assertEqual(clients[0].add_default_route4, 0)
        self.assertEqual(clients[0].add_default_route6, 0)
        self.assertEqual(clients[0].dhcp6_ia_na_enabled, 0)
        self.assertEqual(clients[0].dhcp6_pd_enabled, 0)
        self.assertEqual(clients[0].peer_dns6_count, 0)

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
        self.assertEqual(clients[0].use_peer_dns4, 0)
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

    def test_pppoe_set_options_api(self):
        """Set and verify client options via the set_options API."""

        self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            username="testuser",
            password="testpass",
            use_peer_dns=True,
            add_default_route4=True,
            add_default_route6=False,
            mtu=1492,
            mru=1492,
        )

        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(len(clients), 1)
        self.assertEqual(self.normalize_api_string(clients[0].auth_user), "testuser")
        self.assertEqual(clients[0].use_peer_dns4, True)
        self.assertEqual(clients[0].add_default_route4, True)
        self.assertEqual(clients[0].add_default_route6, False)
        self.assertEqual(clients[0].mtu, 1492)
        self.assertEqual(clients[0].mru, 1492)

    def test_pppoe_set_options_api_can_unset_flags(self):
        """Verify that set_options can clear previously set flags."""

        self.add_client()

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            username="u",
            password="p",
            use_peer_dns=True,
            add_default_route4=True,
            add_default_route6=True,
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].use_peer_dns4, True)
        self.assertEqual(clients[0].add_default_route4, True)
        self.assertEqual(clients[0].add_default_route6, True)

        self.vapi.pppoeclient_set_options(
            pppoeclient_index=0,
            use_peer_dns=False,
            add_default_route4=False,
            add_default_route6=False,
        )
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        self.assertEqual(clients[0].use_peer_dns4, False)
        self.assertEqual(clients[0].add_default_route4, False)
        self.assertEqual(clients[0].add_default_route6, False)

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
