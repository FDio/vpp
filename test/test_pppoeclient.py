#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Hi-Jiajun.

import unittest

from config import config
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPPoED, PPPoED_Tags

from asfframework import VppTestRunner, tag_run_solo
from framework import VppTestCase
from vpp_papi_exceptions import UnexpectedApiReturnValueError


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
    def is_not_padi(pkt):
        pppoed = pkt.getlayer(PPPoED)
        return pppoed is None or pppoed.code != 0x09

    def delete_all_clients(self):
        clients = self.vapi.pppoeclient_dump(sw_if_index=self.ALL_INTERFACES)
        for client in clients:
            self.vapi.pppoeclient_add_del(
                is_add=False,
                sw_if_index=client.sw_if_index,
                host_uniq=client.host_uniq,
            )

    def add_client(self):
        response = self.vapi.pppoeclient_add_del(
            is_add=True,
            sw_if_index=self.pg0.sw_if_index,
            host_uniq=self.HOST_UNIQ,
        )

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

        self.pg0.enable_capture()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME,
            password=self.AUTH_PASSWORD,
        )
        self.assertEqual(response.retval, 0)

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
        for tag in tags.tag_list:
            if tag.tag_type == 0x0103:
                found_host_uniq = True
                self.assertEqual(
                    int.from_bytes(tag.tag_value, "little"), self.HOST_UNIQ
                )

        self.assertTrue(found_host_uniq)

    def test_pppox_set_auth_accepts_full_length_credentials(self):
        """Allow 64-byte username/password values via the API."""

        pppox_sw_if_index = self.add_client()

        response = self.vapi.pppox_set_auth(
            sw_if_index=pppox_sw_if_index,
            username=self.AUTH_USERNAME_MAX,
            password=self.AUTH_PASSWORD_MAX,
        )
        self.assertEqual(response.retval, 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
