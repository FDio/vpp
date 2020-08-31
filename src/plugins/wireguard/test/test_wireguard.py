#!/usr/bin/env python3
""" Wg tests """

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from random import randint

from vpp_ipip_tun_interface import VppIpIpTunInterface
from framework import VppTestCase
from re import compile
import unittest

""" TestWg is a subclass of  VPPTestCase classes.

Wg test.

"""


class TestWg(VppTestCase):
    """ Wg Test Case """

    error_str = compile(r"Error")

    @classmethod
    def setUpClass(cls):
        super(TestWg, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            for i in cls.pg_interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestWg, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestWg, cls).tearDownClass()

    def test_wg_keys_generation(self):
        ret = self.vapi.wireguard_genkey()

        # Check if the same function gives same result
        pub1 = self.vapi.wireguard_pubkey(private_key=ret.private_key)
        pub2 = self.vapi.wireguard_pubkey(private_key=ret.private_key)
        self.assertEqual(pub1.public_key, pub2.public_key)

    def test_wg_set_remove_device(self):
        port = 12312
        key = self.vapi.wireguard_genkey()

        # Set device
        ret = self.vapi.wireguard_set_device(
            private_key=key.private_key,
            port=port)
        self.assertFalse(ret.retval, "wg set device error")
        # Remove device
        self.vapi.wireguard_remove_device()

    def test_wg_set_remove_peer(self):
        port = 12323

        # Set device
        device_key_pr = self.vapi.wireguard_genkey()
        self.vapi.wireguard_set_device(
            private_key=device_key_pr.private_key,
            port=port)

        # Check peer counter
        peers_count = len(self.vapi.wireguard_peers_dump())
        self.assertEqual(peers_count, 0)

        # Create first peer
        tun_if_1 = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4)
        tun_if_1.add_vpp_config()
        tun_if_1.admin_up()
        tun_if_1.config_ip4()

        peer_key_pr = self.vapi.wireguard_genkey()
        peer_key_pub = self.vapi.wireguard_pubkey(
            private_key=peer_key_pr.private_key)
        self.vapi.wireguard_set_peer(
            public_key=peer_key_pub.public_key,
            port=port+1,
            endpoint=self.pg1.remote_ip4,
            allowed_ip="10.10.3.2",
            tun_sw_if_index=tun_if_1.sw_if_index,
            persistent_keepalive=15)

        # Check peer counter
        peers_count = len(self.vapi.wireguard_peers_dump())
        self.assertEqual(peers_count, 1)

        # Create second peer
        tun_if_2 = VppIpIpTunInterface(
            self,
            self.pg0,
            self.pg0.remote_ip4,
            self.pg2.remote_ip4)
        tun_if_2.add_vpp_config()
        tun_if_2.admin_up()
        tun_if_2.config_ip4()

        peer_key_pr = self.vapi.wireguard_genkey()
        peer_key_pub = self.vapi.wireguard_pubkey(
            private_key=peer_key_pr.private_key)
        self.vapi.wireguard_set_peer(
            public_key=peer_key_pub.public_key,
            port=port + 2,
            endpoint=self.pg2.remote_ip4,
            allowed_ip="10.10.3.4",
            tun_sw_if_index=tun_if_2.sw_if_index,
            persistent_keepalive=15)

        # Check peer counter
        peers_count = len(self.vapi.wireguard_peers_dump())
        self.assertEqual(peers_count, 2)

        self.logger.info(self.vapi.cli("show wg"))

        # Check peer counter after second peer removing
        self.vapi.wireguard_remove_peer(public_key=peer_key_pub.public_key)
        peers_count = len(self.vapi.wireguard_peers_dump())
        self.assertEqual(peers_count, 1)

        # Check peer counter after device removing
        self.vapi.wireguard_remove_device()
        peers_count = len(self.vapi.wireguard_peers_dump())
        self.assertEqual(peers_count, 0)

        tun_if_2.remove_vpp_config()
        tun_if_1.remove_vpp_config()
