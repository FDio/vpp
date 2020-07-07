#!/usr/bin/env python3
""" Wg tests """

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from random import randint

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
        ret = self.vapi.wg_genkey()

        #Check if the same function gives same result
        pub1 = self.vapi.wg_pubkey(private_key = ret.private_key)
        pub2 = self.vapi.wg_pubkey(private_key = ret.private_key)
        self.assertEqual(pub1.public_key, pub2.public_key)


    def test_wg_set_remove_device(self):
        port = 12312
        key = self.vapi.wg_genkey()

        #Set device
        ret = self.vapi.wg_set_device(private_key = key.private_key, port = port)
        self.assertFalse(ret.retval, "wg set device error")
        #Remove device
        self.vapi.wg_remove_device()

    def test_wg_set_remove_peer(self):
        port = 12323

        #Set device
        device_key_pr = self.vapi.wg_genkey()
        self.vapi.wg_set_device(private_key = device_key_pr.private_key, port = port)

        #Check peer counter
        peers_count = self.vapi.wg_peers_count()
        self.assertEqual(peers_count.count, 0)

        #Create first peer
        self.vapi.cli("create ipip tunnel src " + self.pg0.remote_ip4 + " dst " + self.pg1.remote_ip4)
        self.vapi.cli("set int state ipip0 up")
        self.vapi.cli("set int ip address ipip0 10.10.3.1/32")
        peer_key_pr = self.vapi.wg_genkey()
        peer_key_pub = self.vapi.wg_pubkey(private_key = peer_key_pr.private_key)
        self.vapi.wg_set_peer (
            public_key = peer_key_pub.public_key,
            port = port + 1,
            endpoint = self.pg1.remote_ip4,
            allowed_ip = "10.10.3.2",
            tun_sw_if_index = 2,
            persistent_keepalive = 15)

        #Check peer counter
        peers_count = self.vapi.wg_peers_count()
        self.assertEqual(peers_count.count, 1)

        #Create second peer
        self.vapi.cli("create ipip tunnel src " + self.pg0.remote_ip4 + " dst " + self.pg2.remote_ip4)
        self.vapi.cli("set int state ipip1 up")
        self.vapi.cli("set int ip address ipip0 10.10.3.3/32")
        peer_key_pr = self.vapi.wg_genkey()
        peer_key_pub = self.vapi.wg_pubkey(private_key = peer_key_pr.private_key)
        self.vapi.wg_set_peer (
            public_key = peer_key_pub.public_key,
            port = port + 2,
            endpoint = self.pg2.remote_ip4,
            allowed_ip = "10.10.3.4",
            tun_sw_if_index = 3,
            persistent_keepalive = 15)

        #Check peer counter
        peers_count = self.vapi.wg_peers_count()
        self.assertEqual(peers_count.count, 2)

        #Check peer counter after second peer removing
        self.vapi.wg_remove_peer(public_key = peer_key_pub.public_key)
        peers_count = self.vapi.wg_peers_count()
        self.assertEqual(peers_count.count, 1)

        #Check peer counter after device removing
        self.vapi.wg_remove_device()
        peers_count = self.vapi.wg_peers_count()
        self.assertEqual(peers_count.count, 0)
