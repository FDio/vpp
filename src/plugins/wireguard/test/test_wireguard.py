#!/usr/bin/env python3
""" Wg tests """

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from random import randint

from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_interface import VppInterface
from vpp_object import VppObject
from framework import VppTestCase
from re import compile
import unittest

""" TestWg is a subclass of  VPPTestCase classes.

Wg test.

"""


class VppWgInterface(VppInterface):
    """
    VPP WireGuard interface
    """

    def __init__(self, test, key, src, port):
        super(VppWgInterface, self).__init__(test)

        self.key = key
        self.port = port
        self.src = src

    def add_vpp_config(self):
        r = self.test.vapi.wireguard_itf_create(itf={
            'user_instance': 0xffffffff,
            'port': self.port,
            'src_ip': self.src,
            'private_key': self.key
        })
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.wireguard_itf_delete(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.wireguard_itf_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.tunnel.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "wireguard-%d" % self._sw_if_index


def find_route(test, prefix, table_id=0):
    routes = test.vapi.ip_route_dump(table_id, False)

    for e in routes:
        if table_id == e.route.table_id \
           and str(e.route.prefix) == str(prefix):
            return True
    return False


class VppWgPeer(VppObject):

    def __init__(self,
                 test,
                 itf,
                 endpoint,
                 port,
                 allowed_ips,
                 private_key=None,
                 persistent_keepalive=15):
        self._test = test
        self.itf = itf
        self.endpoint = endpoint
        self.port = port
        self.allowed_ips = allowed_ips
        self.persistent_keepalive = persistent_keepalive
        if not private_key:
            self.private_key = self._test.vapi.wireguard_genkey()
        self.public_key = self._test.vapi.wireguard_pubkey(
            private_key=self.private_key.private_key)
        self.hash = bytearray(16)

    def validate_routing(self):
        for a in self.allowed_ips:
            self._test.assertTrue(find_route(self._test, a))

    def validate_no_routing(self):
        for a in self.allowed_ips:
            self._test.assertFalse(find_route(self._test, a))

    def add_vpp_config(self):
        rv = self._test.vapi.wireguard_peer_add(
            peer={
                'public_key': self.public_key_bytes(),
                'port': self.port,
                'endpoint': self.endpoint,
                'n_allowed_ips': len(self.allowed_ips),
                'allowed_ips': self.allowed_ips,
                'sw_if_index': self.itf.sw_if_index,
                'persistent_keepalive': self.persistent_keepalive})
        self.index = rv.peer_index
        self._test.registry.register(self, self._test.logger)
        self.validate_routing()
        return self

    def remove_vpp_config(self):
        self._test.vapi.wireguard_peer_remove(peer_index=self.index)
        self.validate_no_routing()

    def object_id(self):
        return ("wg-peer-%s" % self.index)

    def dump(self):
        return self._test.vapi.wireguard_peers_dump()

    def public_key_bytes(self):
        return self.public_key.public_key

    def private_key_bytes(self):
        return self.private_key.private_key

    def query_vpp_config(self):
        peers = self.dump()

        for peer in peers:
            if peer.peer.public_key == self.public_key_bytes():
                return True
        return False


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

    def test_wg_interface(self):
        port = 12312
        key = self.vapi.wireguard_genkey()

        # Create interface
        wg0 = VppWgInterface(self,
                             key.private_key,
                             self.pg1.local_ip4,
                             port).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int"))

        # delete interface
        wg0.remove_vpp_config()

    def test_wg_peer(self):
        port = 12323
        itf_0_key = self.vapi.wireguard_genkey()
        itf_1_key = self.vapi.wireguard_genkey()

        # Create interfaces
        wg0 = VppWgInterface(self,
                             itf_0_key.private_key,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg1 = VppWgInterface(self,
                             itf_1_key.private_key,
                             self.pg2.local_ip4,
                             port+1).add_vpp_config()
        wg0.admin_up()
        wg1.admin_up()

        # Check peer counter
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 0)

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["10.11.2.0/24",
                            "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # Create many peers on sencond interface
        NUM_PEERS = 16
        self.pg2.generate_remote_hosts(NUM_PEERS)
        self.pg2.configure_ipv4_neighbors()

        peers = []
        for i in range(NUM_PEERS):
            peers.append(VppWgPeer(self,
                                   wg1,
                                   self.pg2.remote_hosts[i].ip4,
                                   port+1+i,
                                   ["10.10.%d.4/32" % i]).add_vpp_config())
            self.assertEqual(len(self.vapi.wireguard_peers_dump()), i+2)

        self.logger.error(self.vapi.cli("show wg peer"))
        self.logger.info(self.vapi.cli("show wg itf"))
        self.logger.error(self.vapi.cli("show adj 37"))
        self.logger.error(self.vapi.cli("sh ip fib 172.16.3.17"))
        self.logger.error(self.vapi.cli("sh ip fib 10.11.3.0"))

        # remove peers
        for p in peers:
            p.remove_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)
        peer_1.remove_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 0)

        wg0.remove_vpp_config()
        wg1.remove_vpp_config()
