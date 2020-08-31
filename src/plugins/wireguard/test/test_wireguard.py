#!/usr/bin/env python3
""" Wg tests """

from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, \
    PrivateFormat, PublicFormat, NoEncryption

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

    def __init__(self, test, src, port, key=None):
        super(VppWgInterface, self).__init__(test)

        self.key = key
        if not self.key:
            self.generate = True
        else:
            self.generate = False
        self.port = port
        self.src = src

    def add_vpp_config(self):
        r = self.test.vapi.wireguard_interface_create(interface={
            'user_instance': 0xffffffff,
            'port': self.port,
            'src_ip': self.src,
            'private_key': self.key_bytes()
        })
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def key_bytes(self):
        if self.key:
            return self.key.private_bytes(Encoding.Raw,
                                          PrivateFormat.Raw,
                                          NoEncryption())
        else:
            return bytearray(32)

    def remove_vpp_config(self):
        self.test.vapi.wireguard_interface_delete(
            sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.wireguard_interface_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.interface.sw_if_index == self._sw_if_index and \
               str(t.interface.src_ip) == self.src and \
               t.interface.port == self.port and \
               t.interface.private_key == self.key_bytes():
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
                 persistent_keepalive=15):
        self._test = test
        self.itf = itf
        self.endpoint = endpoint
        self.port = port
        self.allowed_ips = allowed_ips
        self.persistent_keepalive = persistent_keepalive
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
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
        return ("wireguard-peer-%s" % self.index)

    def public_key_bytes(self):
        return self.public_key.public_bytes(Encoding.Raw,
                                            PublicFormat.Raw)

    def private_key_bytes(self):
        return self.private_key.private_bytes(Encoding.Raw,
                                              PrivateFormat.Raw,
                                              NoEncryption())

    def query_vpp_config(self):
        peers = self._test.vapi.wireguard_peers_dump()

        for p in peers:
            if p.peer.public_key == self.public_key_bytes() and \
               p.peer.port == self.port and \
               str(p.peer.endpoint) == self.endpoint and \
               p.peer.sw_if_index == self.itf.sw_if_index and \
               len(self.allowed_ips) == p.peer.n_allowed_ips:
                self.allowed_ips.sort()
                p.peer.allowed_ips.sort()

                for (a1, a2) in zip(self.allowed_ips, p.peer.allowed_ips):
                    if str(a1) != str(a2):
                        return False
                return True
        return False


class TestWg(VppTestCase):
    """ Wireguard Test Case """

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

    def test_wg_interface(self):
        port = 12312

        # Create interface
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int"))

        # delete interface
        wg0.remove_vpp_config()

    def test_wg_peer(self):
        wg_output_node_name = '/err/wg-output-tun/'
        wg_input_node_name = '/err/wg-input/'

        port = 12323

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port,
                             key=X25519PrivateKey.generate()).add_vpp_config()
        wg1 = VppWgInterface(self,
                             self.pg2.local_ip4,
                             port+1).add_vpp_config()
        wg0.admin_up()
        wg1.admin_up()

        # Check peer counter
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 0)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["10.11.2.0/24",
                            "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # wait for the peer to send a handshake
        capture = self.pg1.get_capture(1, timeout=2)
        handshake = capture[0]

        self.assertEqual(handshake[IP].src, wg0.src)
        self.assertEqual(handshake[IP].dst, peer_1.endpoint)
        self.assertEqual(handshake[UDP].sport, wg0.port)
        self.assertEqual(handshake[UDP].dport, peer_1.port)
        handshake = Wireguard(handshake[Raw])
        self.assertEqual(handshake.message_type, 1)  # "initiate")
        init = handshake[WireguardInitiation]

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        # rx = self.send_and_expect(self.pg0, [p], self.pg1)
        rx = self.send_and_assert_no_replies(self.pg0, [p])

        self.logger.info(self.vapi.cli("sh error"))
        init_sent = wg_output_node_name + "Keypair error"
        self.assertEqual(1, self.statistics.get_err_counter(init_sent))

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

        self.logger.info(self.vapi.cli("show wireguard peer"))
        self.logger.info(self.vapi.cli("show wireguard interface"))
        self.logger.info(self.vapi.cli("show adj 37"))
        self.logger.info(self.vapi.cli("sh ip fib 172.16.3.17"))
        self.logger.info(self.vapi.cli("sh ip fib 10.11.3.0"))

        # remove peers
        for p in peers:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)
        peer_1.remove_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 0)

        wg0.remove_vpp_config()
        # wg1.remove_vpp_config()
