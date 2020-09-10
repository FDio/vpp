#!/usr/bin/env python3
""" Wg tests """

import datetime
import base64

from hashlib import blake2s
from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, \
    PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import BLAKE2s, Hash
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from noise.connection import NoiseConnection, Keypair

from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_interface import VppInterface
from vpp_object import VppObject
from framework import VppTestCase
from re import compile
import unittest

""" TestWg is a subclass of  VPPTestCase classes.

Wg test.

"""


def private_key_bytes(k):
    return k.private_bytes(Encoding.Raw,
                           PrivateFormat.Raw,
                           NoEncryption())


def public_key_bytes(k):
    return k.public_bytes(Encoding.Raw,
                          PublicFormat.Raw)


class VppWgInterface(VppInterface):
    """
    VPP WireGuard interface
    """

    def __init__(self, test, src, port):
        super(VppWgInterface, self).__init__(test)

        self.port = port
        self.src = src
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_key_bytes(self):
        return public_key_bytes(self.public_key)

    def private_key_bytes(self):
        return private_key_bytes(self.private_key)

    def add_vpp_config(self):
        r = self.test.vapi.wireguard_interface_create(interface={
            'user_instance': 0xffffffff,
            'port': self.port,
            'src_ip': self.src,
            'private_key': private_key_bytes(self.private_key),
            'generate_key': False
        })
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.wireguard_interface_delete(
            sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.wireguard_interface_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.interface.sw_if_index == self._sw_if_index and \
               str(t.interface.src_ip) == self.src and \
               t.interface.port == self.port and \
               t.interface.private_key == private_key_bytes(self.private_key):
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


NOISE_HANDSHAKE_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
NOISE_IDENTIFIER_NAME = b"WireGuard v1 zx2c4 Jason@zx2c4.com"


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

        # remote peer's public
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.noise = NoiseConnection.from_name(NOISE_HANDSHAKE_NAME)

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
        return public_key_bytes(self.public_key)

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

    def set_responder(self):
        self.noise.set_as_responder()

    def mk_handshake(self, tx_itf, private_key=None):
        self.noise.set_as_initiator()
        self.noise.set_prologue(NOISE_IDENTIFIER_NAME)
        self.noise.set_psks(psk=bytes(bytearray(32)))

        if not private_key:
            private_key = self.private_key

        # local/this private
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            private_key_bytes(private_key))
        # remote's public
        self.noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            self.itf.public_key_bytes())

        self.noise.start_handshake()

        p = (Wireguard() / WireguardInitiation())

        p[Wireguard].message_type = 1
        p[Wireguard].reserved_zero = 0
        p[WireguardInitiation].sender_index = self.index + 1

        # some random data for the message
        #  lifted from the noise protocol's wireguard example
        now = datetime.datetime.now()
        tai = struct.pack('!qi', 4611686018427387914 + int(now.timestamp()),
                          int(now.microsecond * 1e3))
        b = self.noise.write_message(payload=tai)

        # load noise into init message
        p[WireguardInitiation].unencrypted_ephemeral = b[0:32]
        p[WireguardInitiation].encrypted_static = b[32:80]
        p[WireguardInitiation].encrypted_timestamp = b[80:108]

        # generate the mac1 hash
        mac_key = blake2s(b'mac1----' +
                          self.itf.public_key_bytes()).digest()
        print("mac_key1:", mac_key.hex())
        print("pkt1:", bytes(p)[0:116].hex())
        p[WireguardInitiation].mac1 = blake2s(bytes(p)[0:116],
                                              digest_size=16,
                                              key=mac_key).digest()
        p[WireguardInitiation].mac2 = bytearray(16)

        p = (Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac) /
             IP(src=self.endpoint, dst=self.itf.src) /
             UDP(sport=self.port, dport=self.itf.port) /
             p)

        return p

    def consume_response(self, p):
        self._test.assertEqual(p[IP].src, self.itf.src)
        self._test.assertEqual(p[IP].dst, self.endpoint)
        self._test.assertEqual(p[UDP].sport, self.itf.port)
        self._test.assertEqual(p[UDP].dport, self.port)

        resp = Wireguard(p[Raw])
        resp.show()

        self._test.assertEqual(resp[Wireguard].message_type, 2)
        self._test.assertEqual(resp[Wireguard].reserved_zero, 0)
        self._test.assertEqual(resp[WireguardResponse].receiver_index,
                               self.index + 1)

        self.sender = resp[Wireguard].sender_index

        payload = self.noise.read_message(bytes(resp)[12:60])
        self._test.assertEqual(payload, b'')
        self._test.assertTrue(self.noise.handshake_finished)


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

    def test_handshake_hash(self):
        """ test hashing an init message """
        # a init packet generated by linux given the key below
        h = "0100000098b9032b" \
            "55cc4b39e73c3d24" \
            "a2a1ab884b524a81" \
            "1808bb86640fb70d" \
            "e93154fec1879125" \
            "ab012624a27f0b75" \
            "c0a2582f438ddb5f" \
            "8e768af40b4ab444" \
            "02f9ff473e1b797e" \
            "80d39d93c5480c82" \
            "a3d4510f70396976" \
            "586fb67300a5167b" \
            "ae6ca3ff3dfd00eb" \
            "59be198810f5aa03" \
            "6abc243d2155ee4f" \
            "2336483900aef801" \
            "08752cd700000000" \
            "0000000000000000" \
            "00000000"

        b = bytearray.fromhex(h)
        tgt = Wireguard(b)

        pubb = base64.b64decode("aRuHFTTxICIQNefp05oKWlJv3zgKxb8+WW7JJMh0jyM=")
        pub = X25519PublicKey.from_public_bytes(pubb)

        self.assertEqual(pubb, public_key_bytes(pub))

        # strip the macs and build a new packet
        init = b[0:-32]
        mac_key = blake2s(b'mac1----' + public_key_bytes(pub)).digest()
        init += blake2s(init,
                        digest_size=16,
                        key=mac_key).digest()
        init += b'\x00' * 16

        act = Wireguard(init)

        self.assertEqual(tgt, act)

    def test_wg_peer_init(self):
        wg_output_node_name = '/err/wg-output-tun/'
        wg_input_node_name = '/err/wg-input/'

        port = 12323

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()

        # Check peer counter
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

        self.logger.error(self.vapi.cli("sh wireguard peer"))

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        # this is dropped because the peer is not initiated
        # p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
        #      IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
        #      UDP(sport=555, dport=556) /
        #      Raw())
        # rx = self.send_and_assert_no_replies(self.pg0, [p])

        # self.logger.info(self.vapi.cli("sh error"))
        # init_sent = wg_output_node_name + "Keypair error"
        # self.assertEqual(1, self.statistics.get_err_counter(init_sent))

        # send a handsake from the peer with an invalid MAC
        # p = peer_1.mk_handshake(self.pg1)
        # p[WireguardInitiation].mac1 = b'foobar'
        # self.send_and_assert_no_replies(self.pg1, [p])
        # self.assertEqual(1, self.statistics.get_err_counter(
        #     wg_input_node_name + "Invalid MAC handshake"))

        # send a handsake from the peer but signed by the wrong key.
        # p = peer_1.mk_handshake(self.pg1, X25519PrivateKey.generate())
        # self.send_and_assert_no_replies(self.pg1, [p])
        # self.assertEqual(1, self.statistics.get_err_counter(
        #     wg_input_node_name + "Peer error"))

        # send a handsake for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        try:
            rx = self.send_and_expect(self.pg1, [p], self.pg1)
        finally:
            self.logger.error(self.vapi.cli("sh trace"))

        # rx[0].show()
        peer_1.consume_response(rx[0])

        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_multi_peer(self):
        port = 12323

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg1 = VppWgInterface(self,
                             self.pg2.local_ip4,
                             port+1).add_vpp_config()
        wg0.admin_up()
        wg1.admin_up()

        # Check peer counter
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 0)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Create many peers on sencond interface
        NUM_PEERS = 16
        self.pg2.generate_remote_hosts(NUM_PEERS)
        self.pg2.configure_ipv4_neighbors()
        self.pg1.generate_remote_hosts(NUM_PEERS)
        self.pg1.configure_ipv4_neighbors()

        peers_1 = []
        peers_2 = []
        for i in range(NUM_PEERS):
            peers_1.append(VppWgPeer(self,
                                     wg0,
                                     self.pg1.remote_hosts[i].ip4,
                                     port+1+i,
                                     ["10.0.%d.4/32" % i]).add_vpp_config())
            peers_2.append(VppWgPeer(self,
                                     wg1,
                                     self.pg2.remote_hosts[i].ip4,
                                     port+100+i,
                                     ["10.100.%d.4/32" % i]).add_vpp_config())

        self.assertEqual(len(self.vapi.wireguard_peers_dump()), NUM_PEERS*2)

        self.logger.info(self.vapi.cli("show wireguard peer"))
        self.logger.info(self.vapi.cli("show wireguard interface"))
        self.logger.info(self.vapi.cli("show adj 37"))
        self.logger.info(self.vapi.cli("sh ip fib 172.16.3.17"))
        self.logger.info(self.vapi.cli("sh ip fib 10.11.3.0"))

        # remove peers
        for p in peers_1:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()
        for p in peers_2:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()

        wg0.remove_vpp_config()
        wg1.remove_vpp_config()
