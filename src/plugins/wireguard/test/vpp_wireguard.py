import datetime
from hashlib import blake2s
import struct

from cryptography.hazmat.primitives.serialization import Encoding, \
    PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from noise.connection import NoiseConnection, Keypair
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation, WireguardTransport
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP

from vpp_interface import VppInterface
from vpp_object import VppObject


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
        self.receiver_index = self.index + 1
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

    def mk_tunnel_header(self, tx_itf):
        return (Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac) /
                IP(src=self.endpoint, dst=self.itf.src) /
                UDP(sport=self.port, dport=self.itf.port))

    def noise_init(self, public_key=None):
        self.noise.set_prologue(NOISE_IDENTIFIER_NAME)
        self.noise.set_psks(psk=bytes(bytearray(32)))

        if not public_key:
            public_key = self.itf.public_key

        # local/this private
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC,
            private_key_bytes(self.private_key))
        # remote's public
        self.noise.set_keypair_from_public_bytes(
            Keypair.REMOTE_STATIC,
            public_key_bytes(public_key))

        self.noise.start_handshake()

    def mk_handshake(self, tx_itf, public_key=None):
        self.noise.set_as_initiator()
        self.noise_init(public_key)

        p = (Wireguard() / WireguardInitiation())

        p[Wireguard].message_type = 1
        p[Wireguard].reserved_zero = 0
        p[WireguardInitiation].sender_index = self.receiver_index

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
        p[WireguardInitiation].mac1 = blake2s(bytes(p)[0:116],
                                              digest_size=16,
                                              key=mac_key).digest()
        p[WireguardInitiation].mac2 = bytearray(16)

        p = (self.mk_tunnel_header(tx_itf) / p)

        return p

    def verify_header(self, p):
        self._test.assertEqual(p[IP].src, self.itf.src)
        self._test.assertEqual(p[IP].dst, self.endpoint)
        self._test.assertEqual(p[UDP].sport, self.itf.port)
        self._test.assertEqual(p[UDP].dport, self.port)
        self._test.assert_packet_checksums_valid(p)

    def consume_init(self, p, tx_itf):
        self.noise.set_as_responder()
        self.noise_init(self.itf.public_key)
        self.verify_header(p)

        init = Wireguard(p[Raw])

        self._test.assertEqual(init[Wireguard].message_type, 1)
        self._test.assertEqual(init[Wireguard].reserved_zero, 0)

        self.sender = init[WireguardInitiation].sender_index

        # validate the hash
        mac_key = blake2s(b'mac1----' +
                          public_key_bytes(self.public_key)).digest()
        mac1 = blake2s(bytes(init)[0:-32],
                       digest_size=16,
                       key=mac_key).digest()
        self._test.assertEqual(init[WireguardInitiation].mac1, mac1)

        # this passes only unencrypted_ephemeral, encrypted_static,
        # encrypted_timestamp fields of the init
        payload = self.noise.read_message(bytes(init)[8:-32])

        # build the response
        b = self.noise.write_message()
        mac_key = blake2s(b'mac1----' +
                          public_key_bytes(self.itf.public_key)).digest()
        resp = (Wireguard(message_type=2, reserved_zero=0) /
                WireguardResponse(sender_index=self.receiver_index,
                                  receiver_index=self.sender,
                                  unencrypted_ephemeral=b[0:32],
                                  encrypted_nothing=b[32:]))
        mac1 = blake2s(bytes(resp)[:-32],
                       digest_size=16,
                       key=mac_key).digest()
        resp[WireguardResponse].mac1 = mac1

        resp = (self.mk_tunnel_header(tx_itf) / resp)
        self._test.assertTrue(self.noise.handshake_finished)

        return resp

    def consume_response(self, p):
        self.verify_header(p)

        resp = Wireguard(p[Raw])

        self._test.assertEqual(resp[Wireguard].message_type, 2)
        self._test.assertEqual(resp[Wireguard].reserved_zero, 0)
        self._test.assertEqual(resp[WireguardResponse].receiver_index,
                               self.receiver_index)

        self.sender = resp[Wireguard].sender_index

        payload = self.noise.read_message(bytes(resp)[12:60])
        self._test.assertEqual(payload, b'')
        self._test.assertTrue(self.noise.handshake_finished)

    def decrypt_transport(self, p):
        self.verify_header(p)

        p = Wireguard(p[Raw])
        self._test.assertEqual(p[Wireguard].message_type, 4)
        self._test.assertEqual(p[Wireguard].reserved_zero, 0)
        self._test.assertEqual(p[WireguardTransport].receiver_index,
                               self.receiver_index)

        d = self.noise.decrypt(
            p[WireguardTransport].encrypted_encapsulated_packet)
        return d

    def encrypt_transport(self, p):
        return self.noise.encrypt(bytes(p))

    def validate_encapped(self, rxs, tx):
        for rx in rxs:
            rx = IP(self.decrypt_transport(rx))

            # check the original packet is present
            self._test.assertEqual(rx[IP].dst, tx[IP].dst)
            self._test.assertEqual(rx[IP].ttl, tx[IP].ttl-1)

