import datetime
import struct

from hashlib import blake2s
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation, WireguardTransport
from cryptography.hazmat.primitives.serialization import Encoding, \
    PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from noise.connection import NoiseConnection, Keypair

from vpp_pom.vpp_interface import VppInterface
from vpp_pom.vpp_object import VppObject


def private_key_bytes(k):
    return k.private_bytes(Encoding.Raw,
                           PrivateFormat.Raw,
                           NoEncryption())


def public_key_bytes(k):
    return k.public_bytes(Encoding.Raw,
                          PublicFormat.Raw)


def find_route(vclient, prefix, table_id=0):
    routes = vclient.ip_route_dump(table_id, False)

    for e in routes:
        if table_id == e.route.table_id \
           and str(e.route.prefix) == str(prefix):
            return True
    return False


NOISE_HANDSHAKE_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
NOISE_IDENTIFIER_NAME = b"WireGuard v1 zx2c4 Jason@zx2c4.com"


class VppWgInterface(VppInterface):
    """
    VPP WireGuard interface
    """

    def __init__(self, vclient, src, port):
        super(VppWgInterface, self).__init__(vclient)

        self.port = port
        self.src = src
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_key_bytes(self):
        return public_key_bytes(self.public_key)

    def private_key_bytes(self):
        return private_key_bytes(self.private_key)

    def add_vpp_config(self):
        r = self._vclient.wireguard_interface_create(interface={
            'user_instance': 0xffffffff,
            'port': self.port,
            'src_ip': self.src,
            'private_key': private_key_bytes(self.private_key),
            'generate_key': False
        })
        self.set_sw_if_index(r.sw_if_index)
        self._vclient.registry.register(self, self._vclient.logger)
        return self

    def remove_vpp_config(self):
        self._vclient.wireguard_interface_delete(
            sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self._vclient.wireguard_interface_dump(sw_if_index=0xffffffff)
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


class VppWgPeer(VppObject):

    def __init__(self,
                 vclient,
                 itf,
                 endpoint,
                 port,
                 allowed_ips,
                 persistent_keepalive=15):
        self._vclient = vclient
        self.itf = itf
        self.endpoint = endpoint
        self.port = port
        self.allowed_ips = allowed_ips
        self.persistent_keepalive = persistent_keepalive

        # remote peer's public
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.noise = NoiseConnection.from_name(NOISE_HANDSHAKE_NAME)

    def add_vpp_config(self):
        rv = self._vclient.wireguard_peer_add(
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
        self._vclient.registry.register(self, self._vclient.logger)
        return self

    def remove_vpp_config(self):
        self._vclient.wireguard_peer_remove(peer_index=self.index)

    def object_id(self):
        return ("wireguard-peer-%s" % self.index)

    def public_key_bytes(self):
        return public_key_bytes(self.public_key)

    def query_vpp_config(self):
        peers = self._vclient.wireguard_peers_dump()

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

    def encrypt_transport(self, p):
        return self.noise.encrypt(bytes(p))
