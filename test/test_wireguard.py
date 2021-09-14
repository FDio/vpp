#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Wg tests """

import datetime
import base64
import os

from hashlib import blake2s
from scapy.packet import Packet
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation, WireguardTransport
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
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_object import VppObject
from vpp_papi import VppEnum
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

    def want_events(self, peer_index=0xffffffff):
        self.test.vapi.want_wireguard_peer_events(
            enable_disable=1,
            pid=os.getpid(),
            sw_if_index=self._sw_if_index,
            peer_index=peer_index)

    def wait_events(self, expect, peers, timeout=5):
        for i in range(len(peers)):
            rv = self.test.vapi.wait_for_event(timeout, "wireguard_peer_event")
            self.test.assertEqual(rv.peer_index, peers[i])
            self.test.assertEqual(rv.flags, expect)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "wireguard-%d" % self._sw_if_index


def find_route(test, prefix, is_ip6, table_id=0):
    routes = test.vapi.ip_route_dump(table_id, is_ip6)

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

    def add_vpp_config(self, is_ip6=False):
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
        return self

    def remove_vpp_config(self):
        self._test.vapi.wireguard_peer_remove(peer_index=self.index)

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

    def mk_tunnel_header(self, tx_itf, is_ip6=False):
        if is_ip6 is False:
            return (Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac) /
                    IP(src=self.endpoint, dst=self.itf.src) /
                    UDP(sport=self.port, dport=self.itf.port))
        else:
            return (Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac) /
                    IPv6(src=self.endpoint, dst=self.itf.src) /
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

    def mk_handshake(self, tx_itf, is_ip6=False, public_key=None):
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

        p = (self.mk_tunnel_header(tx_itf, is_ip6) / p)

        return p

    def verify_header(self, p, is_ip6=False):
        if is_ip6 is False:
            self._test.assertEqual(p[IP].src, self.itf.src)
            self._test.assertEqual(p[IP].dst, self.endpoint)
        else:
            self._test.assertEqual(p[IPv6].src, self.itf.src)
            self._test.assertEqual(p[IPv6].dst, self.endpoint)
        self._test.assertEqual(p[UDP].sport, self.itf.port)
        self._test.assertEqual(p[UDP].dport, self.port)
        self._test.assert_packet_checksums_valid(p)

    def consume_init(self, p, tx_itf, is_ip6=False):
        self.noise.set_as_responder()
        self.noise_init(self.itf.public_key)
        self.verify_header(p, is_ip6)

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

        resp = (self.mk_tunnel_header(tx_itf, is_ip6) / resp)
        self._test.assertTrue(self.noise.handshake_finished)

        return resp

    def consume_response(self, p, is_ip6=False):
        self.verify_header(p, is_ip6)

        resp = Wireguard(p[Raw])

        self._test.assertEqual(resp[Wireguard].message_type, 2)
        self._test.assertEqual(resp[Wireguard].reserved_zero, 0)
        self._test.assertEqual(resp[WireguardResponse].receiver_index,
                               self.receiver_index)

        self.sender = resp[Wireguard].sender_index

        payload = self.noise.read_message(bytes(resp)[12:60])
        self._test.assertEqual(payload, b'')
        self._test.assertTrue(self.noise.handshake_finished)

    def decrypt_transport(self, p, is_ip6=False):
        self.verify_header(p, is_ip6)

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

    def validate_encapped(self, rxs, tx, is_ip6=False):
        for rx in rxs:
            if is_ip6 is False:
                rx = IP(self.decrypt_transport(rx))

                # chech the oringial packet is present
                self._test.assertEqual(rx[IP].dst, tx[IP].dst)
                self._test.assertEqual(rx[IP].ttl, tx[IP].ttl-1)
            else:
                rx = IPv6(self.decrypt_transport(rx))

                # chech the oringial packet is present
                self._test.assertEqual(rx[IPv6].dst, tx[IPv6].dst)
                self._test.assertEqual(rx[IPv6].ttl, tx[IPv6].ttl-1)

    def want_events(self):
        self._test.vapi.want_wireguard_peer_events(
            enable_disable=1,
            pid=os.getpid(),
            peer_index=self.index,
            sw_if_index=self.itf.sw_if_index)

    def wait_event(self, expect, timeout=5):
        rv = self._test.vapi.wait_for_event(timeout, "wireguard_peer_event")
        self._test.assertEqual(rv.flags, expect)
        self._test.assertEqual(rv.peer_index, self.index)


class TestWg(VppTestCase):
    """ Wireguard Test Case """

    error_str = compile(r"Error")

    wg4_output_node_name = '/err/wg4-output-tun/'
    wg4_input_node_name = '/err/wg4-input/'
    wg6_output_node_name = '/err/wg6-output-tun/'
    wg6_input_node_name = '/err/wg6-input/'
    kp4_error = wg4_output_node_name + "Keypair error"
    mac4_error = wg4_input_node_name + "Invalid MAC handshake"
    peer4_error = wg4_input_node_name + "Peer error"
    kp6_error = wg6_output_node_name + "Keypair error"
    mac6_error = wg6_input_node_name + "Invalid MAC handshake"
    peer6_error = wg6_input_node_name + "Peer error"

    @classmethod
    def setUpClass(cls):
        super(TestWg, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            for i in cls.pg_interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.resolve_ndp()

        except Exception:
            super(TestWg, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestWg, cls).tearDownClass()

    def setUp(self):
        super(VppTestCase, self).setUp()
        self.base_kp4_err = self.statistics.get_err_counter(self.kp4_error)
        self.base_mac4_err = self.statistics.get_err_counter(self.mac4_error)
        self.base_peer4_err = self.statistics.get_err_counter(self.peer4_error)
        self.base_kp6_err = self.statistics.get_err_counter(self.kp6_error)
        self.base_mac6_err = self.statistics.get_err_counter(self.mac6_error)
        self.base_peer6_err = self.statistics.get_err_counter(self.peer6_error)

    def test_wg_interface(self):
        """ Simple interface creation """
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

    def test_wg_peer_resp(self):
        """ Send handshake response """
        port = 12323

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "10.11.3.0", 24,
                        [VppRoutePath("10.11.3.1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # wait for the peer to send a handshake
        rx = self.pg1.get_capture(1, timeout=2)

        # consume the handshake in the noise protocol and
        # generate the response
        resp = peer_1.consume_init(rx[0], self.pg1)

        # send the response, get keepalive
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        for rx in rxs:
            b = peer_1.decrypt_transport(rx)
            self.assertEqual(0, len(b))

        # send a packets that are routed into the tunnel
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw(b'\x00' * 80))

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        peer_1.validate_encapped(rxs, p)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_peer_v4o4(self):
        """ Test v4o4"""

        port = 12333

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "10.11.3.0", 24,
                        [VppRoutePath("10.11.3.1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp4_err + 1,
                         self.statistics.get_err_counter(self.kp4_error))

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1)
        p[WireguardInitiation].mac1 = b'foobar'
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_mac4_err + 1,
                         self.statistics.get_err_counter(self.mac4_error))

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(self.pg1,
                                False,
                                X25519PrivateKey.generate().public_key())
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_peer4_err + 1,
                         self.statistics.get_err_counter(self.peer4_error))

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp4_err + 2,
                         self.statistics.get_err_counter(self.kp4_error))

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
             UDP(sport=222, dport=223) /
             Raw())
        d = peer_1.encrypt_transport(p)
        p = (peer_1.mk_tunnel_header(self.pg1) /
             (Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(receiver_index=peer_1.sender,
                                 counter=0,
                                 encrypted_encapsulated_packet=d)))
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw(b'\x00' * 80))

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IP(peer_1.decrypt_transport(rx))

            # chech the oringial packet is present
            self.assertEqual(rx[IP].dst, p[IP].dst)
            self.assertEqual(rx[IP].ttl, p[IP].ttl-1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii+1,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_peer_v6o6(self):
        """ Test v6o6"""

        port = 12343

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip6,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip6()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip6,
                           port+1,
                           ["1::3:0/112"]).add_vpp_config(True)
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "1::3:0", 112,
                        [VppRoutePath("1::3:1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])

        self.assertEqual(self.base_kp6_err + 1,
                         self.statistics.get_err_counter(self.kp6_error))

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1, True)
        p[WireguardInitiation].mac1 = b'foobar'
        self.send_and_assert_no_replies(self.pg1, [p])

        self.assertEqual(self.base_mac6_err + 1,
                         self.statistics.get_err_counter(self.mac6_error))

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(self.pg1,
                                True,
                                X25519PrivateKey.generate().public_key())
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_peer6_err + 1,
                         self.statistics.get_err_counter(self.peer6_error))

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1, True)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0], True)

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp6_err + 2,
                         self.statistics.get_err_counter(self.kp6_error))

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20) /
             UDP(sport=222, dport=223) /
             Raw())
        d = peer_1.encrypt_transport(p)
        p = (peer_1.mk_tunnel_header(self.pg1, True) /
             (Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(receiver_index=peer_1.sender,
                                 counter=0,
                                 encrypted_encapsulated_packet=d)))
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        # send a packets that are routed into the tunnel
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw(b'\x00' * 80))

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IPv6(peer_1.decrypt_transport(rx, True))

            # chech the oringial packet is present
            self.assertEqual(rx[IPv6].dst, p[IPv6].dst)
            self.assertEqual(rx[IPv6].hlim, p[IPv6].hlim-1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1, True) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii+1,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_peer_v6o4(self):
        """ Test v6o4"""

        port = 12353

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip6()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["1::3:0/112"]).add_vpp_config(True)
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "1::3:0", 112,
                        [VppRoutePath("1::3:1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp6_err + 1,
                         self.statistics.get_err_counter(self.kp6_error))

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1)
        p[WireguardInitiation].mac1 = b'foobar'
        self.send_and_assert_no_replies(self.pg1, [p])

        self.assertEqual(self.base_mac4_err + 1,
                         self.statistics.get_err_counter(self.mac4_error))

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(self.pg1,
                                False,
                                X25519PrivateKey.generate().public_key())
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_peer4_err + 1,
                         self.statistics.get_err_counter(self.peer4_error))

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp6_err + 2,
                         self.statistics.get_err_counter(self.kp6_error))

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20) /
             UDP(sport=222, dport=223) /
             Raw())
        d = peer_1.encrypt_transport(p)
        p = (peer_1.mk_tunnel_header(self.pg1) /
             (Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(receiver_index=peer_1.sender,
                                 counter=0,
                                 encrypted_encapsulated_packet=d)))
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        # send a packets that are routed into the tunnel
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst="1::3:2") /
             UDP(sport=555, dport=556) /
             Raw(b'\x00' * 80))

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IPv6(peer_1.decrypt_transport(rx))

            # chech the oringial packet is present
            self.assertEqual(rx[IPv6].dst, p[IPv6].dst)
            self.assertEqual(rx[IPv6].hlim, p[IPv6].hlim-1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii+1,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_peer_v4o6(self):
        """ Test v4o6"""

        port = 12363

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip6,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip6,
                           port+1,
                           ["10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "10.11.3.0", 24,
                        [VppRoutePath("10.11.3.1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp4_err + 1,
                         self.statistics.get_err_counter(self.kp4_error))

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1, True)
        p[WireguardInitiation].mac1 = b'foobar'
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_mac6_err + 1,
                         self.statistics.get_err_counter(self.mac6_error))

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(self.pg1,
                                True,
                                X25519PrivateKey.generate().public_key())
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(self.base_peer6_err + 1,
                         self.statistics.get_err_counter(self.peer6_error))

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1, True)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0], True)

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(self.base_kp4_err + 2,
                         self.statistics.get_err_counter(self.kp4_error))

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
             UDP(sport=222, dport=223) /
             Raw())
        d = peer_1.encrypt_transport(p)
        p = (peer_1.mk_tunnel_header(self.pg1, True) /
             (Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(receiver_index=peer_1.sender,
                                 counter=0,
                                 encrypted_encapsulated_packet=d)))
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw(b'\x00' * 80))

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IP(peer_1.decrypt_transport(rx, True))

            # chech the oringial packet is present
            self.assertEqual(rx[IP].dst, p[IP].dst)
            self.assertEqual(rx[IP].ttl, p[IP].ttl-1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1, True) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii+1,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_multi_peer(self):
        """ multiple peer setup """
        port = 12373

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
        routes_1 = []
        routes_2 = []
        for i in range(NUM_PEERS):
            peers_1.append(VppWgPeer(self,
                                     wg0,
                                     self.pg1.remote_hosts[i].ip4,
                                     port+1+i,
                                     ["10.0.%d.4/32" % i]).add_vpp_config())
            routes_1.append(VppIpRoute(self, "10.0.%d.4" % i, 32,
                            [VppRoutePath(self.pg1.remote_hosts[i].ip4,
                                          wg0.sw_if_index)]).add_vpp_config())

            peers_2.append(VppWgPeer(self,
                                     wg1,
                                     self.pg2.remote_hosts[i].ip4,
                                     port+100+i,
                                     ["10.100.%d.4/32" % i]).add_vpp_config())
            routes_2.append(VppIpRoute(self, "10.100.%d.4" % i, 32,
                            [VppRoutePath(self.pg2.remote_hosts[i].ip4,
                                          wg1.sw_if_index)]).add_vpp_config())

        self.assertEqual(len(self.vapi.wireguard_peers_dump()), NUM_PEERS*2)

        self.logger.info(self.vapi.cli("show wireguard peer"))
        self.logger.info(self.vapi.cli("show wireguard interface"))
        self.logger.info(self.vapi.cli("show adj 37"))
        self.logger.info(self.vapi.cli("sh ip fib 172.16.3.17"))
        self.logger.info(self.vapi.cli("sh ip fib 10.11.3.0"))

        # remove routes
        for r in routes_1:
            r.remove_vpp_config()
        for r in routes_2:
            r.remove_vpp_config()

        # remove peers
        for p in peers_1:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()
        for p in peers_2:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()

        wg0.remove_vpp_config()
        wg1.remove_vpp_config()

    def test_wg_multi_interface(self):
        """ Multi-tunnel on the same port """
        port = 12500

        # Create many wireguard interfaces
        NUM_IFS = 4
        self.pg1.generate_remote_hosts(NUM_IFS)
        self.pg1.configure_ipv4_neighbors()
        self.pg0.generate_remote_hosts(NUM_IFS)
        self.pg0.configure_ipv4_neighbors()

        # Create interfaces with a peer on each
        peers = []
        routes = []
        wg_ifs = []
        for i in range(NUM_IFS):
            # Use the same port for each interface
            wg0 = VppWgInterface(self,
                                 self.pg1.local_ip4,
                                 port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip4()
            wg_ifs.append(wg0)
            peers.append(VppWgPeer(self,
                                   wg0,
                                   self.pg1.remote_hosts[i].ip4,
                                   port+1+i,
                                   ["10.0.%d.0/24" % i]).add_vpp_config())

            routes.append(VppIpRoute(self, "10.0.%d.0" % i, 24,
                          [VppRoutePath("10.0.%d.4" % i,
                                        wg0.sw_if_index)]).add_vpp_config())

        self.assertEqual(len(self.vapi.wireguard_peers_dump()), NUM_IFS)

        for i in range(NUM_IFS):
            # send a valid handsake init for which we expect a response
            p = peers[i].mk_handshake(self.pg1)
            rx = self.send_and_expect(self.pg1, [p], self.pg1)
            peers[i].consume_response(rx[0])

            # send a data packet from the peer through the tunnel
            # this completes the handshake
            p = (IP(src="10.0.%d.4" % i,
                    dst=self.pg0.remote_hosts[i].ip4, ttl=20) /
                 UDP(sport=222, dport=223) /
                 Raw())
            d = peers[i].encrypt_transport(p)
            p = (peers[i].mk_tunnel_header(self.pg1) /
                 (Wireguard(message_type=4, reserved_zero=0) /
                  WireguardTransport(receiver_index=peers[i].sender,
                                     counter=0,
                                     encrypted_encapsulated_packet=d)))
            rxs = self.send_and_expect(self.pg1, [p], self.pg0)
            for rx in rxs:
                self.assertEqual(rx[IP].dst, self.pg0.remote_hosts[i].ip4)
                self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        for i in range(NUM_IFS):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_hosts[i].ip4, dst="10.0.%d.4" % i) /
                 UDP(sport=555, dport=556) /
                 Raw(b'\x00' * 80))

            rxs = self.send_and_expect(self.pg0, p * 64, self.pg1)

            for rx in rxs:
                rx = IP(peers[i].decrypt_transport(rx))

                # check the oringial packet is present
                self.assertEqual(rx[IP].dst, p[IP].dst)
                self.assertEqual(rx[IP].ttl, p[IP].ttl-1)

        # send packets into the tunnel
        for i in range(NUM_IFS):
            p = [(peers[i].mk_tunnel_header(self.pg1) /
                  Wireguard(message_type=4, reserved_zero=0) /
                  WireguardTransport(
                      receiver_index=peers[i].sender,
                      counter=ii+1,
                      encrypted_encapsulated_packet=peers[i].encrypt_transport(
                          (IP(src="10.0.%d.4" % i,
                              dst=self.pg0.remote_hosts[i].ip4, ttl=20) /
                           UDP(sport=222, dport=223) /
                           Raw())))) for ii in range(64)]

            rxs = self.send_and_expect(self.pg1, p, self.pg0)

            for rx in rxs:
                self.assertEqual(rx[IP].dst, self.pg0.remote_hosts[i].ip4)
                self.assertEqual(rx[IP].ttl, 19)

        for r in routes:
            r.remove_vpp_config()
        for p in peers:
            p.remove_vpp_config()
        for i in wg_ifs:
            i.remove_vpp_config()

    def test_wg_event(self):
        """ Test events """
        port = 12600
        ESTABLISHED_FLAG = VppEnum.\
            vl_api_wireguard_peer_flags_t.\
            WIREGUARD_PEER_ESTABLISHED
        DEAD_FLAG = VppEnum.\
            vl_api_wireguard_peer_flags_t.\
            WIREGUARD_PEER_STATUS_DEAD

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

        # Create peers
        NUM_PEERS = 2
        self.pg2.generate_remote_hosts(NUM_PEERS)
        self.pg2.configure_ipv4_neighbors()
        self.pg1.generate_remote_hosts(NUM_PEERS)
        self.pg1.configure_ipv4_neighbors()

        peers_0 = []
        peers_1 = []
        routes_0 = []
        routes_1 = []
        for i in range(NUM_PEERS):
            peers_0.append(VppWgPeer(self,
                                     wg0,
                                     self.pg1.remote_hosts[i].ip4,
                                     port+1+i,
                                     ["10.0.%d.4/32" % i]).add_vpp_config())
            routes_0.append(VppIpRoute(self, "10.0.%d.4" % i, 32,
                            [VppRoutePath(self.pg1.remote_hosts[i].ip4,
                                          wg0.sw_if_index)]).add_vpp_config())

            peers_1.append(VppWgPeer(self,
                                     wg1,
                                     self.pg2.remote_hosts[i].ip4,
                                     port+100+i,
                                     ["10.100.%d.4/32" % i]).add_vpp_config())
            routes_1.append(VppIpRoute(self, "10.100.%d.4" % i, 32,
                            [VppRoutePath(self.pg2.remote_hosts[i].ip4,
                                          wg1.sw_if_index)]).add_vpp_config())

        self.assertEqual(len(self.vapi.wireguard_peers_dump()), NUM_PEERS*2)

        # Want events from the first perr of wg0
        # and from all wg1 peers
        peers_0[0].want_events()
        wg1.want_events()

        for i in range(NUM_PEERS):
            # send a valid handsake init for which we expect a response
            p = peers_0[i].mk_handshake(self.pg1)
            rx = self.send_and_expect(self.pg1, [p], self.pg1)
            peers_0[i].consume_response(rx[0])
            if (i == 0):
                peers_0[0].wait_event(ESTABLISHED_FLAG)

            p = peers_1[i].mk_handshake(self.pg2)
            rx = self.send_and_expect(self.pg2, [p], self.pg2)
            peers_1[i].consume_response(rx[0])

        wg1.wait_events(
            ESTABLISHED_FLAG,
            [peers_1[0].index, peers_1[1].index])

        # remove routes
        for r in routes_0:
            r.remove_vpp_config()
        for r in routes_1:
            r.remove_vpp_config()

        # remove peers
        for i in range(NUM_PEERS):
            self.assertTrue(peers_0[i].query_vpp_config())
            peers_0[i].remove_vpp_config()
            if (i == 0):
                peers_0[i].wait_event(0)
                peers_0[i].wait_event(DEAD_FLAG)
        for p in peers_1:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()
            p.wait_event(0)
            p.wait_event(DEAD_FLAG)

        wg0.remove_vpp_config()
        wg1.remove_vpp_config()


class WireguardHandoffTests(TestWg):
    """ Wireguard Tests in multi worker setup """
    vpp_worker_count = 2

    def test_wg_peer_init(self):
        """ Handoff """

        port = 12383

        # Create interfaces
        wg0 = VppWgInterface(self,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = VppWgPeer(self,
                           wg0,
                           self.pg1.remote_ip4,
                           port+1,
                           ["10.11.2.0/24",
                            "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(self, "10.11.3.0", 24,
                        [VppRoutePath("10.11.3.1",
                                      wg0.sw_if_index)]).add_vpp_config()

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # send a data packet from the peer through the tunnel
        # this completes the handshake and pins the peer to worker 0
        p = (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
             UDP(sport=222, dport=223) /
             Raw())
        d = peer_1.encrypt_transport(p)
        p = (peer_1.mk_tunnel_header(self.pg1) /
             (Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(receiver_index=peer_1.sender,
                                 counter=0,
                                 encrypted_encapsulated_packet=d)))
        rxs = self.send_and_expect(self.pg1, [p], self.pg0,
                                   worker=0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        # and pins the peer tp worker 1
        pe = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
              UDP(sport=555, dport=556) /
              Raw(b'\x00' * 80))
        rxs = self.send_and_expect(self.pg0, pe * 255, self.pg1, worker=1)
        peer_1.validate_encapped(rxs, pe)

        # send packets into the tunnel, from the other worker
        p = [(peer_1.mk_tunnel_header(self.pg1) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                    receiver_index=peer_1.sender,
                    counter=ii+1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
                         UDP(sport=222, dport=223) /
                         Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0, worker=1)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        # from owrker 0
        rxs = self.send_and_expect(self.pg0, pe * 255, self.pg1, worker=0)

        peer_1.validate_encapped(rxs, pe)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    @unittest.skip("test disabled")
    def test_wg_multi_interface(self):
        """ Multi-tunnel on the same port """
