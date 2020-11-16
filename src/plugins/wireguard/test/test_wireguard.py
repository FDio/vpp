#!/usr/bin/env python3
""" Wg tests """

import base64

from hashlib import blake2s
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.contrib.wireguard import Wireguard, WireguardResponse, \
    WireguardInitiation, WireguardTransport
from cryptography.hazmat.primitives.asymmetric.x25519 import \
    X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import BLAKE2s, Hash
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

from vpp_pom.plugins.vpp_wireguard import VppWgInterface, public_key_bytes, \
    VppWgPeer, find_route
from framework import VppTestCase
from re import compile
import unittest

""" TestWg is a subclass of  VPPTestCase classes.

Wg test.

"""


class MyVppWgPeer(VppWgPeer):
    def __init__(self,
                 test,
                 intf,
                 endpoint,
                 port,
                 allowed_ips,
                 persistent_keepalive=15):
        self._test = test
        super(MyVppWgPeer, self).__init__(
            test.vclient, intf, endpoint, port, allowed_ips,
            persistent_keepalive=persistent_keepalive)

    def validate_routing(self):
        for a in self.allowed_ips:
            self._test.assertTrue(find_route(self._vclient, a))

    def validate_no_routing(self):
        for a in self.allowed_ips:
            self._test.assertFalse(find_route(self._vclient, a))

    def add_vpp_config(self):
        ret = super(MyVppWgPeer, self).add_vpp_config()
        self.validate_routing()
        return ret

    def remove_vpp_config(self):
        super(MyVppWgPeer, self).remove_vpp_config()
        self.validate_no_routing()

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

    def validate_encapped(self, rxs, tx):
        for rx in rxs:
            rx = IP(self.decrypt_transport(rx))

            # chech the oringial packet is present
            self._test.assertEqual(rx[IP].dst, tx[IP].dst)
            self._test.assertEqual(rx[IP].ttl, tx[IP].ttl - 1)


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
        """ Simple interface creation """
        port = 12312

        # Create interface
        wg0 = VppWgInterface(self.vclient,
                             self.pg1.local_ip4,
                             port).add_vpp_config()

        self.logger.info(self.vclient.cli("sh int"))

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
        wg_output_node_name = '/err/wg-output-tun/'
        wg_input_node_name = '/err/wg-input/'

        port = 12323

        # Create interfaces
        wg0 = VppWgInterface(self.vclient,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        peer_1 = MyVppWgPeer(self,
                             wg0,
                             self.pg1.remote_ip4,
                             port + 1,
                             ["10.11.2.0/24",
                              "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vclient.wireguard_peers_dump()), 1)

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

    def test_wg_peer_init(self):
        """ Send handshake init """
        wg_output_node_name = '/err/wg-output-tun/'
        wg_input_node_name = '/err/wg-input/'

        port = 12333

        # Create interfaces
        wg0 = VppWgInterface(self.vclient,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = MyVppWgPeer(self,
                             wg0,
                             self.pg1.remote_ip4,
                             port + 1,
                             ["10.11.2.0/24",
                              "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vclient.wireguard_peers_dump()), 1)

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.11.3.2") /
             UDP(sport=555, dport=556) /
             Raw())
        self.send_and_assert_no_replies(self.pg0, [p])

        kp_error = wg_output_node_name + "Keypair error"
        self.assertEqual(1, self.vclient.statistics.get_err_counter(kp_error))

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1)
        p[WireguardInitiation].mac1 = b'foobar'
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(1, self.vclient.statistics.get_err_counter(
            wg_input_node_name + "Invalid MAC handshake"))

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(self.pg1,
                                X25519PrivateKey.generate().public_key())
        self.send_and_assert_no_replies(self.pg1, [p])
        self.assertEqual(1, self.vclient.statistics.get_err_counter(
            wg_input_node_name + "Peer error"))

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
        self.assertEqual(2, self.vclient.statistics.get_err_counter(kp_error))

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
            self.assertEqual(rx[IP].ttl, p[IP].ttl - 1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [(peer_1.mk_tunnel_header(self.pg1) /
              Wireguard(message_type=4, reserved_zero=0) /
              WireguardTransport(
                  receiver_index=peer_1.sender,
                  counter=ii + 1,
                  encrypted_encapsulated_packet=peer_1.encrypt_transport(
                      (IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20) /
                       UDP(sport=222, dport=223) /
                       Raw())))) for ii in range(255)]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def test_wg_multi_peer(self):
        """ multiple peer setup """
        port = 12343

        # Create interfaces
        wg0 = VppWgInterface(self.vclient,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg1 = VppWgInterface(self.vclient,
                             self.pg2.local_ip4,
                             port + 1).add_vpp_config()
        wg0.admin_up()
        wg1.admin_up()

        # Check peer counter
        self.assertEqual(len(self.vclient.wireguard_peers_dump()), 0)

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
            peers_1.append(VppWgPeer(self.vclient,
                                     wg0,
                                     self.pg1.remote_hosts[i].ip4,
                                     port + 1 + i,
                                     ["10.0.%d.4/32" % i]).add_vpp_config())
            peers_2.append(VppWgPeer(self.vclient,
                                     wg1,
                                     self.pg2.remote_hosts[i].ip4,
                                     port + 100 + i,
                                     ["10.100.%d.4/32" % i]).add_vpp_config())

        self.assertEqual(
            len(self.vclient.wireguard_peers_dump()), NUM_PEERS * 2)

        self.logger.info(self.vclient.cli("show wireguard peer"))
        self.logger.info(self.vclient.cli("show wireguard interface"))
        self.logger.info(self.vclient.cli("show adj 37"))
        self.logger.info(self.vclient.cli("sh ip fib 172.16.3.17"))
        self.logger.info(self.vclient.cli("sh ip fib 10.11.3.0"))

        # remove peers
        for p in peers_1:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()
        for p in peers_2:
            self.assertTrue(p.query_vpp_config())
            p.remove_vpp_config()

        wg0.remove_vpp_config()
        wg1.remove_vpp_config()


class WireguardHandoffTests(TestWg):
    """ Wireguard Tests in multi worker setup """
    worker_config = "workers 2"

    def test_wg_peer_init(self):
        """ Handoff """
        wg_output_node_name = '/err/wg-output-tun/'
        wg_input_node_name = '/err/wg-input/'

        port = 12353

        # Create interfaces
        wg0 = VppWgInterface(self.vclient,
                             self.pg1.local_ip4,
                             port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = MyVppWgPeer(self,
                             wg0,
                             self.pg1.remote_ip4,
                             port + 1,
                             ["10.11.2.0/24",
                              "10.11.3.0/24"]).add_vpp_config()
        self.assertEqual(len(self.vclient.wireguard_peers_dump()), 1)

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
                  counter=ii + 1,
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

        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()
