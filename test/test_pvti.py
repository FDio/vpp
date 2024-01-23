#!/usr/bin/env python3
""" PVTI tests """

import datetime
import base64
import os

from hashlib import blake2s
from config import config
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN

from vpp_interface import VppInterface
from vpp_pg_interface import is_ipv6_misc
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from vpp_vxlan_tunnel import VppVxlanTunnel
from vpp_object import VppObject
from vpp_papi import VppEnum
from asfframework import tag_run_solo, tag_fixme_vpp_debug
from framework import VppTestCase
from re import compile
import unittest

""" TestPvti is a subclass of  VPPTestCase classes.

PVTI test.

"""


def get_field_bytes(pkt, name):
    fld, val = pkt.getfield_and_val(name)
    return fld.i2m(pkt, val)


class VppPvtiInterface(VppInterface):
    """
    VPP PVTI interface
    """

    def __init__(self, test, local_ip, local_port, remote_ip, remote_port):
        super(VppPvtiInterface, self).__init__(test)

        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port

    def add_vpp_config(self):
        r = self.test.vapi.pvti_interface_create(
                interface = {
                    "local_ip": self.local_ip,
                    "local_port": self.local_port,
                    "remote_ip": self.remote_ip,
                    "remote_port": self.remote_port,
                }
        )
        self.set_sw_if_index(r.sw_if_index)
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.pvti_interface_delete(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.pvti_interface_dump(sw_if_index=0xFFFFFFFF)
        for t in ts:
            if (
                t.interface.sw_if_index == self._sw_if_index
                and str(t.interface.local_ip) == self.local_ip
                and t.interface.local_port == self.local_port
                and t.interface.remote_port == self.peer_port
                and str(t.interface.remote_ip) == self.peer_addr
            ):
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "pvti-%d" % self._sw_if_index


class VppPvtiPeer(VppObject):
    def __init__(self, test, itf, endpoint, port, allowed_ips, persistent_keepalive=15):
        self._test = test
        self.itf = itf
        self.endpoint = endpoint
        self.port = port
        self.allowed_ips = allowed_ips

    def change_endpoint(self, endpoint, port):
        self.endpoint = endpoint
        self.port = port

    def add_vpp_config_fixme(self):
        rv = self._test.vapi.wireguard_peer_add(
            peer={
                "public_key": self.public_key_bytes(),
                "port": self.port,
                "endpoint": self.endpoint,
                "n_allowed_ips": len(self.allowed_ips),
                "allowed_ips": self.allowed_ips,
                "sw_if_index": self.itf.sw_if_index,
                "persistent_keepalive": self.persistent_keepalive,
            }
        )
        self.index = rv.peer_index
        self.receiver_index = self.index + 1
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config_fixme(self):
        self._test.vapi.wireguard_peer_remove(peer_index=self.index)

    def object_id(self):
        return "pvti-peer-%s" % self.index

    def query_vpp_config_fixme(self):
        peers = self._test.vapi.wireguard_peers_dump()

        for p in peers:
            # "::" endpoint will be returned as "0.0.0.0" in peer's details
            endpoint = "0.0.0.0" if self.endpoint == "::" else self.endpoint
            if (
                p.peer.public_key == self.public_key_bytes()
                and p.peer.port == self.port
                and str(p.peer.endpoint) == endpoint
                and p.peer.sw_if_index == self.itf.sw_if_index
                and len(self.allowed_ips) == p.peer.n_allowed_ips
            ):
                self.allowed_ips.sort()
                p.peer.allowed_ips.sort()

                for a1, a2 in zip(self.allowed_ips, p.peer.allowed_ips):
                    if str(a1) != str(a2):
                        return False
                return True
        return False

    def mk_tunnel_header(self, tx_itf, is_ip6=False):
        if is_ip6 is False:
            return (
                Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac)
                / IP(src=self.endpoint, dst=self.itf.src)
                / UDP(sport=self.port, dport=self.itf.port)
            )
        else:
            return (
                Ether(dst=tx_itf.local_mac, src=tx_itf.remote_mac)
                / IPv6(src=self.endpoint, dst=self.itf.src)
                / UDP(sport=self.port, dport=self.itf.port)
            )

    def verify_header(self, p, is_ip6=False):
        if is_ip6 is False:
            self._test.assertEqual(p[IP].src, self.itf.src)
            self._test.assertEqual(p[IP].dst, self.endpoint)
            self._test.assert_packet_checksums_valid(p)
        else:
            self._test.assertEqual(p[IPv6].src, self.itf.src)
            self._test.assertEqual(p[IPv6].dst, self.endpoint)
            self._test.assert_packet_checksums_valid(p, False)
        self._test.assertEqual(p[UDP].sport, self.itf.port)
        self._test.assertEqual(p[UDP].dport, self.port)

    def consume_init(self, p, tx_itf, is_ip6=False, is_mac2=False):
        self.verify_header(p, is_ip6)


    def validate_encapped(self, rxs, tx, is_tunnel_ip6=False, is_transport_ip6=False):
        ret_rxs = []
        for rx in rxs:
            rx = self.decrypt_transport(rx, is_tunnel_ip6)
            if is_transport_ip6 is False:
                rx = IP(rx)
                # check the original packet is present
                self._test.assertEqual(rx[IP].dst, tx[IP].dst)
                self._test.assertEqual(rx[IP].ttl, tx[IP].ttl - 1)
            else:
                rx = IPv6(rx)
                # check the original packet is present
                self._test.assertEqual(rx[IPv6].dst, tx[IPv6].dst)
                self._test.assertEqual(rx[IPv6].hlim, tx[IPv6].hlim - 1)
            ret_rxs.append(rx)
        return ret_rxs

@unittest.skipIf(
    "pvti" in config.excluded_plugins, "Exclude PVTI plugin tests"
)
@tag_run_solo
class TestPvti(VppTestCase):
    """Packet Vector Tunnel (PVTI) Test Case"""

    error_str = compile(r"Error")

    wg4_output_node_name = "/err/wg4-output-tun/"
    wg4_input_node_name = "/err/wg4-input/"
    wg6_output_node_name = "/err/wg6-output-tun/"
    wg6_input_node_name = "/err/wg6-input/"
    kp4_error = wg4_output_node_name + "Keypair error"
    mac4_error = wg4_input_node_name + "Invalid MAC handshake"
    peer4_in_err = wg4_input_node_name + "Peer error"
    peer4_out_err = wg4_output_node_name + "Peer error"
    kp6_error = wg6_output_node_name + "Keypair error"
    mac6_error = wg6_input_node_name + "Invalid MAC handshake"
    peer6_in_err = wg6_input_node_name + "Peer error"
    peer6_out_err = wg6_output_node_name + "Peer error"
    cookie_dec4_err = wg4_input_node_name + "Failed during Cookie decryption"
    cookie_dec6_err = wg6_input_node_name + "Failed during Cookie decryption"
    ratelimited4_err = wg4_input_node_name + "Handshake ratelimited"
    ratelimited6_err = wg6_input_node_name + "Handshake ratelimited"

    @classmethod
    def setUpClass(cls):
        super(TestPvti, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            for i in cls.pg_interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.resolve_ndp()

        except Exception:
            super(TestPvti, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestPvti, cls).tearDownClass()

    def setUp(self):
        super(VppTestCase, self).setUp()
        self.base_kp4_err = self.statistics.get_err_counter(self.kp4_error)
        self.base_mac4_err = self.statistics.get_err_counter(self.mac4_error)
        self.base_peer4_in_err = self.statistics.get_err_counter(self.peer4_in_err)
        self.base_peer4_out_err = self.statistics.get_err_counter(self.peer4_out_err)
        self.base_kp6_err = self.statistics.get_err_counter(self.kp6_error)
        self.base_mac6_err = self.statistics.get_err_counter(self.mac6_error)
        self.base_peer6_in_err = self.statistics.get_err_counter(self.peer6_in_err)
        self.base_peer6_out_err = self.statistics.get_err_counter(self.peer6_out_err)
        self.base_cookie_dec4_err = self.statistics.get_err_counter(
            self.cookie_dec4_err
        )
        self.base_cookie_dec6_err = self.statistics.get_err_counter(
            self.cookie_dec6_err
        )
        self.base_ratelimited4_err = self.statistics.get_err_counter(
            self.ratelimited4_err
        )
        self.base_ratelimited6_err = self.statistics.get_err_counter(
            self.ratelimited6_err
        )

    def send_and_assert_no_replies_ignoring_init(
        self, intf, pkts, remark="", timeout=None
    ):
        self.pg_send(intf, pkts)

        def _filter_out_fn(p):
            return is_ipv6_misc(p) or is_handshake_init(p)

        try:
            if not timeout:
                timeout = 1
            for i in self.pg_interfaces:
                i.assert_nothing_captured(
                    timeout=timeout, remark=remark, filter_out_fn=_filter_out_fn
                )
                timeout = 0.1
        finally:
            pass

    def test_pvti_interface(self):
        """Simple interface creation"""
        local_port = 12312
        peer_addr = "192.0.2.1"
        peer_port = 12312

        # Create interface
        pvti0 = VppPvtiInterface(self, self.pg1.local_ip4, local_port, peer_addr, peer_port).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int"))

        # delete interface
        # pvti0.remove_vpp_config()

    def Xtest_wg_under_load_interval(self):
        """Under load interval"""
        port = 12323

        # create wg interface
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # skip the first automatic handshake
        self.pg1.get_capture(1, timeout=HANDSHAKE_JITTER)

        # prepare and send a bunch of handshake initiations
        # expect to switch to under load state
        init = peer_1.mk_handshake(self.pg1)
        txs = [init] * HANDSHAKE_NUM_PER_PEER_UNTIL_UNDER_LOAD
        rxs = self.send_and_expect_some(self.pg1, txs, self.pg1)

        # expect the peer to send a cookie reply
        peer_1.consume_cookie(rxs[-1])

        # sleep till the next counting interval
        # expect under load state is still active
        self.sleep(HANDSHAKE_COUNTING_INTERVAL)

        # prepare and send a handshake initiation with wrong mac2
        # expect a cookie reply
        init = peer_1.mk_handshake(self.pg1)
        init.mac2 = b"1234567890"
        rxs = self.send_and_expect(self.pg1, [init], self.pg1)
        peer_1.consume_cookie(rxs[0])

        # sleep till the end of being under load
        # expect under load state is over
        self.sleep(UNDER_LOAD_INTERVAL - HANDSHAKE_COUNTING_INTERVAL)

        # prepare and send a handshake initiation with wrong mac2
        # expect a handshake response
        init = peer_1.mk_handshake(self.pg1)
        init.mac2 = b"1234567890"
        rxs = self.send_and_expect(self.pg1, [init], self.pg1)

        # verify the response
        peer_1.consume_response(rxs[0])

        # remove configs
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def _test_wg_handshake_ratelimiting_tmpl(self, is_ip6):
        port = 12323

        # create wg interface
        if is_ip6:
            wg0 = VppWgInterface(self, self.pg1.local_ip6, port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip6()
        else:
            wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        if is_ip6:
            peer_1 = VppWgPeer(
                self, wg0, self.pg1.remote_ip6, port + 1, ["1::3:0/112"]
            ).add_vpp_config()
        else:
            peer_1 = VppWgPeer(
                self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
            ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # skip the first automatic handshake
        self.pg1.get_capture(1, timeout=HANDSHAKE_JITTER)

        # prepare and send a bunch of handshake initiations
        # expect to switch to under load state
        init = peer_1.mk_handshake(self.pg1, is_ip6=is_ip6)
        txs = [init] * HANDSHAKE_NUM_PER_PEER_UNTIL_UNDER_LOAD
        rxs = self.send_and_expect_some(self.pg1, txs, self.pg1)

        # expect the peer to send a cookie reply
        peer_1.consume_cookie(rxs[-1], is_ip6=is_ip6)

        # prepare and send a bunch of handshake initiations with correct mac2
        # expect a handshake response and then ratelimiting
        NUM_TO_REJECT = 10
        init = peer_1.mk_handshake(self.pg1, is_ip6=is_ip6)
        txs = [init] * (HANDSHAKE_NUM_BEFORE_RATELIMITING + NUM_TO_REJECT)

        # TODO: Deterimine why no handshake response is sent back if test is
        #       not run in as part of the test suite.  It fails only very occasionally
        #       when run solo.
        #
        #       Until then, if no response, don't fail trying to verify it.
        #       The error counter test still verifies that the correct number of
        #       handshake initiaions are ratelimited.
        try:
            rxs = self.send_and_expect_some(self.pg1, txs, self.pg1)
        except:
            self.logger.debug(
                f"{self._testMethodDoc}: send_and_expect_some() failed to get any response packets."
            )
            rxs = None
            pass

        if is_ip6:
            self.assertEqual(
                self.base_ratelimited6_err + NUM_TO_REJECT,
                self.statistics.get_err_counter(self.ratelimited6_err),
            )
        else:
            self.assertEqual(
                self.base_ratelimited4_err + NUM_TO_REJECT,
                self.statistics.get_err_counter(self.ratelimited4_err),
            )

        # verify the response
        if rxs is not None:
            peer_1.consume_response(rxs[0], is_ip6=is_ip6)

        # clear up under load state
        self.sleep(UNDER_LOAD_INTERVAL)

        # remove configs
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_handshake_ratelimiting_v4(self):
        """Handshake ratelimiting (v4)"""
        self._test_wg_handshake_ratelimiting_tmpl(is_ip6=False)

    def Xtest_wg_handshake_ratelimiting_v6(self):
        """Handshake ratelimiting (v6)"""
        self._test_wg_handshake_ratelimiting_tmpl(is_ip6=True)

    def Xtest_wg_peer_v4o4(self):
        """Test v4o4"""

        port = 12333

        # Create interfaces
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(
            self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
        ).add_vpp_config()
        r2 = VppIpRoute(
            self, "20.22.3.0", 24, [VppRoutePath("20.22.3.1", wg0.sw_if_index)]
        ).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp4_err + 1, self.statistics.get_err_counter(self.kp4_error)
        )

        # route a packet into the wg interface
        #  use a not allowed-ip prefix
        #  this is dropped because there is no matching peer
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="20.22.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_peer4_out_err + 1,
            self.statistics.get_err_counter(self.peer4_out_err),
        )

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1)
        p[PvtiInitiation].mac1 = b"foobar"
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_mac4_err + 1, self.statistics.get_err_counter(self.mac4_error)
        )

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(
            self.pg1, False, X25519PrivateKey.generate().public_key()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_peer4_in_err + 1,
            self.statistics.get_err_counter(self.peer4_in_err),
        )

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp4_err + 2, self.statistics.get_err_counter(self.kp4_error)
        )

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (
            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
            / UDP(sport=222, dport=223)
            / Raw()
        )
        d = peer_1.encrypt_transport(p)
        p = peer_1.mk_tunnel_header(self.pg1) / (
            Pvti(message_type=4, reserved_zero=0)
            / PvtiTransport(
                receiver_index=peer_1.sender, counter=0, encrypted_encapsulated_packet=d
            )
        )
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IP(peer_1.decrypt_transport(rx))

            # check the original packet is present
            self.assertEqual(rx[IP].dst, p[IP].dst)
            self.assertEqual(rx[IP].ttl, p[IP].ttl - 1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [
            (
                peer_1.mk_tunnel_header(self.pg1)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=ii + 1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (
                            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
                            / UDP(sport=222, dport=223)
                            / Raw()
                        )
                    ),
                )
            )
            for ii in range(255)
        ]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        r1.remove_vpp_config()
        r2.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_peer_v6o6(self):
        """Test v6o6"""

        port = 12343

        # Create interfaces
        wg0 = VppWgInterface(self, self.pg1.local_ip6, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip6()

        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip6, port + 1, ["1::3:0/112"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(
            self, "1::3:0", 112, [VppRoutePath("1::3:1", wg0.sw_if_index)]
        ).add_vpp_config()
        r2 = VppIpRoute(
            self, "22::3:0", 112, [VppRoutePath("22::3:1", wg0.sw_if_index)]
        ).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated

        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])

        self.assertEqual(
            self.base_kp6_err + 1, self.statistics.get_err_counter(self.kp6_error)
        )

        # route a packet into the wg interface
        #  use a not allowed-ip prefix
        #  this is dropped because there is no matching peer
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="22::3:2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_peer6_out_err + 1,
            self.statistics.get_err_counter(self.peer6_out_err),
        )

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1, True)
        p[PvtiInitiation].mac1 = b"foobar"
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])

        self.assertEqual(
            self.base_mac6_err + 1, self.statistics.get_err_counter(self.mac6_error)
        )

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(
            self.pg1, True, X25519PrivateKey.generate().public_key()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_peer6_in_err + 1,
            self.statistics.get_err_counter(self.peer6_in_err),
        )

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1, True)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0], True)

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp6_err + 2, self.statistics.get_err_counter(self.kp6_error)
        )

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (
            IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20)
            / UDP(sport=222, dport=223)
            / Raw()
        )
        d = peer_1.encrypt_transport(p)
        p = peer_1.mk_tunnel_header(self.pg1, True) / (
            Pvti(message_type=4, reserved_zero=0)
            / PvtiTransport(
                receiver_index=peer_1.sender, counter=0, encrypted_encapsulated_packet=d
            )
        )
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        # send a packets that are routed into the tunnel
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IPv6(peer_1.decrypt_transport(rx, True))

            # check the original packet is present
            self.assertEqual(rx[IPv6].dst, p[IPv6].dst)
            self.assertEqual(rx[IPv6].hlim, p[IPv6].hlim - 1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [
            (
                peer_1.mk_tunnel_header(self.pg1, True)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=ii + 1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (
                            IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20)
                            / UDP(sport=222, dport=223)
                            / Raw()
                        )
                    ),
                )
            )
            for ii in range(255)
        ]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        r1.remove_vpp_config()
        r2.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_peer_v6o4(self):
        """Test v6o4"""

        port = 12353

        # Create interfaces
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip6()

        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["1::3:0/112"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(
            self, "1::3:0", 112, [VppRoutePath("1::3:1", wg0.sw_if_index)]
        ).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp6_err + 1, self.statistics.get_err_counter(self.kp6_error)
        )

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1)
        p[PvtiInitiation].mac1 = b"foobar"
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])

        self.assertEqual(
            self.base_mac4_err + 1, self.statistics.get_err_counter(self.mac4_error)
        )

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(
            self.pg1, False, X25519PrivateKey.generate().public_key()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_peer4_in_err + 1,
            self.statistics.get_err_counter(self.peer4_in_err),
        )

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp6_err + 2, self.statistics.get_err_counter(self.kp6_error)
        )

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (
            IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20)
            / UDP(sport=222, dport=223)
            / Raw()
        )
        d = peer_1.encrypt_transport(p)
        p = peer_1.mk_tunnel_header(self.pg1) / (
            Pvti(message_type=4, reserved_zero=0)
            / PvtiTransport(
                receiver_index=peer_1.sender, counter=0, encrypted_encapsulated_packet=d
            )
        )
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        # send a packets that are routed into the tunnel
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IPv6(peer_1.decrypt_transport(rx))

            # check the original packet is present
            self.assertEqual(rx[IPv6].dst, p[IPv6].dst)
            self.assertEqual(rx[IPv6].hlim, p[IPv6].hlim - 1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [
            (
                peer_1.mk_tunnel_header(self.pg1)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=ii + 1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (
                            IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20)
                            / UDP(sport=222, dport=223)
                            / Raw()
                        )
                    ),
                )
            )
            for ii in range(255)
        ]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].hlim, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_peer_v4o6(self):
        """Test v4o6"""

        port = 12363

        # Create interfaces
        wg0 = VppWgInterface(self, self.pg1.local_ip6, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip6, port + 1, ["10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(
            self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
        ).add_vpp_config()

        # route a packet into the wg interface
        #  use the allowed-ip prefix
        #  this is dropped because the peer is not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp4_err + 1, self.statistics.get_err_counter(self.kp4_error)
        )

        # send a handsake from the peer with an invalid MAC
        p = peer_1.mk_handshake(self.pg1, True)
        p[PvtiInitiation].mac1 = b"foobar"
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_mac6_err + 1, self.statistics.get_err_counter(self.mac6_error)
        )

        # send a handsake from the peer but signed by the wrong key.
        p = peer_1.mk_handshake(
            self.pg1, True, X25519PrivateKey.generate().public_key()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg1, [p])
        self.assertEqual(
            self.base_peer6_in_err + 1,
            self.statistics.get_err_counter(self.peer6_in_err),
        )

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1, True)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0], True)

        # route a packet into the wg interface
        #  this is dropped because the peer is still not initiated
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p])
        self.assertEqual(
            self.base_kp4_err + 2, self.statistics.get_err_counter(self.kp4_error)
        )

        # send a data packet from the peer through the tunnel
        # this completes the handshake
        p = (
            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
            / UDP(sport=222, dport=223)
            / Raw()
        )
        d = peer_1.encrypt_transport(p)
        p = peer_1.mk_tunnel_header(self.pg1, True) / (
            Pvti(message_type=4, reserved_zero=0)
            / PvtiTransport(
                receiver_index=peer_1.sender, counter=0, encrypted_encapsulated_packet=d
            )
        )
        rxs = self.send_and_expect(self.pg1, [p], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )

        rxs = self.send_and_expect(self.pg0, p * 255, self.pg1)

        for rx in rxs:
            rx = IP(peer_1.decrypt_transport(rx, True))

            # check the original packet is present
            self.assertEqual(rx[IP].dst, p[IP].dst)
            self.assertEqual(rx[IP].ttl, p[IP].ttl - 1)

        # send packets into the tunnel, expect to receive them on
        # the other side
        p = [
            (
                peer_1.mk_tunnel_header(self.pg1, True)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=ii + 1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (
                            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
                            / UDP(sport=222, dport=223)
                            / Raw()
                        )
                    ),
                )
            )
            for ii in range(255)
        ]

        rxs = self.send_and_expect(self.pg1, p, self.pg0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_multi_interface(self):
        """Multi-tunnel on the same port"""
        port = 12500

        # Create many wireguard interfaces
        NUM_IFS = 4
        self.pg1.generate_remote_hosts(NUM_IFS)
        self.pg1.configure_ipv4_neighbors()
        self.pg0.generate_remote_hosts(NUM_IFS)
        self.pg0.configure_ipv4_neighbors()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Create interfaces with a peer on each
        peers = []
        routes = []
        wg_ifs = []
        for i in range(NUM_IFS):
            # Use the same port for each interface
            wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip4()
            wg_ifs.append(wg0)
            peers.append(
                VppWgPeer(
                    self,
                    wg0,
                    self.pg1.remote_hosts[i].ip4,
                    port + 1 + i,
                    ["10.0.%d.0/24" % i],
                ).add_vpp_config()
            )

            routes.append(
                VppIpRoute(
                    self,
                    "10.0.%d.0" % i,
                    24,
                    [VppRoutePath("10.0.%d.4" % i, wg0.sw_if_index)],
                ).add_vpp_config()
            )

        self.assertEqual(len(self.vapi.wireguard_peers_dump()), NUM_IFS)

        # skip the first automatic handshake
        self.pg1.get_capture(NUM_IFS, timeout=HANDSHAKE_JITTER)

        for i in range(NUM_IFS):
            # send a valid handsake init for which we expect a response
            p = peers[i].mk_handshake(self.pg1)
            rx = self.send_and_expect(self.pg1, [p], self.pg1)
            peers[i].consume_response(rx[0])

            # send a data packet from the peer through the tunnel
            # this completes the handshake
            p = (
                IP(src="10.0.%d.4" % i, dst=self.pg0.remote_hosts[i].ip4, ttl=20)
                / UDP(sport=222, dport=223)
                / Raw()
            )
            d = peers[i].encrypt_transport(p)
            p = peers[i].mk_tunnel_header(self.pg1) / (
                Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peers[i].sender,
                    counter=0,
                    encrypted_encapsulated_packet=d,
                )
            )
            rxs = self.send_and_expect(self.pg1, [p], self.pg0)
            for rx in rxs:
                self.assertEqual(rx[IP].dst, self.pg0.remote_hosts[i].ip4)
                self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        for i in range(NUM_IFS):
            p = (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IP(src=self.pg0.remote_hosts[i].ip4, dst="10.0.%d.4" % i)
                / UDP(sport=555, dport=556)
                / Raw(b"\x00" * 80)
            )

            rxs = self.send_and_expect(self.pg0, p * 64, self.pg1)

            for rx in rxs:
                rx = IP(peers[i].decrypt_transport(rx))

                # check the oringial packet is present
                self.assertEqual(rx[IP].dst, p[IP].dst)
                self.assertEqual(rx[IP].ttl, p[IP].ttl - 1)

        # send packets into the tunnel
        for i in range(NUM_IFS):
            p = [
                (
                    peers[i].mk_tunnel_header(self.pg1)
                    / Pvti(message_type=4, reserved_zero=0)
                    / PvtiTransport(
                        receiver_index=peers[i].sender,
                        counter=ii + 1,
                        encrypted_encapsulated_packet=peers[i].encrypt_transport(
                            (
                                IP(
                                    src="10.0.%d.4" % i,
                                    dst=self.pg0.remote_hosts[i].ip4,
                                    ttl=20,
                                )
                                / UDP(sport=222, dport=223)
                                / Raw()
                            )
                        ),
                    )
                )
                for ii in range(64)
            ]

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

    def Xtest_wg_sending_data_when_admin_down(self):
        """Sending data when admin down"""
        port = 12323

        # create wg interface
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # create a route to rewrite traffic into the wg interface
        r1 = VppIpRoute(
            self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
        ).add_vpp_config()

        # wait for the peer to send a handshake initiation
        rxs = self.pg1.get_capture(1, timeout=2)

        # prepare and send a handshake response
        # expect a keepalive message
        resp = peer_1.consume_init(rxs[0], self.pg1)
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        # verify the keepalive message
        b = peer_1.decrypt_transport(rxs[0])
        self.assertEqual(0, len(b))

        # prepare and send a packet that will be rewritten into the wg interface
        # expect a data packet sent
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        rxs = self.send_and_expect(self.pg0, [p], self.pg1)

        # verify the data packet
        peer_1.validate_encapped(rxs, p)

        # administratively disable the wg interface
        wg0.admin_down()

        # send a packet that will be rewritten into the wg interface
        # expect no data packets sent
        self.send_and_assert_no_replies(self.pg0, [p])

        # administratively enable the wg interface
        # expect the peer to send a handshake initiation
        wg0.admin_up()
        peer_1.noise_reset()
        rxs = self.pg1.get_capture(1, timeout=2)
        resp = peer_1.consume_init(rxs[0], self.pg1)

        # send a packet that will be rewritten into the wg interface
        # expect no data packets sent because the peer is not initiated
        self.send_and_assert_no_replies(self.pg0, [p])
        self.assertEqual(
            self.base_kp4_err + 1, self.statistics.get_err_counter(self.kp4_error)
        )

        # send a handshake response and expect a keepalive message
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        # verify the keepalive message
        b = peer_1.decrypt_transport(rxs[0])
        self.assertEqual(0, len(b))

        # send a packet that will be rewritten into the wg interface
        # expect a data packet sent
        rxs = self.send_and_expect(self.pg0, [p], self.pg1)

        # verify the data packet
        peer_1.validate_encapped(rxs, p)

        # remove configs
        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def _test_wg_large_packet_tmpl(self, is_async, is_ip6):
        self.vapi.wg_set_async_mode(is_async)
        port = 12323

        # create wg interface
        if is_ip6:
            wg0 = VppWgInterface(self, self.pg1.local_ip6, port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip6()
        else:
            wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
            wg0.admin_up()
            wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        if is_ip6:
            peer_1 = VppWgPeer(
                self, wg0, self.pg1.remote_ip6, port + 1, ["1::3:0/112"]
            ).add_vpp_config()
        else:
            peer_1 = VppWgPeer(
                self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
            ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # create a route to rewrite traffic into the wg interface
        if is_ip6:
            r1 = VppIpRoute(
                self, "1::3:0", 112, [VppRoutePath("1::3:1", wg0.sw_if_index)]
            ).add_vpp_config()
        else:
            r1 = VppIpRoute(
                self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
            ).add_vpp_config()

        # wait for the peer to send a handshake initiation
        rxs = self.pg1.get_capture(1, timeout=2)

        # prepare and send a handshake response
        # expect a keepalive message
        resp = peer_1.consume_init(rxs[0], self.pg1, is_ip6=is_ip6)
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        # verify the keepalive message
        b = peer_1.decrypt_transport(rxs[0], is_ip6=is_ip6)
        self.assertEqual(0, len(b))

        # prepare and send data packets
        # expect to receive them decrypted
        if is_ip6:
            ip_header = IPv6(src="1::3:1", dst=self.pg0.remote_ip6, hlim=20)
        else:
            ip_header = IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
        packet_len_opts = (
            2500,  # two buffers
            1500,  # one buffer
            4500,  # three buffers
            1910 if is_ip6 else 1950,  # auth tag is not contiguous
        )
        txs = []
        for l in packet_len_opts:
            txs.append(
                peer_1.mk_tunnel_header(self.pg1, is_ip6=is_ip6)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=len(txs),
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        ip_header / UDP(sport=222, dport=223) / Raw(b"\xfe" * l)
                    ),
                )
            )
        rxs = self.send_and_expect(self.pg1, txs, self.pg0)

        # verify decrypted packets
        for i, l in enumerate(packet_len_opts):
            if is_ip6:
                self.assertEqual(rxs[i][IPv6].dst, self.pg0.remote_ip6)
                self.assertEqual(rxs[i][IPv6].hlim, ip_header.hlim - 1)
            else:
                self.assertEqual(rxs[i][IP].dst, self.pg0.remote_ip4)
                self.assertEqual(rxs[i][IP].ttl, ip_header.ttl - 1)
            self.assertEqual(len(rxs[i][Raw]), l)
            self.assertEqual(bytes(rxs[i][Raw]), b"\xfe" * l)

        # prepare and send packets that will be rewritten into the wg interface
        # expect data packets sent
        if is_ip6:
            ip_header = IPv6(src=self.pg0.remote_ip6, dst="1::3:2")
        else:
            ip_header = IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
        packet_len_opts = (
            2500,  # two buffers
            1500,  # one buffer
            4500,  # three buffers
            1980 if is_ip6 else 2000,  # no free space to write auth tag
        )
        txs = []
        for l in packet_len_opts:
            txs.append(
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / ip_header
                / UDP(sport=555, dport=556)
                / Raw(b"\xfe" * l)
            )
        rxs = self.send_and_expect(self.pg0, txs, self.pg1)

        # verify the data packets
        rxs_decrypted = peer_1.validate_encapped(
            rxs, ip_header, is_tunnel_ip6=is_ip6, is_transport_ip6=is_ip6
        )

        for i, l in enumerate(packet_len_opts):
            self.assertEqual(len(rxs_decrypted[i][Raw]), l)
            self.assertEqual(bytes(rxs_decrypted[i][Raw]), b"\xfe" * l)

        # remove configs
        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    def Xtest_wg_large_packet_v4_sync(self):
        """Large packet (v4, sync)"""
        self._test_wg_large_packet_tmpl(is_async=False, is_ip6=False)

    def Xtest_wg_large_packet_v6_sync(self):
        """Large packet (v6, sync)"""
        self._test_wg_large_packet_tmpl(is_async=False, is_ip6=True)

    def Xtest_wg_large_packet_v4_async(self):
        """Large packet (v4, async)"""
        self._test_wg_large_packet_tmpl(is_async=True, is_ip6=False)

    def Xtest_wg_large_packet_v6_async(self):
        """Large packet (v6, async)"""
        self._test_wg_large_packet_tmpl(is_async=True, is_ip6=True)

    def Xtest_wg_lack_of_buf_headroom(self):
        """Lack of buffer's headroom (v6 vxlan over v6 wg)"""
        port = 12323

        # create wg interface
        wg0 = VppWgInterface(self, self.pg1.local_ip6, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip6()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip6, port + 1, ["::/0"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # create a route to enable communication between wg interface addresses
        r1 = VppIpRoute(
            self, wg0.remote_ip6, 128, [VppRoutePath("0.0.0.0", wg0.sw_if_index)]
        ).add_vpp_config()

        # wait for the peer to send a handshake initiation
        rxs = self.pg1.get_capture(1, timeout=2)

        # prepare and send a handshake response
        # expect a keepalive message
        resp = peer_1.consume_init(rxs[0], self.pg1, is_ip6=True)
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        # verify the keepalive message
        b = peer_1.decrypt_transport(rxs[0], is_ip6=True)
        self.assertEqual(0, len(b))

        # create vxlan interface over the wg interface
        vxlan0 = VppVxlanTunnel(self, src=wg0.local_ip6, dst=wg0.remote_ip6, vni=1111)
        vxlan0.add_vpp_config()

        # create bridge domain
        bd1 = VppBridgeDomain(self, bd_id=1)
        bd1.add_vpp_config()

        # add the vxlan interface and pg0 to the bridge domain
        bd1_ports = (
            VppBridgeDomainPort(self, bd1, vxlan0).add_vpp_config(),
            VppBridgeDomainPort(self, bd1, self.pg0).add_vpp_config(),
        )

        # prepare and send packets that will be rewritten into the vxlan interface
        # expect they to be rewritten into the wg interface then and data packets sent
        tx = (
            Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
            / IPv6(src="::1", dst="::2", hlim=20)
            / UDP(sport=1111, dport=1112)
            / Raw(b"\xfe" * 1900)
        )
        rxs = self.send_and_expect(self.pg0, [tx] * 5, self.pg1)

        # verify the data packet
        for rx in rxs:
            rx_decrypted = IPv6(peer_1.decrypt_transport(rx, is_ip6=True))

            self.assertEqual(rx_decrypted[VXLAN].vni, vxlan0.vni)
            inner = rx_decrypted[VXLAN].payload

            # check the original packet is present
            self.assertEqual(inner[IPv6].dst, tx[IPv6].dst)
            self.assertEqual(inner[IPv6].hlim, tx[IPv6].hlim)
            self.assertEqual(len(inner[Raw]), len(tx[Raw]))
            self.assertEqual(bytes(inner[Raw]), bytes(tx[Raw]))

        # remove configs
        for bdp in bd1_ports:
            bdp.remove_vpp_config()
        bd1.remove_vpp_config()
        vxlan0.remove_vpp_config()
        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()


@tag_fixme_vpp_debug
class PvtiHandoffTests(TestPvti):
    """Pvti Tests in multi worker setup"""

    vpp_worker_count = 2

    def test_wg_peer_init(self):
        """Handoff"""

        port = 12383

        # Create interfaces
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.2.0/24", "10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        r1 = VppIpRoute(
            self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
        ).add_vpp_config()

        # skip the first automatic handshake
        self.pg1.get_capture(1, timeout=HANDSHAKE_JITTER)

        # send a valid handsake init for which we expect a response
        p = peer_1.mk_handshake(self.pg1)

        rx = self.send_and_expect(self.pg1, [p], self.pg1)

        peer_1.consume_response(rx[0])

        # send a data packet from the peer through the tunnel
        # this completes the handshake and pins the peer to worker 0
        p = (
            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
            / UDP(sport=222, dport=223)
            / Raw()
        )
        d = peer_1.encrypt_transport(p)
        p = peer_1.mk_tunnel_header(self.pg1) / (
            Pvti(message_type=4, reserved_zero=0)
            / PvtiTransport(
                receiver_index=peer_1.sender, counter=0, encrypted_encapsulated_packet=d
            )
        )
        rxs = self.send_and_expect(self.pg1, [p], self.pg0, worker=0)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        # and pins the peer tp worker 1
        pe = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw(b"\x00" * 80)
        )
        rxs = self.send_and_expect(self.pg0, pe * 255, self.pg1, worker=1)
        peer_1.validate_encapped(rxs, pe)

        # send packets into the tunnel, from the other worker
        p = [
            (
                peer_1.mk_tunnel_header(self.pg1)
                / Pvti(message_type=4, reserved_zero=0)
                / PvtiTransport(
                    receiver_index=peer_1.sender,
                    counter=ii + 1,
                    encrypted_encapsulated_packet=peer_1.encrypt_transport(
                        (
                            IP(src="10.11.3.1", dst=self.pg0.remote_ip4, ttl=20)
                            / UDP(sport=222, dport=223)
                            / Raw()
                        )
                    ),
                )
            )
            for ii in range(255)
        ]

        rxs = self.send_and_expect(self.pg1, p, self.pg0, worker=1)

        for rx in rxs:
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].ttl, 19)

        # send a packets that are routed into the tunnel
        # from worker 0
        rxs = self.send_and_expect(self.pg0, pe * 255, self.pg1, worker=0)

        peer_1.validate_encapped(rxs, pe)

        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()

    @unittest.skip("test disabled")
    def test_wg_multi_interface(self):
        """Multi-tunnel on the same port"""


@unittest.skipIf(
    "pvti" in config.excluded_plugins, "Exclude Pvti plugin tests"
)
@tag_run_solo
class TestPvtiFIB(VppTestCase):
    """Pvti FIB Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestPvtiFIB, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestPvtiFIB, cls).tearDownClass()

    def setUp(self):
        super(TestPvtiFIB, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestPvtiFIB, self).tearDown()

    def test_wg_fib_tracking(self):
        """FIB tracking"""
        port = 12323

        # create wg interface
        wg0 = VppWgInterface(self, self.pg1.local_ip4, port).add_vpp_config()
        wg0.admin_up()
        wg0.config_ip4()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # create a peer
        peer_1 = VppWgPeer(
            self, wg0, self.pg1.remote_ip4, port + 1, ["10.11.3.0/24"]
        ).add_vpp_config()
        self.assertEqual(len(self.vapi.wireguard_peers_dump()), 1)

        # create a route to rewrite traffic into the wg interface
        r1 = VppIpRoute(
            self, "10.11.3.0", 24, [VppRoutePath("10.11.3.1", wg0.sw_if_index)]
        ).add_vpp_config()

        # resolve ARP and expect the adjacency to update
        self.pg1.resolve_arp()

        # wait for the peer to send a handshake initiation
        rxs = self.pg1.get_capture(2, timeout=6)

        # prepare and send a handshake response
        # expect a keepalive message
        resp = peer_1.consume_init(rxs[1], self.pg1)
        rxs = self.send_and_expect(self.pg1, [resp], self.pg1)

        # verify the keepalive message
        b = peer_1.decrypt_transport(rxs[0])
        self.assertEqual(0, len(b))

        # prepare and send a packet that will be rewritten into the wg interface
        # expect a data packet sent
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="10.11.3.2")
            / UDP(sport=555, dport=556)
            / Raw()
        )
        rxs = self.send_and_expect(self.pg0, [p], self.pg1)

        # verify the data packet
        peer_1.validate_encapped(rxs, p)

        # remove configs
        r1.remove_vpp_config()
        peer_1.remove_vpp_config()
        wg0.remove_vpp_config()
