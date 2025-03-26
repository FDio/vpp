#!/usr/bin/env python3
""" PVTI tests """

import datetime
import random
import base64
import os
import copy
import struct

from hashlib import blake2s
from config import config
from scapy.packet import Raw
from scapy.compat import raw
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


from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.fields import (
    FlagsField,
    XByteField,
    XShortField,
    ThreeBytesField,
    ConditionalField,
    ShortField,
    ByteEnumField,
    X3BytesField,
    LEIntField,
    ByteField,
    StrLenField,
    PacketListField,
    LEShortField,
    IntField,
    ShortField,
    XIntField,
)

import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


#
# A custom decoder for Scapy for PVTI packet format
#


class PVTIChunk(Packet):
    name = "PVTIChunk"
    fields_desc = [
        ShortField("total_chunk_length", None),
        XShortField("_pad0", 0),
        XIntField("_pad1", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.total_chunk_length - 8),
    ]

    # This prevents the first chunk from consuming the entire remaining
    # contents of the packet
    def extract_padding(self, s):
        return "", s

    def post_build(self, p, pay):
        if self.total_chunk_length is None and self.data:
            chunk_header_size = 8
            l = chunk_header_size + len(self.data)
            p = struct.pack("!H", l) + p[2:]
        return p + pay


class PVTI(Packet):
    name = "PVTI"
    PVTI_ALIGN_BYTES = 9
    fields_desc = [
        IntField("seq", 0x0),
        ByteField("stream_index", 0),
        ByteField("chunk_count", None),
        ByteField("reass_chunk_count", 0),
        ByteField("mandatory_flags_mask", 0),
        ByteField("flags_value", 0),
        ByteField("pad_bytes", PVTI_ALIGN_BYTES),
        StrLenField(
            "pad", b"\xca" * PVTI_ALIGN_BYTES, length_from=lambda pkt: pkt.pad_bytes
        ),
        PacketListField("chunks", [], PVTIChunk, count_from=lambda p: p.chunk_count),
    ]

    def mysummary(self):
        return self.sprintf("PVTI (len=%PVTI.total_len%)")

    def post_build(self, p, pay):
        if self.chunk_count is None:
            l = len(self.chunks)
            # offset of the chunk count within the fields
            offset_of_chunk_count = 5
            p = (
                p[:offset_of_chunk_count]
                + struct.pack("b", l)
                + p[offset_of_chunk_count + 1 :]
            )
        return p + pay


bind_layers(UDP, PVTI, dport=12312)
# By default, set both ports to the test
# bind_layers(UDP, PVTI, sport=6192, dport=6192)


# PVTI ENcapsulator/DEcapsulator
class PvtiEnDe(object):
    """
    PVTI encapsulator/decapsulator
    """

    def __init__(
        self,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        underlay_mtu=1500,
        for_rx_test=False,
    ):
        self.for_rx_test = for_rx_test
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.underlay_mtu = underlay_mtu
        self.stream_index = 0
        self.tx_chunks = []
        self.tx_n_reass_chunks = 0
        self.tx_seq = 42
        # payload = chunk headers + data
        self.max_payload_len = underlay_mtu - len(raw(IP() / UDP() / PVTI()))
        self.pvti_header_len = len(raw(PVTI()))
        self.chunk_header_len = len(raw(PVTIChunk()))

    def get_curr_payload_len(self):
        tx_len = 0
        for c in self.tx_chunks:
            tx_len = tx_len + len(c.data) + self.chunk_header_len
        return tx_len

    def get_payload_room(self):
        return self.max_payload_len - self.get_curr_payload_len()

    def flush_tx_chunks(self, more_frags=False):
        if self.for_rx_test:
            ip_dst = self.local_ip
            ip_src = self.remote_ip
        else:
            ip_src = self.local_ip
            ip_dst = self.remote_ip
        p = (
            IP(
                src=ip_src,
                dst=ip_dst,
                ttl=127,
                frag=0,
                flags=0,
                id=self.tx_seq,
            )
            / UDP(sport=self.local_port, dport=self.remote_port, chksum=0)
            / PVTI(
                reass_chunk_count=self.tx_n_reass_chunks,
                seq=self.tx_seq,
                stream_index=self.stream_index,
                chunks=self.tx_chunks,
            )
        )

        p = IP(raw(p))

        self.tx_n_reass_chunks = 0
        self.tx_chunks = []
        self.tx_seq = self.tx_seq + 1
        return p

    def encap_pkt(self, p):
        out = []
        if IP in p:
            p[IP].ttl = p[IP].ttl - 1
            payload_wip = p[IP].build()
        elif IPv6 in p:
            p[IPv6].hlim = p[IPv6].hlim - 1
            payload_wip = p[IPv6].build()

        split_chunks = False
        huge_solo_packet = (
            len(payload_wip) + self.chunk_header_len > self.get_payload_room()
        ) and len(self.tx_chunks) == 0

        while True:
            available_room = self.get_payload_room()
            chunk_wip_len = len(payload_wip) + self.chunk_header_len
            xpad0 = 0xABAB
            xpad1 = 0xABABABAB

            if chunk_wip_len <= available_room:
                # happy case - there is enough space to fit the entire chunk
                if split_chunks:
                    self.tx_n_reass_chunks = self.tx_n_reass_chunks + 1
                tx = PVTIChunk(data=payload_wip, _pad0=xpad0, _pad1=xpad1)
                self.tx_chunks.append(tx)
                if chunk_wip_len == available_room:
                    # an unlikely perfect fit - send this packet.
                    out.append(self.flush_tx_chunks())
                break
            elif available_room < self.chunk_header_len + 1:
                # Can not fit even a chunk header + 1 byte of data
                # Flush and retry
                out.append(self.flush_tx_chunks())
                continue
            else:
                # Chop as much as we can from the packet
                chop_len = available_room - self.chunk_header_len
                if split_chunks:
                    self.tx_n_reass_chunks = self.tx_n_reass_chunks + 1
                tx = PVTIChunk(data=payload_wip[:chop_len], _pad0=xpad0, _pad1=xpad1)
                self.tx_chunks.append(tx)
                out.append(self.flush_tx_chunks())
                split_chunks = True
                payload_wip = payload_wip[chop_len:]
                continue
        return out

    def encap_packets(self, pkts):
        out = []
        self.start_encap()
        for p in pkts:
            out.extend(self.encap_pkt(p))
        last_pkt = self.finish_encap()
        if last_pkt != None:
            out.append(last_pkt)
        return out

    def start_encap(self):
        return None

    def finish_encap(self):
        out = None
        if len(self.tx_chunks) > 0:
            out = self.flush_tx_chunks()
        return out


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

    def __init__(
        self, test, local_ip, local_port, remote_ip, remote_port, underlay_mtu=1500
    ):
        super(VppPvtiInterface, self).__init__(test)

        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.underlay_mtu = underlay_mtu

    def get_ende(self, for_rx_test=False):
        return PvtiEnDe(
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.underlay_mtu,
            for_rx_test,
        )

    def verify_encap_packets(self, orig_pkts, recv_pkts):
        ende = self.get_ende()
        recv2_pkts = ende.encap_packets(orig_pkts)
        out1 = []
        out2 = []
        for i, pkt in enumerate(recv_pkts):
            if IP in pkt:
                rx_pkt = pkt[IP]
            elif IPv6 in pkt:
                rx_pkt = pkt[IPv6]
            else:
                raise "Neither IPv4 nor IPv6"
            py_pkt = recv2_pkts[i]
            if rx_pkt != py_pkt:
                eprint("received packet:")
                rx_pkt.show()
                eprint("python packet:")
                py_pkt.show()
            out1.append(rx_pkt)
            out2.append(py_pkt)
        return (out1, out2)

    def add_vpp_config(self):
        r = self.test.vapi.pvti_interface_create(
            interface={
                "local_ip": self.local_ip,
                "local_port": self.local_port,
                "remote_ip": self.remote_ip,
                "remote_port": self.remote_port,
                "underlay_mtu": self.underlay_mtu,
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
                and t.interface.remote_port == self.remote_port
                and str(t.interface.remote_ip) == self.remote_ip
            ):
                self.test.logger.info("QUERY AYXX: true")
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "pvti-%d" % self._sw_if_index


@unittest.skipIf("pvti" in config.excluded_plugins, "Exclude PVTI plugin tests")
# @tag_run_solo
class TestPvti(VppTestCase):
    """Packet Vector Tunnel Interface (PVTI) Test Case"""

    error_str = compile(r"Error")

    # maxDiff = None

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
            cls.create_pg_interfaces(range(2))
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

    def create_packets(
        self, src_ip_if, count=1, size=150, for_rx=False, is_ip6=False, af_mix=False
    ):
        pkts = []
        total_packet_count = count
        padstr0 = ""
        padstr1 = ""
        for i in range(0, 2000):
            padstr0 = padstr0 + (".%03x" % i)
            padstr1 = padstr1 + ("+%03x" % i)

        for i in range(0, total_packet_count):
            if af_mix:
                is_ip6 = i % 2 == 1

            dst_mac = src_ip_if.local_mac
            src_mac = src_ip_if.remote_mac
            if for_rx:
                dst_ip4 = src_ip_if.remote_ip4
                dst_ip6 = src_ip_if.remote_ip6
                src_ip4 = "10.0.%d.4" % (i % 256)
                src_ip6 = "2001:db8::%x" % (i % 256)
            else:
                src_ip4 = src_ip_if.remote_ip4
                src_ip6 = src_ip_if.remote_ip6
                dst_ip4 = "10.0.%d.4" % (i % 256)
                dst_ip6 = "2001:db8::%x" % (i % 256)
            src_l4 = 1234 + i
            dst_l4 = 4321 + i

            ulp = UDP(sport=src_l4, dport=dst_l4)
            payload = "test pkt #%d" % i
            if i % 2 == 1:
                padstr = padstr1
            else:
                padstr = padstr0

            p = Ether(dst=dst_mac, src=src_mac)
            if is_ip6:
                p /= IPv6(src=src_ip6, dst=dst_ip6)
            else:
                p /= IP(src=src_ip4, dst=dst_ip4, frag=0, flags=0)

            p /= ulp / Raw(payload)

            if i % 2 == 1 or total_packet_count == 1:
                self.extend_packet(p, size, padstr)
            else:
                self.extend_packet(p, 150, padstr)
            pkts.append(p)
        return pkts

    def add_rx_ether_header(self, in_pkts, rx_intf=None):
        out = []
        if rx_intf is None:
            rx_intf = self.pg0
        dst_mac = rx_intf.local_mac
        src_mac = rx_intf.remote_mac
        pkts = []
        for p in in_pkts:
            p0 = Ether(dst=dst_mac, src=src_mac) / p[IP]
            out.append(p0)
        return out

    def encap_for_rx_test(self, pkts, rx_intf=None):
        ende = self.pvti0.get_ende(for_rx_test=True)
        encap_pkts = ende.encap_packets(pkts)
        return self.add_rx_ether_header(encap_pkts, rx_intf)

    def decrement_ttl_and_build(self, send_pkts):
        out = []
        pkts = copy.deepcopy(send_pkts)
        for p in pkts:
            p[IP].ttl = p[IP].ttl - 1
            out.append(Ether(p.build()))
        return out

    def create_rx_packets(self, dst_ip_if, rx_intf=None, count=1, size=150):
        pkts = []
        total_packet_count = count
        padstr = ""
        if rx_intf is None:
            rx_intf = self.pg0
        for i in range(0, 2000):
            padstr = padstr + (".%03x" % i)

        dst_mac = rx_intf.local_mac
        src_mac = rx_intf.remote_mac

        for i in range(0, total_packet_count):
            dst_ip4 = dst_ip_if.remote_ip4
            src_ip4 = "10.0.%d.4" % (i % 256)
            src_l4 = 1234 + i
            dst_l4 = 4321 + i

            ulp = UDP(sport=src_l4, dport=dst_l4)
            payload = "test"

            # if i % 2 == 1 or total_packet_count == 1:
            #    self.extend_packet(p, size, padstr)
            # else:
            #    self.extend_packet(p, 150, padstr)

            pvti = PVTI(seq=42 + i, chunks=[])
            for j in range(0, 32):
                p = (
                    IP(src=src_ip4, dst=dst_ip4, frag=0, flags=0, id=j + 0x4000)
                    / ulp
                    / Raw(payload)
                )
                chunk0 = PVTIChunk(data=raw(p))
                pvti.chunks.append(chunk0)

            p = (
                Ether(dst=dst_mac, src=src_mac)
                / IP(src="192.0.2.1", dst=rx_intf.local_ip4, id=0x3000 + i)
                / UDP(sport=12312, dport=12312)
                / pvti
            )
            # p.show()
            # Ether(raw(p)).show()

            pkts.append(p)
        return pkts

    def send_and_assert_no_replies_ignoring_init(
        self, intf, pkts, remark="", timeout=None
    ):
        self.pg_send(intf, pkts)

        def _filter_out_fn(p):
            # return is_ipv6_misc(p) or is_handshake_init(p)
            return is_ipv6_misc(p)

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

    def test_0000_pvti_interface(self):
        """Simple interface creation"""
        local_port = 12312
        peer_addr = self.pg0.remote_ip4  # "192.0.2.1"
        peer_port = 31234
        peer_port = 12312

        # Create interface
        pvti0 = VppPvtiInterface(
            self, self.pg1.local_ip4, local_port, peer_addr, peer_port
        ).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show pvti tx peers"))
        self.logger.info(self.vapi.cli("show pvti rx peers"))

        # delete interface
        pvti0.remove_vpp_config()
        # self.logger.info(self.vapi.cli("show pvti interface"))
        # pvti0.add_vpp_config()

    def test_0001_pvti_send_simple_1pkt(self):
        """v4o4 TX: Simple packet: 1 -> 1"""

        self.prepare_for_test("v4o4_1pkt_simple")
        pkts = self.create_packets(self.pg1)

        recv_pkts = self.send_and_expect(self.pg1, pkts, self.pg0)
        for p in recv_pkts:
            self.logger.info(p)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(pkts, recv_pkts)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0101_pvti_send_simple_1pkt(self):
        """v6o4 TX: Simple packet: 1 -> 1"""

        self.prepare_for_test("v6o4_1pkt_simple")
        pkts = self.create_packets(self.pg1, is_ip6=True)

        recv_pkts = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=1)
        for p in recv_pkts:
            self.logger.info(p)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(pkts, recv_pkts)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0002_pvti_send_simple_2pkt(self):
        """TX: Simple packet: 2 -> 1"""
        self.prepare_for_test("2pkt_simple")

        send_pkts = self.create_packets(self.pg1, count=2)
        pkts = copy.deepcopy(send_pkts)
        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=1)
        for p in rx:
            self.logger.info(p)
            # p.show()

        payload0 = rx[0][PVTI].chunks[0].data
        payload1 = rx[0][PVTI].chunks[1].data

        pktA0 = IP(payload0)
        pktA1 = IP(payload1)

        p0 = pkts[0][IP]
        p0.ttl = p0.ttl - 1
        pktB0 = IP(p0.build())

        p1 = pkts[1][IP]
        p1.ttl = p1.ttl - 1
        pktB1 = IP(p1.build())

        self.assertEqual(pktA0, pktB0)
        self.assertEqual(pktA1, pktB1)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def prepare_for_test(self, test_name, underlay_mtu=1500, is_ip6=False):
        local_port = 12312
        peer_ip4_addr = "192.0.2.1"
        peer_ip6_addr = "2001:db8:dead::1"
        peer_port = 31234
        peer_port = 12312
        for i in self.pg_interfaces:
            i.test_name = test_name
        if is_ip6:
            self.pvti0 = VppPvtiInterface(
                self,
                self.pg1.local_ip6,
                local_port,
                peer_ip6_addr,
                peer_port,
                underlay_mtu,
            ).add_vpp_config()
        else:
            self.pvti0 = VppPvtiInterface(
                self,
                self.pg1.local_ip4,
                local_port,
                peer_ip4_addr,
                peer_port,
                underlay_mtu,
            ).add_vpp_config()
        self.pvti0.config_ip4()
        self.pvti0.config_ip6()
        self.pvti0.admin_up()

        self.logger.info(self.vapi.cli("ip route add 0.0.0.0/0 via 172.16.3.3"))
        ## FIXME: using direct "interface" below results in blackouts. intermittently.
        # self.logger.info(self.vapi.cli("ip route 0.0.0.0/0 via pvti0"))
        self.logger.info(self.vapi.cli("ip route add ::/0 via pvti0"))
        self.logger.info(self.vapi.cli("ip route add 192.0.2.1/32 via pg0"))
        self.logger.info(self.vapi.cli("ip neighbor pg0 192.0.2.1 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip route 2001:db8:dead::1/128 via pg0"))
        self.logger.info(
            self.vapi.cli("ip neighbor pg0 2001:db8:dead::1 000c.0102.0304")
        )
        self.logger.info(self.vapi.cli("ip neighbor pg1 172.16.2.2 000c.0102.0304"))
        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh ip fib"))
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("set interface ip pvti-bypass pg0"))

    def cleanup_after_test(self):
        self.logger.info(self.vapi.cli("ip neighbor del pg0 192.0.2.1 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip neighbor del pg1 172.16.2.2 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip route del 192.0.2.1/32 via pg0"))
        # self.logger.info(self.vapi.cli("ip route del 0.0.0.0/0 via pvti0"))
        self.logger.info(self.vapi.cli("ip route del ::/0 via pvti0"))
        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.pvti0.remove_vpp_config()

    def test_0003_pvti_send_simple_1pkt_big(self):
        """TX: Simple big packet: 1 -> 2"""
        self.prepare_for_test("1big_pkt")

        send_pkts = self.create_packets(self.pg1, count=1, size=1900)
        pkts = copy.deepcopy(send_pkts)
        self.logger.info("count: ")
        self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=2)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()
        payload = rx[0][PVTI].chunks[0].data + rx[1][PVTI].chunks[0].data

        pkt1 = IP(payload)
        p0 = pkts[0][IP]
        p0.ttl = p0.ttl - 1

        pkt0 = IP(p0.build())

        self.assertEqual(pkt0, pkt1)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0004_pvti_send_simple_5pkt_big(self):
        """v4o4 TX: Simple big packets: 5 -> 2"""
        self.prepare_for_test("v4o4_5big_pkt")

        send_pkts = self.create_packets(self.pg1, count=5, size=1050)
        self.logger.info("count: %d " % len(send_pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=2)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0104_pvti_send_simple_5pkt_big(self):
        """v6o4 TX: Simple big packets: 5 -> 2"""
        self.prepare_for_test("v4o4_5big_pkt")

        send_pkts = self.create_packets(self.pg1, count=5, size=1050, is_ip6=True)
        self.logger.info("count: %d " % len(send_pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=2)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def Xtest_0204_pvti_send_simple_5pkt_mix(self):
        """vXo4 TX: Simple packets mix: 5 -> 2"""
        # FIXME: This test is disabled for now, but left here, to have this comment
        # The mix of IPv4 and IPv6 packets in VPP will forward two
        # different graphs, so after encap it will result in two
        # PV packets: one with IPv4 chunks, and one with IPv6 chunks.
        # The python test encapsulator does not do this, and it is probably
        # a useless idea to introduce attempts to mimic this behavior,
        # because in any case one can not expect the orderly scheduling
        # of IPv4 vs IPv6 graph processing.
        self.prepare_for_test("vXo4_5big_pkt")

        send_pkts = self.create_packets(self.pg1, count=5, size=1050, af_mix=True)
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=2)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0005_pvti_send_mix_3pkt_medium_mtu(self):
        """TX: small+big+small packets over medium mtu: 3 -> 3"""
        self.prepare_for_test("3pkt_small_mtu", underlay_mtu=400)

        send_pkts = self.create_packets(self.pg1, count=3, size=500)
        pkts = copy.deepcopy(send_pkts)
        self.logger.info("count: %d " % len(send_pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=3)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()

        # check the middle chunk which is spread across two packets
        payload = rx[0][PVTI].chunks[1].data + rx[1][PVTI].chunks[0].data

        pkt1 = IP(payload)

        p0 = pkts[1][IP]
        p0.ttl = p0.ttl - 1

        pkt0 = IP(p0.build())
        self.assertEqual(pkt0, pkt1)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0006_pvti_send_mix_4pkt_medium_mtu(self):
        """TX: small+big+small packets over 600 mtu: 4 -> 3"""
        self.prepare_for_test("6pkt_small_mtu", underlay_mtu=600)

        send_pkts = self.create_packets(self.pg1, count=4, size=500)
        pkts = copy.deepcopy(send_pkts)
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=3)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()

        # check the middle chunk which is spread across two packets
        payload = rx[0][PVTI].chunks[1].data + rx[1][PVTI].chunks[0].data

        pkt1 = IP(payload)

        p0 = pkts[1][IP]
        p0.ttl = p0.ttl - 1

        pkt0 = IP(p0.build())
        self.assertEqual(pkt0, pkt1)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0007_pvti_send_simple_1_3_pkt(self):
        """TX: Simple packet: 1 -> 3, small mtu"""

        self.prepare_for_test("1_3_pkt_simple", underlay_mtu=520)
        send_pkts = self.create_packets(self.pg1, count=1, size=1400)
        pkts = copy.deepcopy(send_pkts)

        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=3)
        for p in rx:
            self.logger.info(p)

        c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_0008_pvti_chained_1_3_pkt(self):
        """TX: Chained packet: 2700 byte 1 -> 3, mtu 1000"""

        self.prepare_for_test("1_3_pkt_simple", underlay_mtu=1000)
        send_pkts = self.create_packets(self.pg1, count=1, size=2700)
        pkts = copy.deepcopy(send_pkts)

        pkt0 = Ether(raw(pkts[0]))[IP]

        rx = self.send_and_expect(self.pg1, send_pkts, self.pg0, n_rx=3)
        for p in rx:
            self.logger.info(p)

        p0 = pkts[0][IP]
        p0.ttl = p0.ttl - 1
        pkt0 = IP(p0.build())

        payload = (
            rx[0][PVTI].chunks[0].data
            + rx[1][PVTI].chunks[0].data
            + rx[2][PVTI].chunks[0].data
            # + rx[2][PVTI].chunks[1].data
        )
        pkt1 = IP(payload)

        self.assertEqual(pkt0, pkt1)

        # FIXME: this will fail because the send path
        # does not combine the data from two chained blocks.
        # when this succeeds, the above checks in this testcase will need to be redone
        # c_pkts, py_pkts = self.pvti0.verify_encap_packets(send_pkts, rx)
        # self.assertEqual(c_pkts, py_pkts)

        self.cleanup_after_test()

    def test_1001_pvti_rx_simple_1pkt(self):
        """RX: Simple packet: 1 -> 32"""

        self.prepare_for_test("1pkt_rx_simple")
        pkts = self.create_rx_packets(self.pg1, rx_intf=self.pg0)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=32)
        for p in recv_pkts:
            self.logger.info(p)

        self.cleanup_after_test()

    def test_1002_pvti_rx_big_1buf(self):
        """RX: Orig Big packet, single buf: 2 -> 1"""

        self.prepare_for_test("1buf_rx_big")

        pkts_orig = self.create_packets(self.pg1, count=1, size=1900, for_rx=True)
        pkts = self.encap_for_rx_test(pkts_orig, rx_intf=self.pg0)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        known_good_pkts = self.decrement_ttl_and_build(pkts_orig)

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=1)
        for i, p in enumerate(recv_pkts):
            self.logger.info(p)
            self.assertEqual(p[IP], known_good_pkts[i][IP])

        self.cleanup_after_test()

    def test_1003_pvti_rx_big_2buf(self):
        """RX: Very Big packet, chained buf: 3 -> 1"""

        self.prepare_for_test("2buf_rx_big")

        pkts_orig = self.create_packets(self.pg1, count=1, size=3000, for_rx=True)

        pkts = self.encap_for_rx_test(pkts_orig, rx_intf=self.pg0)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        known_good_pkts = self.decrement_ttl_and_build(pkts_orig)

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=1)
        for i, p in enumerate(recv_pkts):
            self.logger.info(p)
            if p[IP] != known_good_pkts[i][IP]:
                p[IP].show()
                known_good_pkts[i][IP].show()
            self.assertEqual(p[IP], known_good_pkts[i][IP])

        self.cleanup_after_test()

    def test_1004_pvti_rx_big_2buf_and_small(self):
        """RX: Very Big packet, chained buf: 3 -> 1 + small pkt"""

        self.prepare_for_test("2buf_rx_big_and_small")

        pkts_orig = self.create_packets(self.pg1, count=2, size=3000, for_rx=True)

        pkts = self.encap_for_rx_test(pkts_orig, rx_intf=self.pg0)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        known_good_pkts = self.decrement_ttl_and_build(pkts_orig)

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=2)
        for i, p in enumerate(recv_pkts):
            self.logger.info(p)
            if p[IP] != known_good_pkts[i][IP]:
                p[IP].show()
                known_good_pkts[i][IP].show()
            self.assertEqual(p[IP], known_good_pkts[i][IP])

        self.cleanup_after_test()

    def test_1005_pvti_rx_big_2buf_and_small_drop(self):
        """RX: Very Big packet, chained buf: 3 -> 1 + small pkt, encap pkt lost"""

        self.prepare_for_test("2buf_rx_big_and_small_drop")

        pkts_orig = self.create_packets(self.pg1, count=3, size=3000, for_rx=True)

        pkts = self.encap_for_rx_test(pkts_orig, rx_intf=self.pg0)
        # drop the second packet after encapsulation (the one with the second frag of the large packet)
        pkts.pop(1)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        known_good_pkts = self.decrement_ttl_and_build(pkts_orig)

        # drop the large original packet, leaving just two small ones
        known_good_pkts.pop(1)

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=2)
        for i, p in enumerate(recv_pkts):
            self.logger.info(p)
            if p[IP] != known_good_pkts[i][IP]:
                p[IP].show()
                known_good_pkts[i][IP].show()
            self.assertEqual(p[IP], known_good_pkts[i][IP])

        self.cleanup_after_test()

    def test_1006_pvti_rx_big_2buf_and_small_drop2(self):
        """RX: Very Big packet, chained buf: 3 -> 1 + small pkt, non-initial frag pkt lost"""

        self.prepare_for_test("2buf_rx_big_and_small_drop2")

        pkts_orig = self.create_packets(self.pg1, count=3, size=6000, for_rx=True)

        pkts = self.encap_for_rx_test(pkts_orig, rx_intf=self.pg0)
        # drop the second packet after encapsulation (the one with the second frag of the large packet)
        pkts.pop(2)
        self.logger.info(self.vapi.cli("show pvti interface"))
        self.logger.info(self.vapi.cli("show udp ports"))

        known_good_pkts = self.decrement_ttl_and_build(pkts_orig)
        # drop the large original packet, leaving just two small ones
        known_good_pkts.pop(1)

        recv_pkts = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=2)
        for i, p in enumerate(recv_pkts):
            self.logger.info(p)
            if p[IP] != known_good_pkts[i][IP]:
                p[IP].show()
                known_good_pkts[i][IP].show()
            self.assertEqual(p[IP], known_good_pkts[i][IP])

        self.cleanup_after_test()

    def test_buffer_allocation_failure(self):
        """Test handling of buffer allocation failures during encapsulation.
        
        This test creates a situation where buffer allocation might fail by
        sending a large number of big packets rapidly, potentially exhausting
        the buffer pool. With the fix, the code should handle allocation failures
        gracefully rather than crashing from null pointer dereference.
        """
        self.prepare_for_test("buffer_alloc_failure")
        
        # Create a large number of packets to increase the chance of buffer exhaustion
        # We're using relatively large packets to consume more buffers
        large_packet_count = 1000  # Adjust based on system capabilities
        large_packets = self.create_packets(self.pg1, count=large_packet_count, size=random.randint(10,6000))
        
        try:
            # Send the packets in rapid succession
            # We're not making specific assertions here - we're just testing that
            # VPP doesn't crash when buffer allocations fail
            for i in range(0, large_packet_count, 300):
                batch = large_packets[i:i+300]
                self.pg1.add_stream(batch)
                self.pg_start()
                
            # Allow time for processing
            self.sleep(1)
            
            # If we get here without a crash, the test has succeeded
            self.logger.info("Buffer allocation failure handling test completed successfully")
        finally:
            self.cleanup_after_test()

    def X_test_malformed_chunk_length(self):
        """Test handling of malformed chunk lengths.
        
        This test creates packets with invalid chunk lengths to test
        proper validation and error handling in the decapsulation path.
        """
        self.prepare_for_test("malformed_chunk_length")
        
        # Create a packet with crafted malformed chunk length
        orig_pkt = self.create_packets(self.pg1, count=1, size=200)[0]
        ende = self.pvti0.get_ende(for_rx_test=True)
        encap_pkts = ende.encap_packets([orig_pkt])
        
        # Modify the packet to have an invalid chunk length
        pkt = encap_pkts[0]
        
        # Access the PVTI layer and first chunk
        pvti_layer = pkt[PVTI]
        chunk = pvti_layer.chunks[0]
        
        # Set an invalid length that exceeds the packet size
        original_length = chunk.total_chunk_length
        chunk.total_chunk_length = 65000  # Much larger than actual data
        
        # Rebuild the packet with modified chunk length
        modified_pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                        IP(src=pkt[IP].src, dst=pkt[IP].dst) /
                        UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport) /
                        pvti_layer)
        
        try:
            # Send the malformed packet
            # VPP should drop it without crashing
            self.pg_send(self.pg0, [modified_pkt])
            
            # Allow time for processing
            self.sleep(0.5)
            
            # If we get here without a crash, the test has succeeded
            self.logger.info("Malformed chunk length test completed successfully")
        finally:
            self.cleanup_after_test()

    def test_reassembly_buffer_allocation_failure(self):
        """Test reassembly behavior when buffer allocation fails.
        
        This test creates a scenario where buffer allocation might fail
        during packet reassembly by sending very large fragmented packets.
        """
        self.prepare_for_test("reassembly_buffer_failure", underlay_mtu=500)
        
        try:
            # Create a very large packet that will be fragmented
            large_pkt = self.create_packets(self.pg1, count=1, size=6000)[0]
            
            # Create multiple large packets to strain buffer resources
            large_pkts = []
            for i in range(20):
                # Make each packet slightly different
                pkt_copy = large_pkt.copy()
                if IP in pkt_copy:
                    pkt_copy[IP].id = i
                large_pkts.append(pkt_copy)
            
            # Send them all at once to increase chance of allocation failures
            self.pg1.add_stream(large_pkts)
            self.pg_start()
            
            # Allow time for processing
            self.sleep(1)
            
            # Verify VPP is still running (no crash)
            self.logger.info(self.vapi.cli("show pvti interface"))
            
            # If we get here without a crash, the test has succeeded
            self.logger.info("Reassembly buffer allocation failure test completed successfully")
        finally:
            self.cleanup_after_test()

import random
import struct

class TestPvtiFuzzingAndEdgeCases(TestPvti):
    """Tests focusing on fuzzing and edge cases to find potential memory corruption bugs"""

    def test_malformed_chunk_headers(self):
        """RX: Test with malformed chunk headers"""
        self.prepare_for_test("malformed_chunk_headers")
        
        # Create a packet as base
        pkt = self.create_packets(self.pg1, count=1, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        # Create packets with various chunk header corruptions
        malformed_pkts = []
        
        # 1. Invalid _pad0 and _pad1 values
        chunk1 = PVTIChunk(data=ip_payload)
        chunk1._pad0 = 0xDEAD
        chunk1._pad1 = 0xDEADBEEF
        
        p1 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=42, chunk_count=1, chunks=[chunk1])
        malformed_pkts.append(p1)
        
        # 2. Zero length chunk
        chunk2 = PVTIChunk(total_chunk_length=8, data=b"")  # Just the header
        
        p2 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=43, chunk_count=1, chunks=[chunk2])
        malformed_pkts.append(p2)
        
        # 3. Chunk with invalid flags
        # Creating raw chunk with specific flag bits set
        raw_chunk_data = b"\x00\x20"  # Length field (32 bytes)
        raw_chunk_data += b"\x03\x00"  # Both MB and MF flags set
        raw_chunk_data += b"\x00\x00\x00\x00"  # pad fields
        raw_chunk_data += ip_payload[:24]  # Some data to match length
        
        p3 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=44, chunk_count=1, chunks=[]) / \
             Raw(raw_chunk_data)
        malformed_pkts.append(p3)
        
        # Send packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, malformed_pkts)
        
        self.cleanup_after_test()

    def test_fuzz_pvti_header_fields(self):
        """RX: Fuzz test for PVTI header fields"""
        self.prepare_for_test("fuzz_pvti_header")
        
        # Create a packet as base
        pkt = self.create_packets(self.pg1, count=1, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        # Create a basic chunk for our packets
        basic_chunk = PVTIChunk(data=ip_payload)
        
        # Generate 20 packets with randomized header fields
        fuzz_pkts = []
        for i in range(20):
            # Randomize various fields
            seq = random.randint(0, 0xFFFFFFFF)
            stream_idx = random.randint(0, 255)
            chunk_count = 1  # Keep this valid
            reass_chunk_count = random.randint(0, 1)  # 0 or 1
            mandatory_mask = random.randint(0, 255)
            flags_value = random.randint(0, 255)
            pad_bytes = random.randint(0, 16)  # Randomize padding
            
            # Create packet with these fields
            p = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                UDP(sport=12312, dport=12312) / \
                PVTI(seq=seq, stream_index=stream_idx,
                     chunk_count=chunk_count, reass_chunk_count=reass_chunk_count,
                     mandatory_flags_mask=mandatory_mask, flags_value=flags_value,
                     pad_bytes=pad_bytes, chunks=[basic_chunk])
            
            fuzz_pkts.append(p)
        
        # Send packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, fuzz_pkts)
        
        self.cleanup_after_test()

    def test_chunked_non_ip_payload(self):
        """RX: Test with non-IP payload in chunks"""
        self.prepare_for_test("non_ip_payload")
        
        # Create various non-IP payloads
        payloads = [
            b"\xDE\xAD\xBE\xEF" * 100,  # Random non-IP data
            b"\x00" * 400,  # All zeros
            b"\xFF" * 400,  # All ones
            b"HTTP/1.1 200 OK\r\nContent-Length: 300\r\n\r\n" + b"X" * 300,  # HTTP-like
        ]
        
        non_ip_pkts = []
        for i, payload in enumerate(payloads):
            p = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                UDP(sport=12312, dport=12312) / \
                PVTI(seq=42+i, chunk_count=1, chunks=[PVTIChunk(data=payload)])
            non_ip_pkts.append(p)
        
        # Send packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, non_ip_pkts)
        
        self.cleanup_after_test()

    def test_overlapping_reassembly(self):
        """RX: Test with overlapping reassembly chunks"""
        self.prepare_for_test("overlapping_reassembly")
        
        # Create a packet
        pkt = self.create_packets(self.pg1, count=1, size=1000, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        # Create 3 chunks with overlapping data
        # Chunk 1: bytes 0-500
        # Chunk 2: bytes 400-800 (overlaps with 1)
        # Chunk 3: bytes 700-1000 (overlaps with 2)
        
        p1 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=42, chunk_count=1, reass_chunk_count=1,
                  chunks=[PVTIChunk(data=ip_payload[:500])])
        
        p2 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=43, chunk_count=1, reass_chunk_count=1,
                  chunks=[PVTIChunk(data=ip_payload[400:800])])
        
        p3 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=44, chunk_count=1, reass_chunk_count=1,
                  chunks=[PVTIChunk(data=ip_payload[700:])])
        
        # Send in different orders to test different reassembly scenarios
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p1, p2, p3])
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p2, p1, p3])
        self.send_and_assert_no_replies_ignoring_init(self.pg0, [p3, p2, p1])
        
        self.cleanup_after_test()

    def test_fragment_boundary_cases(self):
        """RX: Test fragment boundary cases"""
        self.prepare_for_test("fragment_boundary")
        
        # Create a packet
        pkt = self.create_packets(self.pg1, count=1, size=100, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        boundary_pkts = []
        
        # 1. Minimal fragment (1 byte)
        p1 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=42, chunk_count=1, reass_chunk_count=1,
                  chunks=[PVTIChunk(data=ip_payload[:1])])
        boundary_pkts.append(p1)
        
        # 2. Second fragment completes it
        p2 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
             IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
             UDP(sport=12312, dport=12312) / \
             PVTI(seq=43, chunk_count=1, reass_chunk_count=1,
                  chunks=[PVTIChunk(data=ip_payload[1:])])
        boundary_pkts.append(p2)
        
        # 3. Fragments at IP header boundaries
        if len(ip_payload) >= 40:  # Make sure payload is long enough
            # First fragment ends exactly at IP header end
            p3 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                 IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                 UDP(sport=12312, dport=12312) / \
                 PVTI(seq=44, chunk_count=1, reass_chunk_count=1,
                      chunks=[PVTIChunk(data=ip_payload[:20])])  # IP header length
            boundary_pkts.append(p3)
            
            # Second fragment starts right after IP header
            p4 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                 IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                 UDP(sport=12312, dport=12312) / \
                 PVTI(seq=45, chunk_count=1, reass_chunk_count=1,
                      chunks=[PVTIChunk(data=ip_payload[20:])])
            boundary_pkts.append(p4)
        
        # Send packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, boundary_pkts)
        
        self.cleanup_after_test()

    def XXCrashXX_test_binary_fuzzing(self):
        """RX: Test with binary fuzzing of packets"""
        self.prepare_for_test("binary_fuzzing")
        
        # Create a basic valid packet
        pkt = self.create_packets(self.pg1, count=1, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        valid_pvti = PVTI(seq=42, chunk_count=1, chunks=[PVTIChunk(data=ip_payload)])
        valid_raw = raw(valid_pvti)
        
        fuzz_pkts = []
        
        # Create 20 fuzzed variations
        for i in range(20):
            fuzzed_raw = bytearray(valid_raw)
            
            # Introduce random mutations
            num_mutations = random.randint(1, 5)
            for _ in range(num_mutations):
                # Pick a random position, avoiding the first few header bytes
                pos = random.randint(4, len(fuzzed_raw) - 1)
                # Apply a random mutation
                mutation_type = random.randint(0, 2)
                
                if mutation_type == 0:
                    # Bit flip
                    bit_pos = random.randint(0, 7)
                    fuzzed_raw[pos] ^= (1 << bit_pos)
                elif mutation_type == 1:
                    # Byte replacement
                    fuzzed_raw[pos] = random.randint(0, 255)
                else:
                    # Byte swapping if possible
                    if pos < len(fuzzed_raw) - 1:
                        fuzzed_raw[pos], fuzzed_raw[pos+1] = fuzzed_raw[pos+1], fuzzed_raw[pos]
            
            # Create packet with fuzzed payload
            p = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                UDP(sport=12312, dport=12312) / \
                Raw(bytes(fuzzed_raw))
            
            fuzz_pkts.append(p)
        
        # Send fuzzed packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, fuzz_pkts)
        
        self.cleanup_after_test()

    def test_rogue_peer(self):
        """Test with a rogue peer changing addresses"""
        self.prepare_for_test("rogue_peer")
        
        # Create a standard packet
        base_pkt = self.create_packets(self.pg1, count=1, for_rx=True)[0]
        ip_payload = raw(base_pkt[IP])
        
        # Send packets from different IPs but same port
        rogue_pkts = []
        
        for i in range(10):
            src_ip = f"192.168.{i}.{i+1}"
            
            p = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                IP(src=src_ip, dst=self.pg0.local_ip4) / \
                UDP(sport=12312, dport=12312) / \
                PVTI(seq=42+i, chunk_count=1, chunks=[PVTIChunk(data=ip_payload)])
            
            rogue_pkts.append(p)
        
        # Send packets
        self.send_and_assert_no_replies_ignoring_init(self.pg0, rogue_pkts)
        
        self.cleanup_after_test()

    def test_race_condition_simulation(self):
        """Test race condition simulation with rapid parallel processing"""
        self.prepare_for_test("race_condition")
        
        # Simulate race conditions by sending packets that would typically
        # be processed in parallel in a real multi-threaded environment
        
        # Create packets for multiple streams with interleaved sequence
        race_pkts = []
        
        # Base packet
        pkt = self.create_packets(self.pg1, count=1, for_rx=True)[0]
        ip_payload = raw(pkt[IP])
        
        # Create a series of packets for 2 streams with interleaved sequence
        for i in range(10):
            # Stream 0, even sequences
            p1 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                 IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                 UDP(sport=12312, dport=12312) / \
                 PVTI(seq=i*2, stream_index=0, chunk_count=1, 
                      chunks=[PVTIChunk(data=ip_payload)])
            
            # Stream 1, odd sequences
            p2 = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) / \
                 IP(src="192.0.2.1", dst=self.pg0.local_ip4) / \
                 UDP(sport=12312, dport=12312) / \
                 PVTI(seq=i*2+1, stream_index=1, chunk_count=1, 
                      chunks=[PVTIChunk(data=ip_payload)])
            
            # Add in scrambled order to simulate race
            if i % 2 == 0:
                race_pkts.extend([p1, p2])
            else:
                race_pkts.extend([p2, p1])
        
        # Send in a burst to maximize processing overlap
        self.pg_send(self.pg0, race_pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        
        self.cleanup_after_test()

class PvtiHandoffTests(TestPvti):
    """Pvti Tests in multi worker setup"""

    vpp_worker_count = 2

    def xtest_wg_peer_init(self):
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

import time
import threading
import copy
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

class TestPvtiTxCrashConditions(TestPvti):
    """Tests focusing on crashing the TX path in PVTI implementation with corrected interface references"""

    def get_interface_name(self, sw_if_index):
        """Helper function to get interface name from sw_if_index"""
        # For PVTI interfaces, the name format is pvti{instance_num}
        # First get the internal instance number from our test class
        ifaces = self.vapi.pvti_interface_dump(sw_if_index=sw_if_index)
        for iface in ifaces:
            if iface.interface.sw_if_index == sw_if_index:
                # Found the interface
                # Now get the actual interface name from sw_interface_dump
                sw_if = self.vapi.sw_interface_dump(sw_if_index=sw_if_index)
                if sw_if:
                    return sw_if[0].interface_name

        # Fallback - could be inaccurate but better than nothing
        return f"pvti{sw_if_index}"

    def test_tx_buffer_exhaustion(self):
        """TX: Test exhausting buffer pool during transmission"""
        self.prepare_for_test("tx_buffer_exhaustion")

        # Get the interface name for CLI commands
        pvti_name = self.get_interface_name(self.pvti0.sw_if_index)

        # Create a large number of extremely large packets
        # Each packet will need to be fragmented and consume multiple buffers
        jumbo_pkts = []
        for i in range(200):  # Generate enough to potentially exhaust buffer pool
            size = 9000  # Jumbo frame size
            pkt = self.create_packets(self.pg1, count=1, size=size)[0]
            jumbo_pkts.append(pkt)

        # Send packets in quick succession
        # Break into multiple bursts to further stress the system
        burst_size = 50
        for i in range(0, len(jumbo_pkts), burst_size):
            burst = jumbo_pkts[i:i+burst_size]
            self.pg_send(self.pg1, burst)
            # Small wait between bursts to allow partial processing
            time.sleep(0.01)

        # Wait for completion and check if VPP is still alive
        time.sleep(1)
        try:
            # Try to execute a simple CLI command
            self.vapi.cli("show version")
        except Exception as e:
            self.logger.error(f"VPP may have crashed: {e}")

        self.cleanup_after_test()

    def test_tx_rapid_underlay_changes(self):
        """TX: Test rapidly changing underlay FIB during transmission"""
        self.prepare_for_test("tx_underlay_changes")

        # Get the interface name for CLI commands
        pvti_name = self.get_interface_name(self.pvti0.sw_if_index)

        # Prepare packets
        pkts = self.create_packets(self.pg1, count=100, size=1000)

        # Function to rapidly change the underlay FIB index
        def change_underlay_fib():
            for i in range(20):
                # Create a new table
                table_id = 100 + i
                self.vapi.cli(f"ip table add {table_id}")
                # Switch underlay to this table - USE INTERFACE NAME
                self.vapi.cli(f"set interface ip table {pvti_name} {table_id}")
                time.sleep(0.02)  # Short delay between changes

        # Start thread to change underlay during transmission
        change_thread = threading.Thread(target=change_underlay_fib)
        change_thread.start()

        # Send packets while underlay is changing
        self.pg_send(self.pg1, pkts)

        # Wait for changes to complete
        change_thread.join()

        # Clean up the tables we created
        for i in range(20):
            table_id = 100 + i
            try:
                self.vapi.cli(f"ip table del {table_id}")
            except:
                pass

        self.cleanup_after_test()

    def test_tx_rapid_interface_flapping(self):
        """TX: Test rapidly toggling interface state during transmission"""
        self.prepare_for_test("tx_interface_flapping")

        # Get the interface name for CLI commands
        pvti_name = self.get_interface_name(self.pvti0.sw_if_index)

        # Prepare a large batch of packets
        batch_size = 200
        large_pkts = self.create_packets(self.pg1, count=batch_size, size=1500)

        # Function to rapidly toggle interface state
        def flap_interface():
            for i in range(20):
                # Toggle interface state down - USE INTERFACE NAME
                self.vapi.cli(f"set interface state {pvti_name} down")
                time.sleep(0.01)
                # Toggle interface state up - USE INTERFACE NAME
                self.vapi.cli(f"set interface state {pvti_name} up")
                time.sleep(0.01)

        # Start flapping thread
        flap_thread = threading.Thread(target=flap_interface)
        flap_thread.start()

        # Send packets while interface is flapping
        self.pg_send(self.pg1, large_pkts)

        # Wait for flapping to complete
        flap_thread.join()

        self.cleanup_after_test()

    def test_tx_mtu_changes_during_send(self):
        """TX: Test changing MTU during active transmission"""
        self.prepare_for_test("tx_mtu_changes")

        # Get the interface name for CLI commands
        pvti_name = self.get_interface_name(self.pvti0.sw_if_index)

        # Prepare packets larger than the smallest MTU we'll use
        pkts = self.create_packets(self.pg1, count=100, size=1500)

        # Function to randomly change MTU
        def change_mtu():
            for i in range(20):
                # Randomly change between very small and large MTUs
                mtu = [68, 500, 1500, 4000, 9000][i % 5]
                # Use interface name instead of sw_if_index
                self.vapi.cli(f"set interface mtu {mtu} {pvti_name}")
                time.sleep(0.02)

        # Start MTU change thread
        mtu_thread = threading.Thread(target=change_mtu)
        mtu_thread.start()

        # Send packets while MTU is changing
        self.pg_send(self.pg1, pkts)

        # Wait for MTU changes to complete
        mtu_thread.join()

        self.cleanup_after_test()

    def test_tx_multi_interface_peer_collision(self):
        """TX: Test multiple interfaces with duplicate remote peer info"""
        # Create multiple interfaces pointing to the same remote peer
        interfaces = []
        interface_names = []

        for i in range(10):
            # Same remote IP and port for all interfaces
            local_port = 12312 + i
            peer_addr = "192.0.2.1"  # Same for all
            peer_port = 12312  # Same for all

            pvti = VppPvtiInterface(
                self, self.pg1.local_ip4, local_port, peer_addr, peer_port
            ).add_vpp_config()
            pvti.admin_up()
            pvti.config_ip4()
            interfaces.append(pvti)

            # Get interface name for CLI commands
            iface_name = self.get_interface_name(pvti.sw_if_index)
            interface_names.append(iface_name)

            # Set up routes through this interface - USE INTERFACE NAME
            self.vapi.cli(f"ip route add 10.{i}.0.0/24 via {iface_name}")

        # Add neighbor entry for the remote peer
        self.vapi.cli(f"ip neighbor pg0 192.0.2.1 000c.0102.0304")

        # Now send packets to different destinations, all going through different
        # interfaces but to the same remote peer
        for i in range(10):
            dst_ip = f"10.{i}.0.1"
            pkt = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst=dst_ip) /
                  UDP(sport=1234, dport=4321) /
                  Raw(b"test packet"))

            # Send in a burst to stress the system
            self.pg_send(self.pg1, [pkt] * 10)

        # Clean up
        self.vapi.cli(f"ip neighbor del pg0 192.0.2.1 000c.0102.0304")
        for i, pvti in enumerate(interfaces):
            # Use interface name for CLI commands
            self.vapi.cli(f"ip route del 10.{i}.0.0/24 via {interface_names[i]}")
            pvti.remove_vpp_config()

    def test_tx_rapid_mtu_boundary_packets(self):
        """TX: Test with packets right at MTU boundaries with rapid MTU changes"""
        self.prepare_for_test("tx_mtu_boundary", underlay_mtu=1000)

        # Get the interface name for CLI commands
        pvti_name = self.get_interface_name(self.pvti0.sw_if_index)

        # Create packets exactly at MTU boundary
        # In pvti_output_node_common, the max_payload_len is calculated as:
        # underlay_mtu - len(raw(IP() / UDP() / PVTI()))
        # This will be about 1000 - ~40 = ~960 bytes

        # We'll create packets just below, exactly at, and just above this threshold
        sizes = [958, 959, 960, 961, 962]
        boundary_pkts = []

        for size in sizes:
            pkt = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst="10.0.0.1") /
                  UDP(sport=1234, dport=4321) /
                  Raw(b"X" * size))
            boundary_pkts.append(pkt)

        # Function to rapidly change MTU right around our packet sizes
        def change_mtu_at_boundary():
            mtus = [958, 959, 960, 961, 962, 963]
            for mtu in mtus:
                # Use interface name for CLI commands
                self.vapi.cli(f"set interface mtu {mtu} {pvti_name}")
                time.sleep(0.02)

        # Start MTU change thread
        mtu_thread = threading.Thread(target=change_mtu_at_boundary)
        mtu_thread.start()

        # Send boundary packets repeatedly while MTU is changing
        for _ in range(10):
            for pkt in boundary_pkts:
                self.pg_send(self.pg1, [pkt])
                time.sleep(0.01)

        # Wait for MTU changes to complete
        mtu_thread.join()

        self.cleanup_after_test()

    def test_tx_concurrent_buffer_allocation(self):
        """TX: Test concurrent buffer allocation from multiple threads"""
        # This test requires VPP with multiple worker threads
        self.prepare_for_test("tx_concurrent_allocation")

        # Ensure we have multiple worker threads
        num_workers = int(self.vapi.cli("show threads").count("worker"))
        if num_workers < 2:
            self.logger.info("Skipping test_tx_concurrent_buffer_allocation - requires multiple workers")
            self.cleanup_after_test()
            return

        # Create multiple interfaces
        interfaces = []
        interface_names = []

        for i in range(num_workers):
            local_port = 12312 + i
            peer_addr = f"192.0.2.{i+1}"
            peer_port = 12312

            pvti = VppPvtiInterface(
                self, self.pg1.local_ip4, local_port, peer_addr, peer_port
            ).add_vpp_config()
            pvti.admin_up()
            pvti.config_ip4()
            interfaces.append(pvti)

            # Get interface name for CLI commands
            iface_name = self.get_interface_name(pvti.sw_if_index)
            interface_names.append(iface_name)

            # Set up routes - USE INTERFACE NAME
            self.vapi.cli(f"ip route add 10.{i}.0.0/16 via {iface_name}")
            self.vapi.cli(f"ip neighbor pg0 {peer_addr} 000c.0102.0304")

        # Create packets for each worker
        worker_pkts = []
        for i in range(num_workers):
            pkts = []
            for j in range(200):
                dst_ip = f"10.{i}.0.{j+1}"
                pkt = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                      IP(src=self.pg1.remote_ip4, dst=dst_ip) /
                      UDP(sport=1234, dport=4321) /
                      Raw(b"test" * 100))
                pkts.append(pkt)
            worker_pkts.append(pkts)

        # Define function to send packets for a specific worker
        def send_worker_packets(worker_id):
            self.pg_send(self.pg1, worker_pkts[worker_id])

        # Start threads for each worker simultaneously
        threads = []
        for i in range(num_workers):
            thread = threading.Thread(target=send_worker_packets, args=(i,))
            threads.append(thread)

        # Start all threads simultaneously to maximize concurrency
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Clean up
        for i, pvti in enumerate(interfaces):
            # Use interface name for CLI commands
            self.vapi.cli(f"ip route del 10.{i}.0.0/16 via {interface_names[i]}")
            self.vapi.cli(f"ip neighbor del pg0 192.0.2.{i+1} 000c.0102.0304")
            pvti.remove_vpp_config()
