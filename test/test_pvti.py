#!/usr/bin/env python3
""" PVTI tests """

import datetime
import base64
import os
import copy

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
                tx = PVTIChunk(
                    data=payload_wip[:chop_len], _pad0=xpad0, _pad1=xpad1
                )
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
                src_ip4 = "10.0.%d.4" % i
                src_ip6 = "2001:db8::%x" % i
            else:
                src_ip4 = src_ip_if.remote_ip4
                src_ip6 = src_ip_if.remote_ip6
                dst_ip4 = "10.0.%d.4" % i
                dst_ip6 = "2001:db8::%x" % i
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
            src_ip4 = "10.0.%d.4" % i
            src_l4 = 1234 + i
            dst_l4 = 4321 + i

            ulp = UDP(sport=src_l4, dport=dst_l4)
            payload = "test"

            p = IP(src=src_ip4, dst=dst_ip4, frag=0, flags=0) / ulp / Raw(payload)

            # if i % 2 == 1 or total_packet_count == 1:
            #    self.extend_packet(p, size, padstr)
            # else:
            #    self.extend_packet(p, 150, padstr)

            chunk0 = PVTIChunk(data=raw(p))
            chunk1 = PVTIChunk(data=raw(p))
            chunk2 = PVTIChunk(data=raw(p))

            pvti = PVTI(seq=42 + i, chunks=[])
            for j in range(0, 32):
                pvti.chunks.append(chunk0)

            p = (
                Ether(dst=dst_mac, src=src_mac)
                / IP(src="192.0.2.1", dst=rx_intf.local_ip4)
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


# @tag_fixme_vpp_debug
# @unittest.skipIf(True, "WIP")
@unittest.skipIf(
    True,
    "Multiworker PVTI not supported yet"
    # "pvti" in config.excluded_plugins, "Exclude PVTI plugin tests"
)
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


@unittest.skipIf(True or "pvti" in config.excluded_plugins, "Exclude Pvti plugin tests")
# @tag_run_solo
@unittest.skip("WIP")
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

    def xtest_wg_fib_tracking(self):
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
        wg1.remove_vpp_config()
