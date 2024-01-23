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

#
# A custom decoder for Scapy for PVTI packet format
#


class PVTIChunk(Packet):
    name = "PVTIChunk"
    fields_desc = [
        ShortField("total_chunk_length", None),
        XByteField("flags", 0),
        XByteField("_pad0", 0),
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
        ByteField("thread_id", 0),
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
        self.thread_id = 0
        self.tx_chunks = []
        self.tx_n_reass_chunks = 0
        self.tx_seq = 42
        # payload = chunk headers + data
        self.max_payload_len = underlay_mtu - len(raw(IP() / UDP() / PVTI()))
        self.chunk_header_len = len(raw(PVTIChunk()))

    def get_curr_payload_len(self):
        tx_len = 0
        for c in self.tx_chunks:
            tx_len = tx_len + len(c.data)
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
                thread_id=self.thread_id,
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
        p[IP].ttl = p[IP].ttl - 1
        payload_wip = p[IP].build()

        split_chunks = False

        while True:
            available_room = self.get_payload_room()
            chunk_wip_len = len(payload_wip) + self.chunk_header_len
            xpad0 = 0xAB
            xpad1 = 0xABABABAB
            if split_chunks:
                xpad0 = 0xAC
                xpad1 = 0xACACACAC
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
                    data=payload_wip[:chop_len], _pad0=xpad0, _pad1=xpad1, flags=1
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
            rx_pkt = pkt[IP]
            py_pkt = recv2_pkts[i]
            if rx_pkt != py_pkt:
                rx_pkt.show()
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

    def create_packets(self, src_ip_if, count=1, size=150, for_rx=False):
        pkts = []
        total_packet_count = count
        padstr0 = ""
        padstr1 = ""
        for i in range(0, 2000):
            padstr0 = padstr0 + (".%03x" % i)
            padstr1 = padstr1 + ("+%03x" % i)

        for i in range(0, total_packet_count):
            dst_mac = src_ip_if.local_mac
            src_mac = src_ip_if.remote_mac
            if for_rx:
                dst_ip4 = src_ip_if.remote_ip4
                src_ip4 = "10.0.%d.4" % i
            else:
                src_ip4 = src_ip_if.remote_ip4
                dst_ip4 = "10.0.%d.4" % i
            src_l4 = 1234 + i
            dst_l4 = 4321 + i

            ulp = UDP(sport=src_l4, dport=dst_l4)
            payload = "test"
            if i % 2 == 1:
                padstr = padstr1
            else:
                padstr = padstr0

            p = (
                Ether(dst=dst_mac, src=src_mac)
                / IP(src=src_ip4, dst=dst_ip4, frag=0, flags=0)
                / ulp
                / Raw(payload)
            )
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

        # delete interface
        pvti0.remove_vpp_config()
        # self.logger.info(self.vapi.cli("show pvti interface"))
        # pvti0.add_vpp_config()

    def test_0001_pvti_send_simple_1pkt(self):
        """TX: Simple packet: 1 -> 1"""

        self.prepare_for_test("1pkt_simple")
        pkts = self.create_packets(self.pg1)

        recv_pkts = self.send_and_expect(self.pg1, pkts, self.pg0)
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

    def prepare_for_test(self, test_name, underlay_mtu=1500):
        local_port = 12312
        peer_addr = "192.0.2.1"
        peer_port = 31234
        peer_port = 12312
        for i in self.pg_interfaces:
            i.test_name = test_name
        self.pvti0 = VppPvtiInterface(
            self, self.pg1.local_ip4, local_port, peer_addr, peer_port, underlay_mtu
        ).add_vpp_config()
        self.pvti0.config_ip4()
        self.pvti0.admin_up()

        self.logger.info(self.vapi.cli("ip route 0.0.0.0/0 via 172.16.3.3"))
        ## FIXME: using direct "interface" below results in blackouts. intermittently.
        # self.logger.info(self.vapi.cli("ip route 0.0.0.0/0 via pvti0"))
        self.logger.info(self.vapi.cli("ip route add 192.0.2.1/32 via pg0"))
        self.logger.info(self.vapi.cli("ip neighbor pg0 192.0.2.1 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip neighbor pg1 172.16.2.2 000c.0102.0304"))
        self.logger.info(self.vapi.cli("sh int"))
        self.logger.info(self.vapi.cli("sh ip fib"))
        self.logger.info(self.vapi.cli("show pvti interface"))

    def cleanup_after_test(self):
        self.logger.info(self.vapi.cli("ip neighbor del pg0 192.0.2.1 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip neighbor del pg1 172.16.2.2 000c.0102.0304"))
        self.logger.info(self.vapi.cli("ip route del 192.0.2.1/32 via pg0"))
        # self.logger.info(self.vapi.cli("ip route del 0.0.0.0/0 via pvti0"))
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
        """TX: Simple big packets: 5 -> 2"""
        self.prepare_for_test("5big_pkt")

        pkts = self.create_packets(self.pg1, count=5, size=1050)
        self.logger.info("count: %d " % len(pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=2)
        for p in rx:
            self.logger.info(p)
            self.logger.info(len(p[PVTI].chunks[0].data))
            # p.show()

        # payload = rx[0][PVTI].chunks[0].data + rx[1][PVTI].chunks[0].data

        # pkt1 = IP(payload)
        # p0 = pkts[0][IP];
        # p0.ttl = p0.ttl - 1;

        # pkt0 = IP(p0.build())

        # self.assertEqual(pkt0, pkt1)
        self.cleanup_after_test()

    def test_0005_pvti_send_mix_3pkt_medium_mtu(self):
        """TX: small+big+small packets over medium mtu: 3 -> 3"""
        self.prepare_for_test("3pkt_small_mtu", underlay_mtu=400)

        pkts = self.create_packets(self.pg1, count=3, size=500)
        self.logger.info("count: %d " % len(pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=3)
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

        self.cleanup_after_test()

    def test_0006_pvti_send_mix_4pkt_medium_mtu(self):
        """TX: small+big+small packets over 600 mtu: 4 -> 3"""
        self.prepare_for_test("6pkt_small_mtu", underlay_mtu=600)

        pkts = self.create_packets(self.pg1, count=4, size=500)
        self.logger.info("count: %d " % len(pkts))
        # self.logger.info(len(pkts))
        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=3)
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

    def test_0007_pvti_send_simple_1_3_pkt(self):
        """TX: Simple packet: 1 -> 3, small mtu"""

        self.prepare_for_test("1_3_pkt_simple", underlay_mtu=520)
        pkts = self.create_packets(self.pg1, count=1, size=1400)

        recv_pkts = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=3)
        for p in recv_pkts:
            self.logger.info(p)

        self.cleanup_after_test()

    def test_0008_pvti_chained_1_3_pkt(self):
        """TX: Chained packet: 2700 byte 1 -> 3, mtu 1000"""

        self.prepare_for_test("1_3_pkt_simple", underlay_mtu=1000)
        pkts = self.create_packets(self.pg1, count=1, size=2700)

        pkt0 = Ether(raw(pkts[0]))[IP]

        rx = self.send_and_expect(self.pg1, pkts, self.pg0, n_rx=3)
        for p in rx:
            self.logger.info(p)

        p0 = pkts[0][IP]
        p0.ttl = p0.ttl - 1
        pkt0 = IP(p0.build())

        payload = (
            rx[0][PVTI].chunks[0].data
            + rx[1][PVTI].chunks[0].data
            + rx[2][PVTI].chunks[0].data
            + rx[2][PVTI].chunks[1].data
        )
        pkt1 = IP(payload)

        self.assertEqual(pkt0, pkt1)

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

    def X_test_wg_multi_interface(self):
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
