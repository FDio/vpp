#!/usr/bin/env python3

from __future__ import print_function
import logging
import sys
import os
import select
import signal
import subprocess
import unittest
import re
import time
import faulthandler
import random
import copy
import platform
import shutil
from collections import deque
from threading import Thread, Event
from inspect import getdoc, isclass
from traceback import format_exception
from logging import FileHandler, DEBUG, Formatter
from enum import Enum
from abc import ABC, abstractmethod
from struct import pack, unpack

import scapy.compat
from scapy.packet import Raw, Packet
from vpp_pg_interface import VppPGInterface, is_ipv6_misc
from vpp_sub_interface import VppSubInterface
from vpp_lo_interface import VppLoInterface
from vpp_bvi_interface import VppBviInterface
from vpp_papi_provider import VppPapiProvider
from vpp_papi import VppEnum
import vpp_papi
from vpp_object import VppObjectRegistry
from util import ppp, is_core_present
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import ICMPv6DestUnreach, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply
from vpp_running import use_running
from asfframework import VppAsfTestCase


"""
  Packet Generator / Scapy Test framework module.

  The module provides a set of tools for constructing and running tests and
  representing the results.
"""


class _PacketInfo(object):
    """Private class to create packet info object.

    Help process information about the next packet.
    Set variables to default values.
    """

    #: Store the index of the packet.
    index = -1
    #: Store the index of the source packet generator interface of the packet.
    src = -1
    #: Store the index of the destination packet generator interface
    #: of the packet.
    dst = -1
    #: Store expected ip version
    ip = -1
    #: Store expected upper protocol
    proto = -1
    #: Store the copy of the former packet.
    data = None

    def __repr__(self):
        return f"_PacketInfo index:{self.index} src:{self.src} dst:{self.dst} ip:{self.ip} proto:{self.proto} data:{self.data}"

    def __eq__(self, other):
        index = self.index == other.index
        src = self.src == other.src
        dst = self.dst == other.dst
        data = self.data == other.data
        return index and src and dst and data


@use_running
class VppTestCase(VppAsfTestCase):
    """This subclass is a base class for VPP test cases that are implemented as
    classes. It provides methods to create and run test case.
    """

    @property
    def packet_infos(self):
        """List of packet infos"""
        return self._packet_infos

    @classmethod
    def get_packet_count_for_if_idx(cls, dst_if_index):
        """Get the number of packet info for specified destination if index"""
        if dst_if_index in cls._packet_count_for_dst_if_idx:
            return cls._packet_count_for_dst_if_idx[dst_if_index]
        else:
            return 0

    @classmethod
    def setUpClass(cls):
        super(VppTestCase, cls).setUpClass()
        cls.reset_packet_infos()
        cls._pcaps = []
        cls._old_pcaps = []

    @classmethod
    def tearDownClass(cls):
        cls.logger.debug("--- tearDownClass() for %s called ---" % cls.__name__)
        cls.reset_packet_infos()
        super(VppTestCase, cls).tearDownClass()

    @classmethod
    def pg_enable_capture(cls, interfaces=None):
        """
        Enable capture on packet-generator interfaces

        :param interfaces: iterable interface indexes (if None,
                           use self.pg_interfaces)

        """
        if interfaces is None:
            interfaces = cls.pg_interfaces
        for i in interfaces:
            i.enable_capture()

    @classmethod
    def register_pcap(cls, intf, worker):
        """Register a pcap in the testclass"""
        # add to the list of captures with current timestamp
        cls._pcaps.append((intf, worker))

    @classmethod
    def pg_start(cls, trace=True, traceFilter=False):
        """Enable the PG, wait till it is done, then clean up"""
        for intf, worker in cls._old_pcaps:
            intf.remove_old_pcap_file(intf.get_in_path(worker))
        cls._old_pcaps = []
        if trace:
            cls.vapi.cli("clear trace")
            cls.vapi.cli("trace add pg-input 1000" + (" filter" if traceFilter else ""))
        cls.vapi.cli("packet-generator enable")
        # PG, when starts, runs to completion -
        # so let's avoid a race condition,
        # and wait a little till it's done.
        # Then clean it up  - and then be gone.
        deadline = time.time() + 300
        while cls.vapi.cli("show packet-generator").find("Yes") != -1:
            cls.sleep(0.01)  # yield
            if time.time() > deadline:
                cls.logger.error("Timeout waiting for pg to stop")
                break
        for intf, worker in cls._pcaps:
            cls.vapi.cli("packet-generator delete %s" % intf.get_cap_name(worker))
        cls._old_pcaps = cls._pcaps
        cls._pcaps = []

    @classmethod
    def create_pg_interfaces_internal(
        cls, interfaces, csum_offload=0, gso=0, gso_size=0, mode=None
    ):
        """
        Create packet-generator interfaces.

        :param interfaces: iterable indexes of the interfaces.
        :returns: List of created interfaces.

        """
        result = []
        for i in interfaces:
            intf = VppPGInterface(cls, i, csum_offload, gso, gso_size, mode)
            setattr(cls, intf.name, intf)
            result.append(intf)
        cls.pg_interfaces = result
        return result

    @classmethod
    def create_pg_ip4_interfaces(cls, interfaces, csum_offload=0, gso=0, gso_size=0):
        if not hasattr(cls, "vpp"):
            cls.pg_interfaces = []
            return cls.pg_interfaces
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, csum_offload, gso, gso_size, pgmode.PG_API_MODE_IP4
        )

    @classmethod
    def create_pg_ip6_interfaces(cls, interfaces, csum_offload=0, gso=0, gso_size=0):
        if not hasattr(cls, "vpp"):
            cls.pg_interfaces = []
            return cls.pg_interfaces
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, csum_offload, gso, gso_size, pgmode.PG_API_MODE_IP6
        )

    @classmethod
    def create_pg_interfaces(cls, interfaces, csum_offload=0, gso=0, gso_size=0):
        if not hasattr(cls, "vpp"):
            cls.pg_interfaces = []
            return cls.pg_interfaces
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, csum_offload, gso, gso_size, pgmode.PG_API_MODE_ETHERNET
        )

    @classmethod
    def create_pg_ethernet_interfaces(
        cls, interfaces, csum_offload=0, gso=0, gso_size=0
    ):
        if not hasattr(cls, "vpp"):
            cls.pg_interfaces = []
            return cls.pg_interfaces
        pgmode = VppEnum.vl_api_pg_interface_mode_t
        return cls.create_pg_interfaces_internal(
            interfaces, csum_offload, gso, gso_size, pgmode.PG_API_MODE_ETHERNET
        )

    @classmethod
    def create_loopback_interfaces(cls, count):
        """
        Create loopback interfaces.

        :param count: number of interfaces created.
        :returns: List of created interfaces.
        """
        if not hasattr(cls, "vpp"):
            cls.lo_interfaces = []
            return cls.lo_interfaces
        result = [VppLoInterface(cls) for i in range(count)]
        for intf in result:
            setattr(cls, intf.name, intf)
        cls.lo_interfaces = result
        return result

    @classmethod
    def create_bvi_interfaces(cls, count):
        """
        Create BVI interfaces.

        :param count: number of interfaces created.
        :returns: List of created interfaces.
        """
        if not hasattr(cls, "vpp"):
            cls.bvi_interfaces = []
            return cls.bvi_interfaces
        result = [VppBviInterface(cls) for i in range(count)]
        for intf in result:
            setattr(cls, intf.name, intf)
        cls.bvi_interfaces = result
        return result

    @staticmethod
    def extend_packet(packet, size, padding=" "):
        """
        Extend packet to given size by padding with spaces or custom padding
        NOTE: Currently works only when Raw layer is present.

        :param packet: packet
        :param size: target size
        :param padding: padding used to extend the payload

        """
        packet_len = len(packet) + 4
        extend = size - packet_len
        if extend > 0:
            num = (extend // len(padding)) + 1
            packet[Raw].load += (padding * num)[:extend].encode("ascii")

    @classmethod
    def reset_packet_infos(cls):
        """Reset the list of packet info objects and packet counts to zero"""
        cls._packet_infos = {}
        cls._packet_count_for_dst_if_idx = {}

    @classmethod
    def create_packet_info(cls, src_if, dst_if):
        """
        Create packet info object containing the source and destination indexes
        and add it to the testcase's packet info list

        :param VppInterface src_if: source interface
        :param VppInterface dst_if: destination interface

        :returns: _PacketInfo object

        """
        info = _PacketInfo()
        info.index = len(cls._packet_infos)
        info.src = src_if.sw_if_index
        info.dst = dst_if.sw_if_index
        if isinstance(dst_if, VppSubInterface):
            dst_idx = dst_if.parent.sw_if_index
        else:
            dst_idx = dst_if.sw_if_index
        if dst_idx in cls._packet_count_for_dst_if_idx:
            cls._packet_count_for_dst_if_idx[dst_idx] += 1
        else:
            cls._packet_count_for_dst_if_idx[dst_idx] = 1
        cls._packet_infos[info.index] = info
        return info

    @staticmethod
    def info_to_payload(info):
        """
        Convert _PacketInfo object to packet payload

        :param info: _PacketInfo object

        :returns: string containing serialized data from packet info
        """

        # retrieve payload, currently 18 bytes (4 x ints + 1 short)
        return pack("iiiih", info.index, info.src, info.dst, info.ip, info.proto)

    @staticmethod
    def payload_to_info(payload, payload_field="load"):
        """
        Convert packet payload to _PacketInfo object

        :param payload: packet payload
        :type payload:  <class 'scapy.packet.Raw'>
        :param payload_field: packet fieldname of payload "load" for
                <class 'scapy.packet.Raw'>
        :type payload_field: str
        :returns: _PacketInfo object containing de-serialized data from payload

        """

        # retrieve payload, currently 18 bytes (4 x ints + 1 short)
        payload_b = getattr(payload, payload_field)[:18]

        info = _PacketInfo()
        info.index, info.src, info.dst, info.ip, info.proto = unpack("iiiih", payload_b)

        # some SRv6 TCs depend on get an exception if bad values are detected
        if info.index > 0x4000:
            raise ValueError("Index value is invalid")

        return info

    def get_next_packet_info(self, info):
        """
        Iterate over the packet info list stored in the testcase
        Start iteration with first element if info is None
        Continue based on index in info if info is specified

        :param info: info or None
        :returns: next info in list or None if no more infos
        """
        if info is None:
            next_index = 0
        else:
            next_index = info.index + 1
        if next_index == len(self._packet_infos):
            return None
        else:
            return self._packet_infos[next_index]

    def get_next_packet_info_for_interface(self, src_index, info):
        """
        Search the packet info list for the next packet info with same source
        interface index

        :param src_index: source interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info(info)
            if info is None:
                return None
            if info.src == src_index:
                return info

    def get_next_packet_info_for_interface2(self, src_index, dst_index, info):
        """
        Search the packet info list for the next packet info with same source
        and destination interface indexes

        :param src_index: source interface index to search for
        :param dst_index: destination interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info_for_interface(src_index, info)
            if info is None:
                return None
            if info.dst == dst_index:
                return info

    def assert_packet_checksums_valid(self, packet, ignore_zero_udp_checksums=True):
        received = packet.__class__(scapy.compat.raw(packet))
        udp_layers = ["UDP", "UDPerror"]
        checksum_fields = ["cksum", "chksum"]
        checksums = []
        counter = 0
        temp = received.__class__(scapy.compat.raw(received))
        while True:
            layer = temp.getlayer(counter)
            if layer:
                layer = layer.copy()
                layer.remove_payload()
                for cf in checksum_fields:
                    if hasattr(layer, cf):
                        if (
                            ignore_zero_udp_checksums
                            and 0 == getattr(layer, cf)
                            and layer.name in udp_layers
                        ):
                            continue
                        delattr(temp.getlayer(counter), cf)
                        checksums.append((counter, cf))
            else:
                break
            counter = counter + 1
        if 0 == len(checksums):
            return
        temp = temp.__class__(scapy.compat.raw(temp))
        for layer, cf in reversed(checksums):
            calc_sum = getattr(temp[layer], cf)
            self.assert_equal(
                getattr(received[layer], cf),
                calc_sum,
                "packet checksum on layer #%d: %s" % (layer, temp[layer].name),
            )
            self.logger.debug(
                "Checksum field `%s` on `%s` layer has correct value `%s`"
                % (cf, temp[layer].name, calc_sum)
            )

    def assert_checksum_valid(
        self,
        received_packet,
        layer,
        checksum_field_names=["chksum", "cksum"],
        ignore_zero_checksum=False,
    ):
        """Check checksum of received packet on given layer"""
        layer_copy = received_packet[layer].copy()
        layer_copy.remove_payload()
        field_name = None
        for f in checksum_field_names:
            if hasattr(layer_copy, f):
                field_name = f
                break
        if field_name is None:
            raise Exception(
                f"Layer `{layer}` has none of checksum fields: `{checksum_field_names}`."
            )
        received_packet_checksum = getattr(received_packet[layer], field_name)
        if ignore_zero_checksum and 0 == received_packet_checksum:
            return
        recalculated = received_packet.__class__(scapy.compat.raw(received_packet))
        delattr(recalculated[layer], field_name)
        recalculated = recalculated.__class__(scapy.compat.raw(recalculated))
        self.assert_equal(
            received_packet_checksum,
            getattr(recalculated[layer], field_name),
            f"packet checksum (field: {field_name}) on layer: %s" % layer,
        )

    def assert_ip_checksum_valid(self, received_packet, ignore_zero_checksum=False):
        self.assert_checksum_valid(
            received_packet, "IP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_tcp_checksum_valid(self, received_packet, ignore_zero_checksum=False):
        self.assert_checksum_valid(
            received_packet, "TCP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_udp_checksum_valid(self, received_packet, ignore_zero_checksum=True):
        self.assert_checksum_valid(
            received_packet, "UDP", ignore_zero_checksum=ignore_zero_checksum
        )

    def assert_embedded_icmp_checksum_valid(self, received_packet):
        if received_packet.haslayer(IPerror):
            self.assert_checksum_valid(received_packet, "IPerror")
        if received_packet.haslayer(TCPerror):
            self.assert_checksum_valid(received_packet, "TCPerror")
        if received_packet.haslayer(UDPerror):
            self.assert_checksum_valid(
                received_packet, "UDPerror", ignore_zero_checksum=True
            )
        if received_packet.haslayer(ICMPerror):
            self.assert_checksum_valid(received_packet, "ICMPerror")

    def assert_icmp_checksum_valid(self, received_packet):
        self.assert_checksum_valid(received_packet, "ICMP")
        self.assert_embedded_icmp_checksum_valid(received_packet)

    def assert_icmpv6_checksum_valid(self, pkt):
        if pkt.haslayer(ICMPv6DestUnreach):
            self.assert_checksum_valid(pkt, "ICMPv6DestUnreach")
            self.assert_embedded_icmp_checksum_valid(pkt)
        if pkt.haslayer(ICMPv6EchoRequest):
            self.assert_checksum_valid(pkt, "ICMPv6EchoRequest")
        if pkt.haslayer(ICMPv6EchoReply):
            self.assert_checksum_valid(pkt, "ICMPv6EchoReply")

    def assert_packet_counter_equal(self, counter, expected_value):
        counter_value = self.get_counter(counter)
        self.assert_equal(
            counter_value, expected_value, "packet counter `%s'" % counter
        )

    def pg_send(self, intf, pkts, worker=None, trace=True):
        intf.add_stream(pkts, worker=worker)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start(trace=trace)

    def send_and_assert_no_replies(
        self, intf, pkts, remark="", timeout=None, stats_diff=None, trace=True, msg=None
    ):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        self.pg_send(intf, pkts)

        try:
            if not timeout:
                timeout = 1
            for i in self.pg_interfaces:
                i.assert_nothing_captured(timeout=timeout, remark=remark)
                timeout = 0.1
        finally:
            if trace:
                if msg:
                    self.logger.debug(f"send_and_assert_no_replies: {msg}")
                self.logger.debug(self.vapi.cli("show trace"))

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

    def send_and_expect(
        self,
        intf,
        pkts,
        output,
        n_rx=None,
        worker=None,
        trace=True,
        msg=None,
        stats_diff=None,
        filter_out_fn=is_ipv6_misc,
    ):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        if not n_rx:
            n_rx = 1 if isinstance(pkts, Packet) else len(pkts)
        self.pg_send(intf, pkts, worker=worker, trace=trace)
        rx = output.get_capture(n_rx, filter_out_fn=filter_out_fn)
        if trace:
            if msg:
                self.logger.debug(f"send_and_expect: {msg}")
            self.logger.debug(self.vapi.cli("show trace"))

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

        return rx

    def send_and_expect_load_balancing(
        self, input, pkts, outputs, worker=None, trace=True
    ):
        self.pg_send(input, pkts, worker=worker, trace=trace)
        rxs = []
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx), f"0 != len(rx) ({len(rx)})")
            rxs.append(rx)
        if trace:
            self.logger.debug(self.vapi.cli("show trace"))
        return rxs

    def send_and_expect_some(self, intf, pkts, output, worker=None, trace=True):
        self.pg_send(intf, pkts, worker=worker, trace=trace)
        rx = output._get_capture(1)
        if trace:
            self.logger.debug(self.vapi.cli("show trace"))
        self.assertTrue(len(rx) > 0)
        self.assertTrue(
            len(rx) <= len(pkts), f"len(rx) ({len(rx)}) > len(pkts) ({len(pkts)})"
        )
        return rx

    def send_and_expect_only(self, intf, pkts, output, timeout=None, stats_diff=None):
        if stats_diff:
            stats_snapshot = self.snapshot_stats(stats_diff)

        self.pg_send(intf, pkts)
        rx = output.get_capture(len(pkts))
        outputs = [output]
        if not timeout:
            timeout = 1
        for i in self.pg_interfaces:
            if i not in outputs:
                i.assert_nothing_captured(timeout=timeout)
                timeout = 0.1

        if stats_diff:
            self.compare_stats_with_snapshot(stats_diff, stats_snapshot)

        return rx


if __name__ == "__main__":
    pass
