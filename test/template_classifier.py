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

import binascii
import socket
from socket import AF_INET, AF_INET6
import unittest
import sys
from dataclasses import dataclass

from framework import VppTestCase

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from util import ppp


@dataclass
class VarMask:
    offset: int
    spec: str


@dataclass
class VarMatch:
    offset: int
    value: int
    length: int


class TestClassifier(VppTestCase):

    @staticmethod
    def _resolve_mask_match(mask_match):
        mask_match = binascii.unhexlify(mask_match)
        mask_match_len = ((len(mask_match) - 1) // 16 + 1) * 16
        mask_match = mask_match + b'\0' * \
            (mask_match_len - len(mask_match))
        return mask_match, mask_match_len

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestClassifier, cls).setUpClass()
        cls.acl_active_table = ''
        cls.af = AF_INET

    def setUp(self):
        """
        Perform test setup before test case.

        **Config:**
            - create 4 pg interfaces
                - untagged pg0/pg1/pg2 interface
                    pg0 -------> pg1 (IP ACL)
                           \
                            ---> pg2 (MAC ACL))
                             \
                              -> pg3 (PBR)
            - setup interfaces:
                - put it into UP state
                - set IPv4/6 addresses
                - resolve neighbor address using ARP

        :ivar list interfaces: pg interfaces.
        :ivar list pg_if_packet_sizes: packet sizes in test.
        :ivar dict acl_tbl_idx: ACL table index.
        :ivar int pbr_vrfid: VRF id for PBR test.
        """
        self.reset_packet_infos()
        super(TestClassifier, self).setUp()
        if self.af is None:  # l2_acl test case
            return

        # create 4 pg interfaces
        self.create_pg_interfaces(range(4))

        # packet sizes to test
        self.pg_if_packet_sizes = [64, 9018]

        self.interfaces = list(self.pg_interfaces)

        # ACL & PBR vars
        self.acl_tbl_idx = {}
        self.pbr_vrfid = 200

        # setup all interfaces
        for intf in self.interfaces:
            intf.admin_up()
            if self.af == AF_INET:
                intf.config_ip4()
                intf.resolve_arp()
            elif self.af == AF_INET6:
                intf.config_ip6()
                intf.resolve_ndp()

    def tearDown(self):
        """Run standard test teardown and acl related log."""
        if self.af is not None and not self.vpp_dead:
            if self.af == AF_INET:
                self.logger.info(self.vapi.ppcli("show inacl type ip4"))
                self.logger.info(self.vapi.ppcli("show outacl type ip4"))
            elif self.af == AF_INET6:
                self.logger.info(self.vapi.ppcli("show inacl type ip6"))
                self.logger.info(self.vapi.ppcli("show outacl type ip6"))

            self.logger.info(self.vapi.cli("show classify table verbose"))
            self.logger.info(self.vapi.cli("show ip fib"))
            self.logger.info(self.vapi.cli("show error"))

            if self.acl_active_table.endswith('out'):
                self.output_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
            elif self.acl_active_table != '':
                self.input_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
            self.acl_active_table = ''

            for intf in self.interfaces:
                if self.af == AF_INET:
                    intf.unconfig_ip4()
                elif self.af == AF_INET6:
                    intf.unconfig_ip6()
                intf.admin_down()

        super(TestClassifier, self).tearDown()

    @staticmethod
    def build_mac_match(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL match data with hexstring format.

        :param str dst_mac: source MAC address <x:x:x:x:x:x>
        :param str src_mac: destination MAC address <x:x:x:x:x:x>
        :param str ether_type: ethernet type <0-ffff>
        """
        if dst_mac:
            dst_mac = dst_mac.replace(':', '')
        if src_mac:
            src_mac = src_mac.replace(':', '')

        return ('{!s:0>12}{!s:0>12}{!s:0>4}'.format(
            dst_mac, src_mac, ether_type)).rstrip()

    @staticmethod
    def build_mac_mask(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL mask data with hexstring format.

        :param str dst_mac: source MAC address <0-ffffffffffff>
        :param str src_mac: destination MAC address <0-ffffffffffff>
        :param str ether_type: ethernet type <0-ffff>
        """

        return ('{!s:0>12}{!s:0>12}{!s:0>4}'.format(
            dst_mac, src_mac, ether_type)).rstrip()

    @staticmethod
    def build_ip_mask(proto='', src_ip='', dst_ip='',
                      src_port='', dst_port=''):
        """Build IP ACL mask data with hexstring format.

        :param str proto: protocol number <0-ff>
        :param str src_ip: source ip address <0-ffffffff>
        :param str dst_ip: destination ip address <0-ffffffff>
        :param str src_port: source port number <0-ffff>
        :param str dst_port: destination port number <0-ffff>
        """

        return ('{!s:0>20}{!s:0>12}{!s:0>8}{!s:0>4}{!s:0>4}'.format(
            proto, src_ip, dst_ip, src_port, dst_port)).rstrip('0')

    @staticmethod
    def build_ip6_mask(nh='', src_ip='', dst_ip='',
                       src_port='', dst_port=''):
        """Build IPv6 ACL mask data with hexstring format.

        :param str nh: next header number <0-ff>
        :param str src_ip: source ip address <0-ffffffff>
        :param str dst_ip: destination ip address <0-ffffffff>
        :param str src_port: source port number <0-ffff>
        :param str dst_port: destination port number <0-ffff>
        """

        return ('{!s:0>14}{!s:0>34}{!s:0>32}{!s:0>4}{!s:0>4}'.format(
            nh, src_ip, dst_ip, src_port, dst_port)).rstrip('0')

    @staticmethod
    def build_payload_mask(masks):
        payload_mask = ''

        for mask in masks:
            # offset is specified in bytes, convert to hex format.
            length = (mask.offset * 2) + len(mask.spec)
            format_spec = '{!s:0>' + str(length) + '}'
            payload_mask += format_spec.format(mask.spec)

        return payload_mask.rstrip('0')

    @staticmethod
    def build_ip_match(proto=0, src_ip='', dst_ip='',
                       src_port=0, dst_port=0):
        """Build IP ACL match data with hexstring format.

        :param int proto: protocol number with valid option "x"
        :param str src_ip: source ip address with format of "x.x.x.x"
        :param str dst_ip: destination ip address with format of "x.x.x.x"
        :param int src_port: source port number "x"
        :param int dst_port: destination port number "x"
        """
        if src_ip:
            src_ip = binascii.hexlify(socket.inet_aton(src_ip)).decode('ascii')
        if dst_ip:
            dst_ip = binascii.hexlify(socket.inet_aton(dst_ip)).decode('ascii')

        return ('{!s:0>20}{!s:0>12}{!s:0>8}{!s:0>4}{!s:0>4}'.format(
            hex(proto)[2:], src_ip, dst_ip, hex(src_port)[2:],
            hex(dst_port)[2:])).rstrip('0')

    @staticmethod
    def build_ip6_match(nh=0, src_ip='', dst_ip='',
                        src_port=0, dst_port=0):
        """Build IPv6 ACL match data with hexstring format.

        :param int nh: next header number with valid option "x"
        :param str src_ip: source ip6 address with format of "xxx:xxxx::xxxx"
        :param str dst_ip: destination ip6 address with format of
            "xxx:xxxx::xxxx"
        :param int src_port: source port number "x"
        :param int dst_port: destination port number "x"
        """
        if src_ip:
            if sys.version_info[0] == 2:
                src_ip = binascii.hexlify(socket.inet_pton(
                    socket.AF_INET6, src_ip))
            else:
                src_ip = socket.inet_pton(socket.AF_INET6, src_ip).hex()

        if dst_ip:
            if sys.version_info[0] == 2:
                dst_ip = binascii.hexlify(socket.inet_pton(
                    socket.AF_INET6, dst_ip))
            else:
                dst_ip = socket.inet_pton(socket.AF_INET6, dst_ip).hex()

        return ('{!s:0>14}{!s:0>34}{!s:0>32}{!s:0>4}{!s:0>4}'.format(
            hex(nh)[2:], src_ip, dst_ip, hex(src_port)[2:],
            hex(dst_port)[2:])).rstrip('0')

    @staticmethod
    def build_payload_match(matches):
        payload_match = ''

        for match in matches:
            sval = str(hex(match.value)[2:])
            # offset is specified in bytes, convert to hex format.
            length = (match.offset + match.length) * 2

            format_spec = '{!s:0>' + str(length) + '}'
            payload_match += format_spec.format(sval)

        return payload_match.rstrip('0')

    def create_stream(self, src_if, dst_if, packet_sizes,
                      proto_l=UDP(sport=1234, dport=5678),
                      payload_ex=None):
        """Create input packet stream for defined interfaces.

        :param VppInterface src_if: Source Interface for packet stream.
        :param VppInterface dst_if: Destination Interface for packet stream.
        :param list packet_sizes: packet size to test.
        :param Scapy proto_l: Required IP protocol. Default protocol is UDP.
        """
        pkts = []

        for size in packet_sizes:
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)

            # append any additional payload after info
            if payload_ex is not None:
                payload += payload_ex

            if self.af == AF_INET:
                p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                     IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                     proto_l /
                     Raw(payload))
            elif self.af == AF_INET6:
                p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                     IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6) /
                     proto_l /
                     Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture, proto_l=UDP):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream.
        :param list capture: Captured packet stream.
        :param Scapy proto_l: Required IP protocol. Default protocol is UDP.
        """
        ip_proto = IP
        if self.af == AF_INET6:
            ip_proto = IPv6
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index
        for packet in capture:
            try:
                ip_received = packet[ip_proto]
                proto_received = packet[proto_l]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                ip_saved = saved_packet[ip_proto]
                proto_saved = saved_packet[proto_l]
                # Check standard fields
                self.assertEqual(ip_received.src, ip_saved.src)
                self.assertEqual(ip_received.dst, ip_saved.dst)
                self.assertEqual(proto_received.sport, proto_saved.sport)
                self.assertEqual(proto_received.dport, proto_saved.dport)
            except BaseException:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))

    def create_classify_table(self, key, mask, data_offset=0,
                              next_table_index=None):
        """Create Classify Table

        :param str key: key for classify table (ex, ACL name).
        :param str mask: mask value for interested traffic.
        :param int data_offset:
        :param str next_table_index
        """
        mask_match, mask_match_len = self._resolve_mask_match(mask)
        r = self.vapi.classify_add_del_table(
            is_add=1,
            mask=mask_match,
            mask_len=mask_match_len,
            match_n_vectors=(len(mask) - 1) // 32 + 1,
            miss_next_index=0,
            current_data_flag=1,
            current_data_offset=data_offset,
            next_table_index=next_table_index)
        self.assertIsNotNone(r, 'No response msg for add_del_table')
        self.acl_tbl_idx[key] = r.new_table_index

    def create_classify_session(self, table_index, match, pbr_option=0,
                                vrfid=0, is_add=1):
        """Create Classify Session

        :param int table_index: table index to identify classify table.
        :param str match: matched value for interested traffic.
        :param int pbr_option: enable/disable PBR feature.
        :param int vrfid: VRF id.
        :param int is_add: option to configure classify session.
            - create(1) or delete(0)
        """
        mask_match, mask_match_len = self._resolve_mask_match(match)
        r = self.vapi.classify_add_del_session(
            is_add=is_add,
            table_index=table_index,
            match=mask_match,
            match_len=mask_match_len,
            opaque_index=0,
            action=pbr_option,
            metadata=vrfid)
        self.assertIsNotNone(r, 'No response msg for add_del_session')

    def input_acl_set_interface(self, intf, table_index, is_add=1):
        """Configure Input ACL interface

        :param VppInterface intf: Interface to apply Input ACL feature.
        :param int table_index: table index to identify classify table.
        :param int is_add: option to configure classify session.
            - enable(1) or disable(0)
        """
        r = None
        if self.af == AF_INET:
            r = self.vapi.input_acl_set_interface(
                is_add,
                intf.sw_if_index,
                ip4_table_index=table_index)
        elif self.af == AF_INET6:
            r = self.vapi.input_acl_set_interface(
                is_add,
                intf.sw_if_index,
                ip6_table_index=table_index)
        else:
            r = self.vapi.input_acl_set_interface(
                is_add,
                intf.sw_if_index,
                l2_table_index=table_index)
        self.assertIsNotNone(r, 'No response msg for acl_set_interface')

    def output_acl_set_interface(self, intf, table_index, is_add=1):
        """Configure Output ACL interface

        :param VppInterface intf: Interface to apply Output ACL feature.
        :param int table_index: table index to identify classify table.
        :param int is_add: option to configure classify session.
            - enable(1) or disable(0)
        """
        r = None
        if self.af == AF_INET:
            r = self.vapi.output_acl_set_interface(
                is_add,
                intf.sw_if_index,
                ip4_table_index=table_index)
        elif self.af == AF_INET6:
            r = self.vapi.output_acl_set_interface(
                is_add,
                intf.sw_if_index,
                ip6_table_index=table_index)
        else:
            r = self.vapi.output_acl_set_interface(
                is_add,
                intf.sw_if_index,
                l2_table_index=table_index)
        self.assertIsNotNone(r, 'No response msg for acl_set_interface')

    def config_pbr_fib_entry(self, intf, is_add=1):
        """Configure fib entry to route traffic toward PBR VRF table

        :param VppInterface intf: destination interface to be routed for PBR.

        """
        addr_len = 24
        self.vapi.ip_add_del_route(dst_address=intf.local_ip4,
                                   dst_address_length=addr_len,
                                   next_hop_address=intf.remote_ip4,
                                   table_id=self.pbr_vrfid, is_add=is_add)

    def verify_vrf(self, vrf_id):
        """
        Check if the FIB table / VRF ID is configured.

        :param int vrf_id: The FIB table / VRF ID to be verified.
        :return: 1 if the FIB table / VRF ID is configured, otherwise return 0.
        """
        ip_fib_dump = self.vapi.ip_route_dump(vrf_id, False)
        vrf_count = len(ip_fib_dump)
        if vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d is not configured" % vrf_id)
            return 0
        else:
            self.logger.info("IPv4 VRF ID %d is configured" % vrf_id)
            return 1
