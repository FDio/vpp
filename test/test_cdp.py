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
""" CDP tests """

from scapy.packet import Packet
from scapy.all import ShortField, StrField
from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgSoftwareVersion, \
        CDPMsgPlatform, CDPMsgPortID, CDPv2_HDR

from framework import VppTestCase
from scapy.all import raw
from re import compile
from time import sleep
from util import ppp
import platform
import sys
import unittest


""" TestCDP is a subclass of  VPPTestCase classes.

CDP test.

"""


class CustomTLV(Packet):
    """ Custom TLV protocol layer for scapy """

    fields_desc = [
        ShortField("type", 0),
        ShortField("length", 4),
        StrField("value", "")

    ]


class TestCDP(VppTestCase):
    """ CDP Test Case """

    nen_ptr = compile(r"not enabled")
    cdp_ptr = compile(r"^([-\.\w]+)\s+([-\.\w]+)\s+([-\.\w]+)\s+([-\.\w]+)$")
    err_ptr = compile(r"^([\d]+)\s+([-\w]+)\s+([ -\.\w)(]+)$")

    @property
    def device_id(self):
        return platform.node()

    @property
    def version(self):
        return platform.release()

    @property
    def port_id(self):
        return self.interface.name

    @property
    def platform(self):
        return platform.system()

    @classmethod
    def setUpClass(cls):
        super(TestCDP, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            cls.interface = cls.pg_interfaces[0]

            cls.interface.admin_up()
            cls.interface.config_ip4()
            cls.interface.resolve_arp()

        except Exception:
            super(TestCDP, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestCDP, cls).tearDownClass()

    def test_enable_cdp(self):
        self.logger.info(self.vapi.cdp_enable_disable(enable_disable=1))
        ret = self.vapi.cli("show cdp")
        self.logger.info(ret)
        not_enabled = self.nen_ptr.search(ret)
        self.assertFalse(not_enabled, "CDP isn't enabled")

    def test_send_cdp_packet(self):
        self.logger.info(self.vapi.cdp_enable_disable(enable_disable=1))
        self.send_packet(self.create_packet())

        neighbors = list(self.show_cdp())
        self.assertTrue(neighbors, "CDP didn't register neighbor")

        port, system = neighbors[0]
        length = min(len(system), len(self.device_id))

        self.assert_equal(port, self.port_id, "CDP received invalid port id")
        self.assert_equal(system[:length], self.device_id[:length],
                          "CDP received invalid device id")

    def test_cdp_underflow_tlv(self):
        self.send_bad_packet(3, ".")

    def test_cdp_overflow_tlv(self):
        self.send_bad_packet(8, ".")

    def send_bad_packet(self, l, v):
        self.logger.info(self.vapi.cdp_enable_disable(enable_disable=1))
        self.send_packet(self.create_bad_packet(l, v))

        err = self.statistics.get_err_counter(
            '/err/cdp-input/cdp packets with bad TLVs')
        self.assertTrue(err >= 1, "CDP didn't drop bad packet")

    def send_packet(self, packet):
        self.logger.debug(ppp("Sending packet:", packet))
        self.interface.add_stream(packet)
        self.pg_start()

    def create_base_packet(self):
        packet = (Dot3(src=self.interface.remote_mac,
                       dst="01:00:0c:cc:cc:cc") /
                  LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
                  SNAP()/CDPv2_HDR())
        return packet

    def create_packet(self):
        packet = (self.create_base_packet() /
                  CDPMsgDeviceID(val=self.device_id) /
                  CDPMsgSoftwareVersion(val=self.version) /
                  CDPMsgPortID(iface=self.port_id) /
                  CDPMsgPlatform(val=self.platform))
        return packet

    def create_bad_packet(self, tl=4, tv=""):
        packet = (self.create_base_packet() /
                  CustomTLV(type=1,
                            length=tl,
                            value=tv))
        return packet

    def process_cli(self, exp, ptr):
        for line in self.vapi.cli(exp).split('\n')[1:]:
            m = ptr.match(line.strip())
            if m:
                yield m.groups()

    def show_cdp(self):
        for pack in self.process_cli("show cdp", self.cdp_ptr):
            try:
                port, system, _, _ = pack
            except ValueError:
                pass
            else:
                yield port, system
