#!/usr/bin/env python
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

    def test_enable_cdp(self):
        self.logger.info(self.vapi.cli("cdp enable"))
        ret = self.vapi.cli("show cdp")
        self.logger.info(ret)
        not_enabled = self.nen_ptr.search(ret)
        self.assertFalse(not_enabled, "CDP isn't enabled")

    def test_send_cdp_packet(self):
        self.logger.info(self.vapi.cli("cdp enable"))
        self.send_packet(self.create_packet())

        neighbors = list(self.show_cdp())
        self.assertTrue(neighbors, "CDP didn't register neighbor")

        port, system = neighbors[0]

        self.assert_equal(port, self.port_id, "CDP received invalid port id")
        self.assert_equal(system, self.device_id,
                          "CDP received invalid device id")

    def test_cdp_underflow_tlv(self):
        self.send_bad_packet(3, ".")

    def test_cdp_overflow_tlv(self):
        self.send_bad_packet(8, ".")

    def send_bad_packet(self, l, v):
        self.logger.info(self.vapi.cli("cdp enable"))
        self.send_packet(self.create_bad_packet(l, v))

        errors = list(self.show_errors())
        self.assertTrue(errors)

        expected_errors = False
        for count, node, reason in errors:
            if (node == u'cdp-input' and
                    reason == u'cdp packets with bad TLVs' and
                    int(count) >= 1):

                expected_errors = True
                break
        self.logger.info(self.vapi.cli("show errors"))
        self.assertTrue(expected_errors, "CDP didn't drop bad packet")

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

    def show_errors(self):
        for pack in self.process_cli("show errors", self.err_ptr):
            try:
                count, node, reason = pack
            except ValueError:
                pass
            else:
                yield count, node, reason
