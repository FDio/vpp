#!/usr/bin/env python
import unittest

from scapy.fields import BitField, ByteField, FlagsField, IntField
from scapy.packet import bind_layers, Packet, Raw
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.inet6 import IPv6

from framework import VppTestCase, VppTestRunner
from custom_exceptions import CaptureUnexpectedPacketError
from lisp import *
from util import ppp, ForeignAddressFactory

# From py_lispnetworking.lisp.py:  # GNU General Public License v2.0


class LISP_GPE_Header(Packet):
    name = "LISP GPE Header"
    fields_desc = [
        FlagsField("gpe_flags", None, 6, ["N", "L", "E", "V", "I", "P"]),
        BitField("reserved", 0, 18),
        ByteField("next_proto", 0),
        IntField("iid", 0),
    ]
bind_layers(UDP, LISP_GPE_Header, dport=4341)
bind_layers(UDP, LISP_GPE_Header, sport=4341)
bind_layers(LISP_GPE_Header, IP, next_proto=1)
bind_layers(LISP_GPE_Header, IPv6, next_proto=2)
bind_layers(LISP_GPE_Header, Ether, next_proto=3)


class Driver(object):

    config_order = ['locator-sets',
                    'locators',
                    'local-mappings',
                    'remote-mappings',
                    'adjacencies']

    """ Basic class for data driven testing """
    def __init__(self, test, test_cases):
        self._test_cases = test_cases
        self._test = test

    @property
    def test_cases(self):
        return self._test_cases

    @property
    def test(self):
        return self._test

    def create_packet(self, src_if, dst_if, deid, payload=''):
        """
        Create IPv4 packet

        param: src_if
        param: dst_if
        """
        packet = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                  IP(src=src_if.remote_ip4, dst=deid) /
                  Raw(payload))
        return packet

    @abstractmethod
    def run(self):
        """ testing procedure """
        pass


class SimpleDriver(Driver):
    """ Implements simple test procedure """
    def __init__(self, test, test_cases):
        super(SimpleDriver, self).__init__(test, test_cases)

    def verify_capture(self, src_loc, dst_loc, capture):
        """
        Verify captured packet

        :param src_loc: source locator address
        :param dst_loc: destination locator address
        :param capture: list of captured packets
        """
        self.test.assertEqual(len(capture), 1, "Unexpected number of "
                              "packets! Expected 1 but {} received"
                              .format(len(capture)))
        packet = capture[0]
        try:
            ip_hdr = packet[IP]
            # assert the values match
            self.test.assertEqual(ip_hdr.src, src_loc, "IP source address")
            self.test.assertEqual(ip_hdr.dst, dst_loc,
                                  "IP destination address")
            gpe_hdr = packet[LISP_GPE_Header]
            self.test.assertEqual(gpe_hdr.next_proto, 1,
                                  "next_proto is not ipv4!")
            ih = gpe_hdr[IP]
            self.test.assertEqual(ih.src, self.test.pg0.remote_ip4,
                                  "unexpected source EID!")
            self.test.assertEqual(ih.dst, self.test.deid_ip4,
                                  "unexpected dest EID!")
        except:
            self.test.logger.error(ppp("Unexpected or invalid packet:",
                                   packet))
            raise CaptureUnexpectedPacketError(packet=packet)

    def configure_tc(self, tc):
        for config_item in self.config_order:
            for vpp_object in tc[config_item]:
                vpp_object.add_vpp_config()

    def run(self, dest):
        """ Send traffic for each test case and verify that it
            is encapsulated """
        for tc in enumerate(self.test_cases):
            self.test.logger.info('Running {}'.format(tc[1]['name']))
            self.configure_tc(tc[1])

            packet = self.create_packet(self.test.pg0, self.test.pg1, dest,
                                        'data')
            self.test.pg0.add_stream(packet)
            self.test.pg0.enable_capture()
            self.test.pg1.enable_capture()
            self.test.pg_start()
            capture = self.test.pg1.get_capture(1)
            self.verify_capture(self.test.pg1.local_ip4,
                                self.test.pg1.remote_ip4, capture)
            self.test.pg0.assert_nothing_captured()


class TestLisp(VppTestCase):
    """ Basic LISP test """

    @classmethod
    def setUpClass(cls):
        super(TestLisp, cls).setUpClass()
        cls.faf = ForeignAddressFactory()
        cls.create_pg_interfaces(range(2))  # create pg0 and pg1
        for i in cls.pg_interfaces:
            i.admin_up()  # put the interface upsrc_if
            i.config_ip4()  # configure IPv4 address on the interface
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def setUp(self):
        super(TestLisp, self).setUp()
        self.vapi.lisp_enable_disable(is_enabled=1)

    def test_lisp_basic_encap(self):
        """Test case for basic encapsulation"""

        self.deid_ip4_net = self.faf.net
        self.deid_ip4 = self.faf.get_ip4()
        self.seid_ip4 = '{}/{}'.format(self.pg0.local_ip4, 32)
        self.rloc_ip4 = self.pg1.remote_ip4n

        test_cases = [
            {
                'name': 'basic ip4 over ip4',
                'locator-sets': [VppLispLocatorSet(self, 'ls-4o4')],
                'locators': [
                    VppLispLocator(self, self.pg1.sw_if_index, 'ls-4o4')
                ],
                'local-mappings': [
                    VppLocalMapping(self, self.seid_ip4, 'ls-4o4')
                ],
                'remote-mappings': [
                    VppRemoteMapping(self, self.deid_ip4_net,
                                     [{
                                         "is_ip4": 1,
                                         "priority": 1,
                                         "weight": 1,
                                         "addr": self.rloc_ip4
                                     }])
                ],
                'adjacencies': [
                    VppLispAdjacency(self, self.seid_ip4, self.deid_ip4_net)
                ]
            }
        ]
        self.test_driver = SimpleDriver(self, test_cases)
        self.test_driver.run(self.deid_ip4)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
