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
from __future__ import print_function
import binascii
import random
import socket
import unittest
import time
import re

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner, running_extended_tests
from framework import tag_run_solo
from vpp_object import VppObject
from vpp_pg_interface import CaptureTimeoutError
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi.macaddress import mac_ntop
from socket import inet_ntop
from vpp_papi import VppEnum


class VppCFLOW(VppObject):
    """CFLOW object for IPFIX exporter and Flowprobe feature"""

    def __init__(self, test, intf='pg2', active=0, passive=0, timeout=100,
                 mtu=1024, datapath='l2', layer='l2 l3 l4'):
        self._test = test
        self._intf = intf
        self._active = active
        if passive == 0 or passive < active:
            self._passive = active+1
        else:
            self._passive = passive
        self._datapath = datapath           # l2 ip4 ip6
        self._collect = layer               # l2 l3 l4
        self._timeout = timeout
        self._mtu = mtu
        self._configured = False

    def add_vpp_config(self):
        self.enable_exporter()
        l2_flag = 0
        l3_flag = 0
        l4_flag = 0
        if 'l2' in self._collect.lower():
            l2_flag = (VppEnum.vl_api_flowprobe_record_flags_t.
                       FLOWPROBE_RECORD_FLAG_L2)
        if 'l3' in self._collect.lower():
            l3_flag = (VppEnum.vl_api_flowprobe_record_flags_t.
                       FLOWPROBE_RECORD_FLAG_L3)
        if 'l4' in self._collect.lower():
            l4_flag = (VppEnum.vl_api_flowprobe_record_flags_t.
                       FLOWPROBE_RECORD_FLAG_L4)
        self._test.vapi.flowprobe_params(
            record_flags=(l2_flag | l3_flag | l4_flag),
            active_timer=self._active, passive_timer=self._passive)
        self.enable_flowprobe_feature()
        self._test.vapi.cli("ipfix flush")
        self._configured = True

    def remove_vpp_config(self):
        self.disable_exporter()
        self.disable_flowprobe_feature()
        self._test.vapi.cli("ipfix flush")
        self._configured = False

    def enable_exporter(self):
        self._test.vapi.set_ipfix_exporter(
            collector_address=self._test.pg0.remote_ip4,
            src_address=self._test.pg0.local_ip4,
            path_mtu=self._mtu,
            template_interval=self._timeout)

    def enable_flowprobe_feature(self):
        self._test.vapi.ppcli("flowprobe feature add-del %s %s" %
                              (self._intf, self._datapath))

    def disable_exporter(self):
        self._test.vapi.cli("set ipfix exporter collector 0.0.0.0")

    def disable_flowprobe_feature(self):
        self._test.vapi.cli("flowprobe feature add-del %s %s disable" %
                            (self._intf, self._datapath))

    def object_id(self):
        return "ipfix-collector-%s-%s" % (self._src, self.dst)

    def query_vpp_config(self):
        return self._configured

    def verify_templates(self, decoder=None, timeout=1, count=3):
        templates = []
        self._test.assertIn(count, (1, 2, 3))
        for _ in range(count):
            p = self._test.wait_for_cflow_packet(self._test.collector, 2,
                                                 timeout)
            self._test.assertTrue(p.haslayer(IPFIX))
            if decoder is not None and p.haslayer(Template):
                templates.append(p[Template].templateID)
                decoder.add_template(p.getlayer(Template))
        return templates


class MethodHolder(VppTestCase):
    """ Flow-per-packet plugin: test L2, IP4, IP6 reporting """

    # Test variables
    debug_print = False
    max_number_of_packets = 10
    pkts = []

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(MethodHolder, cls).setUpClass()
        try:
            # Create pg interfaces
            cls.create_pg_interfaces(range(9))

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del(bd_id=1, uu_flood=1, learn=1)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg1._sw_if_index, bd_id=1)
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg2._sw_if_index, bd_id=1)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            cls.pg0.config_ip4()
            cls.pg0.configure_ipv4_neighbors()
            cls.collector = cls.pg0

            cls.pg1.config_ip4()
            cls.pg1.resolve_arp()
            cls.pg2.config_ip4()
            cls.pg2.resolve_arp()
            cls.pg3.config_ip4()
            cls.pg3.resolve_arp()
            cls.pg4.config_ip4()
            cls.pg4.resolve_arp()
            cls.pg7.config_ip4()
            cls.pg8.config_ip4()
            cls.pg8.configure_ipv4_neighbors()

            cls.pg5.config_ip6()
            cls.pg5.resolve_ndp()
            cls.pg5.disable_ipv6_ra()
            cls.pg6.config_ip6()
            cls.pg6.resolve_ndp()
            cls.pg6.disable_ipv6_ra()
        except Exception:
            super(MethodHolder, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(MethodHolder, cls).tearDownClass()

    def create_stream(self, src_if=None, dst_if=None, packets=None,
                      size=None, ip_ver='v4'):
        """Create a packet stream to tickle the plugin

        :param VppInterface src_if: Source interface for packet stream
        :param VppInterface src_if: Dst interface for packet stream
        """
        if src_if is None:
            src_if = self.pg1
        if dst_if is None:
            dst_if = self.pg2
        self.pkts = []
        if packets is None:
            packets = random.randint(1, self.max_number_of_packets)
        pkt_size = size
        for p in range(0, packets):
            if size is None:
                pkt_size = random.choice(self.pg_if_packet_sizes)
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = Ether(src=src_if.remote_mac, dst=src_if.local_mac)
            if ip_ver == 'v4':
                p /= IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
            else:
                p /= IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
            p /= UDP(sport=1234, dport=4321)
            p /= Raw(payload)
            info.data = p.copy()
            self.extend_packet(p, pkt_size)
            self.pkts.append(p)

    def verify_cflow_data(self, decoder, capture, cflow):
        octets = 0
        packets = 0
        for p in capture:
            octets += p[IP].len
            packets += 1
        if cflow.haslayer(Data):
            data = decoder.decode_data_set(cflow.getlayer(Set))
            for record in data:
                self.assertEqual(int(binascii.hexlify(record[1]), 16), octets)
                self.assertEqual(int(binascii.hexlify(record[2]), 16), packets)

    def send_packets(self, src_if=None, dst_if=None):
        if src_if is None:
            src_if = self.pg1
        if dst_if is None:
            dst_if = self.pg2
        self.pg_enable_capture([dst_if])
        src_if.add_stream(self.pkts)
        self.pg_start()
        return dst_if.get_capture(len(self.pkts))

    def verify_cflow_data_detail(self, decoder, capture, cflow,
                                 data_set={1: 'octets', 2: 'packets'},
                                 ip_ver='v4'):
        if self.debug_print:
            print(capture[0].show())
        if cflow.haslayer(Data):
            data = decoder.decode_data_set(cflow.getlayer(Set))
            if self.debug_print:
                print(data)
            if ip_ver == 'v4':
                ip_layer = capture[0][IP]
            else:
                ip_layer = capture[0][IPv6]
            if data_set is not None:
                for record in data:
                    # skip flow if ingress/egress interface is 0
                    if int(binascii.hexlify(record[10]), 16) == 0:
                        continue
                    if int(binascii.hexlify(record[14]), 16) == 0:
                        continue

                    for field in data_set:
                        if field not in record.keys():
                            continue
                        value = data_set[field]
                        if value == 'octets':
                            value = ip_layer.len
                            if ip_ver == 'v6':
                                value += 40        # ??? is this correct
                        elif value == 'packets':
                            value = 1
                        elif value == 'src_ip':
                            if ip_ver == 'v4':
                                ip = socket.inet_pton(socket.AF_INET,
                                                      ip_layer.src)
                            else:
                                ip = socket.inet_pton(socket.AF_INET6,
                                                      ip_layer.src)
                            value = int(binascii.hexlify(ip), 16)
                        elif value == 'dst_ip':
                            if ip_ver == 'v4':
                                ip = socket.inet_pton(socket.AF_INET,
                                                      ip_layer.dst)
                            else:
                                ip = socket.inet_pton(socket.AF_INET6,
                                                      ip_layer.dst)
                            value = int(binascii.hexlify(ip), 16)
                        elif value == 'sport':
                            value = int(capture[0][UDP].sport)
                        elif value == 'dport':
                            value = int(capture[0][UDP].dport)
                        self.assertEqual(int(binascii.hexlify(
                            record[field]), 16),
                            value)

    def verify_cflow_data_notimer(self, decoder, capture, cflows):
        idx = 0
        for cflow in cflows:
            if cflow.haslayer(Data):
                data = decoder.decode_data_set(cflow.getlayer(Set))
            else:
                raise Exception("No CFLOW data")

            for rec in data:
                p = capture[idx]
                idx += 1
                self.assertEqual(p[IP].len, int(
                    binascii.hexlify(rec[1]), 16))
                self.assertEqual(1, int(
                    binascii.hexlify(rec[2]), 16))
        self.assertEqual(len(capture), idx)

    def wait_for_cflow_packet(self, collector_intf, set_id=2, timeout=1):
        """ wait for CFLOW packet and verify its correctness

        :param timeout: how long to wait

        """
        self.logger.info("IPFIX: Waiting for CFLOW packet")
        # self.logger.debug(self.vapi.ppcli("show flow table"))
        p = collector_intf.wait_for_packet(timeout=timeout)
        self.assertEqual(p[Set].setID, set_id)
        # self.logger.debug(self.vapi.ppcli("show flow table"))
        self.logger.debug(ppp("IPFIX: Got packet:", p))
        return p


@tag_run_solo
@tag_fixme_vpp_workers
class Flowprobe(MethodHolder):
    """Template verification, timer tests"""

    @classmethod
    def setUpClass(cls):
        super(Flowprobe, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(Flowprobe, cls).tearDownClass()

    def test_0001(self):
        """ timer less than template timeout"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, active=2)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream(packets=1)
        self.send_packets()
        capture = self.pg2.get_capture(1)

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[1], 15)
        self.verify_cflow_data(ipfix_decoder, capture, cflow)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_0002(self):
        """ timer greater than template timeout"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=3, active=4)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        ipfix.verify_templates()

        self.create_stream(packets=2)
        self.send_packets()
        capture = self.pg2.get_capture(2)

        # next set of template packet should arrive after 20 seconds
        # template packet should arrive within 20 s
        templates = ipfix.verify_templates(ipfix_decoder, timeout=5)

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[1], 15)
        self.verify_cflow_data(ipfix_decoder, capture, cflow)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_cflow_packet(self):
        """verify cflow packet fields"""
        self.logger.info("FFP_TEST_START_0000")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg8', datapath="ip4",
                         layer='l2 l3 l4', active=2)
        ipfix.add_vpp_config()

        route_9001 = VppIpRoute(self, "9.0.0.0", 24,
                                [VppRoutePath(self.pg8._remote_hosts[0].ip4,
                                              self.pg8.sw_if_index)])
        route_9001.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.pkts = [(Ether(dst=self.pg7.local_mac,
                            src=self.pg7.remote_mac) /
                      IP(src=self.pg7.remote_ip4, dst="9.0.0.100") /
                      TCP(sport=1234, dport=4321, flags=80) /
                      Raw(b'\xa5' * 100))]

        nowUTC = int(time.time())
        nowUNIX = nowUTC+2208988800
        self.send_packets(src_if=self.pg7, dst_if=self.pg8)

        cflow = self.wait_for_cflow_packet(self.collector, templates[0], 10)
        self.collector.get_capture(2)

        if cflow[0].haslayer(IPFIX):
            self.assertEqual(cflow[IPFIX].version, 10)
            self.assertEqual(cflow[IPFIX].observationDomainID, 1)
            self.assertEqual(cflow[IPFIX].sequenceNumber, 0)
            self.assertAlmostEqual(cflow[IPFIX].exportTime, nowUTC, delta=5)
        if cflow.haslayer(Data):
            record = ipfix_decoder.decode_data_set(cflow[0].getlayer(Set))[0]
            # ingress interface
            self.assertEqual(int(binascii.hexlify(record[10]), 16), 8)
            # egress interface
            self.assertEqual(int(binascii.hexlify(record[14]), 16), 9)
            # packets
            self.assertEqual(int(binascii.hexlify(record[2]), 16), 1)
            # src mac
            self.assertEqual(mac_ntop(record[56]), self.pg8.local_mac)
            # dst mac
            self.assertEqual(mac_ntop(record[80]), self.pg8.remote_mac)
            flowTimestamp = int(binascii.hexlify(record[156]), 16) >> 32
            # flow start timestamp
            self.assertAlmostEqual(flowTimestamp, nowUNIX, delta=1)
            flowTimestamp = int(binascii.hexlify(record[157]), 16) >> 32
            # flow end timestamp
            self.assertAlmostEqual(flowTimestamp, nowUNIX, delta=1)
            # ethernet type
            self.assertEqual(int(binascii.hexlify(record[256]), 16), 8)
            # src ip
            self.assertEqual(inet_ntop(socket.AF_INET, record[8]),
                             self.pg7.remote_ip4)
            # dst ip
            self.assertEqual(inet_ntop(socket.AF_INET, record[12]),
                             "9.0.0.100")
            # protocol (TCP)
            self.assertEqual(int(binascii.hexlify(record[4]), 16), 6)
            # src port
            self.assertEqual(int(binascii.hexlify(record[7]), 16), 1234)
            # dst port
            self.assertEqual(int(binascii.hexlify(record[11]), 16), 4321)
            # tcp flags
            self.assertEqual(int(binascii.hexlify(record[6]), 16), 80)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0000")


@tag_fixme_vpp_workers
class Datapath(MethodHolder):
    """collect information on Ethernet, IP4 and IP6 datapath (no timers)"""

    @classmethod
    def setUpClass(cls):
        super(Datapath, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(Datapath, cls).tearDownClass()

    def test_templatesL2(self):
        """ verify template on L2 datapath"""
        self.logger.info("FFP_TEST_START_0000")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(test=self, layer='l2')
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        ipfix.verify_templates(timeout=3, count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onL2(self):
        """ L2 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, layer='l2')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 256: 8})
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onL2(self):
        """ L3 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, layer='l3')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=2)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 4: 17,
                                       8: 'src_ip', 12: 'dst_ip'})

        self.collector.get_capture(3)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L4onL2(self):
        """ L4 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, layer='l4')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=2)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 7: 'sport', 11: 'dport'})

        self.collector.get_capture(3)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_templatesIp4(self):
        """ verify templates on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0000")

        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(test=self, datapath='ip4')
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        ipfix.verify_templates(timeout=3, count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onIP4(self):
        """ L2 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg4', layer='l2', datapath='ip4')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 256: 8})

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onIP4(self):
        """ L3 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg4', layer='l3', datapath='ip4')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {1: 'octets', 2: 'packets',
                                       8: 'src_ip', 12: 'dst_ip'})

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L4onIP4(self):
        """ L4 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg4', layer='l4', datapath='ip4')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 7: 'sport', 11: 'dport'})

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_templatesIP6(self):
        """ verify templates on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0000")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(test=self, datapath='ip6')
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates(count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onIP6(self):
        """ L2 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg6', layer='l2', datapath='ip6')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1,
                           ip_ver='IPv6')
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 256: 56710},
                                      ip_ver='v6')

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onIP6(self):
        """ L3 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg6', layer='l3', datapath='ip6')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1,
                           ip_ver='IPv6')
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets',
                                       27: 'src_ip', 28: 'dst_ip'},
                                      ip_ver='v6')

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L4onIP6(self):
        """ L4 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg6', layer='l4', datapath='ip6')
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1,
                           ip_ver='IPv6')
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(ipfix_decoder, capture, cflow,
                                      {2: 'packets', 7: 'sport', 11: 'dport'},
                                      ip_ver='v6')

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_0001(self):
        """ no timers, one CFLOW packet, 9 Flows inside"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream(packets=9)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[1])
        self.verify_cflow_data_notimer(ipfix_decoder, capture, [cflow])
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_0002(self):
        """ no timers, two CFLOW packets (mtu=256), 3 Flows in each"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, mtu=256)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream(packets=6)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflows = []
        self.vapi.ipfix_flush()
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[1]))
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[1]))
        self.verify_cflow_data_notimer(ipfix_decoder, capture, cflows)
        self.collector.get_capture(5)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class DisableIPFIX(MethodHolder):
    """Disable IPFIX"""

    @classmethod
    def setUpClass(cls):
        super(DisableIPFIX, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DisableIPFIX, cls).tearDownClass()

    def test_0001(self):
        """ disable IPFIX after first packets"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        self.wait_for_cflow_packet(self.collector, templates[1])
        self.collector.get_capture(4)

        # disable IPFIX
        ipfix.disable_exporter()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in 1 minute
        self.vapi.ipfix_flush()
        self.sleep(1, "wait before verifying no packets sent")
        self.collector.assert_nothing_captured()

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class ReenableIPFIX(MethodHolder):
    """Re-enable IPFIX"""

    @classmethod
    def setUpClass(cls):
        super(ReenableIPFIX, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ReenableIPFIX, cls).tearDownClass()

    def test_0011(self):
        """ disable IPFIX after first packets and re-enable after few packets
        """
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream(packets=5)
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        self.wait_for_cflow_packet(self.collector, templates[1])
        self.collector.get_capture(4)

        # disable IPFIX
        ipfix.disable_exporter()
        self.vapi.ipfix_flush()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in active timer span
        self.vapi.ipfix_flush()
        self.sleep(1, "wait before verifying no packets sent")
        self.collector.assert_nothing_captured()
        self.pg2.get_capture(5)

        # enable IPFIX
        ipfix.enable_exporter()

        capture = self.collector.get_capture(4)
        nr_templates = 0
        nr_data = 0
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                nr_templates += 1
        self.assertTrue(nr_templates, 3)
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Data):
                nr_data += 1
        self.assertTrue(nr_templates, 1)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class DisableFP(MethodHolder):
    """Disable Flowprobe feature"""

    @classmethod
    def setUpClass(cls):
        super(DisableFP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DisableFP, cls).tearDownClass()

    def test_0001(self):
        """ disable flowprobe feature after first packets"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []
        ipfix = VppCFLOW(test=self)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        self.wait_for_cflow_packet(self.collector, templates[1])
        self.collector.get_capture(4)

        # disable IPFIX
        ipfix.disable_flowprobe_feature()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in active timer span
        self.vapi.ipfix_flush()
        self.sleep(1, "wait before verifying no packets sent")
        self.collector.assert_nothing_captured()

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class ReenableFP(MethodHolder):
    """Re-enable Flowprobe feature"""

    @classmethod
    def setUpClass(cls):
        super(ReenableFP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ReenableFP, cls).tearDownClass()

    def test_0001(self):
        """ disable flowprobe feature after first packets and re-enable
        after few packets """
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        templates = ipfix.verify_templates(ipfix_decoder, timeout=3)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        self.wait_for_cflow_packet(self.collector, templates[1], 5)
        self.collector.get_capture(4)

        # disable FPP feature
        ipfix.disable_flowprobe_feature()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in active timer span
        self.vapi.ipfix_flush()
        self.sleep(5, "wait before verifying no packets sent")
        self.collector.assert_nothing_captured()

        # enable FPP feature
        ipfix.enable_flowprobe_feature()
        self.vapi.ipfix_flush()
        templates = ipfix.verify_templates(ipfix_decoder, timeout=3)

        self.send_packets()

        # make sure the next packets (templates and data) we expect actually
        # showed up
        self.vapi.ipfix_flush()
        self.wait_for_cflow_packet(self.collector, templates[1], 5)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
