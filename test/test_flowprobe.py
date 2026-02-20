#!/usr/bin/env python3
from __future__ import print_function
import binascii
import random
import socket
import unittest
import time

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.lacp import SlowProtocol, LACP

from config import config
from framework import VppTestCase
from asfframework import (
    tag_fixme_vpp_workers,
    tag_fixme_debian11,
    tag_run_solo,
    is_distro_debian11,
    VppTestRunner,
)
from vpp_object import VppObject
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi.macaddress import mac_ntop
from socket import inet_ntop
from vpp_papi import VppEnum
from vpp_sub_interface import VppDot1ADSubint
from config import config


TMPL_COMMON_FIELD_COUNT = 6
TMPL_L2_FIELD_COUNT = 3
TMPL_L3_FIELD_COUNT = 4
TMPL_L4_FIELD_COUNT = 3

IPFIX_TCP_FLAGS_ID = 6
IPFIX_SRC_TRANS_PORT_ID = 7
IPFIX_DST_TRANS_PORT_ID = 11
IPFIX_SRC_IP4_ADDR_ID = 8
IPFIX_DST_IP4_ADDR_ID = 12
IPFIX_FLOW_DIRECTION_ID = 61

TCP_F_FIN = 0x01
TCP_F_SYN = 0x02
TCP_F_RST = 0x04
TCP_F_PSH = 0x08
TCP_F_ACK = 0x10
TCP_F_URG = 0x20
TCP_F_ECE = 0x40
TCP_F_CWR = 0x80


class VppCFLOW(VppObject):
    """CFLOW object for IPFIX exporter and Flowprobe feature"""

    def __init__(
        self,
        test,
        intf="pg2",
        active=0,
        passive=0,
        timeout=100,
        mtu=1024,
        datapath="l2",
        layer="l2 l3 l4",
        direction="tx",
    ):
        self._test = test
        self._intf = intf
        self._intf_obj = getattr(self._test, intf)
        self._active = active
        if passive == 0 or passive < active:
            self._passive = active + 1
        else:
            self._passive = passive
        self._datapath = datapath  # l2 ip4 ip6
        self._collect = layer  # l2 l3 l4
        self._direction = direction  # rx tx both
        self._timeout = timeout
        self._mtu = mtu
        self._configured = False

    def add_vpp_config(self):
        self.enable_exporter()
        l2_flag = 0
        l3_flag = 0
        l4_flag = 0
        if "l2" in self._collect.lower():
            l2_flag = VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L2
        if "l3" in self._collect.lower():
            l3_flag = VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L3
        if "l4" in self._collect.lower():
            l4_flag = VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L4
        self._test.vapi.flowprobe_set_params(
            record_flags=(l2_flag | l3_flag | l4_flag),
            active_timer=self._active,
            passive_timer=self._passive,
        )
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
            template_interval=self._timeout,
        )

    def _enable_disable_flowprobe_feature(self, is_add):
        which_map = {
            "l2": VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_L2,
            "ip4": VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_IP4,
            "ip6": VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_IP6,
        }
        direction_map = {
            "rx": VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_RX,
            "tx": VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_TX,
            "both": VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_BOTH,
        }
        self._test.vapi.flowprobe_interface_add_del(
            is_add=is_add,
            which=which_map[self._datapath],
            direction=direction_map[self._direction],
            sw_if_index=self._intf_obj.sw_if_index,
        )

    def enable_flowprobe_feature(self):
        self._enable_disable_flowprobe_feature(is_add=True)

    def disable_exporter(self):
        self._test.vapi.cli("set ipfix exporter collector 0.0.0.0")

    def disable_flowprobe_feature(self):
        self._enable_disable_flowprobe_feature(is_add=False)

    def object_id(self):
        return "ipfix-collector-%s-%s" % (self._src, self.dst)

    def query_vpp_config(self):
        return self._configured

    def verify_templates(self, decoder=None, timeout=1, count=3, field_count_in=None):
        templates = []
        self._test.assertIn(count, (1, 2, 3))
        for _ in range(count):
            p = self._test.wait_for_cflow_packet(self._test.collector, 2, timeout)
            self._test.assertTrue(p.haslayer(IPFIX))
            self._test.assertTrue(p.haslayer(Template))
            if decoder is not None:
                templates.append(p[Template].templateID)
                decoder.add_template(p.getlayer(Template))
            if field_count_in is not None:
                self._test.assertIn(p[Template].fieldCount, field_count_in)
        return templates


class MethodHolder(VppTestCase):
    """Flow-per-packet plugin: test L2, IP4, IP6 reporting"""

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
        if (is_distro_debian11 == True) and not hasattr(cls, "vpp"):
            return
        try:
            # Create pg interfaces
            cls.create_pg_interfaces(range(9))

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del_v2(
                bd_id=1, uu_flood=1, learn=1, flood=1, forward=1, is_add=1
            )
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg1._sw_if_index, bd_id=1
            )
            cls.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=cls.pg2._sw_if_index, bd_id=1
            )

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

    def create_stream(
        self, src_if=None, dst_if=None, packets=None, size=None, ip_ver="v4"
    ):
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
            if ip_ver == "v4":
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

    def verify_cflow_data_detail(
        self,
        decoder,
        capture,
        cflow,
        data_set={1: "octets", 2: "packets"},
        ip_ver="v4",
        field_count=None,
    ):
        if self.debug_print:
            print(capture[0].show())
        if cflow.haslayer(Data):
            data = decoder.decode_data_set(cflow.getlayer(Set))
            if self.debug_print:
                print(data)
            if ip_ver == "v4":
                ip_layer = capture[0][IP] if capture[0].haslayer(IP) else None
            else:
                ip_layer = capture[0][IPv6] if capture[0].haslayer(IPv6) else None
            if data_set is not None:
                for record in data:
                    # skip flow if ingress/egress interface is 0
                    if int(binascii.hexlify(record[10]), 16) == 0:
                        continue
                    if int(binascii.hexlify(record[14]), 16) == 0:
                        continue

                    for field in data_set:
                        value = data_set[field]
                        if value == "octets":
                            value = ip_layer.len
                            if ip_ver == "v6":
                                value += 40  # ??? is this correct
                        elif value == "packets":
                            value = 1
                        elif value == "src_ip":
                            if ip_ver == "v4":
                                ip = socket.inet_pton(socket.AF_INET, ip_layer.src)
                            else:
                                ip = socket.inet_pton(socket.AF_INET6, ip_layer.src)
                            value = int(binascii.hexlify(ip), 16)
                        elif value == "dst_ip":
                            if ip_ver == "v4":
                                ip = socket.inet_pton(socket.AF_INET, ip_layer.dst)
                            else:
                                ip = socket.inet_pton(socket.AF_INET6, ip_layer.dst)
                            value = int(binascii.hexlify(ip), 16)
                        elif value == "sport":
                            value = int(capture[0][UDP].sport)
                        elif value == "dport":
                            value = int(capture[0][UDP].dport)
                        self.assertEqual(
                            int(binascii.hexlify(record[field]), 16), value
                        )
            if field_count is not None:
                for record in data:
                    self.assertEqual(len(record), field_count)

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
                self.assertEqual(p[IP].len, int(binascii.hexlify(rec[1]), 16))
                self.assertEqual(1, int(binascii.hexlify(rec[2]), 16))
        self.assertEqual(len(capture), idx)

    def wait_for_cflow_packet(self, collector_intf, set_id=2, timeout=1):
        """wait for CFLOW packet and verify its correctness

        :param timeout: how long to wait

        """
        self.logger.info("IPFIX: Waiting for CFLOW packet")
        # self.logger.debug(self.vapi.ppcli("show flow table"))
        p = collector_intf.wait_for_packet(timeout=timeout)
        self.assertEqual(p[Set].setID, set_id)
        # self.logger.debug(self.vapi.ppcli("show flow table"))
        self.logger.debug(ppp("IPFIX: Got packet:", p))
        return p


@tag_fixme_debian12
@tag_run_solo
@tag_fixme_vpp_workers
<<<<<<< HEAD   (6ec273 gha: use stable/2510 hst verify workflow)
@tag_fixme_debian11
=======
>>>>>>> CHANGE (66c8f6 tests: fix @tag_fixme_debian12 to properly skip tests on Deb)
@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class Flowprobe(MethodHolder):
    """Template verification, timer tests"""

    @classmethod
    def setUpClass(cls):
        super(Flowprobe, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(Flowprobe, cls).tearDownClass()

    def test_0001(self):
        """timer less than template timeout"""
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

    @unittest.skipUnless(
        config.extended, "Test is unstable (assertion error, needs to be fixed"
    )
    def test_0002(self):
        """timer greater than template timeout [UNSTABLE, FIX ME]"""
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

        ipfix = VppCFLOW(
            test=self, intf="pg8", datapath="ip4", layer="l2 l3 l4", active=2
        )
        ipfix.add_vpp_config()

        route_9001 = VppIpRoute(
            self,
            "9.0.0.0",
            24,
            [VppRoutePath(self.pg8._remote_hosts[0].ip4, self.pg8.sw_if_index)],
        )
        route_9001.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.pkts = [
            (
                Ether(dst=self.pg7.local_mac, src=self.pg7.remote_mac)
                / IP(src=self.pg7.remote_ip4, dst="9.0.0.100")
                / TCP(sport=1234, dport=4321, flags=80)
                / Raw(b"\xa5" * 100)
            )
        ]

        nowUTC = int(time.time())
        nowUNIX = nowUTC + 2208988800
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
            # direction
            self.assertEqual(int(binascii.hexlify(record[61]), 16), 1)
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
            self.assertEqual(inet_ntop(socket.AF_INET, record[8]), self.pg7.remote_ip4)
            # dst ip
            self.assertEqual(inet_ntop(socket.AF_INET, record[12]), "9.0.0.100")
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

    def test_flow_entry_reuse(self):
        """Verify flow entry reuse doesn't accumulate meta info"""
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        # enable ip4 datapath for an interface
        # set active and passive timers
        ipfix = VppCFLOW(
            test=self,
            active=2,
            passive=3,
            intf="pg3",
            layer="l3 l4",
            datapath="ip4",
            direction="rx",
            mtu=100,
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix_decoder = IPFIXDecoder()
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        # make a tcp packet
        self.pkts = [
            (
                Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac)
                / IP(src=self.pg3.remote_ip4, dst=self.pg4.remote_ip4)
                / TCP(sport=1234, dport=4321)
                / Raw(b"\xa5" * 50)
            )
        ]

        # send the tcp packet two times, each time with new set of flags
        tcp_flags = (
            TCP_F_SYN | TCP_F_ACK,
            TCP_F_RST | TCP_F_PSH,
        )
        for f in tcp_flags:
            self.pkts[0][TCP].flags = f
            capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

            # verify meta info - packet/octet delta and tcp flags
            cflow = self.wait_for_cflow_packet(self.collector, templates[0], timeout=6)
            self.verify_cflow_data(ipfix_decoder, capture, cflow)
            self.verify_cflow_data_detail(
                ipfix_decoder,
                capture,
                cflow,
                {
                    IPFIX_TCP_FLAGS_ID: f,
                    IPFIX_SRC_TRANS_PORT_ID: 1234,
                    IPFIX_DST_TRANS_PORT_ID: 4321,
                },
            )

        self.collector.get_capture(3)

        # cleanup
        ipfix.remove_vpp_config()

    def test_interface_dump(self):
        """Dump interfaces with IPFIX flow record generation enabled"""
        self.logger.info("FFP_TEST_START_0003")

        # Enable feature for 3 interfaces
        ipfix1 = VppCFLOW(test=self, intf="pg1", datapath="l2", direction="rx")
        ipfix1.add_vpp_config()

        ipfix2 = VppCFLOW(test=self, intf="pg2", datapath="ip4", direction="tx")
        ipfix2.enable_flowprobe_feature()

        ipfix3 = VppCFLOW(test=self, intf="pg3", datapath="ip6", direction="both")
        ipfix3.enable_flowprobe_feature()

        # When request "all", dump should contain all enabled interfaces
        dump = self.vapi.flowprobe_interface_dump()
        self.assertEqual(len(dump), 3)

        # Verify 1st interface
        self.assertEqual(dump[0].sw_if_index, self.pg1.sw_if_index)
        self.assertEqual(
            dump[0].which, VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_L2
        )
        self.assertEqual(
            dump[0].direction,
            VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_RX,
        )

        # Verify 2nd interface
        self.assertEqual(dump[1].sw_if_index, self.pg2.sw_if_index)
        self.assertEqual(
            dump[1].which, VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_IP4
        )
        self.assertEqual(
            dump[1].direction,
            VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_TX,
        )

        # Verify 3rd interface
        self.assertEqual(dump[2].sw_if_index, self.pg3.sw_if_index)
        self.assertEqual(
            dump[2].which, VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_IP6
        )
        self.assertEqual(
            dump[2].direction,
            VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_BOTH,
        )

        # When request 2nd interface, dump should contain only the specified interface
        dump = self.vapi.flowprobe_interface_dump(sw_if_index=self.pg2.sw_if_index)
        self.assertEqual(len(dump), 1)

        # Verify 2nd interface
        self.assertEqual(dump[0].sw_if_index, self.pg2.sw_if_index)
        self.assertEqual(
            dump[0].which, VppEnum.vl_api_flowprobe_which_t.FLOWPROBE_WHICH_IP4
        )
        self.assertEqual(
            dump[0].direction,
            VppEnum.vl_api_flowprobe_direction_t.FLOWPROBE_DIRECTION_TX,
        )

        # When request 99th interface, dump should be empty
        dump = self.vapi.flowprobe_interface_dump(sw_if_index=99)
        self.assertEqual(len(dump), 0)

        ipfix1.remove_vpp_config()
        ipfix2.remove_vpp_config()
        ipfix3.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_get_params(self):
        """Get IPFIX flow record generation parameters"""
        self.logger.info("FFP_TEST_START_0004")

        # Enable feature for an interface with custom parameters
        ipfix = VppCFLOW(test=self, active=20, passive=40, layer="l2 l3 l4")
        ipfix.add_vpp_config()

        # Get and verify parameters
        params = self.vapi.flowprobe_get_params()
        self.assertEqual(params.active_timer, 20)
        self.assertEqual(params.passive_timer, 40)
        record_flags = VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L2
        record_flags |= VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L3
        record_flags |= VppEnum.vl_api_flowprobe_record_flags_t.FLOWPROBE_RECORD_FLAG_L4
        self.assertEqual(params.record_flags, record_flags)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0004")


@tag_fixme_debian12
class DatapathTestsHolder(object):
    """collect information on Ethernet, IP4 and IP6 datapath (no timers)"""

    @classmethod
    def setUpClass(cls):
        super(DatapathTestsHolder, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DatapathTestsHolder, cls).tearDownClass()

    def test_templatesL2(self):
        """verify template on L2 datapath"""
        self.logger.info("FFP_TEST_START_0000")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, layer="l2", direction=self.direction
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        ipfix.verify_templates(timeout=3, count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onL2(self):
        """L2 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, layer="l2", direction=self.direction
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 256: 8, 61: (self.direction == "tx")},
        )
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onL2(self):
        """L3 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, layer="l3", direction=self.direction
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=2)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {
                2: "packets",
                4: 17,
                8: "src_ip",
                12: "dst_ip",
                61: (self.direction == "tx"),
            },
        )

        self.collector.get_capture(3)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L234onL2(self):
        """L2/3/4 data on L2 datapath"""
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, layer="l2 l3 l4", direction=self.direction
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        tmpl_l2_field_count = TMPL_COMMON_FIELD_COUNT + TMPL_L2_FIELD_COUNT
        tmpl_ip_field_count = (
            TMPL_COMMON_FIELD_COUNT
            + TMPL_L2_FIELD_COUNT
            + TMPL_L3_FIELD_COUNT
            + TMPL_L4_FIELD_COUNT
        )
        templates = ipfix.verify_templates(
            ipfix_decoder,
            count=3,
            field_count_in=(tmpl_l2_field_count, tmpl_ip_field_count),
        )

        # verify IPv4 and IPv6 flows
        for ip_ver in ("v4", "v6"):
            self.create_stream(packets=1, ip_ver=ip_ver)
            capture = self.send_packets()

            # make sure the one packet we expect actually showed up
            self.vapi.ipfix_flush()
            cflow = self.wait_for_cflow_packet(
                self.collector, templates[1 if ip_ver == "v4" else 2]
            )
            src_ip_id = 8 if ip_ver == "v4" else 27
            dst_ip_id = 12 if ip_ver == "v4" else 28
            self.verify_cflow_data_detail(
                ipfix_decoder,
                capture,
                cflow,
                {
                    2: "packets",
                    256: 8 if ip_ver == "v4" else 56710,
                    4: 17,
                    7: "sport",
                    11: "dport",
                    src_ip_id: "src_ip",
                    dst_ip_id: "dst_ip",
                    61: (self.direction == "tx"),
                },
                ip_ver=ip_ver,
                field_count=tmpl_ip_field_count,
            )

        # verify non-IP flow
        self.pkts = [
            (
                Ether(dst=self.pg2.local_mac, src=self.pg1.remote_mac)
                / SlowProtocol()
                / LACP()
            )
        ]
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 256: 2440, 61: (self.direction == "tx")},
            field_count=tmpl_l2_field_count,
        )

        self.collector.get_capture(6)

        ipfix.remove_vpp_config()

    def test_L4onL2(self):
        """L4 data on L2 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, layer="l4", direction=self.direction
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=2)

        self.create_stream(packets=1)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 7: "sport", 11: "dport", 61: (self.direction == "tx")},
        )

        self.collector.get_capture(3)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_templatesIp4(self):
        """verify templates on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0000")

        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, datapath="ip4", direction=self.direction
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        self.vapi.ipfix_flush()
        ipfix.verify_templates(timeout=3, count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onIP4(self):
        """L2 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf2,
            layer="l2",
            datapath="ip4",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 256: 8, 61: (self.direction == "tx")},
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onIP4(self):
        """L3 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf2,
            layer="l3",
            datapath="ip4",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {
                1: "octets",
                2: "packets",
                8: "src_ip",
                12: "dst_ip",
                61: (self.direction == "tx"),
            },
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L4onIP4(self):
        """L4 data on IP4 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf2,
            layer="l4",
            datapath="ip4",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=1)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 7: "sport", 11: "dport", 61: (self.direction == "tx")},
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_templatesIP6(self):
        """verify templates on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0000")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(
            test=self, intf=self.intf1, datapath="ip6", direction=self.direction
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates(count=1)
        self.collector.get_capture(1)

        ipfix.remove_vpp_config()

        self.logger.info("FFP_TEST_FINISH_0000")

    def test_L2onIP6(self):
        """L2 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf3,
            layer="l2",
            datapath="ip6",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1, ip_ver="IPv6")
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 256: 56710, 61: (self.direction == "tx")},
            ip_ver="v6",
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_L3onIP6(self):
        """L3 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf3,
            layer="l3",
            datapath="ip6",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1, ip_ver="IPv6")
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 27: "src_ip", 28: "dst_ip", 61: (self.direction == "tx")},
            ip_ver="v6",
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_L4onIP6(self):
        """L4 data on IP6 datapath"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(
            test=self,
            intf=self.intf3,
            layer="l4",
            datapath="ip6",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        self.create_stream(src_if=self.pg5, dst_if=self.pg6, packets=1, ip_ver="IPv6")
        capture = self.send_packets(src_if=self.pg5, dst_if=self.pg6)

        # make sure the one packet we expect actually showed up
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {2: "packets", 7: "sport", 11: "dport", 61: (self.direction == "tx")},
            ip_ver="v6",
        )

        # expected two templates and one cflow packet
        self.collector.get_capture(2)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_0001(self):
        """no timers, one CFLOW packet, 9 Flows inside"""
        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf=self.intf1, direction=self.direction)
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
        """no timers, two CFLOW packets (mtu=260), 3 Flows in each"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf=self.intf1, direction=self.direction, mtu=260)
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
        cflows.append(self.wait_for_cflow_packet(self.collector, templates[1]))
        cflows.append(self.wait_for_cflow_packet(self.collector, templates[1]))
        self.verify_cflow_data_notimer(ipfix_decoder, capture, cflows)
        self.collector.get_capture(5)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")


@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class DatapathTx(MethodHolder, DatapathTestsHolder):
    """Collect info on Ethernet, IP4 and IP6 datapath (TX) (no timers)"""

    intf1 = "pg2"
    intf2 = "pg4"
    intf3 = "pg6"
    direction = "tx"

    def test_rewritten_traffic(self):
        """Rewritten traffic (from subif to ipfix if)"""
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        # prepare a sub-interface
        subif = VppDot1ADSubint(self, self.pg7, 0, 300, 400)
        subif.admin_up()
        subif.config_ip4()

        # enable ip4 datapath for an interface
        ipfix = VppCFLOW(
            test=self,
            intf="pg8",
            datapath="ip4",
            layer="l2 l3 l4",
            direction=self.direction,
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix_decoder = IPFIXDecoder()
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        # forward some traffic through the ipfix interface
        route = VppIpRoute(
            self,
            "9.0.0.0",
            24,
            [VppRoutePath(self.pg8.remote_ip4, self.pg8.sw_if_index)],
        )
        route.add_vpp_config()

        # prepare an IPv4 packet (subif => ipfix interface)
        pkt = (
            Ether(src=subif.remote_mac, dst=self.pg7.local_mac)
            / IP(src=subif.remote_ip4, dst="9.0.0.1")
            / UDP(sport=1234, dport=4321)
            / Raw(b"\xa5" * 123)
        )
        self.pkts = [
            subif.add_dot1ad_layer(pkt, 300, 400),
        ]

        # send the packet
        capture = self.send_packets(self.pg7, self.pg8)

        # wait for a flow and verify it
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0])
        self.verify_cflow_data(ipfix_decoder, capture, cflow)
        self.verify_cflow_data_detail(
            ipfix_decoder,
            capture,
            cflow,
            {
                IPFIX_SRC_IP4_ADDR_ID: "src_ip",
                IPFIX_DST_IP4_ADDR_ID: "dst_ip",
                IPFIX_SRC_TRANS_PORT_ID: "sport",
                IPFIX_DST_TRANS_PORT_ID: "dport",
                IPFIX_FLOW_DIRECTION_ID: (self.direction == "tx"),
            },
        )

        self.collector.get_capture(2)

        # cleanup
        route.remove_vpp_config()
        subif.remove_vpp_config()
        ipfix.remove_vpp_config()


@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class DatapathRx(MethodHolder, DatapathTestsHolder):
    """Collect info on Ethernet, IP4 and IP6 datapath (RX) (no timers)"""

    intf1 = "pg1"
    intf2 = "pg3"
    intf3 = "pg5"
    direction = "rx"


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class DisableIPFIX(MethodHolder):
    """Disable IPFIX"""

    @classmethod
    def setUpClass(cls):
        super(DisableIPFIX, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DisableIPFIX, cls).tearDownClass()

    def test_0001(self):
        """disable IPFIX after first packets"""
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


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class ReenableIPFIX(MethodHolder):
    """Re-enable IPFIX"""

    @classmethod
    def setUpClass(cls):
        super(ReenableIPFIX, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ReenableIPFIX, cls).tearDownClass()

    def test_0011(self):
        """disable IPFIX after first packets and re-enable after few packets"""
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


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class DisableFP(MethodHolder):
    """Disable Flowprobe feature"""

    @classmethod
    def setUpClass(cls):
        super(DisableFP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DisableFP, cls).tearDownClass()

    def test_0001(self):
        """disable flowprobe feature after first packets"""
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

        # enable FPP feature so the remove_vpp_config() doesn't fail
        # due to missing feature on interface.
        ipfix.enable_flowprobe_feature()

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_no_leftover_flows_after_disabling(self):
        """disable flowprobe feature and expect no leftover flows"""
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        # enable ip4 datapath for an interface
        # set active and passive timers
        ipfix = VppCFLOW(
            test=self,
            active=3,
            passive=4,
            intf="pg3",
            layer="l3",
            datapath="ip4",
            direction="rx",
            mtu=100,
        )
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates(count=1)

        # send some ip4 packets
        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=5)
        self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # disable feature for the interface
        # currently stored ip4 flows should be removed
        ipfix.disable_flowprobe_feature()

        # no leftover ip4 flows are expected
        self.pg_enable_capture([self.collector])
        self.sleep(12, "wait for leftover ip4 flows during three passive intervals")
        self.collector.assert_nothing_captured()

        # re-enable feature for the interface
        ipfix.enable_flowprobe_feature()

        # template packet should arrive immediately
        ipfix_decoder = IPFIXDecoder()
        self.vapi.ipfix_flush()
        templates = ipfix.verify_templates(ipfix_decoder, count=1)

        # send some ip4 packets
        self.create_stream(src_if=self.pg3, dst_if=self.pg4, packets=5)
        capture = self.send_packets(src_if=self.pg3, dst_if=self.pg4)

        # verify meta info - packet/octet delta
        self.vapi.ipfix_flush()
        cflow = self.wait_for_cflow_packet(self.collector, templates[0], timeout=8)
        self.verify_cflow_data(ipfix_decoder, capture, cflow)

        self.collector.get_capture(2)

        # cleanup
        ipfix.remove_vpp_config()


@unittest.skipUnless(config.extended, "part of extended tests")
@unittest.skipIf(
    "flowprobe" in config.excluded_plugins, "Exclude Flowprobe plugin tests"
)
class ReenableFP(MethodHolder):
    """Re-enable Flowprobe feature"""

    @classmethod
    def setUpClass(cls):
        super(ReenableFP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ReenableFP, cls).tearDownClass()

    def test_0001(self):
        """disable flowprobe feature after first packets and re-enable
        after few packets"""
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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
