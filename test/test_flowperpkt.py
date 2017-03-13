#!/usr/bin/env python
import random
import unittest
import time

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_pg_interface import CaptureTimeoutError
from util import Host, ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder


class VppCFLOW(VppObject):
    """CFLOW object for IPFIX exporter and FLowPerPkt feature"""

    def __init__(self, test, intf, active=0, passive=0, timeout=20, mtu=512,
                 datapath='l2', level='l2 l3 l4'):
        self._test = test
        self._intf = intf
        self._active = active
        self._passive = passive
        self._datapath = datapath           # l2 ip4 ip6
        self._collect = level               # l2 l3 l4
        self._timeout = timeout
        self._mtu = mtu
        self._configured = False

    def add_vpp_config(self):
        self.enable_exporter()
        self._test.vapi.ppcli("flowperpkt params record %s active %s "
                              "passive %s" % (self._collect, self._active,
                                              self._passive))
        self.enable_flowperpkt_feature()
        self._test.vapi.cli("ipfix flush")
        self._configured = True

    def remove_vpp_config(self):
        self.disable_exporter()
        self.disable_flowperpkt_feature()
        self._configured = False
        self._test.vapi.cli("ipfix flush")

    def enable_exporter(self):
        self._test.vapi.set_ipfix_exporter(
            collector_address=self._test.pg0.remote_ip4n,
            src_address=self._test.pg0.local_ip4n,
            path_mtu=self._mtu,
            template_interval=self._timeout)

    def enable_flowperpkt_feature(self):
        self._test.vapi.ppcli("flowperpkt feature add-del %s %s" %
                              (self._intf, self._datapath))

    def disable_exporter(self):
        self._test.vapi.cli("set ipfix exporter collector 0.0.0.0")

    def disable_flowperpkt_feature(self):
        self._test.vapi.cli("flowperpkt feature add-del %s %s disable" %
                            (self._intf, self._datapath))

    def object_id(self):
        return "ipfix-collector-%s" % (self._src, self.dst)

    def query_vpp_config(self):
        return self._configured

    def verify_templates(self, decoder=None, timeout=1):
        templates = []
        p = self._test.wait_for_cflow_packet(self._test.collector, 2, timeout)
        self._test.assertTrue(p.haslayer(IPFIX))
        if decoder is not None and p.haslayer(Template):
            templates.append(p[Template].templateID)
            decoder.add_template(p.getlayer(Template))
        p = self._test.wait_for_cflow_packet(self._test.collector, 2)
        self._test.assertTrue(p.haslayer(IPFIX))
        if decoder is not None and p.haslayer(Template):
            templates.append(p[Template].templateID)
            decoder.add_template(p.getlayer(Template))
        p = self._test.wait_for_cflow_packet(self._test.collector, 2)
        self._test.assertTrue(p.haslayer(IPFIX))
        if decoder is not None and p.haslayer(Template):
            templates.append(p[Template].templateID)
            decoder.add_template(p.getlayer(Template))
        return templates


class TestFlowPerPkt(VppTestCase):
    """ Flow-per-packet plugin: test both L2 and IP4 reporting """

    # Test variables
    max_number_of_packets = 16
    active_timer = 5
    passive_timer = 30
    pkts = []

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestFlowPerPkt, cls).setUpClass()

        try:
            # Create pg interfaces
            cls.create_pg_interfaces(range(3))

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del(bd_id=1, uu_flood=1, learn=1)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1._sw_if_index, bd_id=1)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2._sw_if_index, bd_id=1)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()
                i.config_ip4()
                if i != cls.pg0:
                    i.resolve_arp()
            cls.pg0.configure_ipv4_neighbors()
            cls.collector = cls.pg0

        except Exception:
            super(TestFlowPerPkt, cls).tearDownClass()
            raise

    def setUp(self):
        """
        """
        super(TestFlowPerPkt, self).setUp()

    def create_stream(self, src_if=None, dst_if=None, packets=None, size=None):
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
            p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=4321) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, pkt_size)
            self.pkts.append(p)

    @staticmethod
    def compare_with_mask(payload, masked_expected_data):
        if len(payload) * 2 != len(masked_expected_data):
            return False

        # iterate over pairs: raw byte from payload and ASCII code for that
        # byte from masked payload (or XX if masked)
        for i in range(len(payload)):
            p = payload[i]
            m = masked_expected_data[2 * i:2 * i + 2]
            if m != "XX":
                if "%02x" % ord(p) != m:
                    return False
        return True

    def verify_ipfix(self, collector_if):
        """Check the ipfix capture"""
        found_data_packet = False
        found_template_packet = False
        found_l2_data_packet = False
        found_l2_template_packet = False

        # Scapy, of course, understands ipfix not at all...
        # These data vetted by manual inspection in wireshark
        # X'ed out fields are timestamps, which will absolutely
        # fail to compare.

        data_udp_string = "1283128300370000000a002fXXXXXXXX000000000000000101"\
            "00001f0000000100000002ac100102ac10020200XXXXXXXXXXXXXXXX0092"

        template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000000"\
            "010002002401000007000a0004000e000400080004000c000400050001009c00"\
            "0801380002"

        l2_data_udp_string = "12831283003c0000000a0034XXXXXXXX000000010000000"\
            "1010100240000000100000002%s02020000ff020008XXXXXXXXXXX"\
            "XXXXX0092" % self.pg1.local_mac.translate(None, ":")

        l2_template_udp_string = "12831283003c0000000a0034XXXXXXXX00000002000"\
            "000010002002401010007000a0004000e0004003800060050000601000002009"\
            "c000801380002"

        self.logger.info("Look for ipfix packets on %s sw_if_index %d "
                         % (collector_if.name, collector_if.sw_if_index))
        # expecting 4 packets on collector interface based on traffic on other
        # interfaces

        self.wait_for_cflow_packet(15)
        capture = collector_if.get_capture(4)

        for p in capture:
            ip = p[IP]
            udp = p[UDP]
            self.logger.info("src %s dst %s" % (ip.src, ip.dst))
            self.logger.info(" udp src_port %s dst_port %s"
                             % (udp.sport, udp.dport))

            payload = str(udp)

            if self.compare_with_mask(payload, data_udp_string):
                self.logger.info("found ip4 data packet")
                found_data_packet = True
            elif self.compare_with_mask(payload, template_udp_string):
                self.logger.info("found ip4 template packet")
                found_template_packet = True
            elif self.compare_with_mask(payload, l2_data_udp_string):
                self.logger.info("found l2 data packet")
                found_l2_data_packet = True
            elif self.compare_with_mask(payload, l2_template_udp_string):
                self.logger.info("found l2 template packet")
                found_l2_template_packet = True
            else:
                unmasked_payload = "".join(["%02x" % ord(c) for c in payload])
                self.logger.error("unknown pkt '%s'" % unmasked_payload)

        self.assertTrue(found_data_packet, "Data packet not found")
        self.assertTrue(found_template_packet, "Template packet not found")
        self.assertTrue(found_l2_data_packet, "L2 data packet not found")
        self.assertTrue(found_l2_template_packet,
                        "L2 template packet not found")

    def create_ipfix(self, collector, watched, active=0, passive=0,
                     collect="l2 l3 l4", datapath="l2", template_timout=20):
        """Create a IPFIX collector and setup flowperpkt feature

        :param VppInterface collector: interfcae used as colector
        :param VppInterface watched: which interface is monitored
        :param int active: flowperpkt active timer
        :param int passive: flowperpkt passive timer
        :param str collect: flowperpkt - what to collect
        :param str datapath: data path
        """
        self.vapi.set_ipfix_exporter(collector_address=collector.remote_ip4n,
                                     src_address=collector.local_ip4n,
                                     path_mtu=512,
                                     template_interval=template_timout)
        self.vapi.cli("flowperpkt params record %s active %d passive %d" % (
            collect, active, passive))
        self.vapi.cli("flowperpkt feature add-del %s %s" % (watched, datapath))
        # poke the flow reporting process
        self.vapi.cli("ipfix flush")

        # template packet should arrive immediately
        self.wait_for_cflow_packet(self.pg0)
        self.wait_for_cflow_packet(self.pg0)
        self.wait_for_cflow_packet(self.pg0)

    def verify_cflow_data(self, decoder, capture, cflow):
        octets = 0
        packets = 0
        for p in capture:
            octets += p[IP].len
            packets += 1
        if cflow.haslayer(Data):
            data = decoder.decode_data_set(cflow.getlayer(Set))
            for record in data:
                self.assertEqual(int(record[1].encode('hex'), 16), octets)
                self.assertEqual(int(record[2].encode('hex'), 16), packets)

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
                self.assertEqual(p[IP].len, int(rec[1].encode('hex'), 16))
                self.assertEqual(1, int(rec[2].encode('hex'), 16))
        self.assertEqual(len(capture), idx)

    def wait_for_cflow_packet(self, collector_intf, set_id=2, timeout=1,
                              expected=True):
        """ wait for CFLOW packet and verify its correctness

        :param timeout: how long to wait

        :returns: tuple (packet, time spent waiting for packet)
        """
        self.logger.info("IPFIX: Waiting for CFLOW packet")
        deadline = time.time() + timeout
        counter = 0
        while True:
            counter += 1
            # sanity check
            self.assert_in_range(counter, 0, 100, "number of packets ignored")
            time_left = deadline - time.time()
            try:
                if time_left < 0 and expected:
                    raise CaptureTimeoutError(
                          "Packet did not arrive within timeout")
                p = collector_intf.wait_for_packet(timeout=time_left)
            except CaptureTimeoutError:
                if expected:
                    raise CaptureTimeoutError(
                          "Packet did not arrive within timeout")
                else:
                    return
            if not expected:
                raise CaptureTimeoutError("Packet arrived even not expected")
            self.assertEqual(p[Set].setID, set_id)
            self.logger.debug(ppp("IPFIX: Got packet:", p))
            break
        return p

    def send_packets(self, src_if=None, dst_if=None):
        if src_if is None:
            src_if = self.pg1
        if dst_if is None:
            dst_if = self.pg2
        self.pg_enable_capture([dst_if])
        src_if.add_stream(self.pkts)
        self.pg_start()
        return dst_if.get_capture(len(self.pkts))

    def test_0004(self):
        """ receive template data packets
        """

        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=5, active=10)
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates(timeout=10)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_0005(self):
        """ timer=10s, less than template timeout
        """
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=20, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder)

        self.create_stream()
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[0], 15)
        self.verify_cflow_data(ipfix_decoder, capture, cflow)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0002")

    def test_0006(self):
        """ timer=30s, greater than template timeout
        """
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=20, active=30)
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates()

        self.create_stream()
        capture = self.send_packets()

        self.vapi.cli("ipfix flush")
        # next set of template packet should arrive after 20 seconds
        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive within 20 s
        templates = ipfix.verify_templates(ipfix_decoder, timeout=20)

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[0], 15)
        self.verify_cflow_data(ipfix_decoder, capture, cflow)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0003")

    def test_0007(self):
        """ sent packet after first cflow packet arrived
        """
        self.logger.info("FFP_TEST_START_0004")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=60)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 60)

        self.pg_enable_capture([self.pg2])

        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 60)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0004")

    def test_0008(self):
        """ disable IPFIX after first packets
        """
        self.logger.info("FFP_TEST_START_0005")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=30)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        # disble IPFIX
        ipfix.disable_exporter()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in 1 minute
        self.wait_for_cflow_packet(self.collector, templates[0], 60,
                                   expected=False)
        self.collector.get_capture(0)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0005")

    def test_0009(self):
        """ disable IPFIX after first packets and re-enable after few packets
        """
        self.logger.info("FFP_TEST_START_0006")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=30)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        # disble IPFIX
        ipfix.disable_exporter()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in 1 minute
        self.wait_for_cflow_packet(self.collector, templates[0], 60,
                                   expected=False)
        self.collector.get_capture(0)

        # enable IPFIX
        ipfix.enable_exporter()
        ipfix.verify_templates(ipfix_decoder)

        self.send_packets()

        # make sure the next packets (templates and data) we expect actually
        # showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0006")

    def test_0010(self):
        """ disable flowperpkt feature after first packets
        """
        self.logger.info("FFP_TEST_START_0007")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []
        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=30)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        # disble IPFIX
        ipfix.disable_flowperpkt_feature()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in 1 minute
        self.wait_for_cflow_packet(self.collector, templates[0], 60,
                                   expected=False)
        self.collector.get_capture(0)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0007")

    def test_0001(self):
        """ disable flowperpkt feature after first packets and re-enable
        after few packets
        """
        self.logger.info("FFP_TEST_START_0008")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=30)

        self.create_stream()
        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        # disble FPP feature
        ipfix.disable_flowperpkt_feature()
        self.pg_enable_capture([self.collector])

        self.send_packets()

        # make sure no one packet arrived in 1 minute
        self.wait_for_cflow_packet(self.collector, templates[0], 60,
                                   expected=False)
        self.collector.get_capture(0)

        # enable FPP feature
        ipfix.enable_flowperpkt_feature()
        templates = ipfix.verify_templates(ipfix_decoder, timeout=150)

        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0008")

    def test_0002(self):
        """ no timer, one CFLOW packet, 9 Flows inside
        """
        self.logger.info("FFP_TEST_START_1000")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=0)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

        self.create_stream(packets=9)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[0], 6)
        self.verify_cflow_data_notimer(ipfix_decoder, capture, [cflow])
        self.wait_for_cflow_packet(self.collector, templates[0], 10,
                                   expected=False)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_1000")

    def test_0003(self):
        """ no timer, two CFLOW packets (mtu=256), 3 Flows in each
        """
        self.logger.info("FFP_TEST_START_1001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, intf='pg2', timeout=120, active=0,
                         mtu=256)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

        self.create_stream(packets=6)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflows = []
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[0], 6))
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[0], 6))
        self.verify_cflow_data_notimer(ipfix_decoder, capture, cflows)
        self.collector.get_capture(5)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_1001")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
