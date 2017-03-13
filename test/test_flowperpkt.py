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

    def __init__(self, test, intf='pg2', active=0, passive=0, timeout=20,
                 mtu=512,
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
        self._test.vapi.cli("ipfix flush")
        self._configured = False

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


class MethodHolder(VppTestCase):
    """ Flow-per-packet plugin: test both L2 and IP4 reporting """

    # Test variables
    max_number_of_packets = 16
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
            super(MethodHolder, cls).tearDownClass()
            raise

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


class TestFFP_Timers(MethodHolder):
    """Template verification, timer tests"""

    def test_0001(self):
        """ receive template data packets"""

        self.logger.info("FFP_TEST_START_0001")
        self.pg_enable_capture(self.pg_interfaces)

        ipfix = VppCFLOW(test=self, timeout=5, active=10)
        ipfix.add_vpp_config()

        # template packet should arrive immediately
        ipfix.verify_templates(timeout=10)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0001")

    def test_0002(self):
        """ timer=10s, less than template timeout"""
        self.logger.info("FFP_TEST_START_0002")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=20, active=10)
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

    def test_0003(self):
        """ timer=30s, greater than template timeout"""
        self.logger.info("FFP_TEST_START_0003")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=20, active=30)
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

    def test_0004(self):
        """ sent packet after first cflow packet arrived"""
        self.logger.info("FFP_TEST_START_0004")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=120, active=10)
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


class TestFFP_NoTimer(MethodHolder):
    """No timer"""

    def test_0001(self):
        """ no timer, one CFLOW packet, 9 Flows inside
        """
        self.logger.info("FFP_TEST_START_1000")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=120, active=0)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

        self.create_stream(packets=9)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflow = self.wait_for_cflow_packet(self.collector, templates[0], 10)
        self.verify_cflow_data_notimer(ipfix_decoder, capture, [cflow])
        self.wait_for_cflow_packet(self.collector, templates[0], 10,
                                   expected=False)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_1000")

    def test_0002(self):
        """ no timer, two CFLOW packets (mtu=256), 3 Flows in each
        """
        self.logger.info("FFP_TEST_START_1001")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=120, active=0, mtu=256)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

        self.create_stream(packets=6)
        capture = self.send_packets()

        # make sure the one packet we expect actually showed up
        cflows = []
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[0], 10))
        cflows.append(self.wait_for_cflow_packet(self.collector,
                                                 templates[0], 10))
        self.verify_cflow_data_notimer(ipfix_decoder, capture, cflows)
        self.collector.get_capture(5)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_1001")


class TestFFP_DisableIPFIX(MethodHolder):
    """Disable IPFIX"""

    def test_0001(self):
        """ disable IPFIX after first packets
        """
        self.logger.info("FFP_TEST_START_0005")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=20, active=10)
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
        self.wait_for_cflow_packet(self.collector, templates[0], 30,
                                   expected=False)
        self.collector.get_capture(0)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0005")


class TestFFP_ReenableIPFIX(MethodHolder):
    """Re-enable IPFIX"""
    def test_0001(self):
        """ disable IPFIX after first packets and re-enable after few packets
        """
        self.logger.info("FFP_TEST_START_0006")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=30, active=10)
        ipfix.add_vpp_config()

        ipfix_decoder = IPFIXDecoder()
        # template packet should arrive immediately
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

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
        self.wait_for_cflow_packet(self.collector, templates[0], 30,
                                   expected=False)
        self.collector.get_capture(0)

        # enable IPFIX
        ipfix.enable_exporter()
        self.vapi.cli("ipfix flush")
        ipfix.verify_templates(ipfix_decoder)

        self.send_packets()

        # make sure the next packets (templates and data) we expect actually
        # showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0006")


class TestFFP_DisableFFP(MethodHolder):
    """Disable FlowPerPkt feature"""
    def test_0001(self):
        """ disable flowperpkt feature after first packets
        """
        self.logger.info("FFP_TEST_START_0007")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []
        ipfix = VppCFLOW(test=self, timeout=30, active=10)
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
        self.wait_for_cflow_packet(self.collector, templates[0], 30,
                                   expected=False)
        self.collector.get_capture(0)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0007")


class TestFFP_ReenableFFP(MethodHolder):
    """Re-enable FlowPerPkt feature"""

    def test_0001(self):
        """ disable flowperpkt feature after first packets and re-enable
        after few packets
        """
        self.logger.info("FFP_TEST_START_0008")
        self.pg_enable_capture(self.pg_interfaces)
        self.pkts = []

        ipfix = VppCFLOW(test=self, timeout=30, active=10)
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
        self.wait_for_cflow_packet(self.collector, templates[0], 30,
                                   expected=False)
        self.collector.get_capture(0)

        # enable FPP feature
        ipfix.enable_flowperpkt_feature()
        self.vapi.cli("ipfix flush")
        templates = ipfix.verify_templates(ipfix_decoder, timeout=10)

        self.send_packets()

        # make sure the one packet we expect actually showed up
        self.wait_for_cflow_packet(self.collector, templates[0], 30)
        self.collector.get_capture(4)

        ipfix.remove_vpp_config()
        self.logger.info("FFP_TEST_FINISH_0008")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
