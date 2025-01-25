#!/usr/bin/env python3

import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from random import randint
import re  # for finding counters in "sh errors" output


class SFlowTestCase(VppTestCase):
    """sFlow test case"""

    @classmethod
    def setUpClass(self):
        super(SFlowTestCase, self).setUpClass()

    @classmethod
    def teadDownClass(cls):
        super(SFlowTestCase, cls).tearDownClass()

    def setUp(self):
        self.create_pg_interfaces(range(2))  #  create pg0 and pg1
        for i in self.pg_interfaces:
            i.admin_up()  # put the interface up
            i.config_ip4()  # configure IPv4 address on the interface
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig()
            i.set_table_ip4(0)
            i.set_table_ip6(0)

    def is_hw_interface_in_dump(self, dump, hw_if_index):
        for i in dump:
            if i.hw_if_index == hw_if_index:
                return True
        else:
            return False

    def enable_sflow_via_api(self):
        ## TEST: Enable one interface
        ret = self.vapi.sflow_enable_disable(hw_if_index=1, enable_disable=True)
        self.assertEqual(ret.retval, 0)

        ## TEST: interface dump all
        ret = self.vapi.sflow_interface_dump()
        self.assertTrue(self.is_hw_interface_in_dump(ret, 1))

        ## TEST: Disable one interface
        ret = self.vapi.sflow_enable_disable(hw_if_index=1, enable_disable=False)
        self.assertEqual(ret.retval, 0)

        ## TEST: interface dump all after enable + disable
        ret = self.vapi.sflow_interface_dump()
        self.assertEqual(len(ret), 0)

        ## TEST: Enable both interfaces
        ret = self.vapi.sflow_enable_disable(hw_if_index=1, enable_disable=True)
        self.assertEqual(ret.retval, 0)
        ret = self.vapi.sflow_enable_disable(hw_if_index=2, enable_disable=True)
        self.assertEqual(ret.retval, 0)

        ## TEST: interface dump all
        ret = self.vapi.sflow_interface_dump()
        self.assertTrue(self.is_hw_interface_in_dump(ret, 1))
        self.assertTrue(self.is_hw_interface_in_dump(ret, 2))

        ## TEST: the default sampling rate
        ret = self.vapi.sflow_sampling_rate_get()
        self.assert_equal(ret.sampling_N, 10000)

        ## TEST: sflow_sampling_rate_set()
        self.vapi.sflow_sampling_rate_set(sampling_N=1)
        ret = self.vapi.sflow_sampling_rate_get()
        self.assert_equal(ret.sampling_N, 1)

        ## TEST: the default polling interval
        ret = self.vapi.sflow_polling_interval_get()
        self.assert_equal(ret.polling_S, 20)

        ## TEST: sflow_polling_interval_set()
        self.vapi.sflow_polling_interval_set(polling_S=10)
        ret = self.vapi.sflow_polling_interval_get()
        self.assert_equal(ret.polling_S, 10)

        ## TEST: the default header bytes
        ret = self.vapi.sflow_header_bytes_get()
        self.assert_equal(ret.header_B, 128)

        ## TEST: sflow_header_bytes_set()
        self.vapi.sflow_header_bytes_set(header_B=96)
        ret = self.vapi.sflow_header_bytes_get()
        self.assert_equal(ret.header_B, 96)

    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
                / UDP(sport=randint(49152, 65535), dport=5678)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)
            # return the created packet list
        return packets

    def verify_capture(self, src_if, dst_if, capture):
        packet_info = None
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                # convert the payload to packet info object
                payload_info = self.payload_to_info(packet[Raw])
                # make sure the indexes match
                self.assert_equal(
                    payload_info.src, src_if.sw_if_index, "source sw_if_index"
                )
                self.assert_equal(
                    payload_info.dst, dst_if.sw_if_index, "destination sw_if_index"
                )
                packet_info = self.get_next_packet_info_for_interface2(
                    src_if.sw_if_index, dst_if.sw_if_index, packet_info
                )
                # make sure we didn't run out of saved packets
                self.assertIsNotNone(packet_info)
                self.assert_equal(
                    payload_info.index, packet_info.index, "packet info index"
                )
                saved_packet = packet_info.data  # fetch the saved packet
                # assert the values match
                self.assert_equal(ip.src, saved_packet[IP].src, "IP source address")
                self.assert_equal(udp.sport, saved_packet[UDP].sport, "UDP source port")
            except:
                self.logger.error("Unexpected or invalid packet:", packet)
                raise
        remaining_packet = self.get_next_packet_info_for_interface2(
            src_if.sw_if_index, dst_if.sw_if_index, packet_info
        )
        self.assertIsNone(
            remaining_packet,
            "Interface %s: Packet expected from interface "
            "%s didn't arrive" % (dst_if.name, src_if.name),
        )

    def get_sflow_counter(self, counter):
        counters = self.vapi.cli("sh errors").split("\n")
        for i in range(1, len(counters) - 1):
            results = counters[i].split()
            if results[1] == "sflow":
                if re.search(counter, counters[i]) is not None:
                    return int(results[0])
        return None

    def verify_sflow(self, count):
        ctr_processed = "sflow packets processed"
        ctr_sampled = "sflow packets sampled"
        ctr_dropped = "sflow packets dropped"
        ctr_ps_sent = "sflow PSAMPLE sent"
        ctr_ps_fail = "sflow PSAMPLE send failed"
        processed = self.get_sflow_counter(ctr_processed)
        sampled = self.get_sflow_counter(ctr_sampled)
        dropped = self.get_sflow_counter(ctr_dropped)
        ps_sent = self.get_sflow_counter(ctr_ps_sent)
        ps_fail = self.get_sflow_counter(ctr_ps_fail)
        self.assert_equal(processed, count, ctr_processed)
        self.assert_equal(sampled, count, ctr_sampled)
        self.assert_equal(dropped, None, ctr_dropped)
        # TODO decide how to warn if PSAMPLE is not working
        # It requires a prior "sudo modprobe psample", but
        # that should probably be done at system boot time
        # or maybe in a systemctl startup script, so we
        # should only warn here.
        self.logger.info(ctr_ps_sent + "=" + str(ps_sent))
        self.logger.info(ctr_ps_fail + "=" + str(ps_fail))

    def test_basic(self):
        self.enable_sflow_via_api()
        count = 7
        # create the packet stream
        packets = self.create_stream(self.pg0, self.pg1, count)
        # add the stream to the source interface
        self.pg0.add_stream(packets)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        # get capture - the proper count of packets was saved by
        # create_packet_info() based on dst_if parameter
        capture = self.pg1.get_capture()
        # assert nothing captured on pg0 (always do this last, so that
        # some time has already passed since pg_start())
        self.pg0.assert_nothing_captured()
        # verify capture
        self.verify_capture(self.pg0, self.pg1, capture)
        # verify sflow counters
        self.verify_sflow(count)
