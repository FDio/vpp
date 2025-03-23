#!/usr/bin/env python3

import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from random import randint
import re  # for finding counters in "sh errors" output


class SFlowDropTestCase(VppTestCase):
    """sFlow test case"""

    @classmethod
    def setUpClass(self):
        super(SFlowDropTestCase, self).setUpClass()

    @classmethod
    def teadDownClass(cls):
        super(SFlowDropTestCase, cls).tearDownClass()

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

    def enable_sflow_via_api(self):
        ## TEST: Enable both interfaces
        ret = self.vapi.sflow_enable_disable(hw_if_index=1, enable_disable=True)
        self.assertEqual(ret.retval, 0)
        ret = self.vapi.sflow_enable_disable(hw_if_index=2, enable_disable=True)
        self.assertEqual(ret.retval, 0)

        ## TEST: sflow_sampling_rate_set()
        self.vapi.sflow_sampling_rate_set(sampling_N=1)
        ret = self.vapi.sflow_sampling_rate_get()
        self.assert_equal(ret.sampling_N, 1)

        ## TEST: sflow_drop_monitoring_set()
        self.vapi.sflow_drop_monitoring_set(drop_M=1)
        ret = self.vapi.sflow_drop_monitoring_get()
        self.assert_equal(ret.drop_M, 1)

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
                / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4, ttl=i + 1)
                / UDP(sport=randint(49152, 65535), dport=5678)
                / Raw(payload)
            )
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)
            # return the created packet list
        return packets

    def get_sflow_counter(self, counter):
        counters = self.vapi.cli("sh errors").split("\n")
        for i in range(1, len(counters) - 1):
            results = counters[i].split()
            if results[1] == "sflow":
                if re.search(counter, counters[i]) is not None:
                    return int(results[0])
        return None

    def verify_sflow(self, count):
        ctr_pk_proc = "sflow packets processed"
        ctr_pk_samp = "sflow packets sampled"
        ctr_pk_drop = "sflow packets dropped"
        ctr_di_proc = "sflow discards processed"
        ctr_di_drop = "sflow discards dropped"
        ctr_ps_sent = "sflow PSAMPLE sent"
        ctr_ps_fail = "sflow PSAMPLE send failed"
        ctr_dm_sent = "sflow DROPMON sent"
        ctr_dm_fail = "sflow DROPMON send failed"
        pk_proc = self.get_sflow_counter(ctr_pk_proc)
        pk_samp = self.get_sflow_counter(ctr_pk_samp)
        pk_drop = self.get_sflow_counter(ctr_pk_drop)
        di_proc = self.get_sflow_counter(ctr_di_proc)
        di_drop = self.get_sflow_counter(ctr_di_drop)
        ps_sent = self.get_sflow_counter(ctr_ps_sent)
        ps_fail = self.get_sflow_counter(ctr_ps_fail)
        dm_sent = self.get_sflow_counter(ctr_dm_sent)
        dm_fail = self.get_sflow_counter(ctr_dm_fail)
        self.logger.info(ctr_pk_proc + "=" + str(pk_proc))
        self.logger.info(ctr_pk_samp + "=" + str(pk_samp))
        self.logger.info(ctr_pk_drop + "=" + str(pk_drop))
        self.logger.info(ctr_di_proc + "=" + str(di_proc))
        self.logger.info(ctr_di_drop + "=" + str(di_drop))
        self.logger.info(ctr_ps_sent + "=" + str(ps_sent))
        self.logger.info(ctr_ps_fail + "=" + str(ps_fail))
        self.logger.info(ctr_dm_sent + "=" + str(dm_sent))
        self.logger.info(ctr_dm_fail + "=" + str(dm_fail))
        self.assert_equal(pk_proc, count, ctr_pk_proc)
        self.assert_equal(pk_samp, count, ctr_pk_samp)
        self.assert_equal(pk_drop, None, ctr_pk_drop)
        self.assert_equal(di_proc, 1, ctr_di_proc)
        self.assert_equal(di_drop, None, ctr_di_drop)
        self.assert_equal(ps_sent, count, ctr_ps_sent)
        self.assert_equal(ps_fail, None, ctr_ps_fail)
        self.assert_equal(dm_sent, 1, ctr_dm_sent)
        self.assert_equal(dm_fail, None, ctr_dm_fail)

    def test_basic(self):
        self.enable_sflow_via_api()
        count = 7
        # create the packet stream, with ttl decrementing so
        # that just 1 packet will be dropped
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
        capture = self.pg1.get_capture(count - 1, timeout=2)
        # expect an ICMP TTL exceeded message back on pg0
        # and a dropped packet that sflow will write to DROPMON
        capture0 = self.pg0.get_capture(1, timeout=2)
        # allow time for the dropped packet to be fully
        # processed, and for the counters to be updated
        self.sleep(1.0)
        # verify sflow counters
        self.verify_sflow(count)
