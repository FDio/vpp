#!/usr/bin/env python3
# Copyright (c) 2021 Graphiant, Inc.

import unittest
from config import config
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi import VppEnum
from vpp_policer import VppPolicer, PolicerAction, Dir

NUM_PKTS = 67


@unittest.skipIf("policer" in config.excluded_plugins, "Exclude Policer plugin tests")
class TestPolicerInput(VppTestCase):
    """Policer on an interface"""

    vpp_worker_count = 2

    def setUp(self):
        super(TestPolicerInput, self).setUp()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        self.pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 100)
        )

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestPolicerInput, self).tearDown()

    def policer_interface_test(self, dir: Dir):
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "pol1",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        sw_if_index = self.pg0.sw_if_index if dir == Dir.RX else self.pg1.sw_if_index

        # Start policing on pg0
        policer.apply_vpp_config(sw_if_index, dir, True)

        rx = self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)
        stats = policer.get_stats()

        # Single rate, 2 colour policer - expect conform, violate but no exceed
        self.assertGreater(stats["conform_packets"], 0)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        # Stop policing on pg0
        policer.apply_vpp_config(sw_if_index, dir, False)

        rx = self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)

        statsnew = policer.get_stats()

        # No new packets counted
        self.assertEqual(stats, statsnew)

        policer.remove_vpp_config()

    def test_policer_input(self):
        """Input Policing"""
        self.policer_interface_test(Dir.RX)

    def test_policer_output(self):
        """Output Policing"""
        self.policer_interface_test(Dir.TX)

    def test_policer_reset(self):
        """Policer reset bucket"""
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "pol1",
            1,
            0,
            10000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Start policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, Dir.RX, True)

        self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)
        details = policer.get_details()

        self.assertGreater(details.current_limit, details.current_bucket)

        self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)
        self.vapi.policer_reset(policer_index=policer.policer_index)
        details = policer.get_details()

        self.assertEqual(details.current_limit, details.current_bucket)

        policer.apply_vpp_config(self.pg0.sw_if_index, Dir.RX, False)

        policer.remove_vpp_config()

    def test_policer_update(self):
        """Policer update"""
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "pol1",
            1,
            0,
            10000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Start policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, Dir.RX, True)

        self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)
        details_before = policer.get_details()

        self.assertGreater(details_before.current_limit, details_before.current_bucket)

        policer.cir = 8000
        policer.commited_burst = 100000
        policer.update()

        details_after = policer.get_details()

        self.assertGreater(details_after.cir, details_before.cir)
        self.assertGreater(details_after.cb, details_before.cb)

        policer.apply_vpp_config(self.pg0.sw_if_index, Dir.RX, False)

        policer.remove_vpp_config()

    def policer_handoff_test(self, dir: Dir):
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "pol2",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        sw_if_index = self.pg0.sw_if_index if dir == Dir.RX else self.pg1.sw_if_index

        # Bind the policer to worker 1
        policer.bind_vpp_config(1, True)

        # Start policing on pg0
        policer.apply_vpp_config(sw_if_index, dir, True)

        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        stats = policer.get_stats()
        stats0 = policer.get_stats(worker=0)
        stats1 = policer.get_stats(worker=1)

        # Worker 1, should have done all the policing
        self.assertEqual(stats, stats1)

        # Worker 0, should have handed everything off
        self.assertEqual(stats0["conform_packets"], 0)
        self.assertEqual(stats0["exceed_packets"], 0)
        self.assertEqual(stats0["violate_packets"], 0)

        # Unbind the policer from worker 1 and repeat
        policer.bind_vpp_config(1, False)
        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        # The policer should auto-bind to worker 0 when packets arrive
        stats = policer.get_stats()

        # The 2 workers should now have policed the same amount
        stats = policer.get_stats()
        stats0 = policer.get_stats(worker=0)
        stats1 = policer.get_stats(worker=1)

        self.assertGreater(stats0["conform_packets"], 0)
        self.assertEqual(stats0["exceed_packets"], 0)
        self.assertGreater(stats0["violate_packets"], 0)

        self.assertGreater(stats1["conform_packets"], 0)
        self.assertEqual(stats1["exceed_packets"], 0)
        self.assertGreater(stats1["violate_packets"], 0)

        self.assertEqual(
            stats0["conform_packets"] + stats1["conform_packets"],
            stats["conform_packets"],
        )

        self.assertEqual(
            stats0["violate_packets"] + stats1["violate_packets"],
            stats["violate_packets"],
        )

        # Stop policing on pg0
        policer.apply_vpp_config(sw_if_index, dir, False)

        policer.remove_vpp_config()

    def test_policer_handoff_input(self):
        """Worker thread handoff policer input"""
        self.policer_handoff_test(Dir.RX)

    def test_policer_handoff_output(self):
        """Worker thread handoff policer output"""
        self.policer_handoff_test(Dir.TX)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
