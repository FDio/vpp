#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.
#
# Multi-worker test for SFDP kill immediacy.
#
# This test validates that sfdp_expire_session_now sends the interrupt to the
# correct worker thread (via vlib_get_main_by_index) so that killing a session
# owned by a worker thread is immediate, not delayed until the next scheduled
# tick.
#
# Regression test for the following bug:
#   sfdp_expire_session_now used vlib_get_main() to send the interrupt.
#   Since sfdp_kill_session is called from the API/CLI handler (main thread),
#   vlib_get_main() returns the main thread's vm — not the owning worker's vm.
#   The interrupt therefore never reached the owning worker's sfdp-expire node,
#   so the kill was not immediate.
#
# Kill operations use the sfdp_kill_session API.
#
import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpKillMultiWorker(VppTestCase):
    """SFDP kill immediacy with multiple worker threads"""

    # 1 worker thread: sessions go to thread index 1 (worker 0)
    vpp_worker_count = 1

    # 20ms per tick; sessions-log2 5 = 32 sessions (small memory footprint)
    extra_vpp_config = ["sfdp { timer-interval 0.02 sessions-log2 5 }"]

    @classmethod
    def setUpClass(cls):
        super(TestSfdpKillMultiWorker, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            cls.pg0.config_ip4()
            cls.pg0.admin_up()
        except Exception:
            super(TestSfdpKillMultiWorker, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.pg0.unconfig_ip4()
        cls.pg0.admin_down()
        super(TestSfdpKillMultiWorker, cls).tearDownClass()

    def setUp(self):
        super(TestSfdpKillMultiWorker, self).setUp()
        self.vapi.cli("sfdp tenant add 1 context 100")
        self.vapi.cli("set sfdp interface-input pg0 tenant 1")
        # Very long timeout: natural expiry must not interfere with the test
        self.vapi.cli("set sfdp timeout tenant 1 embryonic 3600")

    def tearDown(self):
        self.vapi.sfdp_kill_session(session_index=0, is_all=True)
        self.virtual_sleep(0.02)
        self.vapi.cli("set sfdp interface-input pg0 tenant 1 disable")
        self.vapi.cli("sfdp tenant del 1")
        super(TestSfdpKillMultiWorker, self).tearDown()

    def _make_syn(self, dst_ip, sport):
        """Build a single TCP SYN packet."""
        return (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=dst_ip)
            / TCP(sport=sport, dport=80, flags="S")
        )

    def _send_syns(self, pkts, worker):
        """Send one or more TCP SYNs through a specific VPP worker thread."""
        if not isinstance(pkts, list):
            pkts = [pkts]
        self.pg0.add_stream(pkts, worker=worker)

    def _sessions(self):
        return list(self.vapi.sfdp_session_dump())

    def test_kill_all_sessions_on_worker(self):
        """kill_all expires multiple sessions on a worker thread within one tick

        With the original bug: sfdp_expire_session_now called vlib_get_main(),
        which from the API/CLI handler (main thread) returns thread 0's vm.
        The interrupt never reached the owning worker's sfdp-expire node,
        so sessions were not killed within one tick.

        With the fix (vlib_get_main_by_index(thread_index)): the interrupt goes
        to the owning worker thread and sessions are processed within one tick.
        """
        # Both SYNs go through the same worker (thread index 1)
        self._send_syns(
            [
                self._make_syn("198.51.100.2", 10001),
                self._make_syn("198.51.100.2", 10002),
            ],
            worker=0,
        )
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        sessions = self._sessions()
        self.assertGreater(len(sessions), 0, "Expected at least one SFDP session")

        # Verify sessions are on the worker thread, not the main thread (0).
        # This is the key precondition: if sessions were on thread 0, the old
        # broken code (vlib_get_main()) would accidentally work.
        for s in sessions:
            self.assertNotEqual(
                s.thread_index,
                0,
                f"Session {s.session_idx} landed on main thread; "
                "should be on worker thread 1",
            )
        self.logger.info(f"Sessions on threads: {[s.thread_index for s in sessions]}")

        self.vapi.sfdp_kill_session(session_index=0, is_all=True)

        # One tick is enough if the interrupt reaches the owning worker.
        # With the broken code, worker-thread sessions would survive here.
        self.virtual_sleep(0.02)
        remaining = self._sessions()
        self.assertEqual(
            len(remaining),
            0,
            f"Sessions not killed within one tick: "
            f"{[(s.thread_index, s.session_idx) for s in remaining]}",
        )

    def test_kill_individual_session_on_worker(self):
        """Killing a single session on a worker thread is immediate

        Ensures that the interrupt targets the owning worker's sfdp-expire node,
        not just the kill_all path.
        """
        # Force the session onto worker 0 (VPP thread index 1)
        self._send_syns(self._make_syn("198.51.100.2", 10003), worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 1)
        sess = sessions[0]

        # Confirm this session is on a worker thread, not main (thread 0)
        self.assertNotEqual(
            sess.thread_index,
            0,
            "Session landed on main thread; use worker=0 to force a worker thread",
        )
        self.logger.info(f"Session on thread {sess.thread_index}")

        self.vapi.sfdp_kill_session(session_index=sess.session_idx, is_all=False)

        # Must be gone within one tick
        self.virtual_sleep(0.02)
        self.assertEqual(len(self._sessions()), 0)

    def test_kill_rearmed_session_on_worker(self):
        """Killing a rearmed session on a worker thread completes within a few ticks

        Rearm happens when timeout > one wheel turn (2048 * 0.02s ≈ 41s).
        The session moves to the second pass of the wheel.  Kill must still
        be processed regardless of which pass the timer is on.
        """
        self.vapi.cli("set sfdp timeout tenant 1 embryonic 50")

        # Force session onto worker 0 (VPP thread index 1)
        self._send_syns(self._make_syn("198.51.100.2", 10004), worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 1)
        sess = sessions[0]
        self.assertNotEqual(sess.thread_index, 0)

        # Advance past one wheel turn to trigger rearm (virtual_sleep is instantaneous)
        self.virtual_sleep(41)
        sessions = self._sessions()
        self.assertEqual(len(sessions), 1, "Session should still be alive after 41s")

        self.vapi.sfdp_kill_session(session_index=sess.session_idx, is_all=False)
        self.virtual_sleep(0.1)
        self.assertEqual(len(self._sessions()), 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
