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
        so sessions were not killed.

        With the fix (vlib_get_main_by_index + bypass timing wheel): kills
        bypass the timing wheel and directly add to expired_sessions, making
        them truly immediate (processed on next sfdp-expire run).
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

        # With the fix (commit XXX), kill bypasses the timing wheel and directly
        # adds sessions to expired_sessions, so one tick is enough.
        # With the broken code (wrong thread), worker sessions would never be killed.
        self.virtual_sleep(0.02)
        remaining = self._sessions()
        self.assertEqual(
            len(remaining),
            0,
            f"Sessions not killed: "
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

        # With the fix (commit XXX), kill bypasses the timing wheel and directly
        # adds the session to expired_sessions. One tick is enough.
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

    # ------------------------------------------------------------------
    # Step 1 — no side-effects
    # ------------------------------------------------------------------

    def test_no_side_effects_kill_nonexistent(self):
        """Killing a non-existent session index returns an error, no crash

        Verifies that an invalid kill request does not corrupt state: the
        session table must remain consistent and a subsequent valid session
        must still work normally.
        """
        # No sessions exist yet — kill index 0 must fail gracefully
        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_kill_session(session_index=0, is_all=False)

        # Create a real session and verify the table is still intact
        self._send_syns(self._make_syn("198.51.100.2", 30001), worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        sessions = self._sessions()
        self.assertEqual(len(sessions), 1, "Session table corrupted after bad kill")

    def test_no_side_effects_natural_expiry_unaffected(self):
        """Sessions not targeted by kill still expire naturally

        Creates two sessions. Kills only one. The other must survive until
        its natural timeout, confirming no accidental collateral kill.
        """
        self._send_syns(
            [
                self._make_syn("198.51.100.2", 30002),
                self._make_syn("198.51.100.2", 30003),
            ],
            worker=0,
        )
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 2)
        # Kill only the first one
        self.vapi.sfdp_kill_session(session_index=sessions[0].session_idx, is_all=False)
        self._wait_for_n_sessions(1, timeout=1.0)

        remaining = self._sessions()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].session_idx, sessions[1].session_idx)

    def test_kill_is_immediate_sub_tick(self):
        """Kill is processed within a sub-tick wait (0.005 s < 1 tick = 0.02 s)

        With the timing-wheel bypass, the session is placed in expired_sessions
        before the barrier is released.  The first sfdp-expire run after the
        kill therefore processes it regardless of the timing wheel's nticks
        state.  A wait of 0.005 s — one quarter of a tick — is sufficient.

        This would fail with the old timing-wheel path (nticks = 0 whenever
        sfdp-expire ran in the last ~15 ms, ~75 % of the time).
        """
        self._send_syns(self._make_syn("198.51.100.2", 40001), worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 1)
        sess = sessions[0]
        self.assertNotEqual(sess.thread_index, 0)

        self.vapi.sfdp_kill_session(session_index=sess.session_idx, is_all=False)
        self.virtual_sleep(0.005)
        self.assertEqual(
            len(self._sessions()),
            0,
            "Session not killed within sub-tick (0.005 s) — "
            "timing wheel bypass is not working correctly",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _wait_for_n_sessions(self, n, timeout=1.0, tick=0.02):
        """Poll until exactly n sessions remain, or fail on timeout."""
        steps = int(timeout / tick)
        for _ in range(steps):
            if len(self._sessions()) == n:
                return
            self.virtual_sleep(tick)
        remaining = self._sessions()
        self.assertEqual(
            len(remaining),
            n,
            f"Expected {n} sessions after {timeout}s, got {len(remaining)}: "
            f"{[(s.thread_index, s.session_idx) for s in remaining]}",
        )


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpKillTwoWorkers(VppTestCase):
    """SFDP kill immediacy with sessions spread across two worker threads"""

    # 2 worker threads: sessions go to thread index 1 (worker 0)
    # and thread index 2 (worker 1)
    vpp_worker_count = 2

    # 20ms per tick; sessions-log2 5 = 32 sessions (small memory footprint)
    extra_vpp_config = ["sfdp { timer-interval 0.02 sessions-log2 5 }"]

    @classmethod
    def setUpClass(cls):
        super(TestSfdpKillTwoWorkers, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            cls.pg0.config_ip4()
            cls.pg0.admin_up()
        except Exception:
            super(TestSfdpKillTwoWorkers, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.pg0.unconfig_ip4()
        cls.pg0.admin_down()
        super(TestSfdpKillTwoWorkers, cls).tearDownClass()

    def setUp(self):
        super(TestSfdpKillTwoWorkers, self).setUp()
        self.vapi.cli("sfdp tenant add 1 context 100")
        self.vapi.cli("set sfdp interface-input pg0 tenant 1")
        # Very long timeout: natural expiry must not interfere with the test
        self.vapi.cli("set sfdp timeout tenant 1 embryonic 3600")

    def tearDown(self):
        self.vapi.sfdp_kill_session(session_index=0, is_all=True)
        self.virtual_sleep(0.02)
        self.vapi.cli("set sfdp interface-input pg0 tenant 1 disable")
        self.vapi.cli("sfdp tenant del 1")
        super(TestSfdpKillTwoWorkers, self).tearDown()

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

    def test_kill_all_sessions_across_two_workers(self):
        """kill_all kills sessions owned by two different worker threads

        With two workers, sessions land on thread index 1 (worker 0) and
        thread index 2 (worker 1).  sfdp_expire_session_now must send the
        interrupt to the correct owning thread for each session.

        With the original bug (vlib_get_main()), both interrupts would have
        gone to thread 0 (main), reaching neither worker.
        """
        # Send one SYN through each worker so sessions land on different threads
        self.pg0.add_stream([self._make_syn("198.51.100.2", 60001)], worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        self.pg0.add_stream([self._make_syn("198.51.100.3", 60002)], worker=1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 2, "Expected 2 sessions")

        threads = {s.thread_index for s in sessions}
        self.assertEqual(
            len(threads),
            2,
            f"Expected sessions on 2 different threads, got: "
            f"{[s.thread_index for s in sessions]}",
        )
        self.assertNotIn(0, threads, "Sessions must not be on main thread (0)")
        self.logger.info(f"Sessions on threads: {sorted(threads)}")

        self.vapi.sfdp_kill_session(session_index=0, is_all=True)

        self.virtual_sleep(0.02)
        remaining = self._sessions()
        self.assertEqual(
            len(remaining),
            0,
            f"Sessions not killed across workers: "
            f"{[(s.thread_index, s.session_idx) for s in remaining]}",
        )

    def test_kill_individual_sessions_on_different_workers(self):
        """Killing sessions individually works regardless of owning worker

        Creates one session per worker, kills them one by one, and verifies
        that each kill targets only the intended session.
        """
        self.pg0.add_stream([self._make_syn("198.51.100.2", 60003)], worker=0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.add_stream([self._make_syn("198.51.100.3", 60004)], worker=1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self._sessions()
        self.assertEqual(len(sessions), 2)

        threads = {s.thread_index for s in sessions}
        self.assertEqual(len(threads), 2, "Expected sessions on 2 different threads")

        # Kill the first session; the second must survive
        self.vapi.sfdp_kill_session(session_index=sessions[0].session_idx, is_all=False)
        self.virtual_sleep(0.02)

        remaining = self._sessions()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            remaining[0].session_idx,
            sessions[1].session_idx,
            "Wrong session was killed",
        )

        # Kill the second session
        self.vapi.sfdp_kill_session(session_index=sessions[1].session_idx, is_all=False)
        self.virtual_sleep(0.02)
        self.assertEqual(len(self._sessions()), 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
