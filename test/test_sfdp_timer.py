#!/usr/bin/env python3

import re
import time
import unittest

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from asfframework import VppTestRunner
from framework import VppTestCase


class TestSfdpTimer(VppTestCase):
    """SFDP timer wheel behavior"""

    # 1ms makes one wheel turn (2048 slots) in 2.048s.
    extra_vpp_config = ["sfdp { timer-interval-ms 1 }"]

    def setUp(self):
        super(TestSfdpTimer, self).setUp()

        self.create_pg_interfaces(range(1))
        self.pg0.admin_up()
        self.pg0.config_ip4()

        self.vapi.cli("sfdp tenant add 1 context 100")
        self.vapi.cli("set sfdp timeout tenant 1 embryonic 5")
        self.vapi.cli("set sfdp interface-input pg0 tenant 1")

    def tearDown(self):
        self.vapi.cli("set sfdp interface-input pg0 tenant 1 disable")
        self.vapi.cli("sfdp tenant del 1")
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(TestSfdpTimer, self).tearDown()

    def _active_sessions(self):
        output = self.vapi.cli("show sfdp status")
        match = re.search(r"^  active sessions: ([0-9]+)", output, re.MULTILINE)
        self.assertIsNotNone(
            match, "Unable to parse active sessions from show sfdp status"
        )
        return int(match.group(1))

    def _wait_for_active_sessions(self, expected, timeout):
        deadline = time.time() + timeout
        current = self._active_sessions()
        while current != expected and time.time() < deadline:
            time.sleep(0.1)
            current = self._active_sessions()
        self.assertEqual(current, expected)

    def _wait_for_active_sessions_gt(self, baseline, timeout):
        deadline = time.time() + timeout
        current = self._active_sessions()
        while current <= baseline and time.time() < deadline:
            time.sleep(0.1)
            current = self._active_sessions()
        self.assertGreater(current, baseline)

    def test_sfdp_rearm_after_wheel_wrap(self):
        """Long timeout survives first wheel wrap and expires later"""
        baseline = self._active_sessions()

        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="198.51.100.1")
            / TCP(sport=12345, dport=80, flags="S")
        )

        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        self._wait_for_active_sessions_gt(baseline, timeout=2.0)

        # Timeout is 5s, while one full wheel turn is 2.048s at 1ms interval.
        # If re-arm was broken, the session would be expired around first wrap.
        time.sleep(3.0)
        self.assertGreater(self._active_sessions(), baseline)

        # Session should expire around 5s after creation.
        self._wait_for_active_sessions(baseline, timeout=5.0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
