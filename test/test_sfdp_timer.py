#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

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
        self.vapi.cli("set sfdp timeout tenant 1 embryonic 1")
        self.vapi.cli("set sfdp interface-input pg0 tenant 1")

    def tearDown(self):
        self.vapi.cli("set sfdp interface-input pg0 tenant 1 disable")
        self.vapi.cli("sfdp tenant del 1")
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(TestSfdpTimer, self).tearDown()

    def _tenant_session_ids(self):
        output = self.vapi.cli("show sfdp session-table tenant 1")
        return set(re.findall(r"0x[0-9a-fA-F]+", output))

    def _wait_for_session_appear(self, timeout):
        deadline = time.time() + timeout
        ids = self._tenant_session_ids()
        while not ids and time.time() < deadline:
            time.sleep(0.1)
            ids = self._tenant_session_ids()
        self.assertTrue(ids, "No SFDP session created for tenant 1")
        return next(iter(ids))

    def _wait_for_session_disappear(self, session_id, timeout):
        deadline = time.time() + timeout
        ids = self._tenant_session_ids()
        while session_id in ids and time.time() < deadline:
            time.sleep(0.1)
            ids = self._tenant_session_ids()
        self.assertNotIn(session_id, ids)

    def test_sfdp_timer_interval_basic_expiry(self):
        """Session expires with non-default timer interval"""
        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="198.51.100.1")
            / TCP(sport=12345, dport=80, flags="S")
        )

        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        session_id = self._wait_for_session_appear(timeout=4.0)

        # Embryonic timeout is 1s; with a non-default timer interval (1ms),
        # the session should still expire predictably.
        self._wait_for_session_disappear(session_id, timeout=4.0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
