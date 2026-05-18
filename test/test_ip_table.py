#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""IP table tests"""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


class TestIpTableCli(VppTestCase):
    """Exercise ip table / set interface ip table CLI paths."""

    IP_TABLE_ID_1 = 1
    IP_TABLE_ID_2 = 2

    pg0 = None

    @classmethod
    def setUpClass(cls):
        super(TestIpTableCli, cls).setUpClass()

        cls.create_pg_interfaces([0])
        cls.pg0.admin_up()

    @classmethod
    def tearDownClass(cls):
        super(TestIpTableCli, cls).tearDownClass()

    def setUp(self):
        super(TestIpTableCli, self).setUp()

    def tearDown(self):
        super(TestIpTableCli, self).tearDown()
        self.vapi.cli(f"set interface ip table {self.pg0.name} 0")
        self.vapi.cli(f"ip table del {self.IP_TABLE_ID_1}")
        self.vapi.cli(f"ip table del {self.IP_TABLE_ID_2}")

    def _cli(self, cmd):
        return self.vapi.cli(cmd)

    def test_ip_table_cli_no_mfib_then_full_mfib(self):
        """ip table add <id> no-mfib then ip table add <id> (same id).

        Regression for double ip_table add-callback invocation when MFIB is
        added in a second step for an existing unicast-only table.
        """
        tid = self.IP_TABLE_ID_1
        r1 = self.vapi.cli(f"ip table add {tid} no-mfib")
        r2 = self.vapi.cli(f"ip table add {tid}")
        self.assertNotIn("error", (r1 or "").lower(), msg=f"first add: {r1!r}")
        self.assertNotIn("error", (r2 or "").lower(), msg=f"second add: {r2!r}")

        fib_sum = self.vapi.cli("show ip fib summary")
        self.assertIn(
            f"ipv4-VRF:{tid}",
            fib_sum,
            "unicast FIB for table should exist after both CLI adds",
        )
        mfib_sum = self.vapi.cli("show ip mfib summary")
        self.assertIn(
            f"ipv4-VRF:{tid}",
            mfib_sum,
            "MFIB for table should exist after second CLI add",
        )

    def test_ip_table_cli_bind_no_mfib_releases_prior_mfib(self):
        """bind to full VRF then to no-mfib VRF; deleted VRF MFIB must go.

        Regression for MFIB_SOURCE_INTERFACE leak and stale mfib_index_by_sw_if
        when ip_table_bind skipped mfib_table_bind for NO_MFIB targets.
        """
        t_full = self.IP_TABLE_ID_1
        t_no_mfib = self.IP_TABLE_ID_2
        self.vapi.cli(f"ip table add {t_full}")
        self.vapi.cli(f"set interface ip table {self.pg0.name} {t_full}")
        self.vapi.cli(f"ip table add {t_no_mfib} no-mfib")
        self.vapi.cli(f"set interface ip table {self.pg0.name} {t_no_mfib}")
        self.vapi.cli(f"ip table del {t_full}")

        mfib_sum = self.vapi.cli("show ip mfib summary")
        self.assertNotIn(
            f"ipv4-VRF:{t_full}",
            mfib_sum,
            "MFIB for a deleted table must not remain after rebinding the "
            "interface to a no-mfib table (interface lock must be dropped)",
        )

    def test_ip6_table_cli_no_mfib_then_full_mfib(self):
        """ip6 table add <id> no-mfib then ip6 table add <id>."""
        tid = self.IP_TABLE_ID_1
        r1 = self.vapi.cli(f"ip6 table add {tid} no-mfib")
        r2 = self.vapi.cli(f"ip6 table add {tid}")
        self.assertNotIn("error", (r1 or "").lower(), msg=f"first add: {r1!r}")
        self.assertNotIn("error", (r2 or "").lower(), msg=f"second add: {r2!r}")

    def test_ip6_table_cli_bind_no_mfib_releases_prior_mfib(self):
        """set interface ip6 table through full VRF then no-mfib VRF."""
        t_full = self.IP_TABLE_ID_1
        t_no_mfib = self.IP_TABLE_ID_2
        self.vapi.cli(f"ip6 table add {t_full}")
        self.vapi.cli(f"set interface ip6 table {self.pg0.name} {t_full}")
        self.vapi.cli(f"ip6 table add {t_no_mfib} no-mfib")
        self.vapi.cli(f"set interface ip6 table {self.pg0.name} {t_no_mfib}")
        self.vapi.cli(f"ip6 table del {t_full}")

        mfib_sum = self.vapi.cli("show ip6 mfib summary")
        self.assertNotIn(
            f"ipv6-VRF:{t_full}",
            mfib_sum,
            "IPv6 MFIB for a deleted table must not remain after rebinding "
            "to a no-mfib table",
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
