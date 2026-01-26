import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from asfframework import VppTestRunner
from config import config
from framework import VppTestCase
from vpp_ip import VppIpPuntPolicer, VppIpPuntRedirect
from vpp_ip_route import FibPathType, VppIpRoute, VppRoutePath
from vpp_papi import VppEnum
from vpp_policer import PolicerAction, VppPolicer


class TestTracePath(VppTestCase):
    """Tracepath plugin tests"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super().tearDownClass()

    def test_tracepath(self):
        """Test tracepath CLIs"""
        # Send forwarded t
        n_fwd, n_drop = 5, 7

        # Add drop route
        drop_route = VppIpRoute(
            self,
            "192.0.2.0",
            24,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, type=FibPathType.FIB_PATH_TYPE_DROP)],
        )
        drop_route.add_vpp_config()

        # Send traffic, which will be either forwarded or dropped
        self.send_and_expect(
            self.pg0,
            list(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=1234, dport=5678)
                )
                * n_fwd
            )
            + list(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_ip4, dst="192.0.2.1")
                    / UDP(sport=1234, dport=5678)
                )
                * n_drop
            ),
            self.pg1,
            n_rx=n_fwd,
        )

        out = self.vapi.cli("show trace paths")
        self.assertEqual(out.count("Count:"), 2)
        self.assertIn(f"Count: {n_drop}", out)
        self.assertIn(f"Count: {n_fwd}", out)
        self.assertIn("ip4-drop -> error-drop -> drop", out)
        self.assertIn("ip4-rewrite -> pg1-output -> pg1-tx", out)

        # Paths sorted by count descending: index 0 = drop, index 1 = fwd.
        # Verify 'show trace path' shows only the traces belonging to that path.
        out = self.vapi.cli("show trace path 0")
        self.assertIn("ip4-drop", out)
        self.assertNotIn("ip4-rewrite", out)

        out = self.vapi.cli("show trace path 1")
        self.assertIn("ip4-rewrite", out)
        self.assertNotIn("ip4-drop", out)

        drop_route.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
