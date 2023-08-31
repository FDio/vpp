from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config


@unittest.skipIf("stn" in config.excluded_plugins, "Exclude stn plugin tests")
class TestStn(VppTestCase):
    """STN plugin tests"""

    # TODO: actually test the rules by sending packets
    @classmethod
    def setUpClass(cls):
        super(TestStn, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestStn, cls).tearDownClass()

    def test_stn_cli(self):
        """Add, dump and delete stn rule [CLI]"""
        expected = [
            "rule_index: 0",
            f"address: {self.pg0.local_ip4}",
            "iface: pg0",
            "next_node: pg0-output",
        ]
        self.vapi.cli(f"stn rule address {self.pg0.local_ip4} interface pg0")

        reply = self.vapi.cli("show stn rules")
        for entry in expected:
            self.assertIn(entry, reply)

        self.vapi.cli(f"stn rule address {self.pg0.local_ip4} interface pg0 del")

    def test_stn_vapi(self):
        """Add, dump and delete stn rule [VAPI]"""
        self.vapi.stn_add_del_rule(
            ip_address=self.pg1.local_ip4,
            sw_if_index=1,
            is_add=1,
        )
        self.vapi.stn_rules_dump()
        self.vapi.stn_add_del_rule(
            ip_address=self.pg1.local_ip4,
            sw_if_index=1,
            is_add=0,
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
