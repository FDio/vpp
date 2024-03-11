from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config
from scapy.layers.l2 import Ether
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
    LLDPDU,
)


@unittest.skipIf("lldp" in config.excluded_plugins, "Exclude lldp plugin tests")
class TestLldpCli(VppTestCase):
    """LLDP plugin tests [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestLldpCli, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestLldpCli, cls).tearDownClass()

    def create_frame(self, src_if):
        if src_if == self.pg0:
            chassis_id = "01:02:03:04:05:06"
            port_id = "07:08:09:0a:0b:0c"
        else:
            chassis_id = "11:12:13:14:15:16"
            port_id = "17:18:19:1a:1b:1c"

        lldp_frame = (
            Ether(src=src_if.remote_mac, dst="01:80:C2:00:00:03")
            / LLDPDU()
            / LLDPDUChassisID(subtype=4, id=chassis_id)
            / LLDPDUPortID(subtype=3, id=port_id)
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUEndOfLLDPDU()
        )

        return lldp_frame

    def test_lldp_cli(self):
        """Enable, send frames, show, disable, verify"""

        packets = self.create_frame(self.pg0)
        self.pg0.add_stream(packets)
        packets = self.create_frame(self.pg1)
        self.pg1.add_stream(packets)

        self.vapi.cli("set lldp system-name VPP tx-hold 4 tx-interval 10")
        # configure everything to increase coverage
        self.vapi.cli(
            f"set interface lldp pg0 port-desc vtf:pg0 mgmt-ip4"
            f" {self.pg0.local_ip4} mgmt-ip6 {self.pg0.local_ip6} mgmt-oid '1234'"
        )
        self.vapi.cli("set interface lldp pg1 port-desc vtf:pg1")

        self.pg_start()

        reply = self.vapi.cli("show lldp")
        expected = [
            "01:02:03:04:05:06",
            "07:08:09:0a:0b:0c",
            "11:12:13:14:15:16",
            "17:18:19:1a:1b:1c",
        ]
        for entry in expected:
            self.assertIn(entry, reply)

        # only checking for an output
        reply = self.vapi.cli("show lldp detail")
        self.assertIn("Local Interface name: pg0", reply)
        self.assertIn("Local Interface name: pg1", reply)

        # disable LLDP on an interface and verify
        self.vapi.cli("set interface lldp pg0 disable")
        reply = self.vapi.cli("show lldp")
        self.assertNotIn("pg0", reply)


@unittest.skipIf("lldp" in config.excluded_plugins, "Exclude lldp plugin tests")
class TestLldpVapi(VppTestCase):
    """LLDP plugin test [VAPI]"""

    @classmethod
    def setUpClass(cls):
        super(TestLldpVapi, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestLldpVapi, cls).tearDownClass()

    def test_lldp_vapi(self):
        """Enable, show, disable, verify"""
        self.vapi.lldp_config(tx_hold=4, tx_interval=1, system_name="VAPI")
        self.vapi.sw_interface_set_lldp(
            sw_if_index=1,
            mgmt_ip4=self.pg0.local_ip4,
            port_desc="vtf:pg0",
        )
        self.vapi.sw_interface_set_lldp(
            sw_if_index=2,
            mgmt_ip4=self.pg1.local_ip4,
            port_desc="vtf:pg1",
            mgmt_ip6=self.pg1.local_ip6,
            mgmt_oid=b"1",
        )

        # only check if LLDP gets enabled, functionality is tested in CLI class
        reply = self.vapi.cli("show lldp")
        self.assertIn("pg1", reply)

        self.vapi.sw_interface_set_lldp(sw_if_index=2, enable=False)
        reply = self.vapi.cli("show lldp")
        self.assertNotIn("pg1", reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
