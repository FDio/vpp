from config import config
from framework import VppTestCase
from asfframework import VppTestRunner
import unittest
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from random import randint


# TODO: get an actual output from "show ip6 connection-tracker"
@unittest.skipIf("ct6" in config.excluded_plugins, "Exclude CT6 plugin tests")
class TestCt6(VppTestCase):
    """CT6 plugin tests"""

    @classmethod
    def setUpClass(cls):
        super(TestCt6, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip6().resolve_ndp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestCt6, cls).tearDownClass()

    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            p = (
                Ether(src=src_if.remote_mac, dst=src_if.local_mac)
                / IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
                / UDP(sport=randint(49152, 65535), dport=5678, chksum=0)
            )
            packets.append(p)
        return packets

    def test_ct6_vapi(self):
        self.vapi.ct6_enable_disable(enable_disable=True, is_inside=True, sw_if_index=1)
        self.vapi.ct6_enable_disable(
            enable_disable=True, is_inside=False, sw_if_index=1
        )

        packets = self.create_stream(self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg_start()

        self.vapi.ct6_enable_disable(1234, 567, True, True, "pg0", "disable")

    def test_ct6_cli(self):
        self.vapi.cli("set ct6 outside pg1")
        self.vapi.cli("set ct6 inside pg1")

        packets = self.create_stream(self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)
        self.pg_start()

        reply = self.vapi.cli("show ip6 connection-tracker")
        self.assertIn("Thread 0", reply)
        reply = self.vapi.cli("test ip6 connection-tracker")
        self.assertIn("End state", reply)

        self.vapi.cli("set ct6 inside pg1 disable")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
