#!/usr/bin/env python3
"""Vpp HTTP tests"""

import unittest
import http.client
from asfframework import VppAsfTestCase, VppTestRunner
from config import config


@unittest.skipIf(
    "http" in config.excluded_plugins or "http_unittest" in config.excluded_plugins,
    "Exclude HTTP plugin unit tests",
)
class TestHttpNameOwnership(VppAsfTestCase):
    """HTTP transport name ownership tests"""

    extra_vpp_plugin_config = ["plugin http_unittest_plugin.so { enable }"]

    def test_app_name_ownership(self):
        """Transport copies retain independent application names"""
        reply = self.vapi.cli("test http app-name-ownership")
        self.assertIn("accepted connections own separate names", reply)
        self.assertIn("empty names can be copied and disposed", reply)
        self.assertIn("SUCCESS", reply)
        self.assertNotIn("FAIL", reply)


@unittest.skip("Requires root")
class TestHttpTps(VppAsfTestCase):
    """HTTP test class"""

    @classmethod
    def setUpClass(cls):
        super(TestHttpTps, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestHttpTps, cls).tearDownClass()

    def setUp(self):
        self.client_ip4 = "172.0.0.2"
        self.server_ip4 = "172.0.0.1"
        self.vapi.cli(f"create tap id 0 host-ip4-addr {self.client_ip4}/24")
        self.vapi.cli(f"set int ip addr tap0 {self.server_ip4}/24")
        self.vapi.cli("set int state tap0 up")
        self.vapi.session_enable_disable(is_enable=1)

    def test_http_tps(self):
        fname = "test_file_1M"
        self.vapi.cli("http tps uri http://0.0.0.0/8080")
        con = http.client.HTTPConnection(f"{self.server_ip4}", 8080)
        con.request("GET", f"/{fname}")
        r = con.getresponse()
        self.assertEqual(len(r.read()), 1 << 20)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
