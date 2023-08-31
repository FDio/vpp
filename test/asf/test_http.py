#!/usr/bin/env python3
""" Vpp HTTP tests """

import unittest
import os
import subprocess
import http.client
from asfframework import VppAsfTestCase, VppTestRunner, Worker
from vpp_devices import VppTAPInterface


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
        self.vapi.cli("http tps uri tcp://0.0.0.0/8080")
        con = http.client.HTTPConnection(f"{self.server_ip4}", 8080)
        con.request("GET", f"/{fname}")
        r = con.getresponse()
        self.assertEqual(len(r.read()), 1 << 20)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
