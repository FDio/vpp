from config import config
from asfframework import VppAsfTestCase, VppTestRunner
import unittest
import subprocess
import random
import string
from vpp_qemu_utils import (
    create_host_interface,
    delete_host_interfaces,
    create_namespace,
    delete_namespace,
    generate_unique_namespace_name,
    generate_unique_host_interface_name,
)


@unittest.skipIf(
    "http_static" in config.excluded_plugins, "Exclude HTTP Static Server plugin tests"
)
@unittest.skipIf("prom" in config.excluded_plugins, "Exclude Prometheus plugin tests")
@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestProm(VppAsfTestCase):
    """Prometheus plugin test"""

    @classmethod
    def setUpClass(cls):
        super(TestProm, cls).setUpClass()

        cls.ns_name = generate_unique_namespace_name()
        cls.host_name = generate_unique_host_interface_name()
        out_suffix = "".join(random.choices(string.digits, k=7))
        out_name = f"vppOut{out_suffix}"

        create_namespace(cls.ns_name)
        create_host_interface(cls.host_name, out_name, cls.ns_name, "10.10.1.1/24")

        cls.vapi.cli(f"create host-interface name {out_name}")
        cls.vapi.cli(f"set int state host-{out_name} up")
        cls.vapi.cli(f"set int ip address host-{out_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_namespace([cls.ns_name])
        delete_host_interfaces(cls.host_name)
        super(TestProm, cls).tearDownClass()

    def test_prom(self):
        """Enable HTTP Static server and prometheus exporter, get stats"""
        self.vapi.cli("http static server uri tcp://0.0.0.0/80 url-handlers")
        self.vapi.cli("prom enable")
        self.sleep(1, "wait for min-scrape-interval to expire")

        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/stats.prom",
            ],
            capture_output=True,
        )
        self.assertIn(b"TYPE", process.stdout)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
