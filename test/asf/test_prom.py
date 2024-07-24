from config import config
from asfframework import VppAsfTestCase, VppTestRunner
import unittest
import subprocess
from vpp_qemu_utils import (
    create_host_interface,
    delete_host_interfaces,
    create_namespace,
    delete_namespace,
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

        create_namespace("HttpStaticProm")
        create_host_interface("vppHost", "vppOut", "HttpStaticProm", "10.10.1.1/24")

        cls.vapi.cli("create host-interface name vppOut")
        cls.vapi.cli("set int state host-vppOut up")
        cls.vapi.cli("set int ip address host-vppOut 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_namespace(["HttpStaticProm"])
        delete_host_interfaces("vppHost")
        super(TestProm, cls).tearDownClass()

    def test_prom(self):
        """Enable HTTP Static server and prometheus exporter, get stats"""
        self.vapi.cli("http static server uri tcp://0.0.0.0/80 url-handlers")
        self.vapi.cli("prom enable")

        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                "HttpStaticProm",
                "curl",
                "-v",
                "-s",
                f"10.10.1.2/stats.prom",
            ],
            capture_output=True,
        )
        self.logger.error(process.stderr)
        self.assertIn(b"TYPE", process.stdout)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
