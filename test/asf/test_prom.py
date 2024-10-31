from config import config
from asfframework import VppAsfTestCase, VppTestRunner
import unittest
import subprocess
import os
from vpp_qemu_utils import (
    create_host_interface,
    delete_all_host_interfaces,
    create_namespace,
    delete_all_namespaces,
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

        cls.ns_history_file = os.path.join(cls.get_tempdir(), "history_ns.txt")
        cls.if_history_name = os.path.join(cls.get_tempdir(), "history_if.txt")

        try:
            # CleanUp
            delete_all_namespaces(cls.ns_history_file)
            delete_all_host_interfaces(cls.if_history_name)

            cls.ns_name = create_namespace(cls.ns_history_file)
            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.if_history_name, cls.ns_name, "10.10.1.1/24"
            )
        except Exception as e:
            cls.logger.warning("Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_file)
        delete_all_host_interfaces(cls.if_history_name)

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
