from config import config
from asfframework import VppAsfTestCase, VppTestRunner
import unittest
import subprocess
import tempfile
import os
from vpp_qemu_utils import (
    create_host_interface,
    delete_host_interfaces,
    delete_host_interfaces_from_file,
    create_namespace,
    delete_namespace,
    delete_namespaces_from_file,
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

        cls.ns_file_name = os.path.join(tempfile.gettempdir(), f"{cls.__name__}_ns.txt")
        cls.if_file_name = os.path.join(tempfile.gettempdir(), f"{cls.__name__}_if.txt")

        try:
            # CleanUp
            delete_namespaces_from_file(cls.ns_file_name)
            delete_host_interfaces_from_file(cls.if_file_name)

            cls.ns_name = create_namespace()

            with open(cls.ns_file_name, "a") as ns_file:
                ns_file.write(f"{cls.ns_name}\n")

            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.ns_name, "10.10.1.1/24"
            )

            with open(cls.if_file_name, "a") as if_file:
                if_file.write(f"{cls.host_if_name}\n")
        except Exception as e:
            cls.logger.warning("Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_namespace(cls.ns_name)
        delete_namespaces_from_file(cls.ns_file_name)

        delete_host_interfaces(cls.host_if_name)
        delete_host_interfaces_from_file(cls.if_file_name)

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
