from config import config
from asfframework import VppAsfTestCase, VppTestRunner, get_testcase_dirname
import unittest
import subprocess
import tempfile
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
@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestHttpStaticVapi(VppAsfTestCase):
    """enable the http static server and send requests [VAPI]"""

    @classmethod
    def setUpClass(cls):
        super(TestHttpStaticVapi, cls).setUpClass()
        # 2 temp files to improve coverage of http_cache.c
        cls.temp = tempfile.NamedTemporaryFile()
        cls.temp.write(b"Hello world")

        cls.temp2 = tempfile.NamedTemporaryFile()
        cls.temp2.write(b"Hello world2")

        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        cls.if_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_if.txt"
        )

        try:
            # CleanUp
            delete_all_namespaces(cls.ns_history_name)
            delete_all_host_interfaces(cls.if_history_name)

            cls.ns_name = create_namespace(cls.ns_history_name)
            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.if_history_name, cls.ns_name, "10.10.1.1/24"
            )

        except Exception as e:
            cls.logger.warning(f"Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        delete_all_host_interfaces(cls.if_history_name)

        cls.temp.close()
        cls.temp2.close()
        super(TestHttpStaticVapi, cls).tearDownClass()

    def test_http_static_vapi(self):
        self.vapi.http_static_enable_v5(
            www_root="/tmp",
            uri="tcp://0.0.0.0/80",
        )
        # move file pointer to the beginning
        self.temp.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                "-v",
                f"10.10.1.2/{self.temp.name[5:]}",
            ],
            capture_output=True,
        )
        if process.returncode != 0:
            self.logger.error(
                f"Subprocess failed with return code {process.returncode}"
            )
            self.logger.error(f"stderr: {process.stderr.decode()}")
            raise RuntimeError("Subprocess execution failed")
        self.logger.info(self.vapi.cli("sh session verbose"))
        self.assertIn(b"Hello world", process.stdout)
        self.assertIn(b"max-age=600", process.stderr)

        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                "--noproxy",
                "10.10.1.2",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)


@unittest.skipIf(
    "http_static" in config.excluded_plugins, "Exclude HTTP Static Server plugin tests"
)
@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled from cli")
class TestHttpStaticCli(VppAsfTestCase):
    """enable the static http server and send requests [CLI]"""

    @classmethod
    def setUpClass(cls):
        super(TestHttpStaticCli, cls).setUpClass()
        # 2 temp files to improve coverage of http_cache.c
        cls.temp = tempfile.NamedTemporaryFile()
        cls.temp.write(b"Hello world")

        cls.temp2 = tempfile.NamedTemporaryFile()
        cls.temp2.write(b"Hello world2")

        cls.ns_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_ns.txt"
        )
        cls.if_history_name = (
            f"{config.tmp_dir}/{get_testcase_dirname(cls.__name__)}/history_if.txt"
        )

        try:
            delete_all_namespaces(cls.ns_history_name)
            delete_all_host_interfaces(cls.if_history_name)

            cls.ns_name = create_namespace(cls.ns_history_name)
            cls.host_if_name, cls.vpp_if_name = create_host_interface(
                cls.if_history_name, cls.ns_name, "10.10.1.1/24"
            )

        except Exception as e:
            cls.logger.warning(f"Unable to complete setup: {e}")
            raise unittest.SkipTest("Skipping tests due to setup failure.")

        cls.vapi.cli(f"create host-interface name {cls.vpp_if_name}")
        cls.vapi.cli(f"set int state host-{cls.vpp_if_name} up")
        cls.vapi.cli(f"set int ip address host-{cls.vpp_if_name} 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_all_namespaces(cls.ns_history_name)
        delete_all_host_interfaces(cls.if_history_name)

        cls.temp.close()
        cls.temp2.close()
        super(TestHttpStaticCli, cls).tearDownClass()

    def test_http_static_cli(self):
        self.vapi.cli(
            "http static server www-root /tmp uri tcp://0.0.0.0/80 cache-size 2m"
        )
        # move file pointer to the beginning
        self.temp.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/{self.temp.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world", process.stdout)

        self.temp2.seek(0)
        process = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                self.ns_name,
                "curl",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)

        self.logger.info(self.vapi.cli("show http static server cache"))
        self.logger.info(self.vapi.cli("clear http static cache"))
        self.logger.info(self.vapi.cli("show http static server sessions"))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
