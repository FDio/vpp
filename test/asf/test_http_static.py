from config import config
from asfframework import VppAsfTestCase, VppTestRunner
import unittest
import subprocess
import tempfile
from vpp_qemu_utils import (
    create_host_interface,
    delete_host_interfaces,
    create_namespace,
    delete_namespace,
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

        create_namespace("HttpStatic")
        create_host_interface("vppHost", "vppOut", "HttpStatic", "10.10.1.1/24")

        cls.vapi.cli("create host-interface name vppOut")
        cls.vapi.cli("set int state host-vppOut up")
        cls.vapi.cli("set int ip address host-vppOut 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_namespace(["HttpStatic"])
        delete_host_interfaces("vppHost")
        cls.temp.close()
        cls.temp2.close()
        super(TestHttpStaticVapi, cls).tearDownClass()

    def test_http_static_vapi(self):
        self.vapi.http_static_enable(
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
                "HttpStatic",
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
                "HttpStatic",
                "curl",
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

        create_namespace("HttpStatic2")
        create_host_interface("vppHost2", "vppOut2", "HttpStatic2", "10.10.1.1/24")

        cls.vapi.cli("create host-interface name vppOut2")
        cls.vapi.cli("set int state host-vppOut2 up")
        cls.vapi.cli("set int ip address host-vppOut2 10.10.1.2/24")

    @classmethod
    def tearDownClass(cls):
        delete_namespace(["HttpStatic2"])
        delete_host_interfaces("vppHost2")
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
                "HttpStatic2",
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
                "HttpStatic2",
                "curl",
                f"10.10.1.2/{self.temp2.name[5:]}",
            ],
            capture_output=True,
        )
        self.assertIn(b"Hello world2", process.stdout)

        self.vapi.cli("show http static server cache")
        self.vapi.cli("clear http static cache")
        self.vapi.cli("show http static server sessions")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
