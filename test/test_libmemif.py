#!/usr/bin/env python3
""" Vpp LibMemif tests """

import unittest
import os
import subprocess
import signal
import glob
from config import config
from framework import VppTestCase, VppTestRunner, Worker
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath, FibPathProto

loopback_test = f"{config.vpp_build_dir}/libmemif/examples/loopback"
icmp_responder_test = f"{config.vpp_build_dir}/libmemif/examples/icmp_responder"


def have_app(app):
    try:
        subprocess.check_output([app, "-v"])
    except (subprocess.CalledProcessError, OSError):
        return False
    return True


_have_loopback_test = have_app(loopback_test)
_have_icmp_responder_test = have_app(icmp_responder_test)


class LibMemifAppWorker(Worker):
    """LibMemif Test Application Worker"""

    class LibraryNotFound(Exception):
        pass

    def __init__(
        self, appname, executable_args, logger, env=None, role=None, *args, **kwargs
    ):
        self.role = role

        if env is None:
            env = {}
        app = appname
        self.args = [app] + executable_args
        super(LibMemifAppWorker, self).__init__(self.args, logger, env, *args, **kwargs)


class LibMemifTestCase(VppTestCase):
    """LibMemif Test Class"""

    session_startup = ["poll-main"]

    @classmethod
    def setUpClass(cls):
        super(LibMemifTestCase, cls).setUpClass()

    def show_commands_at_teardown(self):
        cli = "show run"
        self.logger.info(self.vapi.ppcli(cli))

    @classmethod
    def tearDownClass(cls):
        super(LibMemifTestCase, cls).tearDownClass()

    def setUp(self):
        super(LibMemifTestCase, self).setUp()

    @unittest.skipUnless(_have_loopback_test, "'%s' not found, Skipping.")
    def test_0010_libmemif_loopback(self):
        """run libmemif loopback test"""
        correct_output_index = subprocess.check_output([loopback_test]).find(
            b"INFO: Received correct data."
        )
        self.assertTrue(
            correct_output_index >= 0,
            "loopback test output did not contain expected text",
        )

    @unittest.skipUnless(_have_icmp_responder_test, "'%s' not found, Skipping.")
    def test_0020_libmemif_echo_responder(self):
        """run libmemif responder test"""
        self.memif_socket_path = f"{self.tempdir}/memif.sock"
        if os.path.exists(self.memif_socket_path):
            os.remove(self.memif_socket_path)

        self.libmemif_app = LibMemifAppWorker(
            icmp_responder_test,
            ["-r", "master", "-s", self.memif_socket_path],
            self.logger,
            {},
            "server",
        )
        self.libmemif_app.start()
        while self.libmemif_app.process is None:
            self.sleep(0.1)
        if not os.path.isdir("/proc/{}".format(self.libmemif_app.process.pid)):
            self.logger.error(
                "libmemif_app finished, result: {}".format(self.libmemif_app.result)
            )
            self.fail("Could not start libmemif_app")

        self.logger.debug(
            self.vapi.cli(f"create memif socket id 1 filename {self.memif_socket_path}")
        )
        self.logger.debug(self.vapi.cli("create interface memif socket-id 1"))
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("set int state memif1/0 up"))
        self.logger.debug(self.vapi.cli("set int ip address memif1/0 192.168.1.2/24"))
        self.logger.debug(self.vapi.cli("show interface"))
        output = self.vapi.cli("arping 192.168.1.1 memif1/0")
        self.logger.debug(output)
        self.assertTrue(
            output.find("Received 1 ARP Replies from aa:aa:aa:aa:aa:aa") >= 0,
            "Could not find the expected arping reply",
        )

        output = self.vapi.cli("ping 192.168.1.1 repeat 1")
        self.sleep(1)
        self.assertTrue(
            output.find("Statistics: 1 sent, 1 received, 0% packet loss") >= 0,
            "Could not find the expected ping reply",
        )
        if os.path.isdir("/proc/{}".format(self.libmemif_app.process.pid)):
            self.logger.info(
                "Killing server worker process (pid %d)" % self.libmemif_app.process.pid
            )
            os.killpg(os.getpgid(self.libmemif_app.process.pid), signal.SIGTERM)
            self.libmemif_app.join(10)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
