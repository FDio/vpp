#!/usr/bin/env python
""" Vpp VCL tests """

import unittest
import os
import signal
import subprocess
from threading import Thread
from log import single_line_delim
from framework import VppTestCase, running_extended_tests, \
    running_on_centos, VppTestRunner, Worker


class VCLTestCase(VppTestCase):
    """ VPP Communications Library Test """

    server_addr = "127.0.0.1"
    server_port = "22000"

    @classmethod
    def setUpClass(cls):
        super(VCLTestCase, cls).setUpClass()

        cls.vapi.session_enable_disable(is_enabled=1)

    def setUp(self):
        super(VCLTestCase, self).setUp()

    def test_vcl_cutthru(self):
        """ run VCL cut-thru test """
        timeout = 5
        var = "VPP_TEST_BUILD_DIR"
        build_dir = os.getenv(var, None)
        self.assertIsNotNone(build_dir,
                             "Environment variable `%s' not set" % var)
        vcl_exe_dir = "%s/vpp/.libs" % build_dir
        executable = "%s/vcl_test_server" % vcl_exe_dir
        worker_server = Worker([executable, self.server_port], self.logger)
        worker_server.env["VCL_API_PREFIX"] = self.shm_prefix
#        worker_server.env["VCL_DEBUG"] = "2"
        worker_server.env["VCL_APP_SCOPE_LOCAL"] = "true"
        worker_server.start()
        executable = "%s/vcl_test_client" % vcl_exe_dir
        worker_client = Worker(
            [executable, self.server_addr, self.server_port,
             "-E", "Hello, world!", "-X"], self.logger)
        worker_client.env["VCL_API_PREFIX"] = self.shm_prefix
#        worker_client.env["VCL_DEBUG"] = "2"
        worker_client.env["VCL_APP_SCOPE_LOCAL"] = "true"
        worker_client.start()
        worker_client.join(timeout)
        self.logger.info("Client worker result is `%s'" % worker_client.result)
        error = False
        if worker_client.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout! Client worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker_client.process.pid),
                          signal.SIGTERM)
                worker_client.join()
            except:
                raise Exception("Couldn't kill client worker-spawned process")
        if error:
            os.killpg(os.getpgid(worker_server.process.pid), signal.SIGTERM)
            worker_server.join()
            raise Exception(
                "Timeout! Client worker did not finish in %ss" % timeout)
        self.assert_equal(worker_client.result, 0, "Binary test return code")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
