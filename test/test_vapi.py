#!/usr/bin/env python3
""" VAPI test """

import unittest
import os
import signal
from framework import VppTestCase, VppTestRunner, Worker


class VAPITestCase(VppTestCase):
    """ VAPI test """

    @classmethod
    def setUpClass(cls):
        super(VAPITestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VAPITestCase, cls).tearDownClass()

    def test_vapi_c(self):
        """ run C VAPI tests """
        var = "VPP_BUILD_DIR"
        build_dir = os.getenv(var, None)
        self.assertIsNotNone(build_dir,
                             "Environment variable `%s' not set" % var)
        executable = f"{build_dir}/bin/vapi_c_test"
        worker = Worker([executable, "vapi client",
                         self.get_api_segment_prefix()], self.logger)
        worker.start()
        timeout = 60
        worker.join(timeout)
        self.logger.info("Worker result is `%s'" % worker.result)
        error = False
        if worker.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout! Worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker.process.pid), signal.SIGTERM)
                worker.join()
            except:
                self.logger.debug("Couldn't kill worker-spawned process")
                raise
        if error:
            raise Exception(
                "Timeout! Worker did not finish in %ss" % timeout)
        self.assert_equal(worker.result, 0, "Binary test return code")

    def test_vapi_cpp(self):
        """ run C++ VAPI tests """
        var = "VPP_BUILD_DIR"
        build_dir = os.getenv(var, None)
        self.assertIsNotNone(build_dir,
                             "Environment variable `%s' not set" % var)
        executable = f"{build_dir}/bin/vapi_cpp_test"
        worker = Worker([executable, "vapi client",
                         self.get_api_segment_prefix()], self.logger)
        worker.start()
        timeout = 120
        worker.join(timeout)
        self.logger.info("Worker result is `%s'" % worker.result)
        error = False
        if worker.result is None:
            try:
                error = True
                self.logger.error(
                    "Timeout! Worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker.process.pid), signal.SIGTERM)
                worker.join()
            except:
                raise Exception("Couldn't kill worker-spawned process")
        if error:
            raise Exception(
                "Timeout! Worker did not finish in %ss" % timeout)
        self.assert_equal(worker.result, 0, "Binary test return code")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
