#!/usr/bin/env python3
""" VAPI test """

import unittest
import os
import signal
from config import config
from asfframework import VppAsfTestCase, VppTestRunner, Worker


class VAPITestCase(VppAsfTestCase):
    """VAPI test"""

    @classmethod
    def setUpClass(cls):
        super(VAPITestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VAPITestCase, cls).tearDownClass()

    def run_vapi_c(self, use_uds):
        """run C VAPI tests"""
        executable = f"{config.vpp_build_dir}/vpp/bin/vapi_c_test"
        path = self.get_api_sock_path() if use_uds else self.get_api_segment_prefix()
        worker = Worker(
            [executable, "vapi client", path, "1" if use_uds else "0"], self.logger
        )
        worker.start()
        timeout = 60
        worker.join(timeout)
        self.logger.info("Worker result is `%s'" % worker.result)
        error = False
        if worker.result is None:
            try:
                error = True
                self.logger.error("Timeout! Worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker.process.pid), signal.SIGTERM)
                worker.join()
            except:
                self.logger.debug("Couldn't kill worker-spawned process")
                raise
        if error:
            raise Exception("Timeout! Worker did not finish in %ss" % timeout)
        self.assert_equal(worker.result, 0, "Binary test return code")

    def test_vapi_c_shm(self):
        self.run_vapi_c(False)

    def test_vapi_c_uds(self):
        self.run_vapi_c(True)

    def run_vapi_cpp(self, use_uds):
        """run C++ VAPI tests"""
        executable = f"{config.vpp_build_dir}/vpp/bin/vapi_cpp_test"
        path = self.get_api_sock_path() if use_uds else self.get_api_segment_prefix()
        worker = Worker(
            [executable, "vapi client", path, "1" if use_uds else "0"], self.logger
        )
        worker.start()
        timeout = 120
        worker.join(timeout)
        self.logger.info("Worker result is `%s'" % worker.result)
        error = False
        if worker.result is None:
            try:
                error = True
                self.logger.error("Timeout! Worker did not finish in %ss" % timeout)
                os.killpg(os.getpgid(worker.process.pid), signal.SIGTERM)
                worker.join()
            except:
                raise Exception("Couldn't kill worker-spawned process")
        if error:
            raise Exception("Timeout! Worker did not finish in %ss" % timeout)
        self.assert_equal(worker.result, 0, "Binary test return code")

    def test_vapi_cpp_shm(self):
        self.run_vapi_cpp(False)

    def test_vapi_cpp_uds(self):
        self.run_vapi_cpp(True)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
