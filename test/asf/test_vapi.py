#!/usr/bin/env python3
"""VAPI test"""

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

    def run_vapi_c(self, path, transport):
        executable = f"{config.vpp_build_dir}/vpp/bin/vapi_c_test"
        worker = Worker([executable, "vapi client", path, transport], self.logger)
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
        """run C VAPI tests (over shared memory)"""
        self.run_vapi_c(self.get_api_segment_prefix(), "shm")

    def test_vapi_c_uds(self):
        """run C VAPI tests (over unix domain socket)"""
        self.run_vapi_c(self.get_api_sock_path(), "uds")

    def run_vapi_cpp(self, path, transport):
        """run C++ VAPI tests"""
        executable = f"{config.vpp_build_dir}/vpp/bin/vapi_cpp_test"
        worker = Worker([executable, "vapi client", path, transport], self.logger)
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
        """run C++ VAPI tests (over shared memory)"""
        self.run_vapi_cpp(self.get_api_segment_prefix(), "shm")

    def test_vapi_cpp_uds(self):
        """run C++ VAPI tests (over unix domain socket)"""
        self.run_vapi_cpp(self.get_api_sock_path(), "uds")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
