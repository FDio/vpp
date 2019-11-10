#!/usr/bin/env python3
""" VAPI test """

import os
import signal
import unittest

from framework import (
    VppTestCase,
    VppTestRunner,
    Worker,
    running_extended_tests,
)


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class VOMTestCase(VppTestCase):
    """ VPP Object Model Test """

    @classmethod
    def setUpClass(cls):
        super(VOMTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(VOMTestCase, cls).tearDownClass()

    def test_vom_cpp(self):
        """ run C++ VOM tests """
        var = "TEST_DIR"
        built_root = os.getenv(var, None)
        self.assertIsNotNone(built_root,
                             "Environment variable `%s' not set" % var)
        executable = "%s/build/vom_test/vom_test" % built_root
        worker = Worker(
            [executable, "vpp object model", self.shm_prefix], self.logger)
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
