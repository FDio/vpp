#!/usr/bin/env python
""" VAPI test """

import unittest
import os
import signal
import subprocess
from threading import Thread
from log import single_line_delim
from framework import VppTestCase, running_extended_tests, \
    running_on_centos, VppTestRunner, Worker


@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class VOMTestCase(VppTestCase):
    """ VPP Object Model Test """

    def test_vom_cpp(self):
        """ run C++ VOM tests """
        var = "BR"
        built_root = os.getenv(var, None)
        self.assertIsNotNone(built_root,
                             "Environment variable `%s' not set" % var)
        executable = "%s/vom_test/vom_test" % built_root
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
