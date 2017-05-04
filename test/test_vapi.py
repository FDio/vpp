#!/usr/bin/env python
""" VAPI test """

from __future__ import division
import unittest
import os
import signal
import subprocess
from threading import Thread
from log import single_line_delim
from framework import VppTestCase, running_extended_tests, VppTestRunner


class Worker(Thread):
    def __init__(self, args, logger):
        self.logger = logger
        self.args = args
        self.result = None
        super(Worker, self).__init__()

    def run(self):
        executable = self.args[0]
        self.logger.debug("Running executable w/args `%s'" % self.args)
        env = os.environ.copy()
        env["CK_LOG_FILE_NAME"] = "-"
        self.process = subprocess.Popen(
            self.args, shell=False, env=env, preexec_fn=os.setpgrp,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = self.process.communicate()
        self.logger.debug("Finished running `%s'" % executable)
        self.logger.info("Return code is `%s'" % self.process.returncode)
        self.logger.info(single_line_delim)
        self.logger.info("Executable `%s' wrote to stdout:" % executable)
        self.logger.info(single_line_delim)
        self.logger.info(out)
        self.logger.info(single_line_delim)
        self.logger.info("Executable `%s' wrote to stderr:" % executable)
        self.logger.info(single_line_delim)
        self.logger.error(err)
        self.logger.info(single_line_delim)
        self.result = self.process.returncode


@unittest.skipUnless(running_extended_tests(), "part of extended tests")
class VAPITestCase(VppTestCase):
    """ VAPI test """

    def test_vapi(self):
        """ run VAPI tests """
        var = "BR"
        built_root = os.getenv(var, None)
        self.assertIsNotNone(built_root,
                             "Environment variable `%s' not set" % var)
        executable = "%s/vapi_test/vapi_test" % built_root
        worker = Worker(
            [executable, "vapi client", self.shm_prefix], self.logger)
        worker.start()
        timeout = 45
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
