#!/usr/bin/env python3

# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" VAPI test """

import unittest
import os
import signal
# The framework library integrates with scapy, so GPL is mandatory.
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
        var = "TEST_BR"
        built_root = os.getenv(var, None)
        self.assertIsNotNone(built_root,
                             "Environment variable `%s' not set" % var)
        executable = "%s/vapi_test/vapi_c_test" % built_root
        worker = Worker(
            [executable, "vapi client", self.shm_prefix], self.logger)
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
        var = "TEST_BR"
        built_root = os.getenv(var, None)
        self.assertIsNotNone(built_root,
                             "Environment variable `%s' not set" % var)
        executable = "%s/vapi_test/vapi_cpp_test" % built_root
        worker = Worker(
            [executable, "vapi client", self.shm_prefix], self.logger)
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
