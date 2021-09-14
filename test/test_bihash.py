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

import unittest

from framework import VppTestCase, VppTestRunner, running_gcov_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestBihash(VppTestCase):
    """ Bihash Test Cases """

    @classmethod
    def setUpClass(cls):
        # increase vapi timeout, to avoid spurious "test bihash ..."
        # failures reported on aarch64 w/ test-debug
        cls.vapi_response_timeout = 20
        super(TestBihash, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestBihash, cls).tearDownClass()

    def setUp(self):
        super(TestBihash, self).setUp()

    def tearDown(self):
        super(TestBihash, self).tearDown()

    def test_bihash_unittest(self):
        """ Bihash Add/Del Test """
        error = self.vapi.cli("test bihash careful 0 verbose 0")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_bihash_thread(self):
        """ Bihash Thread Test """

        error = self.vapi.cli("test bihash threads 2 nbuckets" +
                              " 64000 careful 0 verbose 0")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_bihash_vec64(self):
        """ Bihash vec64 Test """

        error = self.vapi.cli("test bihash vec64")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    @unittest.skipUnless(running_gcov_tests, "part of code coverage tests")
    def test_bihash_coverage(self):
        """ Improve Code Coverage """

        error = self.vapi.cli("test bihash nitems 10 ncycles 3" +
                              "search 2 careful 1 verbose 2 non-random-keys")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

        error = self.vapi.cli("test bihash nitems 10 nbuckets 1 ncycles 3" +
                              "search 2 careful 1 verbose 2 non-random-keys")
        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
