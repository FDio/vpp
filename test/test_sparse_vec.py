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

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestSparseVec(VppTestCase):
    """ SparseVec Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestSparseVec, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSparseVec, cls).tearDownClass()

    def setUp(self):
        super(TestSparseVec, self).setUp()

    def tearDown(self):
        super(TestSparseVec, self).tearDown()

    def test_string_unittest(self):
        """ SparseVec unit tests """
        error = self.vapi.cli("test sparse_vec")
        if error.find("failed") != -1:
            self.logger.critical("FAILURE in the sparse_vec test")
        self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
