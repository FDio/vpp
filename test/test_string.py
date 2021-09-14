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


class TestString(VppTestCase):
    """ String Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestString, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestString, cls).tearDownClass()

    def setUp(self):
        super(TestString, self).setUp()

    def tearDown(self):
        super(TestString, self).tearDown()

    def test_string_unittest(self):
        """ String unit tests """
        names = ["memcpy_s",
                 "clib_memcmp", "clib_memcpy", "clib_memset",
                 "clib_strcat", "clib_strcmp", "clib_strcpy",
                 "clib_strncat", "clib_strncmp", "clib_strncpy",
                 "clib_strnlen", "clib_strstr", "clib_strtok",
                 "memcmp_s", "memcpy_s", "memset_s ",
                 "strcat_s", "strcmp_s", "strcpy_s",
                 "strncat_s", "strncmp_s", "strncpy_s",
                 "strnlen_s", "strstr_s", "strtok_s", "clib_count_equal"]

        for name in names:
            error = self.vapi.cli("test string " + name)
            if error.find("failed") != -1:
                self.logger.critical("FAILURE in the " + name + " test")
                self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
