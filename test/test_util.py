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
"""Test framework utility functions tests"""

import unittest
from framework import VppTestRunner, CPUInterface
from vpp_papi import mac_pton, mac_ntop


class TestUtil (CPUInterface, unittest.TestCase):
    """ Test framework utility tests """

    @classmethod
    def is_tagged_run_solo(cls):
        """ if the test case class is timing-sensitive - return true """
        return False

    @classmethod
    def has_tag(cls, tag):
        """ if the test case has a given tag - return true """
        try:
            return tag in cls.test_tags
        except AttributeError:
            pass
        return False

    @classmethod
    def get_cpus_required(cls):
        return 0

    def test_mac_to_binary(self):
        """ MAC to binary and back """
        mac = 'aa:bb:cc:dd:ee:ff'
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
