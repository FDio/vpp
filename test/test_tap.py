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
import os

from framework import VppTestCase, VppTestRunner
from vpp_devices import VppTAPInterface


def check_tuntap_driver_access():
    return os.access("/dev/net/tun", os.R_OK and os.W_OK)


@unittest.skip("Requires root")
class TestTAP(VppTestCase):
    """ TAP Test Case """

    def test_tap_add_del(self):
        """Create TAP interface"""
        tap0 = VppTAPInterface(self, tap_id=0)
        tap0.add_vpp_config()
        self.assertTrue(tap0.query_vpp_config())

    def test_tap_dump(self):
        """ Test api dump w/ and w/o sw_if_index filtering"""
        MAX_INSTANCES = 10
        tap_instances = []
        for instance in range(MAX_INSTANCES):
            i = VppTAPInterface(self, tap_id=instance)
            i.add_vpp_config()
            tap_instances.append(i)
        details = self.vapi.sw_interface_tap_v2_dump()
        self.assertEqual(MAX_INSTANCES, len(details))
        details = self.vapi.sw_interface_tap_v2_dump(
            tap_instances[5].sw_if_index)
        self.assertEqual(1, len(details))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
