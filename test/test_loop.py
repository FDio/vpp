#  Copyright (c) 2020. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import unittest

import framework

MAX_INSTANCE = 16 * 1024


class TestLoopbackInterface(framework.VppTestCase):
    """ Loopback interface tests """

    def test_mac_address(self):
        """ test that mac addresses of different instances don't collide. """
        s_0 = self.vapi.create_loopback_instance(
            is_specified=True, user_instance=255).sw_if_index
        s_max = self.vapi.create_loopback_instance(
            is_specified=True, user_instance=MAX_INSTANCE - 1).sw_if_index
        rv_0 = self.vapi.sw_interface_dump(sw_if_index=s_0)[0]
        rv_max = self.vapi.sw_interface_dump(sw_if_index=s_max)[0]
        self.assertNotEqual(rv_0.l2_address, rv_max.l2_address,
                            "expected different mac addresses "
                            "for different instances.")


if __name__ == '__main__':
    unittest.main(testRunner=framework.VppTestRunner)
