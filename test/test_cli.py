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
"""CLI functional tests"""

import datetime
import time
import unittest

from vpp_papi import VPPIOError

from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # using the framework default
        cls.vapi_response_timeout = 5
        super(TestCLI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLI, cls).tearDownClass()

    def setUp(self):
        super(TestCLI, self).setUp()

    def tearDown(self):
        super(TestCLI, self).tearDown()

    def test_cli_retval(self):
        """ CLI inband retval """
        rv = self.vapi.papi.cli_inband(cmd='this command does not exist')
        self.assertNotEqual(rv.retval, 0)

        rv = self.vapi.papi.cli_inband(cmd='show version')
        self.assertEqual(rv.retval, 0)

    def test_long_cli_delay(self):
        """ Test that VppApiClient raises VppIOError if timeout."""  # noqa
        with self.assertRaises(VPPIOError) as ctx:
            rv = self.vapi.papi.cli_inband(cmd='wait 10')

    def test_long_cli_delay_override(self):
        """ Test per-command _timeout option."""  # noqa
        rv = self.vapi.papi.cli_inband(cmd='wait 10', _timeout=15)
        self.assertEqual(rv.retval, 0)


class TestCLIExtendedVapiTimeout(VppTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = " CLI Test Case w/ Extended (%ssec) Vapi Timeout " \
                      % cls.vapi_response_timeout
        super(TestCLIExtendedVapiTimeout, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLIExtendedVapiTimeout, cls).tearDownClass()

    def setUp(self):
        super(TestCLIExtendedVapiTimeout, self).setUp()

    def tearDown(self):
        super(TestCLIExtendedVapiTimeout, self).tearDown()

    def test_long_cli_delay(self):
        """ Test that delayed result returns with extended timeout."""
        wait_secs = self.vapi_response_timeout - 1

        # get vpp time as float
        start = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True).vpe_system_time
        rv = self.vapi.papi.cli_inband(cmd='wait %s' % wait_secs)
        now = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True).vpe_system_time

        # assume that the overhead of the measurement is not more that .5 sec.
        self.assertEqual(round(now - start), wait_secs)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
