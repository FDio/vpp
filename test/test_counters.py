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

from framework import VppTestCase
from framework import tag_fixme_vpp_workers


@tag_fixme_vpp_workers
class TestCounters(VppTestCase):
    """ Counters C Unit Tests """

    @classmethod
    def setUpClass(cls):
        super(TestCounters, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCounters, cls).tearDownClass()

    def setUp(self):
        super(TestCounters, self).setUp()

    def tearDown(self):
        super(TestCounters, self).tearDown()

    def test_counter_simple_expand(self):
        """ Simple Counter Expand """
        error = self.vapi.cli("test counter simple expand")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_counter_combined_expand(self):
        """ Combined Counter Expand """
        error = self.vapi.cli("test counter combined expand")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)
