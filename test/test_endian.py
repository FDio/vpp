# Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import framework
import vpp_papi_provider

F64_ONE = 1.0


class TestEndian(framework.VppTestCase):
    """TestEndian"""

    def test_f64_endian_value(self):
        try:
            rv = self.vapi.get_f64_endian_value(f64_one=F64_ONE)
            self.assertEqual(rv.f64_one_result, F64_ONE,
                             "client incorrectly deserializes f64 values.  "
                             "Expected: %r. Received: %r." % (
                                 F64_ONE, rv.f64_one_result))
        except vpp_papi_provider.UnexpectedApiReturnValueError:
            self.fail('client incorrectly serializes f64 values.')

    def test_get_f64_increment_by_one(self):
        expected = 43.0
        rv = self.vapi.get_f64_increment_by_one(f64_value=42.0)
        self.assertEqual(rv.f64_value, expected, 'Expected %r, received:%r.'
                         % (expected, rv.f64_value))
