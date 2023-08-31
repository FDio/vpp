#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import asfframework
import vpp_papi_provider

F64_ONE = 1.0


class TestEndian(asfframework.VppAsfTestCase):
    """TestEndian"""

    def test_f64_endian_value(self):
        try:
            rv = self.vapi.get_f64_endian_value(f64_one=F64_ONE)
            self.assertEqual(
                rv.f64_one_result,
                F64_ONE,
                "client incorrectly deserializes f64 values.  "
                "Expected: %r. Received: %r." % (F64_ONE, rv.f64_one_result),
            )
        except vpp_papi_provider.UnexpectedApiReturnValueError:
            self.fail("client incorrectly serializes f64 values.")

    def test_get_f64_increment_by_one(self):
        expected = 43.0
        rv = self.vapi.get_f64_increment_by_one(f64_value=42.0)
        self.assertEqual(
            rv.f64_value,
            expected,
            "Expected %r, received:%r." % (expected, rv.f64_value),
        )
