# Copyright (c) 2019 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from framework import VppTestCase


class TestTiming(VppTestCase):
    """Tests involving timing in one way or another."""

    def test_wait_with_barrier(self):
        expected = 0.1
        rv = self.vapi.wait_with_barrier(wait=expected)
        self.assertAlmostEqual(
            rv.inner_time, expected, places=5, msg='Expected %r, received:%r.'
            % (expected, rv.inner_time))
        self.assertAlmostEqual(
            rv.outer_time, expected, places=5, msg='Expected %r, received:%r.'
            % (expected, rv.outer_time))
        self.assertGreater(rv.outer_time, rv.inner_time, 'Outer %r, inner:%r.'
                           % (rv.outer_time, rv.inner_time))
