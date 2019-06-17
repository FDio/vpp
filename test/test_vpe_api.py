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

import unittest
from framework import VppTestCase


class TestVpeApi(VppTestCase):
    """TestVpeApi"""

    @unittest.skip('Needs: https://gerrit.fd.io/r/#/c/20154/ or '
                   'https://gerrit.fd.io/r/#/c/20208/ '
                   'merged to pass.')
    def test_api_strerror_all_default(self):
        rv = self.vapi.api_strerror_dump()

        self.assertTrue(rv)

    def test_api_strerror_all_specified(self):
        rv = self.vapi.api_strerror_dump(api_errno=0x7fffffff)

        self.assertTrue(rv)

    def test_api_strerror_neg127(self):
        rv = self.vapi.api_strerror_dump(api_errno=-127)

        self.assertEqual(len(rv), 1)
        self.assertEqual(-127, rv[0].api_errno)

    def test_api_strerror_pos127(self):
        rv = self.vapi.api_strerror_dump(api_errno=127)

        self.assertFalse(rv)
