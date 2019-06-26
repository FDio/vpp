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
import time
import unittest
from framework import VppTestCase


class TestVpeApi(VppTestCase):
    """TestVpeApi"""

    def test_log_dump_default(self):
        rv = self.vapi.cli('test log notice fib entry this is a test')
        rv = self.vapi.log_dump()
        # print('\n'.join([str(v) for v in rv]))
        self.assertTrue(rv)

    def test_log_dump_timestamp_0(self):
        rv = self.vapi.cli('test log notice fib entry this is a test')
        rv = self.vapi.log_dump(start_timestamp=0.0)
        # print('\n'.join([str(v) for v in rv]))
        self.assertTrue(rv)

    @unittest.skip('Requires https://gerrit.fd.io/r/#/c/19581/ '
                   'to use timestamp_ticks.')
    def test_log_dump_timestamp_future(self):
        rv = self.vapi.cli('test log debug fib entry test')
        rv = self.vapi.log_dump(start_timestamp=time.time() + 60.0)
        # print('\n'.join([str(v) for v in rv]))
        self.assertFalse(rv)

    @unittest.skip('Requires https://gerrit.fd.io/r/#/c/19581/ '
                   'to use timestamp_ticks.')
    def test_show_vpe_system_time_ticks(self):
        rv = self.vapi.show_vpe_system_time_ticks()
        self.assertTrue(rv.vpe_system_time_ticks > 1.0)
