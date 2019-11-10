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
import datetime
import time
import unittest

from framework import VppTestCase

enable_print = False


class TestVpeApi(VppTestCase):
    """TestVpeApi"""

    def test_log_dump_default(self):
        rv = self.vapi.cli('test log notice fib entry this is a test')
        rv = self.vapi.log_dump()
        if enable_print:
            print('\n'.join([str(v) for v in rv]))
        self.assertTrue(rv)

    def test_log_dump_timestamp_0(self):
        rv = self.vapi.cli('test log notice fib entry this is a test')
        rv = self.vapi.log_dump(start_timestamp=0.0)
        if enable_print:
            print('\n'.join([str(v) for v in rv]))
        self.assertTrue(rv)

    def test_log_dump_timestamp_future(self):
        rv = self.vapi.cli('test log debug fib entry test')
        rv = self.vapi.log_dump(start_timestamp=time.time() + 60.0)
        if enable_print:
            print('\n'.join([str(v) for v in rv]))
        self.assertFalse(rv)

    def test_show_vpe_system_time(self):
        local_start_time = datetime.datetime.now()
        rv = self.vapi.show_vpe_system_time()
        self.assertTrue(rv.vpe_system_time > local_start_time -
                        datetime.timedelta(hours=1.0),
                        'system times differ by more than an hour.')
        if enable_print:
            print('\n'.join([str(v) for v in rv]))
            print('%r %s' % (rv.vpe_system_time,
                             rv.vpe_system_time))
