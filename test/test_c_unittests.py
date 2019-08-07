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

import framework

from parameterized import parameterized

from framework import VppTestCase


class CUnittestVppTestCase(VppTestCase):
    """C Unit Tests (unittest.so Plugin) """

    @classmethod
    def setUpClass(cls):
        super(CUnittestVppTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(CUnittestVppTestCase, cls).tearDownClass()

    @parameterized.expand([
     #   ('bier',),
        ('bihash',),
        ('crypto',),
        ('fib',),
        ('interface link-state local0',),
        ('ipsec',),
     #   ('http server',),
        ('time-range',),
     #   ('mfib',),
        ('punt',),
        ('rbtree',),
     #   ('session all',),
        ('sparse_vec'),
        ('svm fifo all',),
        ('tcp',),
        ('time-range',),

                           ])
    def test_c_unittest(self, command):
        test_results = self.vapi.cli('test %s' % command)
        if test_results:
            self.logger.critical(test_results)
        # unittests do not report 'failed' consistently. Force lower.
        self.assertNotIn('fail', test_results.lower(),
                         "c-unit test '%s' failed. Returned: '%s'" % (
                             command, test_results ))

