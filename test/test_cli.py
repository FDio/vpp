#!/usr/bin/env python

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

import timeout_decorator

from framework import VppTestCase, VppTestRunner


class TestCli(VppTestCase):
    """Tests for identified CLI issues.  (pls. ref. patch or jira in unittest)"""

    @timeout_decorator.timeout(2)
    def test_cli_show_node_loop(self):
        """show node deadloop. (https://gerrit.fd.io/r/#/c/18310/) """
        output = self.vapi.cli('show node foo')
        self.assertIn("show node: unknown input: 'foo'", output)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
