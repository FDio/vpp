#!/usr/bin/env python3
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

from framework import VppTestCase, VppTestRunner


class TestVppCorefileGeneration(VppTestCase):
    """test_corefile_generation.TestVppCorefileGeneration"""

    @classmethod
    def SetUpClass(cls):
        super(TestVppCorefileGeneration, cls).SetUpClass()

    @classmethod
    def TearDownClass(cls):
        super(TestVppCorefileGeneration, cls).TearDownClass()

    def test_crash(self):
        """test_crash"""
        rv = self.vapi.cli_inband('test crash')
        print('rv:')
        print(rv)


if __name__ == '__main__':
    framework.main(testRunner=VppTestRunner)

